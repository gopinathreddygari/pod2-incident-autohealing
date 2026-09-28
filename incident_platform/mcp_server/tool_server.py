"""In-process MCP tool server: ``list_tools()`` / ``call_tool()``.

Why this shape: the Model Context Protocol splits tool use into discovery
(``tools/list``) and invocation (``tools/call``). Results come back as
``{"content": [...], "isError": bool}``, so tool failures are *data* the
caller inspects, not exceptions that escape. Every caller in this codebase
goes through exactly these two methods. Moving the server out of process
(stdio or streamable HTTP via the official ``mcp`` SDK) means putting a
transport in front of this class. No agent code changes. See ADR-02.

Every ``call_tool`` passes through the same four protections, in order:
    schema validation -> argument guardrail -> per-tool circuit breaker -> audit + span

All nine handlers are **mocked**. They read and mutate a small in-memory
``MockCluster`` instead of calling the Kubernetes API, Prometheus or Datadog
(``correlate_telemetry`` stands in for both metrics backends). Each tool
carries a ``risk_class`` that the HITL gate uses (see ADR-04). The
mutation is real enough that post-remediation verification is genuine:
applying the wrong action leaves the service unhealthy.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable

from state.circuit_breaker import BreakerRegistry, CircuitOpenError


class ToolExecutionError(Exception):
    pass


# Risk classes drive the HITL gate (hitl/hitl_gate.py; rationale in ADR-04).
RISK_READ_ONLY = "read_only"        # observes only
RISK_SAFE_RESET = "safe_reset"      # resets runtime state; desired state unchanged -> autonomous
RISK_CONFIG_PATCH = "config_patch"  # changes desired-state spec (replicas, image patch) -> gated
RISK_DESTRUCTIVE = "destructive"    # withdraws a release / evicts workloads -> gated
RISK_FAILOVER = "failover"          # moves traffic between regions/clusters -> gated
RISK_CLASSES = (RISK_READ_ONLY, RISK_SAFE_RESET, RISK_CONFIG_PATCH, RISK_DESTRUCTIVE, RISK_FAILOVER)


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    input_schema: dict[str, Any]
    read_only: bool
    destructive: bool
    command_template: str
    blast_radius: str
    risk_class: str

    def to_mcp(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
            "annotations": {"readOnlyHint": self.read_only, "destructiveHint": self.destructive,
                            "riskClass": self.risk_class},
        }


def _schema(required: dict[str, str], optional: dict[str, str] | None = None) -> dict[str, Any]:
    props = {k: {"type": t} for k, t in {**required, **(optional or {})}.items()}
    return {"type": "object", "properties": props, "required": list(required), "additionalProperties": False}


TOOL_SPECS: list[ToolSpec] = [
    ToolSpec(
        "fetch_k8s_logs",
        "Fetch recent container logs for a workload.",
        _schema({"namespace": "string", "workload": "string"}, {"tail_lines": "integer"}),
        read_only=True,
        destructive=False,
        command_template="kubectl logs -l app={workload} -n {namespace} --tail=50",
        blast_radius="none (read-only)",
        risk_class=RISK_READ_ONLY,
    ),
    ToolSpec(
        "correlate_telemetry",
        "Correlate metrics and alerts for a service over a time window (stands in for Prometheus and "
        "Datadog); also used for post-remediation health checks.",
        _schema({"namespace": "string", "service": "string"}, {"window_minutes": "integer"}),
        read_only=True,
        destructive=False,
        # Prometheus query proxied through the API server, so it is a kubectl command like the rest.
        command_template=("kubectl get --raw /api/v1/namespaces/monitoring/services/prometheus:9090/proxy"
                          '/api/v1/query?query=up{{service="{service}",namespace="{namespace}"}}'),
        blast_radius="none (read-only)",
        risk_class=RISK_READ_ONLY,
    ),
    ToolSpec(
        "restart_service",
        "Rolling restart of a service's pods (replicas are replaced one at a time). Use when pods are wedged "
        "or crash-looping but a fresh start would be healthy (e.g. after a dependency or DNS blip).",
        _schema({"namespace": "string", "workload": "string"}),
        read_only=False,
        destructive=False,
        command_template="kubectl rollout restart deployment/{workload} -n {namespace}",
        blast_radius="pods of deployment/{workload} replaced one at a time; no capacity loss",
        risk_class=RISK_SAFE_RESET,
    ),
    ToolSpec(
        "clear_pod_cache",
        "Flush the in-memory caches of a workload's pods without restarting them. Use when the application "
        "serves stale data from its own cache; not for DNS problems, crash loops or slowness.",
        _schema({"namespace": "string", "workload": "string"}),
        read_only=False,
        destructive=False,
        command_template="kubectl annotate deployment/{workload} -n {namespace} cache.cloudscale.io/flush=now --overwrite",
        blast_radius="in-memory caches of deployment/{workload} are emptied; brief cold-cache latency",
        risk_class=RISK_SAFE_RESET,
    ),
    ToolSpec(
        "scale_deployment",
        "Set the replica count of a deployment. Use when load exceeds capacity: OOM kills under load, or "
        "latency from a capacity shortfall.",
        _schema({"namespace": "string", "deployment": "string", "replicas": "integer"}),
        read_only=False,
        destructive=False,
        command_template="kubectl scale deployment/{deployment} --replicas={replicas} -n {namespace}",
        blast_radius="deployment/{deployment} scaled to {replicas} replicas; extra cluster cost",
        risk_class=RISK_CONFIG_PATCH,
    ),
    ToolSpec(
        "apply_hotfix",
        "Apply a vetted strategic-merge patch (by patch id) to a deployment's spec. Use when a known defect "
        "or a bad configuration value has a vetted patch in the hotfix catalog.",
        _schema({"namespace": "string", "deployment": "string", "patch": "string"}),
        read_only=False,
        destructive=True,
        # `kubectl patch -p` expects JSON; the tool argument is a vetted catalog id, and the patch
        # itself is a reviewed file from HOTFIX_CATALOG.
        command_template=("kubectl patch deployment/{deployment} -n {namespace} --type=strategic "
                          "--patch-file=hotfixes/{patch}.yaml"),
        blast_radius="deployment/{deployment} spec patched with {patch}; triggers a rolling update of every pod",
        risk_class=RISK_CONFIG_PATCH,
    ),
    ToolSpec(
        "rollback_deployment",
        "Roll a deployment back to its previous revision. Use when a regression started right after the "
        "latest rollout of the service's code.",
        _schema({"namespace": "string", "deployment": "string"}),
        read_only=False,
        destructive=True,
        command_template="kubectl rollout undo deployment/{deployment} -n {namespace}",
        blast_radius="all traffic for deployment/{deployment} moves to the previous revision; the current release is withdrawn",
        risk_class=RISK_DESTRUCTIVE,
    ),
    ToolSpec(
        "drain_node",
        "Cordon a node and evict all of its pods. Use when a single node is unhealthy (e.g. DiskPressure) and "
        "its workloads must move elsewhere.",
        _schema({"node": "string"}),
        read_only=False,
        destructive=True,
        command_template="kubectl drain {node} --ignore-daemonsets --delete-emptydir-data",
        blast_radius="every pod on node {node} is evicted and rescheduled; emptyDir data is lost",
        risk_class=RISK_DESTRUCTIVE,
    ),
    ToolSpec(
        "failover_cluster",
        "Shift a region's traffic to its standby cluster. Use only when an entire region is down and its "
        "standby is healthy.",
        _schema({"region": "string"}),
        read_only=False,
        destructive=True,
        command_template="kubectl annotate service/global-router -n edge failover.cloudscale.io/region={region} --overwrite",
        blast_radius="all traffic for region {region} moves to the standby cluster; in-flight sessions may drop",
        risk_class=RISK_FAILOVER,
    ),
]


# --------------------------------------------------------------------------
# Hotfix catalog (mocked)
# --------------------------------------------------------------------------

# apply_hotfix only accepts ids from this catalog: reviewed strategic-merge
# patches stored as hotfixes/<id>.yaml. The model can pick the action, but it
# can never supply patch content.
PATCH_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")

HOTFIX_CATALOG: dict[str, dict[str, str]] = {
    "db-pool-size": {
        "description": "restore DB_POOL_MAX to 50 (bad config pushed with v3.2 set it to 5)",
        "patch": """spec:
  template:
    spec:
      containers:
        - name: app
          env:
            - name: DB_POOL_MAX
              value: "50"
""",
    },
    "hotfix-2141": {
        "description": "billing-api 5.2.1 with the multi-currency rounding fix",
        "patch": """spec:
  template:
    spec:
      containers:
        - name: app
          image: registry.cloudscale.example/billing-api:5.2.1-hotfix.2141
""",
    },
}


# --------------------------------------------------------------------------
# Mock cluster
# --------------------------------------------------------------------------


@dataclass
class Fault:
    service: str
    workload: str
    logs: list[str]
    signals: list[str]
    fixed_by: set[str]
    healed: bool = False


@dataclass
class MockCluster:
    faults: dict[str, Fault] = field(default_factory=dict)

    def register_fault(self, service: str, workload: str, logs: list[str], signals: list[str], fixed_by: set[str]) -> None:
        self.faults[service] = Fault(service, workload, list(logs), list(signals), set(fixed_by))

    def find(self, name: str) -> Fault | None:
        for fault in self.faults.values():
            if name in (fault.service, fault.workload):
                return fault
        return None

    def apply(self, action: str, name: str) -> bool:
        """Apply a remediation; returns whether it actually fixed an active fault."""
        fault = self.find(name)
        if fault is None or fault.healed:
            return False
        if action in fault.fixed_by:
            fault.healed = True
        return fault.healed


# --------------------------------------------------------------------------
# Server
# --------------------------------------------------------------------------


class MCPToolServer:
    def __init__(
        self,
        breakers: BreakerRegistry,
        guardrails,
        audit,
        tracer,
        metrics,
        fail_injection: dict[str, int] | None = None,
        cluster: MockCluster | None = None,
    ):
        self._breakers = breakers
        self._guardrails = guardrails
        self._audit = audit
        self._tracer = tracer
        self._metrics = metrics
        self._fail_remaining: dict[str, int] = dict(fail_injection or {})
        self.cluster = cluster or MockCluster()
        self._specs = {spec.name: spec for spec in TOOL_SPECS}
        self._handlers: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
            "fetch_k8s_logs": self._fetch_k8s_logs,
            "correlate_telemetry": self._correlate_telemetry,
            "restart_service": self._restart_service,
            "clear_pod_cache": self._clear_pod_cache,
            "scale_deployment": self._scale_deployment,
            "apply_hotfix": self._apply_hotfix,
            "rollback_deployment": self._rollback_deployment,
            "drain_node": self._drain_node,
            "failover_cluster": self._failover_cluster,
        }

    # --- MCP surface -------------------------------------------------------
    def list_tools(self) -> list[dict[str, Any]]:
        return [spec.to_mcp() for spec in self._specs.values()]

    def get_spec(self, name: str) -> ToolSpec | None:
        return self._specs.get(name)

    def call_tool(self, name: str, arguments: dict[str, Any], incident_id: str | None = None) -> dict[str, Any]:
        with self._tracer.start_span(f"mcp.call_tool/{name}", {"mcp.tool": name, "incident.id": incident_id}) as span:
            spec = self._specs.get(name)
            if spec is None:
                return self._error(span, name, incident_id, "unknown_tool", f"no tool named '{name}'", arguments)

            problem = self._validate(spec, arguments)
            if problem:
                return self._error(span, name, incident_id, "invalid_arguments", problem, arguments)

            for key, value in arguments.items():
                if isinstance(value, str):
                    verdict = self._guardrails.check_argument(value)
                    if not verdict.allowed:
                        self._metrics.record_tool_call(name, "rejected")
                        return self._error(
                            span, name, incident_id, "guardrail_blocked",
                            f"argument '{key}': {', '.join(verdict.reasons)}", arguments,
                        )

            problem = self._validate_semantics(name, arguments)
            if problem:
                return self._error(span, name, incident_id, "invalid_arguments", problem, arguments)

            breaker = self._breakers.get(name)
            try:
                data = breaker.call(self._invoke, name, arguments)
            except CircuitOpenError as exc:
                self._metrics.record_tool_call(name, "rejected")
                return self._error(span, name, incident_id, "circuit_open", str(exc), arguments)
            except Exception as exc:
                self._metrics.record_tool_call(name, "failed")
                return self._error(span, name, incident_id, "execution_error", str(exc), arguments)

            self._metrics.record_tool_call(name, "ok")
            span.set_attribute("mcp.is_error", False)
            self._audit.record(
                "mcp_server",
                "tool_call",
                {"incident_id": incident_id, "tool": name, "arguments": arguments,
                 "destructive": spec.destructive, "result_keys": sorted(data),
                 **({"fault_cleared": data["fault_cleared"]} if "fault_cleared" in data else {})},
            )
            return {
                "content": [{"type": "text", "text": json.dumps(data)}],
                "structuredContent": data,
                "isError": False,
            }

    # --- failure injection (demo / tests) ----------------------------------
    def inject_failures(self, mapping: dict[str, int]) -> None:
        for tool, count in mapping.items():
            self._fail_remaining[tool] = self._fail_remaining.get(tool, 0) + count

    def clear_injected_failures(self) -> None:
        """Injection is scoped to one scenario; breakers keep their real state."""
        self._fail_remaining.clear()

    # --- internals ---------------------------------------------------------
    @staticmethod
    def _validate(spec: ToolSpec, arguments: dict[str, Any]) -> str | None:
        schema = spec.input_schema
        missing = [k for k in schema["required"] if k not in arguments]
        if missing:
            return f"missing required argument(s): {', '.join(missing)}"
        unknown = [k for k in arguments if k not in schema["properties"]]
        if unknown:
            return f"unknown argument(s): {', '.join(unknown)}"
        for key, value in arguments.items():
            expected = schema["properties"][key]["type"]
            if expected == "string" and not isinstance(value, str):
                return f"'{key}' must be a string"
            if expected == "integer" and (not isinstance(value, int) or isinstance(value, bool)):
                return f"'{key}' must be an integer"
        return None

    @staticmethod
    def _validate_semantics(name: str, arguments: dict[str, Any]) -> str | None:
        """Value checks the JSON schema can't express."""
        if name == "apply_hotfix":
            patch = arguments["patch"]
            if not PATCH_ID_RE.match(patch):
                return f"patch id '{patch}' is not a valid identifier"
            if patch not in HOTFIX_CATALOG:
                return f"patch id '{patch}' is not in the vetted hotfix catalog ({', '.join(sorted(HOTFIX_CATALOG))})"
        return None

    def _invoke(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if self._fail_remaining.get(name, 0) > 0:
            self._fail_remaining[name] -= 1
            raise ToolExecutionError(f"{name}: upstream timeout (injected failure)")
        return self._handlers[name](arguments)

    def _error(self, span, name, incident_id, error_type, message, arguments) -> dict[str, Any]:
        span.status = "ERROR"
        span.set_attribute("mcp.is_error", True)
        span.set_attribute("mcp.error_type", error_type)
        self._audit.record(
            "mcp_server",
            "tool_call_error",
            {"incident_id": incident_id, "tool": name, "arguments": arguments,
             "error_type": error_type, "message": self._guardrails.redact_text(message)},
        )
        return {
            "content": [{"type": "text", "text": message}],
            "isError": True,
            "errorType": error_type,
        }

    # --- mocked handlers ---------------------------------------------------
    def _fetch_k8s_logs(self, args: dict[str, Any]) -> dict[str, Any]:
        fault = self.cluster.find(args["workload"])
        tail = args.get("tail_lines", 50)
        if fault is None or fault.healed:
            lines = [f"{args['workload']}: request served in 42ms status=200"]
        else:
            lines = fault.logs[-tail:]
        return {"namespace": args["namespace"], "workload": args["workload"], "lines": lines}

    def _correlate_telemetry(self, args: dict[str, Any]) -> dict[str, Any]:
        fault = self.cluster.find(args["service"])
        healthy = fault is None or fault.healed
        return {
            "namespace": args["namespace"],
            "service": args["service"],
            "window_minutes": args.get("window_minutes", 15),
            "healthy": healthy,
            "signals": ["all SLOs within budget"] if healthy else list(fault.signals),
        }

    def _restart_service(self, args: dict[str, Any]) -> dict[str, Any]:
        fixed = self.cluster.apply("restart_service", args["workload"])
        return {"action": "rollout_restart", "workload": args["workload"], "fault_cleared": fixed}

    def _clear_pod_cache(self, args: dict[str, Any]) -> dict[str, Any]:
        fixed = self.cluster.apply("clear_pod_cache", args["workload"])
        return {"action": "cache_flush", "workload": args["workload"], "fault_cleared": fixed}

    def _apply_hotfix(self, args: dict[str, Any]) -> dict[str, Any]:
        fixed = self.cluster.apply("apply_hotfix", args["deployment"])
        return {"action": "patch", "deployment": args["deployment"], "patch": args["patch"],
                "patch_file": f"hotfixes/{args['patch']}.yaml",
                "description": HOTFIX_CATALOG[args["patch"]]["description"], "fault_cleared": fixed}

    def _failover_cluster(self, args: dict[str, Any]) -> dict[str, Any]:
        fixed = self.cluster.apply("failover_cluster", args["region"])
        return {"action": "failover", "region": args["region"], "standby": f"{args['region']}-standby",
                "fault_cleared": fixed}

    def _scale_deployment(self, args: dict[str, Any]) -> dict[str, Any]:
        fixed = self.cluster.apply("scale_deployment", args["deployment"])
        return {"action": "scale", "deployment": args["deployment"], "replicas": args["replicas"], "fault_cleared": fixed}

    def _rollback_deployment(self, args: dict[str, Any]) -> dict[str, Any]:
        fixed = self.cluster.apply("rollback_deployment", args["deployment"])
        return {"action": "rollout_undo", "deployment": args["deployment"], "fault_cleared": fixed}

    def _drain_node(self, args: dict[str, Any]) -> dict[str, Any]:
        fixed = self.cluster.apply("drain_node", args["node"])
        return {"action": "drain", "node": args["node"], "fault_cleared": fixed}
