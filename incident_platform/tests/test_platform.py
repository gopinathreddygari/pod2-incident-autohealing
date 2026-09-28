import unittest
from dataclasses import replace

import _path  # noqa: F401

import main
from agents.recovery_scripts import SCRIPT_TEMPLATES, render_script
from config import Settings
from guardrails import GuardrailMiddleware
from hitl import (
    REASON_CONFIG_PATCH,
    REASON_DESTRUCTIVE,
    REASON_FAILOVER,
    REASON_LOW_CONFIDENCE,
    REASON_UNCLASSIFIED,
    AutoApprovalChannel,
    HITLGate,
)
from mcp_server import HOTFIX_CATALOG, TOOL_SPECS, RISK_CONFIG_PATCH, RISK_DESTRUCTIVE, RISK_FAILOVER, RISK_READ_ONLY, RISK_SAFE_RESET
from orchestrator import IncidentOrchestrator, IncidentPlatform
from state import Incident, IncidentState

SAMPLE_ARGS = {"namespace": "payments", "workload": "checkout-service", "service": "checkout-service",
               "deployment": "orders-api", "replicas": 8, "patch": "hotfix-2141", "node": "ip-10-0-7-22",
               "region": "eu-west-1", "tail_lines": 50}

# (label, blocked argument value, benign look-alike) -- one per FR4 privilege pattern.
PRIVILEGE_CASES = [
    # A bare DNS-1123 name such as "su" is allowed (fix 4), so these carry a command around the word.
    ("privilege escalation (sudo/su/doas)", "sudo -i", "pseudo-api"),
    ("privilege escalation (sudo/su/doas)", "su root", "superset"),
    ("privilege escalation (sudo/su/doas)", "doas sh", "doasync-worker"),
    ("chmod setuid / world-writable", "chmod u+s /bin/sh", "chmod-audit"),
    ("chmod setuid / world-writable", "chmod 4755 /bin/bash", "mode-4755"),
    ("chmod setuid / world-writable", "chmod 777 /etc", "chmod-report-777"),
    ("chown to root", "chown root /tmp/x", "root-cause-api"),
    ("kubectl impersonation (--as)", "--as=system:admin", "assets-api"),
    ("kubectl impersonation (--as)", "--as-group=system:masters", "as-group-sync"),
    ("cluster-admin binding", "clusterrolebinding", "clusterroles-viewer"),
    ("cluster-admin binding", "cluster-admin", "cluster-api"),
    ("privileged container", "--privileged", "privileges-audit"),
    ("host namespace access", "hostPID", "host-team"),
    ("host namespace access", "hostNetwork", "network-host-probe"),
    ("kubectl exec into a container", "kubectl exec -it pod", "exec-runner"),
]


class ToolServerTests(unittest.TestCase):
    def setUp(self):
        self.platform = IncidentPlatform(settings=Settings())

    def test_list_tools_exposes_nine_annotated_tools(self):
        tools = {t["name"]: t for t in self.platform.tools.list_tools()}
        self.assertEqual(len(tools), 9)
        destructive = {n for n, t in tools.items() if t["annotations"]["destructiveHint"]}
        self.assertEqual(destructive, {"rollback_deployment", "drain_node", "apply_hotfix", "failover_cluster"})
        self.assertEqual({n: t["annotations"]["riskClass"] for n, t in tools.items()}, {
            "fetch_k8s_logs": RISK_READ_ONLY, "correlate_telemetry": RISK_READ_ONLY,
            "restart_service": RISK_SAFE_RESET, "clear_pod_cache": RISK_SAFE_RESET,
            "scale_deployment": RISK_CONFIG_PATCH, "apply_hotfix": RISK_CONFIG_PATCH,
            "rollback_deployment": RISK_DESTRUCTIVE, "drain_node": RISK_DESTRUCTIVE,
            "failover_cluster": RISK_FAILOVER,
        })

    def test_fr2_restart_pod_is_renamed_restart_service(self):
        self.assertIsNone(self.platform.tools.get_spec("restart_pod"))
        spec = self.platform.tools.get_spec("restart_service")
        self.assertEqual((spec.risk_class, spec.destructive), (RISK_SAFE_RESET, False))

    def test_fr2_apply_hotfix_is_a_mocked_destructive_patch(self):
        spec = self.platform.tools.get_spec("apply_hotfix")
        self.assertEqual(spec.to_mcp()["annotations"], {"readOnlyHint": False, "destructiveHint": True,
                                                        "riskClass": RISK_CONFIG_PATCH})
        args = {"namespace": "billing", "deployment": "billing-api", "patch": "hotfix-2141"}
        self.assertEqual(spec.command_template.format(**args),
                         "kubectl patch deployment/billing-api -n billing --type=strategic "
                         "--patch-file=hotfixes/hotfix-2141.yaml")
        self.platform.cluster.register_fault("billing-api", "billing-api", [], [], {"apply_hotfix"})
        res = self.platform.tools.call_tool("apply_hotfix", args)
        self.assertFalse(res["isError"])
        self.assertTrue(res["structuredContent"]["fault_cleared"])
        # The patch value is an identifier, so a shell fragment is refused.
        bad = self.platform.tools.call_tool("apply_hotfix", {**args, "patch": "x; rm -rf /"})
        self.assertEqual(bad["errorType"], "guardrail_blocked")

    def test_hotfix_catalog_rejects_unknown_ids_and_heals_with_known_ones(self):
        tools = self.platform.tools
        base = {"namespace": "inventory", "deployment": "inventory-api"}
        for patch in ("hotfix-9999", "Db-Pool-Size", "-leading-dash", "a" * 64):
            with self.subTest(patch=patch):
                res = tools.call_tool("apply_hotfix", {**base, "patch": patch})
                self.assertEqual(res["errorType"], "invalid_arguments")
        self.assertEqual(self.platform.metrics.tool_calls["apply_hotfix"]["ok"], 0)
        self.platform.cluster.register_fault("inventory-api", "inventory-api", [], [], {"apply_hotfix"})
        res = tools.call_tool("apply_hotfix", {**base, "patch": "db-pool-size"})
        self.assertFalse(res["isError"])
        self.assertEqual(res["structuredContent"]["patch_file"], "hotfixes/db-pool-size.yaml")
        self.assertTrue(res["structuredContent"]["fault_cleared"])
        self.assertTrue(tools.call_tool("correlate_telemetry", {"namespace": "inventory", "service": "inventory-api"})
                        ["structuredContent"]["healthy"])

    def test_fr3_new_safe_reset_and_failover_tools_are_mocked(self):
        tools = self.platform.tools
        self.platform.cluster.register_fault("catalog-api", "catalog-api", [], [], {"clear_pod_cache"})
        self.platform.cluster.register_fault("eu-west-1", "global-router", [], [], {"failover_cluster"})
        self.assertTrue(tools.call_tool("clear_pod_cache", {"namespace": "catalog", "workload": "catalog-api"})
                        ["structuredContent"]["fault_cleared"])
        self.assertTrue(tools.call_tool("failover_cluster", {"region": "eu-west-1"})
                        ["structuredContent"]["fault_cleared"])

    def test_argument_guardrail_blocks_shell_metacharacters(self):
        tools = self.platform.tools
        res = tools.call_tool("restart_service", {"namespace": "prod; rm -rf /", "workload": "x"})
        self.assertTrue(res["isError"])
        self.assertEqual(res["errorType"], "guardrail_blocked")
        # FR4: one blocked argument per privilege-escalation pattern, plus a benign look-alike.
        for label, blocked, benign in PRIVILEGE_CASES:
            with self.subTest(blocked=blocked):
                res = tools.call_tool("restart_service", {"namespace": "prod", "workload": blocked})
                self.assertEqual(res["errorType"], "guardrail_blocked")
                self.assertIn(label, res["content"][0]["text"])
            with self.subTest(benign=benign):
                self.assertFalse(tools.call_tool("restart_service", {"namespace": "prod", "workload": benign})["isError"])

    def test_fr4_no_tool_template_trips_guardrails(self):
        g = GuardrailMiddleware()
        self.assertEqual(len(TOOL_SPECS), 9)
        for spec in TOOL_SPECS:  # all nine, read-only ones included: every template is a kubectl command
            with self.subTest(tool=spec.name):
                command = spec.command_template.format(**SAMPLE_ARGS)
                self.assertTrue(command.startswith("kubectl "))
                verdict = g.check_output(command)
                self.assertTrue(verdict.allowed, verdict.reasons)
        telemetry = next(s for s in TOOL_SPECS if s.name == "correlate_telemetry")
        self.assertIn('query=up{service="checkout-service",namespace="payments"}',
                      telemetry.command_template.format(**SAMPLE_ARGS))

    def test_schema_validation(self):
        res = self.platform.tools.call_tool("scale_deployment", {"namespace": "a", "deployment": "b", "replicas": "9"})
        self.assertEqual(res["errorType"], "invalid_arguments")
        res = self.platform.tools.call_tool("drain_node", {})
        self.assertEqual(res["errorType"], "invalid_arguments")

    def test_breaker_opens_on_injected_failures(self):
        tools = self.platform.tools
        tools.inject_failures({"fetch_k8s_logs": 5})
        args = {"namespace": "n", "workload": "w"}
        kinds = [tools.call_tool("fetch_k8s_logs", args)["errorType"] for _ in range(4)]
        self.assertEqual(kinds, ["execution_error"] * 3 + ["circuit_open"])
        self.assertEqual(self.platform.breakers.snapshot()["fetch_k8s_logs"], "OPEN")

    def test_cleared_injection_lets_half_open_trial_succeed(self):
        clock = [0.0]
        platform = IncidentPlatform(settings=Settings(), clock=lambda: clock[0])
        tools, args = platform.tools, {"namespace": "n", "workload": "w"}
        tools.inject_failures({"fetch_k8s_logs": 5})
        for _ in range(3):
            tools.call_tool("fetch_k8s_logs", args)
        tools.clear_injected_failures()  # 2 unused failures must not leak into the next scenario
        clock[0] = Settings().BREAKER_RECOVERY_TIMEOUT_S
        self.assertFalse(tools.call_tool("fetch_k8s_logs", args)["isError"])
        self.assertEqual(platform.breakers.snapshot()["fetch_k8s_logs"], "CLOSED")


class RetryBackoffTests(unittest.TestCase):
    """Read-only retries: exponential backoff + jitter, stop when the breaker opens, respect the budget."""

    def _platform(self, **settings_overrides):
        import random
        now = [0.0]
        sleeps = []

        def sleep(seconds):
            sleeps.append(seconds)
            now[0] += seconds

        settings = replace(Settings(), **settings_overrides)
        platform = IncidentPlatform(settings=settings, clock=lambda: now[0], sleep=sleep, rng=random.Random(1))
        platform.cluster.register_fault("svc", "svc", ["log line"], ["signal"], {"restart_service"})
        return platform, sleeps

    def _read(self, platform, args=None):
        from agents import TriageAgent
        inc = Incident("INC-R1", "t", "P1", {"symptoms": "s"}, {"namespace": "n", "workload": "svc", "service": "svc"})
        return TriageAgent(platform)._read_tool(inc, "fetch_k8s_logs", args or {"namespace": "n", "workload": "svc"})

    def _retries(self, platform):
        return [e["payload"] for e in platform.audit.filter(action="tool_retry")]

    def test_transient_failures_are_retried_with_growing_jittered_waits(self):
        platform, sleeps = self._platform()
        platform.tools.inject_failures({"fetch_k8s_logs": 2})
        self.assertFalse(self._read(platform)["isError"])        # third attempt succeeds
        self.assertEqual(len(sleeps), 2)
        self.assertLessEqual(sleeps[0], 0.2)                       # cap 0.2 s before retry 1
        self.assertLessEqual(sleeps[1], 0.4)                       # cap doubles to 0.4 s
        self.assertEqual([r["next_attempt"] for r in self._retries(platform)], [2, 3])
        self.assertEqual(len([s for s in platform.tracer.spans if s.name == "retry.backoff"]), 2)

    def test_no_wait_once_the_breaker_is_open(self):
        platform, sleeps = self._platform()
        platform.tools.inject_failures({"fetch_k8s_logs": 5})
        result = self._read(platform)
        self.assertEqual(result["errorType"], "circuit_open")      # 4th attempt rejected instantly
        self.assertEqual(len(sleeps), 2)                           # waited before attempts 2 and 3 only
        self.assertEqual(platform.metrics.tool_calls["fetch_k8s_logs"], {"ok": 0, "failed": 3, "rejected": 1})

    def test_retry_budget_stops_retrying(self):
        platform, sleeps = self._platform(RETRY_BASE_DELAY_S=1.0, RETRY_BUDGET_S=0.05)
        platform.rng.uniform = lambda a, b: b                      # always wait the full cap
        platform.tools.inject_failures({"fetch_k8s_logs": 5})
        self.assertEqual(self._read(platform)["errorType"], "execution_error")
        self.assertEqual(sleeps, [])
        self.assertEqual(len(platform.audit.filter(action="retry_budget_exhausted")), 1)

    def test_non_transient_errors_are_not_retried(self):
        platform, sleeps = self._platform()
        result = self._read(platform, {"namespace": "n; id", "workload": "svc"})
        self.assertEqual(result["errorType"], "guardrail_blocked")
        self.assertEqual((sleeps, self._retries(platform)), ([], []))

    def test_breaker_open_period_is_recorded(self):
        platform, _ = self._platform()
        platform.tools.inject_failures({"fetch_k8s_logs": 5})
        self._read(platform)
        opened = [e["payload"] for e in platform.audit.filter(action="state_change") if e["payload"]["to"] == "OPEN"]
        self.assertEqual(opened[0]["open_for_s"], Settings().BREAKER_RECOVERY_TIMEOUT_S)


def _run_one(incident_id, decisions=None, settings=None, target_override=None):
    """Run one scripted scenario on a fresh platform; returns (platform, incident, channel)."""
    platform = IncidentPlatform(settings=settings or Settings())
    channel = AutoApprovalChannel(decisions or {})
    sc = next(s for s in main.build_scenarios() if s.incident.incident_id == incident_id)
    if target_override:
        sc.incident.target.update(target_override)
    main.prepare_scenario(platform, sc)
    IncidentOrchestrator(platform, channel).handle(sc.incident)
    return platform, sc.incident, channel


class HITLGateTests(unittest.TestCase):
    def setUp(self):
        self.gate = HITLGate(AutoApprovalChannel(), None, None, None, min_confidence=0.75)

    def test_gating_rules(self):
        g = self.gate
        self.assertEqual(g.evaluate(RISK_SAFE_RESET, 0.9), [])
        self.assertEqual(g.evaluate(RISK_DESTRUCTIVE, 0.9), [REASON_DESTRUCTIVE])
        self.assertEqual(g.evaluate(RISK_SAFE_RESET, 0.5), [REASON_LOW_CONFIDENCE])
        self.assertEqual(g.evaluate(RISK_DESTRUCTIVE, 0.5), [REASON_DESTRUCTIVE, REASON_LOW_CONFIDENCE])
        self.assertEqual(g.evaluate("made_up_class", 0.9), [REASON_UNCLASSIFIED])  # fail-safe

    def test_fr3_read_only_and_safe_reset_are_autonomous(self):
        self.assertEqual(self.gate.evaluate(RISK_READ_ONLY, 0.9), [])
        self.assertEqual(self.gate.evaluate(RISK_SAFE_RESET, 0.9), [])
        # ... but the low-confidence trigger still applies to them.
        self.assertEqual(self.gate.evaluate(RISK_SAFE_RESET, 0.6), [REASON_LOW_CONFIDENCE])
        platform, inc, channel = _run_one("INC-1007")  # clear_pod_cache, no scripted decisions at all
        self.assertIs(inc.state, IncidentState.VERIFIED)
        self.assertEqual(channel.requests, [])
        self.assertEqual(inc.notes["plan"].risk_class, RISK_SAFE_RESET)
        self.assertEqual(platform.metrics.tool_calls["clear_pod_cache"]["ok"], 1)

    def test_fr3_config_patch_requires_approval(self):
        self.assertEqual(self.gate.evaluate(RISK_CONFIG_PATCH, 0.99), [REASON_CONFIG_PATCH])
        # INC-1003 (scale) with the threshold below its 0.62 confidence: still gated, by class alone.
        settings = replace(Settings(), MIN_AUTONOMOUS_CONFIDENCE=0.5)
        _, inc, channel = _run_one("INC-1003", {"INC-1003": True}, settings)
        self.assertEqual([r.reasons for r in channel.requests], [[REASON_CONFIG_PATCH]])
        self.assertIs(inc.state, IncidentState.VERIFIED)
        payload = channel.requests[0].to_payload()
        self.assertEqual(payload["blocks"][1]["fields"]["Risk class"], RISK_CONFIG_PATCH)
        self.assertIn("config patch", payload["blocks"][1]["fields"]["Why approval is required"])

    def test_fr3_failover_requires_approval(self):
        self.assertEqual(self.gate.evaluate(RISK_FAILOVER, 0.99), [REASON_FAILOVER])
        platform = IncidentPlatform(settings=Settings())
        channel = AutoApprovalChannel({})  # nobody approves -> fail-safe reject
        inc = Incident("INC-F1", "eu-west-1 region outage", "P1",
                       {"alert": "RegionUnreachable", "symptoms": "region outage: load balancers unreachable"},
                       {"namespace": "edge", "workload": "global-router", "service": "eu-west-1", "region": "eu-west-1"})
        platform.cluster.register_fault("eu-west-1", "global-router", ["lb timeout"], ["region down"], {"failover_cluster"})
        self.assertIs(IncidentOrchestrator(platform, channel).handle(inc), IncidentState.REJECTED)
        self.assertEqual(inc.notes["plan"].action, "failover_cluster")
        self.assertEqual(channel.requests[0].reasons, [REASON_FAILOVER])
        self.assertEqual(platform.metrics.tool_calls["failover_cluster"]["ok"], 0)

    def test_fr3_destructive_requires_approval(self):
        for incident_id, tool in (("INC-1002", "rollback_deployment"), ("INC-1006", "drain_node")):
            with self.subTest(incident=incident_id):
                platform, inc, channel = _run_one(incident_id)  # no scripted approval -> rejected
                self.assertIs(inc.state, IncidentState.REJECTED)
                self.assertIn(REASON_DESTRUCTIVE, channel.requests[0].reasons)
                self.assertEqual(platform.metrics.tool_calls[tool]["ok"], 0)

    def test_unscripted_request_is_rejected_fail_safe(self):
        platform = IncidentPlatform(settings=Settings())
        orchestrator = IncidentOrchestrator(platform, AutoApprovalChannel({}))
        inc = Incident("INC-X", "Node ip-1 reporting DiskPressure", "P1",
                       {"symptoms": "DiskPressure=True"},
                       {"namespace": "kube-system", "workload": "npd", "service": "ip-1", "node": "ip-1"})
        platform.cluster.register_fault("ip-1", "npd", ["x"], ["y"], {"drain_node"})
        self.assertIs(orchestrator.handle(inc), IncidentState.REJECTED)
        self.assertEqual(platform.metrics.tool_calls["drain_node"]["ok"], 0)


class RecoveryScriptTests(unittest.TestCase):
    EXPECTED_FORMATS = {
        "apply_hotfix": "kubernetes-yaml", "scale_deployment": "kubernetes-yaml",
        "rollback_deployment": "kubernetes-yaml", "restart_service": "ansible-yaml",
        "clear_pod_cache": "ansible-yaml", "drain_node": "ansible-yaml", "failover_cluster": "terraform-hcl",
    }

    def test_fr1_every_remediation_action_has_a_draft(self):
        g = GuardrailMiddleware()
        remediation = {t.name for t in TOOL_SPECS if not t.read_only}
        self.assertEqual(remediation, set(self.EXPECTED_FORMATS))
        self.assertEqual(set(SCRIPT_TEMPLATES), remediation)
        for spec in TOOL_SPECS:
            if spec.read_only:
                continue
            with self.subTest(action=spec.name):
                args = {k: SAMPLE_ARGS[k] for k in spec.input_schema["properties"]}
                fmt, script = render_script(spec.name, args, "INC-T1")
                self.assertEqual(fmt, self.EXPECTED_FORMATS[spec.name])
                self.assertTrue(script.strip())
                self.assertIn("INC-T1", script)
                self.assertNotIn("$", script)  # every placeholder was bound
                for value in args.values():
                    self.assertIn(str(value), script)
                self.assertTrue(g.check_script(script).allowed, g.check_script(script).reasons)
        # The hotfix draft shows the vetted catalog content, not just the id.
        _, draft = render_script("apply_hotfix", {"namespace": "inventory", "deployment": "inventory-api",
                                                  "patch": "db-pool-size"}, "INC-T2")
        self.assertIn(HOTFIX_CATALOG["db-pool-size"]["patch"], draft)
        self.assertIn("--patch-file=hotfixes/db-pool-size.yaml", draft)

    def test_fr1_plan_carries_draft_and_command_only_executes_kubectl(self):
        platform, inc, channel = _run_one("INC-1002", {"INC-1002": True})
        plan = inc.notes["plan"]
        self.assertEqual(plan.script_format, "kubernetes-yaml")
        self.assertIn("name: orders-api", plan.script)
        self.assertTrue(plan.command.startswith("kubectl rollout undo"))
        # The draft travels in the approval payload...
        code = [b for b in channel.requests[0].to_payload()["blocks"] if b["type"] == "code"]
        self.assertEqual(code[0]["text"], plan.script)
        # ...but the only remediation executed is the kubectl-backed MCP tool.
        executed = [e["payload"]["tool"] for e in platform.audit.filter(action="tool_call")]
        self.assertEqual([t for t in executed if t not in ("fetch_k8s_logs", "correlate_telemetry")],
                         ["rollback_deployment"])

    def test_fr1_blocked_draft_escalates(self):
        platform = IncidentPlatform(settings=Settings())
        sc = next(s for s in main.build_scenarios() if s.incident.incident_id == "INC-1001")
        main.prepare_scenario(platform, sc)
        original = platform.guardrails.check_script
        platform.guardrails.check_script = lambda s: original(s + "\nsudo sh")  # simulate a poisoned draft
        state = IncidentOrchestrator(platform, AutoApprovalChannel()).handle(sc.incident)
        self.assertIs(state, IncidentState.ESCALATED)
        self.assertEqual(sc.incident.notes["guardrail"]["stage"], "script")


class EndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.platform, cls.results = main.run_demo(audit_path=None, verbose=False)

    def test_every_incident_reaches_expected_state(self):
        for sc, final in self.results:
            with self.subTest(incident=sc.incident.incident_id):
                self.assertIs(final, sc.expected)

    def test_duplicate_incident_spends_no_tokens(self):
        inc = next(sc.incident for sc, _ in self.results if sc.incident.incident_id == "INC-1004")
        self.assertEqual(inc.notes["triage"].cache_layer, "L2")
        self.assertEqual(inc.notes["plan"].cache_layer, "L1")
        llm_calls = [e for e in self.platform.audit.filter(action="llm_call")
                     if e["payload"]["incident_id"] == "INC-1004"]
        self.assertEqual(llm_calls, [])

    def test_injection_never_reaches_llm_and_pii_never_reaches_audit(self):
        self.assertFalse(any(e["payload"].get("incident_id") == "INC-1005"
                             for e in self.platform.audit.filter(action="llm_call")))
        dump = str(self.platform.audit.entries)
        self.assertNotIn("jane.doe@cloudscale.example", dump)

    def test_breaker_changes_are_attributed_to_the_incident(self):
        changes = self.platform.audit.filter(action="state_change")
        self.assertTrue(changes)
        self.assertEqual({e["payload"]["incident_id"] for e in changes}, {"INC-1010"})

    def test_demo_shows_hotfix_verified_and_failover_rejected(self):
        by_id = {sc.incident.incident_id: (sc.incident, final) for sc, final in self.results}
        hotfix, state = by_id["INC-1008"]
        self.assertIs(state, IncidentState.VERIFIED)
        self.assertEqual((hotfix.notes["triage"].category, hotfix.notes["plan"].action), ("bad_config", "apply_hotfix"))
        self.assertEqual(hotfix.notes["approval"]["reasons"], [REASON_CONFIG_PATCH])
        self.assertEqual(self.platform.metrics.tool_calls["apply_hotfix"]["ok"], 1)
        failover, state = by_id["INC-1009"]
        self.assertIs(state, IncidentState.REJECTED)
        self.assertEqual((failover.notes["triage"].category, failover.notes["plan"].action),
                         ("region_outage", "failover_cluster"))
        self.assertEqual(failover.notes["approval"]["reasons"], [REASON_FAILOVER])
        executed = {e["payload"]["tool"] for e in self.platform.audit.filter(action="tool_call")}
        self.assertNotIn("failover_cluster", executed)
        self.assertEqual(self.platform.metrics.tool_calls["failover_cluster"]["ok"], 0)

    def test_rejected_destructive_action_never_executes(self):
        self.assertEqual(self.platform.metrics.tool_calls["drain_node"]["ok"], 0)

    def test_audit_chain_intact_and_traces_per_incident(self):
        self.assertTrue(self.platform.audit.verify_chain())
        self.assertEqual(len({s.trace_id for s in self.platform.tracer.spans}), 10)

    def test_p2_uses_cost_tier(self):
        inc = next(sc.incident for sc, _ in self.results if sc.incident.incident_id == "INC-1003")
        self.assertEqual(inc.notes["triage"].model, Settings().COST_TIER.name)


if __name__ == "__main__":
    unittest.main()
