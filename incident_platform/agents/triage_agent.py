"""Triage: gather evidence with read-only MCP tools, then ask for RCA + confidence."""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from llm.llm_backend import LLMOutputError

from .base_agent import BaseAgent

# One-line definitions go into the prompt: a real model can't be expected to infer what a
# bare label like "stale_cache" covers (e.g. it is *not* DNS resolution trouble).
CATEGORY_DEFINITIONS: dict[str, str] = {
    "pod_crashloop": "containers restart repeatedly (CrashLoopBackOff), e.g. wedged after a dependency or "
                     "DNS blip, while freshly started pods would be healthy",
    "resource_exhaustion": "containers are OOMKilled or throttled because load exceeds the current capacity or limits",
    "bad_deployment": "errors or regressions that start right after a new release/rollout of the service's code",
    "node_disk_pressure": "a single node reports DiskPressure or a full disk and is evicting pods",
    "latency_degradation": "responses are slower (p95/p99 up) without crashes, errors or a recent deploy; "
                           "typically a capacity shortfall",
    "stale_cache": "the application serves outdated data from its own in-memory cache (entries past their TTL); "
                   "not DNS resolution problems and not crash loops",
    "known_defect": "a known software defect for which a vetted hotfix is available",
    "bad_config": "a wrong configuration value (e.g. pool size, limit) shipped with a release, fixable by a "
                  "vetted config patch",
    "region_outage": "an entire region or cluster is unreachable while its standby is healthy",
    "unknown": "none of the above fits, or the evidence is insufficient",
}
CATEGORIES = tuple(CATEGORY_DEFINITIONS)


@dataclass
class TriageResult:
    root_cause: str
    confidence: float
    category: str
    degraded: list[str] = field(default_factory=list)  # evidence we could not collect
    cache_layer: str | None = None
    cache_similarity: float | None = None
    model: str | None = None


class TriageAgent(BaseAgent):
    name = "triage_agent"

    def run(self, incident) -> TriageResult:
        target = incident.target
        evidence: dict[str, object] = {}
        degraded: list[str] = []

        logs = self._read_tool(incident, "fetch_k8s_logs",
                               {"namespace": target["namespace"], "workload": target["workload"]})
        if logs["isError"]:
            degraded.append(f"fetch_k8s_logs: {logs['errorType']}")
        else:
            evidence["logs"] = logs["structuredContent"]["lines"]

        telemetry = self._read_tool(incident, "correlate_telemetry",
                                    {"namespace": target["namespace"], "service": target["service"]})
        if telemetry["isError"]:
            degraded.append(f"correlate_telemetry: {telemetry['errorType']}")
        else:
            evidence["signals"] = telemetry["structuredContent"]["signals"]

        prompt = self._prompt(incident, evidence, degraded)
        # Reasoning over partial evidence is harder: always use the accuracy tier then.
        complexity = "high" if degraded else "normal"
        result = self.think(incident, prompt, cache_key=self.cache_key(incident), complexity=complexity)
        data = result.data
        try:
            confidence = max(0.0, min(1.0, float(data["confidence"])))
            root_cause = str(data["root_cause"])
        except (KeyError, TypeError, ValueError) as exc:
            raise LLMOutputError(f"triage reply missing/invalid field: {exc}") from exc
        category = data.get("category") if data.get("category") in CATEGORIES else "unknown"

        return TriageResult(root_cause, confidence, category, degraded,
                            result.cache_layer, result.similarity, result.model)

    @staticmethod
    def cache_key(incident) -> str:
        """Content only -- no template boilerplate, no namespace/pod names."""
        t = incident.telemetry
        return f"{incident.title} | {t.get('alert', '')} | {t.get('symptoms', '')}"

    def _read_tool(self, incident, tool: str, args: dict) -> dict:
        """Call a read-only tool, retrying transient failures with exponential backoff + jitter.

        * Only ``execution_error`` (timeouts / 5xx) is retried; validation, guardrail and
          circuit-open results are returned immediately.
        * If the tool's breaker is OPEN after a failure, don't wait: the next call is rejected
          instantly, which ends the loop (and records the fast rejection).
        * Stop when the next wait would overrun the policy's time budget.
        """
        p, policy, iid = self.p, self.p.retry_policy, incident.incident_id
        started = p.clock()
        result: dict = {}
        for attempt in range(1, policy.max_attempts + 1):
            result = p.tools.call_tool(tool, args, incident_id=iid)
            if not result["isError"] or result["errorType"] != "execution_error":
                break
            if attempt == policy.max_attempts:
                break
            if p.breakers.get(tool).state.value == "OPEN":
                continue  # no point waiting: the next call is rejected instantly
            delay = policy.delay(attempt, p.rng)
            if p.clock() - started + delay > policy.budget_s:
                p.audit.record(self.name, "retry_budget_exhausted",
                               {"incident_id": iid, "tool": tool, "attempts": attempt, "budget_s": policy.budget_s})
                break
            p.audit.record(self.name, "tool_retry", {
                "incident_id": iid, "tool": tool, "next_attempt": attempt + 1, "max_attempts": policy.max_attempts,
                "delay_s": round(delay, 3), "cap_s": round(policy.cap(attempt), 3),
            })
            with p.tracer.start_span("retry.backoff", {"incident.id": iid, "mcp.tool": tool,
                                                       "retry.attempt": attempt + 1,
                                                       "retry.delay_s": round(delay, 3)}):
                p.sleep(delay)
        return result

    @staticmethod
    def _prompt(incident, evidence: dict, degraded: list[str]) -> str:
        missing = f"\nMISSING EVIDENCE (tools unavailable): {', '.join(degraded)}" if degraded else ""
        return (
            "TASK: TRIAGE\n"
            "Role: triage agent for production Kubernetes incidents.\n"
            "Determine the most likely root cause from the evidence below.\n"
            "Respond with JSON keys: root_cause (string), confidence (float 0-1), "
            "category (exactly one of the names below).\n"
            "CATEGORIES:\n"
            + "".join(f"- {name}: {text}\n" for name, text in CATEGORY_DEFINITIONS.items())
            + "Pick the category whose definition matches the evidence best. "
            "Lower your confidence when evidence is missing or circumstantial."
            f"{missing}\n"
            "EVIDENCE:\n"
            f"title: {incident.title}\n"
            f"severity: {incident.severity}\n"
            f"telemetry: {json.dumps(incident.telemetry)}\n"
            f"logs: {json.dumps(evidence.get('logs', []))}\n"
            f"signals: {json.dumps(evidence.get('signals', []))}\n"
        )
