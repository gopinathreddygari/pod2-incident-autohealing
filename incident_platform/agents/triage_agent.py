"""Triage: gather evidence with read-only MCP tools, then ask for RCA + confidence."""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from llm.llm_backend import LLMOutputError

from .base_agent import BaseAgent

CATEGORIES = (
    "pod_crashloop",
    "resource_exhaustion",
    "bad_deployment",
    "node_disk_pressure",
    "latency_degradation",
    "stale_cache",
    "known_defect",
    "bad_config",
    "region_outage",
    "unknown",
)


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
        """Read-only tools are safe to retry. Stop as soon as the breaker is open."""
        result: dict = {}
        for _ in range(self.p.settings.READ_TOOL_MAX_ATTEMPTS):
            result = self.p.tools.call_tool(tool, args, incident_id=incident.incident_id)
            if not result["isError"] or result["errorType"] != "execution_error":
                break
        return result

    @staticmethod
    def _prompt(incident, evidence: dict, degraded: list[str]) -> str:
        missing = f"\nMISSING EVIDENCE (tools unavailable): {', '.join(degraded)}" if degraded else ""
        return (
            "TASK: TRIAGE\n"
            "Role: triage agent for production Kubernetes incidents.\n"
            "Determine the most likely root cause from the evidence below.\n"
            "Respond with JSON keys: root_cause (string), confidence (float 0-1), "
            f"category (one of {', '.join(CATEGORIES)}).\n"
            "Lower your confidence when evidence is missing or circumstantial."
            f"{missing}\n"
            "EVIDENCE:\n"
            f"title: {incident.title}\n"
            f"severity: {incident.severity}\n"
            f"telemetry: {json.dumps(incident.telemetry)}\n"
            f"logs: {json.dumps(evidence.get('logs', []))}\n"
            f"signals: {json.dumps(evidence.get('signals', []))}\n"
        )
