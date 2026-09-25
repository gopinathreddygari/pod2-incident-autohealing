"""Execution + verification: HITL gate -> MCP tool call -> post-remediation health check."""

from __future__ import annotations

from state.incident_state import IncidentState

from .base_agent import BaseAgent


class ExecutionVerificationAgent(BaseAgent):
    name = "execution_verification_agent"

    def __init__(self, platform, hitl_gate):
        super().__init__(platform)
        self.hitl = hitl_gate

    def run(self, incident, triage, plan) -> IncidentState:
        p = self.p
        store = p.store
        iid = incident.incident_id

        # Gate on the tool's risk class (not just a destructive flag), plus low confidence.
        reasons = self.hitl.evaluate(plan.risk_class, triage.confidence)
        if reasons:
            decision = self.hitl.request(
                incident, action=plan.action, arguments=plan.arguments, command=plan.command,
                reasons=reasons, confidence=triage.confidence, root_cause=triage.root_cause,
                blast_radius=plan.blast_radius, steps=plan.steps, risk_class=plan.risk_class,
                script_format=plan.script_format, script=plan.script,
            )
            if not decision.approved:
                return incident.state  # REJECTED -- nothing executes
        store.transition(iid, IncidentState.EXECUTING, f"executing {plan.command}")

        result = p.tools.call_tool(plan.action, plan.arguments, incident_id=iid)
        incident.notes["execution"] = {"isError": result["isError"],
                                       "detail": result.get("structuredContent") or result.get("errorType")}
        if result["isError"]:
            store.transition(iid, IncidentState.FAILED, f"{plan.action} failed: {result['errorType']}")
            return incident.state

        target = incident.target
        health = p.tools.call_tool("correlate_telemetry",
                                   {"namespace": target["namespace"], "service": target["service"]},
                                   incident_id=iid)
        if health["isError"]:
            store.transition(iid, IncidentState.FAILED, f"could not verify health: {health['errorType']}")
            return incident.state

        healthy = health["structuredContent"]["healthy"]
        incident.notes["verification"] = health["structuredContent"]
        if healthy:
            store.transition(iid, IncidentState.VERIFIED, "post-remediation health check passed")
        else:
            store.transition(iid, IncidentState.FAILED, "service still unhealthy after remediation: "
                             + "; ".join(health["structuredContent"]["signals"]))
        return incident.state
