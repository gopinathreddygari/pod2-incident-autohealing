"""Remediation planning: the LLM chooses *which* runbook action; code binds *what to*.

The model only picks an action name from the server's non-read-only tools.
Arguments are bound deterministically from the incident's validated
``target`` fields, never from free-form model output. The rendered command is
then scanned by the output guardrail before anything can execute.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from guardrails.guardrail_middleware import GuardrailViolation
from llm.llm_backend import LLMOutputError

from .base_agent import BaseAgent
from .recovery_scripts import render_script


class PlanningError(Exception):
    pass


@dataclass
class RemediationPlan:
    action: str
    arguments: dict[str, Any]
    command: str
    steps: list[str]
    destructive: bool
    blast_radius: str
    risk_class: str = ""
    # IaC recovery draft for human review (kubernetes-yaml / ansible-yaml / terraform-hcl).
    # Shown, never executed: only ``command`` goes through the MCP tool server.
    script_format: str = ""
    script: str = ""
    rationale: str = ""
    cache_layer: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


class RemediationPlannerAgent(BaseAgent):
    name = "remediation_planner_agent"

    def run(self, incident, triage) -> RemediationPlan | None:
        """Returns None when the model recommends no automated action."""
        tools = self.p.tools
        actions = [t for t in tools.list_tools() if not t["annotations"]["readOnlyHint"]]
        prompt = (
            "TASK: PLAN\n"
            "Role: remediation planner. Choose exactly one action from AVAILABLE ACTIONS, or 'none'.\n"
            "Respond with JSON keys: action (string), steps (list of strings), rationale (string).\n"
            "AVAILABLE ACTIONS:\n"
            + "\n".join(f"- {t['name']}: {t['description']}" for t in actions)
            + f"\nCATEGORY: {triage.category}\n"
            f"CONFIDENCE: {triage.confidence:.2f}\n"
            f"EVIDENCE:\nroot_cause: {triage.root_cause}\n"
        )
        result = self.think(incident, prompt, cache_key=f"{triage.category} | {triage.root_cause}")
        data = result.data

        action = str(data.get("action", "none"))
        if action == "none":
            return None
        spec = tools.get_spec(action)
        if spec is None or spec.read_only:
            raise LLMOutputError(f"model proposed '{action}', which is not a remediation tool")

        arguments = self._bind_arguments(spec, incident.target)
        command = spec.command_template.format(**arguments)

        verdict = self.p.guardrails.check_output(command)
        if not verdict.allowed:
            self.p.audit.record(self.name, "guardrail_blocked_output", {
                "incident_id": incident.incident_id, "command": command, "reasons": verdict.reasons,
            })
            raise GuardrailViolation("output", verdict.reasons)

        script_format, script = render_script(action, arguments, incident.incident_id)
        script_verdict = self.p.guardrails.check_script(script)
        if not script_verdict.allowed:
            self.p.audit.record(self.name, "guardrail_blocked_output", {
                "incident_id": incident.incident_id, "command": f"{script_format} draft",
                "reasons": script_verdict.reasons,
            })
            raise GuardrailViolation("script", script_verdict.reasons)

        steps = data.get("steps") or []
        return RemediationPlan(
            action=action,
            arguments=arguments,
            command=command,
            steps=[str(s) for s in steps] if isinstance(steps, list) else [str(steps)],
            destructive=spec.destructive,
            blast_radius=spec.blast_radius.format(**arguments),
            risk_class=spec.risk_class,
            script_format=script_format,
            script=script,
            rationale=str(data.get("rationale", "")),
            cache_layer=result.cache_layer,
        )

    @staticmethod
    def _bind_arguments(spec, target: dict[str, Any]) -> dict[str, Any]:
        schema = spec.input_schema
        aliases = {"deployment": "workload"}
        arguments: dict[str, Any] = {}
        for name in schema["properties"]:
            if name in target:
                arguments[name] = target[name]
            elif aliases.get(name) in target:
                arguments[name] = target[aliases[name]]
        missing = [k for k in schema["required"] if k not in arguments]
        if missing:
            raise PlanningError(f"{spec.name}: incident target lacks {', '.join(missing)}")
        return arguments
