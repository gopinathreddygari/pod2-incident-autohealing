"""Human-in-the-loop approval gate.

Two independent triggers put a human in the loop:

* **risk class**     every MCP tool carries a ``risk_class`` (see ADR-04).
                     ``read_only`` and ``safe_reset`` may run autonomously;
                     ``destructive``, ``failover`` and ``config_patch`` always
                     need an SRE. An unknown class is gated too (fail-safe).
* **low_confidence** triage confidence is below ``MIN_AUTONOMOUS_CONFIDENCE``,
                     for *any* class. We don't let a guess act alone.

When either fires, the incident *pauses* in AWAITING_APPROVAL and the gate
builds an approval payload (the same structure a Slack or PagerDuty bot would
render). It then blocks on the channel's decision, moves the incident to
APPROVED or REJECTED, and resumes. The state machine has no edge that
bypasses this.

Channels are pluggable. ``ConsoleApprovalChannel`` asks on the terminal.
``AutoApprovalChannel`` replays scripted decisions for a reproducible demo
and **rejects** anything it has no decision for (fail-safe).
"""

from __future__ import annotations

import getpass
import json
import uuid
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from mcp_server.tool_server import (
    RISK_CONFIG_PATCH,
    RISK_DESTRUCTIVE,
    RISK_FAILOVER,
    RISK_READ_ONLY,
    RISK_SAFE_RESET,
)
from state.incident_state import IncidentState

REASON_DESTRUCTIVE = "destructive_action"
REASON_FAILOVER = "failover_action"
REASON_CONFIG_PATCH = "config_patch"
REASON_UNCLASSIFIED = "unclassified_action"
REASON_LOW_CONFIDENCE = "low_confidence"

# Risk class -> the reason that always requires an SRE.
GATED_RISK_CLASSES: dict[str, str] = {
    RISK_DESTRUCTIVE: REASON_DESTRUCTIVE,
    RISK_FAILOVER: REASON_FAILOVER,
    RISK_CONFIG_PATCH: REASON_CONFIG_PATCH,
}
AUTONOMOUS_RISK_CLASSES = frozenset({RISK_READ_ONLY, RISK_SAFE_RESET})

_REASON_TEXT = {
    REASON_DESTRUCTIVE: "destructive action (withdraws a release or evicts workloads)",
    REASON_FAILOVER: "failover (moves a region's traffic to another cluster)",
    REASON_CONFIG_PATCH: "config patch (changes the deployment's desired state)",
    REASON_UNCLASSIFIED: "unclassified tool (gated by default)",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ApprovalRequest:
    incident_id: str
    severity: str
    title: str
    action: str
    arguments: dict[str, Any]
    command: str
    reasons: list[str]
    confidence: float
    min_confidence: float
    root_cause: str
    blast_radius: str
    steps: list[str] = field(default_factory=list)
    risk_class: str = ""
    script_format: str = ""
    script: str = ""
    request_id: str = field(default_factory=lambda: f"apr-{uuid.uuid4().hex[:8]}")
    created_at: str = field(default_factory=_now)

    def to_payload(self) -> dict[str, Any]:
        """Slack Block Kit-shaped message: what the approver actually sees."""
        why = [_REASON_TEXT[r] for r in self.reasons if r in _REASON_TEXT]
        if REASON_LOW_CONFIDENCE in self.reasons:
            why.append(f"confidence {self.confidence:.2f} < {self.min_confidence:.2f}")
        blocks: list[dict[str, Any]] = [
            {"type": "header", "text": f"{self.incident_id} - {self.title}"},
            {"type": "section", "fields": {
                "Severity": self.severity,
                "Proposed action": self.action,
                "Risk class": self.risk_class or "unknown",
                "Command": self.command,
                "Why approval is required": "; ".join(why),
                "Triage confidence": f"{self.confidence:.2f}",
            }},
            {"type": "section", "text": f"Root cause: {self.root_cause}"},
            {"type": "section", "text": f"Blast radius: {self.blast_radius}"},
            {"type": "section", "text": "Plan: " + " -> ".join(self.steps)},
        ]
        if self.script:
            blocks.append({"type": "code", "title": f"Recovery script draft ({self.script_format}), not executed",
                           "language": self.script_format, "text": self.script})
        blocks.append({"type": "actions", "elements": [
            {"type": "button", "text": "Approve", "style": "primary", "value": f"approve:{self.request_id}"},
            {"type": "button", "text": "Reject", "style": "danger", "value": f"reject:{self.request_id}"},
        ]})
        return {
            "request_id": self.request_id,
            "text": f"[{self.severity}] Approval needed for {self.incident_id}: {self.action} ({self.risk_class})",
            "reasons": list(self.reasons),
            "blocks": blocks,
        }


@dataclass
class ApprovalDecision:
    approved: bool
    approver: str
    comment: str = ""
    decided_at: str = field(default_factory=_now)


class ApprovalChannel(ABC):
    @abstractmethod
    def request_approval(self, request: ApprovalRequest) -> ApprovalDecision: ...


class ConsoleApprovalChannel(ApprovalChannel):
    """Interactive y/n on the terminal. EOF or Ctrl-C counts as a rejection."""

    def request_approval(self, request: ApprovalRequest) -> ApprovalDecision:
        print("\n" + "=" * 72)
        print("HUMAN APPROVAL REQUIRED -- execution is paused")
        print(json.dumps(request.to_payload(), indent=2))
        try:
            user = getpass.getuser()
        except Exception:
            user = "console-operator"
        while True:
            try:
                # lstrip: piped input on Windows can arrive with a UTF-8 BOM.
                answer = input("Approve this action? [y/n]: ").strip().lstrip("﻿").lower()
            except (EOFError, KeyboardInterrupt):
                print()
                return ApprovalDecision(False, user, "no answer; rejected by default")
            if answer in {"y", "yes"}:
                return ApprovalDecision(True, user, "approved at console")
            if answer in {"n", "no"}:
                return ApprovalDecision(False, user, "rejected at console")


class AutoApprovalChannel(ApprovalChannel):
    """Scripted decisions keyed by incident id, for non-interactive runs."""

    def __init__(self, decisions: dict[str, bool] | None = None, approver: str = "scripted-sre",
                 verbose: bool = False):
        self.decisions = dict(decisions or {})
        self.approver = approver
        self.verbose = verbose
        self.requests: list[ApprovalRequest] = []

    def request_approval(self, request: ApprovalRequest) -> ApprovalDecision:
        self.requests.append(request)
        approved = self.decisions.get(request.incident_id, False)
        if self.verbose:
            print("    HITL approval payload (as a Slack/PagerDuty bot would render it):")
            for line in json.dumps(request.to_payload(), indent=2).splitlines():
                print("      " + line)
        comment = "scripted decision" if request.incident_id in self.decisions else "no scripted decision; fail-safe reject"
        return ApprovalDecision(approved, self.approver, comment)


class HITLGate:
    def __init__(self, channel: ApprovalChannel, store, audit, tracer, min_confidence: float):
        self.channel = channel
        self.store = store
        self.audit = audit
        self.tracer = tracer
        self.min_confidence = min_confidence

    def evaluate(self, risk_class: str, confidence: float) -> list[str]:
        """Reasons an SRE must approve; [] means the action may run autonomously."""
        reasons = []
        if risk_class in GATED_RISK_CLASSES:
            reasons.append(GATED_RISK_CLASSES[risk_class])
        elif risk_class not in AUTONOMOUS_RISK_CLASSES:
            reasons.append(REASON_UNCLASSIFIED)
        if confidence < self.min_confidence:
            reasons.append(REASON_LOW_CONFIDENCE)
        return reasons

    def request(self, incident, *, action: str, arguments: dict[str, Any], command: str, reasons: list[str],
                confidence: float, root_cause: str, blast_radius: str, steps: list[str],
                risk_class: str = "", script_format: str = "", script: str = "") -> ApprovalDecision:
        with self.tracer.start_span("hitl.approval", {"incident.id": incident.incident_id, "hitl.reasons": reasons}) as span:
            request = ApprovalRequest(
                incident_id=incident.incident_id,
                severity=incident.severity,
                title=incident.title,
                action=action,
                arguments=arguments,
                command=command,
                reasons=reasons,
                confidence=confidence,
                min_confidence=self.min_confidence,
                root_cause=root_cause,
                blast_radius=blast_radius,
                steps=steps,
                risk_class=risk_class,
                script_format=script_format,
                script=script,
            )
            self.store.transition(incident.incident_id, IncidentState.AWAITING_APPROVAL,
                                  f"HITL gate: {', '.join(reasons)}")
            self.audit.record("hitl_gate", "approval_requested", asdict(request))

            decision = self.channel.request_approval(request)

            span.set_attribute("hitl.approved", decision.approved)
            span.set_attribute("hitl.approver", decision.approver)
            self.audit.record("hitl_gate", "approval_decision", {
                "incident_id": incident.incident_id, "request_id": request.request_id, **asdict(decision),
            })
            new_state = IncidentState.APPROVED if decision.approved else IncidentState.REJECTED
            self.store.transition(incident.incident_id, new_state,
                                  f"{'approved' if decision.approved else 'rejected'} by {decision.approver}")
            incident.notes["approval"] = {
                "request_id": request.request_id,
                "reasons": reasons,
                "approved": decision.approved,
                "approver": decision.approver,
                "comment": decision.comment,
                "payload": request.to_payload(),
            }
            return decision
