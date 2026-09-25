"""Incident lifecycle: the state enum, the valid-transition graph, and the store.

The transition graph is the single authority on what may happen to an
incident. Every component asks the store to move an incident; the store
refuses anything not in ``VALID_TRANSITIONS``. In particular, there is no
edge from PLANNING or AWAITING_APPROVAL straight into a remediation for a
gated action -- the only way to EXECUTING through the HITL gate is via
APPROVED.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class IncidentState(str, Enum):
    RECEIVED = "RECEIVED"
    TRIAGING = "TRIAGING"
    PLANNING = "PLANNING"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTING = "EXECUTING"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    ESCALATED = "ESCALATED"


S = IncidentState

VALID_TRANSITIONS: dict[IncidentState, frozenset[IncidentState]] = {
    S.RECEIVED: frozenset({S.TRIAGING, S.ESCALATED}),
    S.TRIAGING: frozenset({S.PLANNING, S.ESCALATED, S.FAILED}),
    S.PLANNING: frozenset({S.EXECUTING, S.AWAITING_APPROVAL, S.ESCALATED, S.FAILED}),
    S.AWAITING_APPROVAL: frozenset({S.APPROVED, S.REJECTED}),
    S.APPROVED: frozenset({S.EXECUTING}),
    S.EXECUTING: frozenset({S.VERIFIED, S.FAILED}),
    S.REJECTED: frozenset(),
    S.VERIFIED: frozenset(),
    S.FAILED: frozenset(),
    S.ESCALATED: frozenset(),
}

TERMINAL_STATES = frozenset(s for s, nxt in VALID_TRANSITIONS.items() if not nxt)


class InvalidTransitionError(Exception):
    def __init__(self, incident_id: str, current: IncidentState, requested: IncidentState):
        super().__init__(
            f"{incident_id}: illegal transition {current.value} -> {requested.value}"
        )
        self.incident_id = incident_id
        self.current = current
        self.requested = requested


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Incident:
    incident_id: str
    title: str
    severity: str  # "P1" | "P2"
    telemetry: dict[str, Any]
    # Validated identifiers of what the incident is about (namespace, workload,
    # node, ...). Tool arguments are bound from here, never from LLM output.
    target: dict[str, Any] = field(default_factory=dict)
    state: IncidentState = IncidentState.RECEIVED
    history: list[dict[str, Any]] = field(default_factory=list)
    # Free-form per-stage results for reporting (triage, plan, approval, ...).
    notes: dict[str, Any] = field(default_factory=dict)


class IncidentStateStore:
    """In-memory incident store with a Redis-shaped get/put/transition surface."""

    def __init__(self, audit=None, redact=None):
        """``redact`` (text -> text) scrubs PII from free text before it is audited."""
        self._incidents: dict[str, Incident] = {}
        self._audit = audit
        self._redact = redact or (lambda text: text)

    def put(self, incident: Incident) -> None:
        self._incidents[incident.incident_id] = incident
        incident.history.append(
            {"from": None, "to": incident.state.value, "reason": "incident received", "ts": _now()}
        )
        if self._audit is not None:
            self._audit.record(
                "state_store",
                "incident_received",
                {
                    "incident_id": incident.incident_id,
                    "severity": incident.severity,
                    "title": self._redact(incident.title),
                },
            )

    def get(self, incident_id: str) -> Incident:
        return self._incidents[incident_id]

    def all(self) -> list[Incident]:
        return list(self._incidents.values())

    def can_transition(self, incident_id: str, new_state: IncidentState) -> bool:
        return new_state in VALID_TRANSITIONS[self.get(incident_id).state]

    def transition(self, incident_id: str, new_state: IncidentState, reason: str = "") -> Incident:
        incident = self.get(incident_id)
        current = incident.state
        if new_state not in VALID_TRANSITIONS[current]:
            if self._audit is not None:
                self._audit.record(
                    "state_store",
                    "illegal_transition_refused",
                    {"incident_id": incident_id, "from": current.value, "to": new_state.value},
                )
            raise InvalidTransitionError(incident_id, current, new_state)
        incident.state = new_state
        incident.history.append(
            {"from": current.value, "to": new_state.value, "reason": reason, "ts": _now()}
        )
        if self._audit is not None:
            self._audit.record(
                "state_store",
                "state_transition",
                {
                    "incident_id": incident_id,
                    "from": current.value,
                    "to": new_state.value,
                    "reason": self._redact(reason),
                },
            )
        return incident
