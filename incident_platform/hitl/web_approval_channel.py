"""Browser approval channel for the local demo dashboard (``ui_server.py``).

Same seam a Slack or PagerDuty bot would use. ``request_approval`` is called
on the incident's worker thread and *blocks* until someone decides in the
browser (``decide``) or the approval SLA runs out. A timeout is a fail-safe
reject.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any

from .hitl_gate import ApprovalChannel, ApprovalDecision, ApprovalRequest

APPROVAL_SLA_S = 15 * 60  # NFR matrix: decision within 15 minutes, else rejected


@dataclass
class _Pending:
    request: ApprovalRequest
    event: threading.Event = field(default_factory=threading.Event)
    decision: ApprovalDecision | None = None


class WebApprovalChannel(ApprovalChannel):
    def __init__(self, timeout_s: float = APPROVAL_SLA_S):
        self.timeout_s = timeout_s
        self._pending: dict[str, _Pending] = {}
        self._lock = threading.Lock()

    def request_approval(self, request: ApprovalRequest) -> ApprovalDecision:
        entry = _Pending(request)
        with self._lock:
            self._pending[request.request_id] = entry
        try:
            decided = entry.event.wait(self.timeout_s)
            if decided and entry.decision is not None:
                return entry.decision
            return ApprovalDecision(False, "web-timeout",
                                    f"no decision within {self.timeout_s:.0f}s; rejected by default")
        finally:
            with self._lock:
                self._pending.pop(request.request_id, None)

    def decide(self, request_id: str, approved: bool, approver: str = "web-sre") -> bool:
        with self._lock:
            entry = self._pending.get(request_id)
            if entry is None or entry.decision is not None:
                return False
            verb = "approved" if approved else "rejected"
            entry.decision = ApprovalDecision(bool(approved), approver, f"{verb} in web dashboard")
        entry.event.set()
        return True

    def pending_payloads(self) -> list[dict[str, Any]]:
        with self._lock:
            entries = [e for e in self._pending.values() if e.decision is None]
        return [{"incident_id": e.request.incident_id, **e.request.to_payload()} for e in entries]

    def cancel_all(self) -> None:
        """Reject everything still waiting (used when a new run replaces this one)."""
        with self._lock:
            ids = list(self._pending)
        for request_id in ids:
            self.decide(request_id, False, approver="web-reset")
