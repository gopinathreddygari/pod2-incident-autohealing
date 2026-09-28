"""Live local demo dashboard (standard library only).

    python ui_server.py                 # opens http://127.0.0.1:8000
    python ui_server.py --port 9000 --no-browser

Runs the same ten scenarios as ``main.py``, on the same platform code, but:

* incidents are paced so the state machine visibly animates,
* the HITL gate uses ``WebApprovalChannel``: the incident really pauses until
  you click Approve or Reject in the browser,
* knobs change the confidence threshold and the failure injection,
* you can submit your own incident (including a prompt injection) and it
  goes through the same guardrails,
* "Tamper" edits a *copy* of the audit chain to show verification failing.

Binds to 127.0.0.1 only. There is no authentication: this is a local demo, not
a deployable approval service.
"""

from __future__ import annotations

import argparse
import copy
import json
import queue
from collections import deque
import threading
import time
import webbrowser
from dataclasses import replace
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from config import DOTENV_STATUS, SETTINGS
from hitl import WebApprovalChannel
from main import Scenario, build_scenarios, prepare_scenario
from mcp_server import TOOL_SPECS
from observability import AuditLog
from orchestrator import IncidentOrchestrator, IncidentPlatform
from state import TERMINAL_STATES, Incident, IncidentStateStore

UI_DIR = Path(__file__).resolve().parent / "ui"
TOOL_NAMES = [t.name for t in TOOL_SPECS]
REMEDIATION_TOOLS = [t.name for t in TOOL_SPECS if not t.read_only]
MAX_BODY = 64 * 1024

DEFAULT_KNOBS = {
    "min_confidence": SETTINGS.MIN_AUTONOMOUS_CONFIDENCE,
    "fail_tool": "fetch_k8s_logs",
    "fail_count": 5,
    "pace": 0.8,
    "mode": "step",  # "step": presenter clicks Next between incidents; "auto": run straight through
}
MODES = ("step", "auto")


class BadRequest(Exception):
    pass


class Conflict(BadRequest):
    """Valid request, wrong moment (e.g. Next while an incident is still running) -> HTTP 409."""


class PacedStateStore(IncidentStateStore):
    """Sleeps after each transition so a human can watch the state machine move."""

    def __init__(self, audit, pace: float, redact=None):
        super().__init__(audit=audit, redact=redact)
        self.pace = pace

    def transition(self, incident_id, new_state, reason=""):
        incident = super().transition(incident_id, new_state, reason)
        if self.pace:
            time.sleep(self.pace)
        return incident


# --------------------------------------------------------------------------
# Session: one platform + one worker thread processing a queue of scenarios
# --------------------------------------------------------------------------


class DemoSession:
    def __init__(self, knobs: dict[str, Any]):
        self.knobs = knobs
        settings = replace(SETTINGS, MIN_AUTONOMOUS_CONFIDENCE=knobs["min_confidence"])
        self.platform = IncidentPlatform(settings=settings, audit_path=None)
        self.platform.store = PacedStateStore(self.platform.audit, knobs["pace"],
                                              redact=self.platform.guardrails.redact_text)
        self.channel = WebApprovalChannel()
        self.orchestrator = IncidentOrchestrator(self.platform, self.channel)
        self.created = time.time()

        self._lock = threading.Lock()
        self._queue: queue.Queue[Scenario | None] = queue.Queue()
        self._outstanding = 0
        self._stopped = False
        self.scenarios: list[Scenario] = []   # everything shown in the UI, in order
        self._backlog: deque[Scenario] = deque()  # step mode: planned but not yet submitted
        self.started: set[str] = set()
        self.errors: list[str] = []
        self._custom_seq = 0
        self._worker = threading.Thread(target=self._loop, name="incident-worker", daemon=True)
        self._worker.start()

    @property
    def busy(self) -> bool:
        return self._outstanding > 0

    def submit(self, sc: Scenario) -> None:
        """Show and run now (auto mode, custom incidents)."""
        with self._lock:
            self._outstanding += 1
            self.scenarios.append(sc)
        self._queue.put(sc)

    def plan(self, sc: Scenario) -> None:
        """Show as QUEUED, but run only when the presenter advances."""
        with self._lock:
            self.scenarios.append(sc)
            self._backlog.append(sc)

    def advance(self) -> Scenario | None:
        """Submit the next planned scenario, if any."""
        with self._lock:
            if not self._backlog:
                return None
            sc = self._backlog.popleft()
            self._outstanding += 1
        self._queue.put(sc)
        return sc

    @property
    def next_up(self) -> str | None:
        backlog = self._backlog
        return backlog[0].incident.incident_id if backlog else None

    @property
    def backlog_size(self) -> int:
        return len(self._backlog)

    def next_custom_id(self) -> str:
        with self._lock:
            self._custom_seq += 1
            return f"CUS-{self._custom_seq:03d}"

    def stop(self) -> None:
        self._stopped = True
        self.channel.cancel_all()
        self._queue.put(None)

    def _loop(self) -> None:
        while not self._stopped:
            sc = self._queue.get()
            if sc is None or self._stopped:
                break
            try:
                self.started.add(sc.incident.incident_id)
                prepare_scenario(self.platform, sc)
                try:
                    self.orchestrator.handle(sc.incident)
                finally:
                    self.platform.tools.clear_injected_failures()
            except Exception as exc:  # surface in the UI rather than killing the worker
                self.errors.append(f"{sc.incident.incident_id}: {type(exc).__name__}: {exc}")
            finally:
                with self._lock:
                    self._outstanding -= 1


# --------------------------------------------------------------------------
# Snapshot helpers (the worker mutates state while HTTP threads read it)
# --------------------------------------------------------------------------


def _incident_view(sc: Scenario, started: bool, redact, pii_find) -> dict[str, Any]:
    inc = sc.incident
    notes = dict(inc.notes)
    triage, plan = notes.get("triage"), notes.get("plan")
    approval = dict(notes["approval"]) if "approval" in notes else None
    if approval:
        approval.pop("payload", None)
    state = inc.state.value if started else "QUEUED"
    return {
        "id": inc.incident_id,
        "title": inc.title,
        "severity": inc.severity,
        "state": state,
        "terminal": started and inc.state in TERMINAL_STATES,
        "telemetry": dict(inc.telemetry),
        "target": dict(inc.target),
        "history": [dict(h) for h in list(inc.history)],
        "triage": None if triage is None else {
            "category": triage.category, "confidence": triage.confidence, "root_cause": triage.root_cause,
            "model": triage.model, "cache_layer": triage.cache_layer,
            "cache_similarity": triage.cache_similarity, "degraded": list(triage.degraded),
        },
        "plan": None if plan is None else {
            "action": plan.action, "command": plan.command, "destructive": plan.destructive,
            "blast_radius": plan.blast_radius, "steps": list(plan.steps), "cache_layer": plan.cache_layer,
            "risk_class": plan.risk_class, "script_format": plan.script_format, "script": plan.script,
        },
        "guardrail": notes.get("guardrail"),
        "pii": notes.get("pii_redactions"),
        "pii_sources": notes.get("pii_sources"),
        # Per-finding detail for the current text, so the UI can show which layer caught what.
        "pii_findings": [
            {"label": f.label, "source": f.source, "text": f.text}
            for f in pii_find(inc.title + "\n" + str(inc.telemetry.get("symptoms", "")))
        ],
        # What leaves for the model: same redaction BaseAgent.think() applies.
        "llm_view": {"title": redact(inc.title), "symptoms": redact(str(inc.telemetry.get("symptoms", "")))},
        "approval": approval,
        "verification": notes.get("verification"),
        "execution": notes.get("execution"),
        "escalation": notes.get("escalation_reason"),
        "fail_injection": dict(sc.fail_injection),
    }


def _summarise_event(entry: dict[str, Any]) -> str:
    p, action = entry.get("payload", {}), entry.get("action")
    if action == "state_transition":
        return f"{p.get('from')} -> {p.get('to')}"
    if action == "incident_received":
        return f"[{p.get('severity')}] {p.get('title')}"
    if action in ("tool_call", "tool_call_error"):
        suffix = f" ({p.get('error_type')})" if action == "tool_call_error" else ""
        return f"{p.get('tool')}{suffix}"
    if action == "llm_call":
        return f"{p.get('model')} {p.get('tokens_in', 0) + p.get('tokens_out', 0)} tokens ${p.get('cost_usd')}"
    if action == "llm_cache_hit":
        return f"{p.get('layer')} hit, similarity {p.get('similarity')}"
    if action in ("guardrail_blocked_input", "guardrail_blocked_output"):
        return ", ".join(p.get("reasons", []))
    if action == "approval_requested":
        return f"{p.get('action')} ({', '.join(p.get('reasons', []))})"
    if action == "approval_decision":
        return f"{'approved' if p.get('approved') else 'rejected'} by {p.get('approver')}"
    if action == "state_change":
        return f"breaker {p.get('tool')}: {p.get('from')} -> {p.get('to')}"
    return ""


_ACTOR_LABELS = {
    "state_store": "state", "triage_agent": "triage", "remediation_planner_agent": "planner",
    "execution_verification_agent": "executor", "mcp_server": "MCP", "hitl_gate": "HITL",
    "circuit_breaker": "breaker",
}
_PHASE_BY_STATE = {
    "RECEIVED": "Intake", "TRIAGING": "Triage", "PLANNING": "Planning", "AWAITING_APPROVAL": "Approval",
    "APPROVED": "Approval", "REJECTED": "Outcome", "EXECUTING": "Execution", "VERIFIED": "Outcome",
    "FAILED": "Outcome", "ESCALATED": "Outcome",
}


def _args(arguments: dict[str, Any]) -> str:
    return ", ".join(f"{k}={v}" for k, v in arguments.items())


def _describe_step(entry: dict[str, Any]) -> tuple[str, str]:
    """Plain-English line + level (info | ok | warn | error) for one audit entry."""
    p, action = entry.get("payload", {}), entry.get("action")
    if action == "incident_received":
        return f"Incident received [{p.get('severity')}]: {p.get('title')}", "info"
    if action == "state_transition":
        to, reason = p.get("to"), p.get("reason") or ""
        level = {"VERIFIED": "ok", "APPROVED": "ok", "REJECTED": "error", "FAILED": "error",
                 "ESCALATED": "warn", "AWAITING_APPROVAL": "warn"}.get(to, "info")
        return f"→ {to}" + (f": {reason}" if reason else ""), level
    if action == "tool_call":
        mark = "  [destructive]" if p.get("destructive") else ""
        if p.get("fault_cleared") is False:
            return (f"MCP {p.get('tool')}({_args(p.get('arguments', {}))}) ✓ executed, "
                    f"but it did not clear the fault{mark}"), "warn"
        return f"MCP {p.get('tool')}({_args(p.get('arguments', {}))}) ✓{mark}", "ok"
    if action == "tool_call_error":
        return f"MCP {p.get('tool')} failed: {p.get('error_type')} ({p.get('message')})", "error"
    if action == "llm_call" and p.get("fallback_error"):
        by = p.get("backend")
        level = "warn" if by == "anthropic" else "error"   # a real second provider is a healthy fallback
        return (f"LLM {p.get('model')}: earlier provider call FAILED ({p.get('fallback_error')}) -> answered by "
                f"{'Anthropic' if by == 'anthropic' else 'the mock'} fallback instead"), level
    if action == "llm_call":
        pii = ", ".join(f"{k}×{n}" for k, n in (p.get("pii_sources") or {}).items())
        return (f"LLM {p.get('model')} ({p.get('backend')}): {p.get('tokens_in')} in / {p.get('tokens_out')} out tokens, "
                f"${p.get('cost_usd')}" + (f" · PII redacted: {pii}" if pii else "")), "info"
    if action == "llm_cache_hit":
        return f"Semantic cache {p.get('layer')} hit (similarity {p.get('similarity')}): 0 tokens spent", "ok"
    if action == "guardrail_blocked_input":
        return f"Input guardrail blocked the prompt: {', '.join(p.get('reasons', []))}. Nothing sent to the LLM", "error"
    if action == "guardrail_blocked_output":
        return f"Output guardrail blocked command `{p.get('command')}`: {', '.join(p.get('reasons', []))}", "error"
    if action == "approval_requested":
        return f"⏸ Paused for human approval: {p.get('action')} ({', '.join(p.get('reasons', []))})", "warn"
    if action == "approval_decision":
        verb = "Approved" if p.get("approved") else "Rejected"
        return f"{verb} by {p.get('approver')} ({p.get('comment')})", "ok" if p.get("approved") else "error"
    if action == "state_change":
        to = p.get("to")
        held = f" for {p['open_for_s']:g} s" if to == "OPEN" and p.get("open_for_s") else ""
        return f"Circuit breaker {p.get('tool')}: {p.get('from')} → {to}{held}", "error" if to == "OPEN" else "warn"
    if action == "tool_retry":
        return (f"Retrying {p.get('tool')} (attempt {p.get('next_attempt')}/{p.get('max_attempts')}) after "
                f"{p.get('delay_s')} s backoff (jitter, cap {p.get('cap_s')} s)"), "warn"
    if action == "retry_budget_exhausted":
        return f"Stopped retrying {p.get('tool')}: {p.get('budget_s')} s retry budget used up", "error"
    if action == "illegal_transition_refused":
        return f"Refused illegal transition {p.get('from')} → {p.get('to')}", "error"
    return action or "", "info"


def _ms_between(start_iso: str, ts_iso: str) -> float:
    try:
        return (datetime.fromisoformat(ts_iso) - datetime.fromisoformat(start_iso)).total_seconds() * 1000
    except (TypeError, ValueError):
        return 0.0


def _steps_by_incident(entries: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """One pass over the audit chain, grouped per incident and tagged with a lifecycle phase."""
    out: dict[str, list[dict[str, Any]]] = {}
    start: dict[str, str] = {}
    phase: dict[str, str] = {}
    for e in entries:
        iid = e.get("payload", {}).get("incident_id")
        if not iid:
            continue
        start.setdefault(iid, e["ts"])
        current = phase.get(iid, "Intake")
        if e["action"] == "state_transition":
            current = _PHASE_BY_STATE.get(e["payload"].get("to"), current)
        elif e["action"] == "tool_call" and e["payload"].get("tool") == "correlate_telemetry" and current == "Execution":
            current = "Verification"
        phase[iid] = current
        text, level = _describe_step(e)
        out.setdefault(iid, []).append({
            "seq": e["seq"], "t_ms": round(_ms_between(start[iid], e["ts"]), 1), "phase": current,
            "actor": _ACTOR_LABELS.get(e["actor"], e["actor"]), "action": e["action"], "text": text, "level": level,
        })
    return out


def _llm_calls_by_incident(entries: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Per incident: who answered each LLM step -- 'openai', 'mock', 'fallback' (OpenAI failed) or 'cache'."""
    out: dict[str, list[dict[str, Any]]] = {}
    for e in entries:
        p = e.get("payload", {})
        iid = p.get("incident_id")
        if not iid or e["action"] not in ("llm_call", "llm_cache_hit"):
            continue
        if e["action"] == "llm_cache_hit":
            source = "cache"
        elif p.get("fallback_error"):
            source = "fallback"
        else:
            source = p.get("backend") if p.get("backend") in ("openai", "anthropic") else "mock"
        out.setdefault(iid, []).append({
            "agent": _ACTOR_LABELS.get(e["actor"], e["actor"]), "source": source, "model": p.get("model"),
            "backend": p.get("backend"),
            "layer": p.get("layer"), "error": p.get("fallback_error"),
        })
    return out


def _llm_totals(entries: list[dict[str, Any]]) -> dict[str, int]:
    totals = {"openai": 0, "anthropic": 0, "mock": 0, "fallback": 0, "cache": 0}
    for calls in _llm_calls_by_incident(entries).values():
        for c in calls:
            totals[c["source"]] += 1
    return totals


_SPAN_ATTRS = ("retry.attempt", "retry.delay_s", "agent", "llm.model", "llm.tokens", "llm.backend", "cache.hit", "cache.similarity", "mcp.tool",
               "mcp.error_type", "hitl.reasons", "hitl.approved", "hitl.approver", "guardrail.blocked",
               "incident.final_state", "error.type")


def _traces_by_incident(tracer) -> dict[str, list[dict[str, Any]]]:
    """Finished + still-running spans, grouped into one trace per incident."""
    now_ns = time.perf_counter_ns()
    spans = list(tracer.spans) + list(tracer.active.values())
    roots = {s.trace_id: s for s in spans if s.name == "incident.handle"}
    out: dict[str, list[dict[str, Any]]] = {}
    for s in sorted(spans, key=lambda s: s.mono_start_ns):
        root = roots.get(s.trace_id)
        if root is None:
            continue
        iid = root.attributes.get("incident.id")
        running = s.mono_end_ns is None
        end = now_ns if running else s.mono_end_ns
        attrs = dict(s.attributes)
        out.setdefault(iid, []).append({
            "span_id": s.span_id, "parent_id": s.parent_id, "name": s.name,
            "start_ms": round((s.mono_start_ns - root.mono_start_ns) / 1e6, 3),
            "duration_ms": round((end - s.mono_start_ns) / 1e6, 3),
            "status": "RUNNING" if running else s.status, "running": running,
            "attrs": {k: attrs[k] for k in _SPAN_ATTRS if k in attrs},
        })
    return out


class DemoApp:
    def __init__(self, default_pace: float | None = None):
        self._lock = threading.Lock()
        self.knobs = dict(DEFAULT_KNOBS)
        if default_pace is not None:
            self.knobs["pace"] = default_pace
        self.session: DemoSession | None = None

    # --- actions -------------------------------------------------------------
    def run_all(self, body: dict[str, Any]) -> dict[str, Any]:
        knobs = self._parse_knobs(body)
        with self._lock:
            if self.session is not None and self.session.busy:
                raise Conflict("a run is already in progress")
            if self.session is not None:
                self.session.stop()
            self.knobs = knobs
            self.session = DemoSession(knobs)
            for sc in build_scenarios():
                if sc.incident.incident_id == "INC-1010":  # the circuit-breaker scenario
                    sc.fail_injection = {knobs["fail_tool"]: knobs["fail_count"]} if knobs["fail_count"] else {}
                if knobs["mode"] == "auto":
                    self.session.submit(sc)
                else:
                    self.session.plan(sc)
            first = self.session.advance() if knobs["mode"] == "step" else None
        return {"ok": True, "incident_id": first.incident.incident_id if first else "INC-1001"}

    def next_incident(self, body: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            session = self.session
            if session is None or not session.backlog_size:
                raise Conflict("nothing left to run -- start a new run")
            if session.busy:
                raise Conflict("finish the current incident first (it is still running or awaiting approval)")
            sc = session.advance()
        return {"ok": True, "incident_id": sc.incident.incident_id}

    def run_rest(self, body: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            session = self.session
            if session is None or not session.backlog_size:
                raise Conflict("nothing left to run -- start a new run")
            session.knobs = {**session.knobs, "mode": "auto"}
            first = session.advance()
            while session.advance():
                pass
        return {"ok": True, "incident_id": first.incident.incident_id}

    def custom_incident(self, body: dict[str, Any]) -> dict[str, Any]:
        def text(name: str, limit: int, required: bool = True) -> str:
            value = str(body.get(name, "")).strip()
            if required and not value:
                raise BadRequest(f"'{name}' is required")
            if len(value) > limit:
                raise BadRequest(f"'{name}' is longer than {limit} characters")
            return value

        title = text("title", 200)
        severity = text("severity", 2)
        if severity not in ("P1", "P2"):
            raise BadRequest("severity must be P1 or P2")
        alert = text("alert", 100, required=False)
        symptoms = text("symptoms", 1000)
        namespace = text("namespace", 63)
        workload = text("workload", 63)
        node = text("node", 63, required=False)
        patch = text("patch", 40, required=False)    # apply_hotfix patch id, e.g. hotfix-2141
        region = text("region", 40, required=False)  # failover_cluster region, e.g. eu-west-1
        fix = text("fix", 40, required=False) or "none"
        if fix != "none" and fix not in REMEDIATION_TOOLS:
            raise BadRequest(f"fix must be one of {REMEDIATION_TOOLS} or 'none'")
        try:
            replicas = int(body.get("replicas", 6))
        except (TypeError, ValueError):
            raise BadRequest("replicas must be an integer") from None
        if not 1 <= replicas <= 100:
            raise BadRequest("replicas must be between 1 and 100")

        with self._lock:
            if self.session is None:
                self.session = DemoSession(self.knobs)
            session = self.session
        # The health-checked "service" is the node or region when the incident is about one.
        target: dict[str, Any] = {"namespace": namespace, "workload": workload, "service": node or region or workload,
                                  "replicas": replicas}
        if node:
            target["node"] = node
        if patch:
            target["patch"] = patch
        if region:
            target["region"] = region
        incident = Incident(session.next_custom_id(), title, severity,
                            {"alert": alert, "source": "web-form", "symptoms": symptoms}, target)
        session.submit(Scenario(incident, "custom incident from the web form", incident.state,
                                logs=[symptoms], signals=[alert or "custom alert"],
                                fixed_by=set() if fix == "none" else {fix}))
        return {"ok": True, "incident_id": incident.incident_id}

    def approve(self, body: dict[str, Any]) -> dict[str, Any]:
        session = self.session
        request_id = str(body.get("request_id", ""))
        if session is None or not session.channel.decide(request_id, bool(body.get("approved"))):
            raise BadRequest("no pending approval with that id")
        return {"ok": True}

    def tamper(self, body: dict[str, Any]) -> dict[str, Any]:
        session = self.session
        if session is None or not session.platform.audit.entries:
            raise BadRequest("run something first -- the audit log is empty")
        real = session.platform.audit
        entries = copy.deepcopy(list(real.entries))
        seq = body.get("seq")
        seq = len(entries) // 2 if not isinstance(seq, int) or not 0 <= seq < len(entries) else seq
        original = entries[seq]["actor"]
        entries[seq]["actor"] = "attacker"
        forged = AuditLog()
        forged.entries = entries
        return {
            "tampered_seq": seq,
            "field_changed": f"actor: '{original}' -> 'attacker'",
            "copy_intact": forged.verify_chain(),
            "first_broken_seq": forged.first_broken_seq(),
            "real_intact": real.verify_chain(),
        }

    # --- state ---------------------------------------------------------------
    def state(self) -> dict[str, Any]:
        for _ in range(3):
            try:
                return self._state()
            except RuntimeError:  # a dict changed size mid-read; just read again
                time.sleep(0.01)
        return self._state()

    def _state(self) -> dict[str, Any]:
        session = self.session
        base = {"knobs": self.knobs, "tools": TOOL_NAMES, "remediation_tools": REMEDIATION_TOOLS,
                "backend": None, "status": "idle", "incidents": [], "pending": [], "errors": []}
        if session is None:
            return base
        p = session.platform
        pending = session.channel.pending_payloads()
        audit_entries = list(p.audit.entries)
        broken = AuditLog()
        broken.entries = audit_entries
        first_broken = broken.first_broken_seq()
        steps = _steps_by_incident(audit_entries)
        llm_calls = _llm_calls_by_incident(audit_entries)
        traces = _traces_by_incident(p.tracer)
        views = []
        for sc in list(session.scenarios):
            iid = sc.incident.incident_id
            view = _incident_view(sc, iid in session.started, p.guardrails.redact_text, p.guardrails.pii.find)
            views.append({**view, "steps": steps.get(iid, []), "trace": traces.get(iid, []),
                          "llm": llm_calls.get(iid, [])})
        return {
            **base,
            "knobs": session.knobs,
            "backend": p.backend.name,
            "status": ("awaiting_approval" if pending else "running" if session.busy
                       else "waiting_next" if session.backlog_size else "done"),
            "mode": session.knobs.get("mode", "auto"),
            "next_up": session.next_up,
            "backlog": session.backlog_size,
            "pii_detector": p.guardrails.pii.name,
            "real_llm": bool(p.settings.USE_REAL_LLM and (p.settings.OPENAI_API_KEY or p.settings.ANTHROPIC_API_KEY)),
            "llm_totals": _llm_totals(audit_entries),
            "incidents": views,
            "pending": pending,
            "errors": list(session.errors),
            "metrics": p.metrics.summary(),
            "breakers": p.breakers.snapshot(),
            "cache": {"l1": p.cache.hits_l1, "l2": p.cache.hits_l2, "misses": p.cache.misses},
            "cost": {"total_usd": round(p.profiler.total_cost, 6),
                     "saved_usd": round(p.profiler.cost_saved_by_cache, 6),
                     "saved_tokens": p.profiler.tokens_saved_by_cache,
                     "by_model": p.profiler.by_model(),
                     "router": dict(p.router.decisions)},
            "audit": {
                "count": len(audit_entries),
                "intact": first_broken is None,
                "first_broken_seq": first_broken,
                "head": audit_entries[-1]["hash"] if audit_entries else None,
                "recent": [{"seq": e["seq"], "ts": e["ts"], "actor": e["actor"], "action": e["action"],
                            "incident_id": e["payload"].get("incident_id"), "summary": _summarise_event(e)}
                           for e in audit_entries[-40:]],
            },
            "spans": len(p.tracer.spans),
        }

    @staticmethod
    def _parse_knobs(body: dict[str, Any]) -> dict[str, Any]:
        try:
            knobs = {
                "min_confidence": float(body.get("min_confidence", DEFAULT_KNOBS["min_confidence"])),
                "fail_tool": str(body.get("fail_tool", DEFAULT_KNOBS["fail_tool"])),
                "fail_count": int(body.get("fail_count", DEFAULT_KNOBS["fail_count"])),
                "pace": float(body.get("pace", DEFAULT_KNOBS["pace"])),
                "mode": str(body.get("mode", DEFAULT_KNOBS["mode"])),
            }
        except (TypeError, ValueError):
            raise BadRequest("knobs must be numbers") from None
        if knobs["mode"] not in MODES:
            raise BadRequest(f"mode must be one of {MODES}")
        if not 0.3 <= knobs["min_confidence"] <= 0.99:
            raise BadRequest("min_confidence must be between 0.30 and 0.99")
        if knobs["fail_tool"] not in TOOL_NAMES:
            raise BadRequest(f"fail_tool must be one of {TOOL_NAMES}")
        if not 0 <= knobs["fail_count"] <= 10:
            raise BadRequest("fail_count must be between 0 and 10")
        if not 0 <= knobs["pace"] <= 3:
            raise BadRequest("pace must be between 0 and 3 seconds")
        return knobs


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------


class Handler(BaseHTTPRequestHandler):
    server_version = "IncidentDemo/1.0"

    @property
    def app(self) -> DemoApp:
        return self.server.app  # type: ignore[attr-defined]

    def log_message(self, fmt, *args):  # keep the terminal quiet
        pass

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, data: Any) -> None:
        self._send(status, json.dumps(data, default=str).encode("utf-8"), "application/json")

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            self._send(200, (UI_DIR / "index.html").read_bytes(), "text/html; charset=utf-8")
        elif path == "/api/state":
            self._json(200, self.app.state())
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        routes = {"/api/run": self.app.run_all, "/api/incident": self.app.custom_incident,
                  "/api/approve": self.app.approve, "/api/tamper": self.app.tamper,
                  "/api/next": self.app.next_incident, "/api/run_rest": self.app.run_rest}
        action = routes.get(self.path.split("?", 1)[0])
        if action is None:
            return self._json(404, {"error": "not found"})
        try:
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                raise BadRequest("request body too large")
            raw = self.rfile.read(length) if length else b"{}"
            body = json.loads(raw or b"{}")
            if not isinstance(body, dict):
                raise BadRequest("body must be a JSON object")
            self._json(200, action(body))
        except BadRequest as exc:
            self._json(409 if isinstance(exc, Conflict) else 400, {"error": str(exc)})
        except json.JSONDecodeError:
            self._json(400, {"error": "invalid JSON"})


def make_server(port: int = 8000, host: str = "127.0.0.1", default_pace: float | None = None) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    server.app = DemoApp(default_pace)  # type: ignore[attr-defined]
    return server


def main() -> None:
    parser = argparse.ArgumentParser(description="Live demo dashboard for the incident platform")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--no-browser", action="store_true", help="don't open a browser tab")
    args = parser.parse_args()
    server = make_server(args.port)
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    print(f"Incident demo dashboard running at {url}  (Ctrl+C to stop)")
    print(f"config: {DOTENV_STATUS}; real LLM {'ON' if SETTINGS.USE_REAL_LLM else 'off'}; "
          f"OpenAI key {'set' if SETTINGS.OPENAI_API_KEY else 'not set'}; "
          f"Anthropic key {'set' if SETTINGS.ANTHROPIC_API_KEY else 'not set'}")
    if not args.no_browser:
        threading.Timer(0.5, webbrowser.open, args=(url,)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
