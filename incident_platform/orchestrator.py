"""Hierarchical coordinator + dependency-injection container.

``IncidentPlatform`` builds every shared component once and hands the same
instances to every agent, so there is one tracer, one audit chain, one cache
and one breaker registry per run. Tests build their own platform with fakes.

``IncidentOrchestrator`` is the coordinator in the hierarchical topology
(ADR-01). It owns the incident lifecycle and delegates each stage to one
specialist agent. The specialists never call each other; every hand-off goes
through the coordinator, so the whole control flow is readable in ``handle()``.
"""

from __future__ import annotations

import random
import time

from agents import ExecutionVerificationAgent, PlanningError, RemediationPlannerAgent, TriageAgent
from config import SETTINGS, Settings
from guardrails import GuardrailMiddleware, GuardrailViolation
from hitl import ApprovalChannel, HITLGate
from llm import LLMOutputError, ModelRouter, SemanticCache, TokenProfiler, get_backend
from mcp_server import MCPToolServer, MockCluster
from observability import AuditLog, MetricsCollector, Tracer
from state import VALID_TRANSITIONS, BreakerRegistry, Incident, IncidentState, IncidentStateStore, RetryPolicy


class IncidentPlatform:
    def __init__(
        self,
        settings: Settings | None = None,
        audit_path: str | None = None,
        backend=None,
        fail_injection: dict[str, int] | None = None,
        clock=time.monotonic,
        sleep=time.sleep,
        rng: random.Random | None = None,
    ):
        self.settings = settings or SETTINGS
        # Injectable so tests can run retries/backoff instantly and deterministically.
        self.clock = clock
        self.sleep = sleep
        self.rng = rng or random.Random()
        self.retry_policy = RetryPolicy(
            max_attempts=self.settings.READ_TOOL_MAX_ATTEMPTS,
            base_delay_s=self.settings.RETRY_BASE_DELAY_S,
            max_delay_s=self.settings.RETRY_MAX_DELAY_S,
            budget_s=self.settings.RETRY_BUDGET_S,
        )
        self.tracer = Tracer()
        self.audit = AuditLog(audit_path)
        self.metrics = MetricsCollector()
        self.guardrails = GuardrailMiddleware(self.settings.PII_NER)
        self.cache = SemanticCache(self.settings.CACHE_SIMILARITY_THRESHOLD, self.settings.CACHE_EMBEDDING_DIM)
        self.router = ModelRouter(self.settings.ACCURACY_TIER, self.settings.COST_TIER)
        self.profiler = TokenProfiler()
        self.backend = backend or get_backend(self.settings, on_breaker_change=self._on_breaker_change)
        self.store = IncidentStateStore(audit=self.audit, redact=self.guardrails.redact_text)
        self.breakers = BreakerRegistry(
            failure_threshold=self.settings.BREAKER_FAILURE_THRESHOLD,
            recovery_timeout=self.settings.BREAKER_RECOVERY_TIMEOUT_S,
            clock=clock,
            on_state_change=self._on_breaker_change,
            max_recovery_timeout=self.settings.BREAKER_MAX_RECOVERY_TIMEOUT_S,
        )
        self.cluster = MockCluster()
        self.tools = MCPToolServer(
            self.breakers, self.guardrails, self.audit, self.tracer, self.metrics,
            fail_injection=fail_injection, cluster=self.cluster,
        )

    def _on_breaker_change(self, name, old, new) -> None:
        # Breakers don't know about incidents; the tool-call span they fire inside does.
        span = self.tracer.current_span()
        incident_id = span.attributes.get("incident.id") if span else None
        payload = {"incident_id": incident_id, "tool": name, "from": old.value, "to": new.value}
        if new.value == "OPEN":
            payload["open_for_s"] = self.breakers.get(name).recovery_timeout
        self.audit.record("circuit_breaker", "state_change", payload)


class IncidentOrchestrator:
    def __init__(self, platform: IncidentPlatform, approval_channel: ApprovalChannel):
        self.platform = platform
        self.hitl = HITLGate(approval_channel, platform.store, platform.audit, platform.tracer,
                             platform.settings.MIN_AUTONOMOUS_CONFIDENCE)
        self.triage = TriageAgent(platform)
        self.planner = RemediationPlannerAgent(platform)
        self.executor = ExecutionVerificationAgent(platform, self.hitl)

    def handle(self, incident: Incident) -> IncidentState:
        p = self.platform
        iid = incident.incident_id
        p.metrics.record_incident()
        started = time.perf_counter()
        with p.tracer.start_span("incident.handle", {"incident.id": iid, "incident.severity": incident.severity}) as span:
            p.store.put(incident)
            try:
                p.store.transition(iid, IncidentState.TRIAGING, "triage started")
                triage = self._timed("triage", self.triage.run, incident)
                incident.notes["triage"] = triage
                if triage.degraded:
                    # Policy: never auto-remediate on incomplete evidence.
                    return self._escalate(incident, "incomplete evidence: " + "; ".join(triage.degraded))

                p.store.transition(iid, IncidentState.PLANNING,
                                   f"{triage.category} (confidence {triage.confidence:.2f})")
                plan = self._timed("planning", self.planner.run, incident, triage)
                incident.notes["plan"] = plan
                if plan is None:
                    return self._escalate(incident, "no safe automated action; handing to on-call")

                return self._timed("execution", self.executor.run, incident, triage, plan)

            except GuardrailViolation as exc:
                incident.notes["guardrail"] = {"stage": exc.stage, "reasons": exc.reasons}
                return self._escalate(incident, str(exc))
            except (LLMOutputError, PlanningError) as exc:
                return self._escalate(incident, f"{type(exc).__name__}: {exc}")
            except Exception as exc:  # last-resort fail-safe: never leave an incident mid-flight
                span.status = "ERROR"
                return self._fail_safe(incident, f"unexpected {type(exc).__name__}: {exc}")
            finally:
                span.set_attribute("incident.final_state", incident.state.value)
                p.metrics.record_latency("incident", (time.perf_counter() - started) * 1000)

    def _timed(self, task: str, fn, *args):
        started = time.perf_counter()
        try:
            return fn(*args)
        finally:
            self.platform.metrics.record_latency(task, (time.perf_counter() - started) * 1000)

    def _escalate(self, incident: Incident, reason: str) -> IncidentState:
        incident.notes["escalation_reason"] = reason
        return self._fail_safe(incident, reason)

    def _fail_safe(self, incident: Incident, reason: str) -> IncidentState:
        allowed = VALID_TRANSITIONS[incident.state]
        for target in (IncidentState.ESCALATED, IncidentState.FAILED):
            if target in allowed:
                self.platform.store.transition(incident.incident_id, target, reason)
                break
        return incident.state
