import unittest

import _path  # noqa: F401

from observability import AuditLog
from state import (
    TERMINAL_STATES,
    BreakerState,
    CircuitBreaker,
    CircuitOpenError,
    Incident,
    IncidentState,
    IncidentStateStore,
    InvalidTransitionError,
)

S = IncidentState


def _incident(iid="INC-T1"):
    return Incident(iid, "t", "P1", {})


class IncidentStateTests(unittest.TestCase):
    def setUp(self):
        self.audit = AuditLog()
        self.store = IncidentStateStore(audit=self.audit)
        self.store.put(_incident())

    def test_happy_path_through_approval(self):
        for s in (S.TRIAGING, S.PLANNING, S.AWAITING_APPROVAL, S.APPROVED, S.EXECUTING, S.VERIFIED):
            self.store.transition("INC-T1", s)
        inc = self.store.get("INC-T1")
        self.assertEqual(inc.state, S.VERIFIED)
        self.assertEqual([h["to"] for h in inc.history][0], "RECEIVED")
        self.assertEqual(len(self.audit.filter(action="state_transition")), 6)

    def test_cannot_skip_approval(self):
        for s in (S.TRIAGING, S.PLANNING, S.AWAITING_APPROVAL):
            self.store.transition("INC-T1", s)
        with self.assertRaises(InvalidTransitionError):
            self.store.transition("INC-T1", S.EXECUTING)
        self.assertEqual(len(self.audit.filter(action="illegal_transition_refused")), 1)

    def test_rejected_is_terminal(self):
        for s in (S.TRIAGING, S.PLANNING, S.AWAITING_APPROVAL, S.REJECTED):
            self.store.transition("INC-T1", s)
        with self.assertRaises(InvalidTransitionError):
            self.store.transition("INC-T1", S.EXECUTING)

    def test_terminal_states(self):
        self.assertEqual(TERMINAL_STATES, {S.VERIFIED, S.FAILED, S.REJECTED, S.ESCALATED})


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def _boom():
    raise RuntimeError("down")


class CircuitBreakerTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.changes = []
        self.breaker = CircuitBreaker("tool", failure_threshold=3, recovery_timeout=10, clock=self.clock,
                                      on_state_change=lambda n, a, b: self.changes.append((a, b)))

    def _fail(self, n):
        for _ in range(n):
            with self.assertRaises(RuntimeError):
                self.breaker.call(_boom)

    def test_opens_after_threshold_and_rejects_fast(self):
        self._fail(2)
        self.assertIs(self.breaker.state, BreakerState.CLOSED)
        self._fail(1)
        self.assertIs(self.breaker.state, BreakerState.OPEN)
        with self.assertRaises(CircuitOpenError):
            self.breaker.call(lambda: "never runs")
        self.assertEqual(self.breaker.rejected_calls, 1)

    def test_success_resets_consecutive_count(self):
        self._fail(2)
        self.assertEqual(self.breaker.call(lambda: "ok"), "ok")
        self._fail(2)
        self.assertIs(self.breaker.state, BreakerState.CLOSED)

    def test_half_open_trial_success_closes(self):
        self._fail(3)
        self.clock.t = 10
        self.assertIs(self.breaker.state, BreakerState.HALF_OPEN)
        self.assertEqual(self.breaker.call(lambda: 42), 42)
        self.assertIs(self.breaker.state, BreakerState.CLOSED)
        self.assertEqual(
            self.changes,
            [(BreakerState.CLOSED, BreakerState.OPEN), (BreakerState.OPEN, BreakerState.HALF_OPEN),
             (BreakerState.HALF_OPEN, BreakerState.CLOSED)],
        )

    def test_half_open_trial_failure_reopens(self):
        self._fail(3)
        self.clock.t = 10
        self._fail(1)
        self.assertIs(self.breaker.state, BreakerState.OPEN)


class RetryPolicyTests(unittest.TestCase):
    def test_caps_double_and_are_bounded(self):
        from state import RetryPolicy
        policy = RetryPolicy(base_delay_s=0.2, max_delay_s=1.0)
        self.assertEqual([policy.cap(n) for n in range(1, 6)], [0.2, 0.4, 0.8, 1.0, 1.0])

    def test_full_jitter_stays_within_the_cap(self):
        import random
        from state import RetryPolicy
        policy, rng = RetryPolicy(base_delay_s=0.2, max_delay_s=2.0), random.Random(42)
        for n in range(1, 6):
            delays = [policy.delay(n, rng) for _ in range(200)]
            self.assertTrue(all(0.0 <= d <= policy.cap(n) for d in delays))
            self.assertGreater(len({round(d, 6) for d in delays}), 150)  # actually jittered


class BreakerRecoveryBackoffTests(unittest.TestCase):
    def test_failed_trials_double_the_open_period_and_success_resets_it(self):
        clock = FakeClock()
        b = CircuitBreaker("t", failure_threshold=1, recovery_timeout=30, clock=clock, max_recovery_timeout=100)

        def fail():
            with self.assertRaises(RuntimeError):
                b.call(_boom)

        fail()                                   # CLOSED -> OPEN for 30 s
        self.assertEqual(b.recovery_timeout, 30)
        for expected in (60, 100, 100):          # each failed trial doubles, capped at 100
            clock.t += b.recovery_timeout
            self.assertIs(b.state, BreakerState.HALF_OPEN)
            fail()
            self.assertIs(b.state, BreakerState.OPEN)
            self.assertEqual(b.recovery_timeout, expected)
        clock.t += 99
        self.assertIs(b.state, BreakerState.OPEN)  # not yet: the period is now 100 s
        clock.t += 1
        self.assertEqual(b.call(lambda: "ok"), "ok")
        self.assertIs(b.state, BreakerState.CLOSED)
        self.assertEqual(b.recovery_timeout, 30)   # reset after a successful trial

    def test_without_a_max_the_period_stays_fixed(self):
        clock = FakeClock()
        b = CircuitBreaker("t", failure_threshold=1, recovery_timeout=30, clock=clock)
        with self.assertRaises(RuntimeError):
            b.call(_boom)
        clock.t = 30
        with self.assertRaises(RuntimeError):
            b.call(_boom)
        self.assertEqual(b.recovery_timeout, 30)


class TracerTests(unittest.TestCase):
    def test_active_spans_are_visible_until_finished(self):
        from observability import Tracer
        tracer = Tracer()
        with tracer.start_span("outer") as outer:
            with tracer.start_span("inner") as inner:
                self.assertIs(tracer.current_span(), inner)
                self.assertEqual(set(tracer.active), {outer.span_id, inner.span_id})
                self.assertEqual(inner.parent_id, outer.span_id)
            self.assertIs(tracer.current_span(), outer)
        self.assertEqual(tracer.active, {})
        self.assertIsNone(tracer.current_span())
        self.assertEqual([s.name for s in tracer.spans], ["inner", "outer"])
        self.assertGreaterEqual(outer.duration_ms, inner.duration_ms)


if __name__ == "__main__":
    unittest.main()
