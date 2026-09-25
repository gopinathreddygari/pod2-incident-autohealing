"""Per-tool circuit breaker (CLOSED -> OPEN -> HALF_OPEN -> CLOSED).

CLOSED     calls pass through; consecutive failures are counted.
OPEN       after ``failure_threshold`` consecutive failures. Calls are
           rejected immediately with ``CircuitOpenError`` -- we stop hammering
           a dependency that is already down.
HALF_OPEN  once ``recovery_timeout`` has elapsed. The next call is a trial:
           success closes the breaker, failure re-opens it.

The clock is injectable so tests can move time without sleeping.
"""

from __future__ import annotations

import time
from enum import Enum
from typing import Any, Callable


class BreakerState(str, Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class CircuitOpenError(Exception):
    def __init__(self, name: str):
        super().__init__(f"circuit '{name}' is OPEN; call rejected")
        self.name = name


StateChangeHook = Callable[[str, BreakerState, BreakerState], None]


class CircuitBreaker:
    def __init__(
        self,
        name: str,
        failure_threshold: int = 3,
        recovery_timeout: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
        on_state_change: StateChangeHook | None = None,
    ):
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self._clock = clock
        self._on_state_change = on_state_change
        self._state = BreakerState.CLOSED
        self._consecutive_failures = 0
        self._opened_at: float | None = None
        self.rejected_calls = 0

    @property
    def state(self) -> BreakerState:
        if (
            self._state is BreakerState.OPEN
            and self._opened_at is not None
            and self._clock() - self._opened_at >= self.recovery_timeout
        ):
            self._set_state(BreakerState.HALF_OPEN)
        return self._state

    @property
    def consecutive_failures(self) -> int:
        return self._consecutive_failures

    def call(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        if self.state is BreakerState.OPEN:
            self.rejected_calls += 1
            raise CircuitOpenError(self.name)
        try:
            result = fn(*args, **kwargs)
        except Exception:
            self._record_failure()
            raise
        self._record_success()
        return result

    def _record_failure(self) -> None:
        self._consecutive_failures += 1
        if (
            self._state is BreakerState.HALF_OPEN
            or self._consecutive_failures >= self.failure_threshold
        ):
            self._opened_at = self._clock()
            self._set_state(BreakerState.OPEN)

    def _record_success(self) -> None:
        self._consecutive_failures = 0
        self._opened_at = None
        if self._state is not BreakerState.CLOSED:
            self._set_state(BreakerState.CLOSED)

    def _set_state(self, new_state: BreakerState) -> None:
        old = self._state
        if old is new_state:
            return
        self._state = new_state
        if self._on_state_change is not None:
            self._on_state_change(self.name, old, new_state)


class BreakerRegistry:
    """Lazily creates one breaker per tool name, all sharing the same policy."""

    def __init__(
        self,
        failure_threshold: int = 3,
        recovery_timeout: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
        on_state_change: StateChangeHook | None = None,
    ):
        self._kwargs = dict(
            failure_threshold=failure_threshold,
            recovery_timeout=recovery_timeout,
            clock=clock,
            on_state_change=on_state_change,
        )
        self._breakers: dict[str, CircuitBreaker] = {}

    def get(self, name: str) -> CircuitBreaker:
        if name not in self._breakers:
            self._breakers[name] = CircuitBreaker(name, **self._kwargs)
        return self._breakers[name]

    def snapshot(self) -> dict[str, str]:
        return {name: b.state.value for name, b in self._breakers.items()}
