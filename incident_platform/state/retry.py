"""Retry policy: exponential backoff with full jitter, inside a per-call time budget.

Used for **read-only** MCP tools only (safe to repeat) and only on transient
failures (``execution_error``: timeouts, 5xx). Remediations are never retried
automatically, because running a rollback or a drain twice is not harmless.

Retries sit *inside* the circuit breaker: every attempt counts towards the
breaker's failure threshold, and once the breaker is OPEN the caller stops
waiting; the next call would be rejected instantly anyway.

Full jitter (``uniform(0, cap)``) rather than a fixed delay stops many callers
from retrying in lock-step against a recovering dependency. See ADR-03.
"""

from __future__ import annotations

import random
from dataclasses import dataclass


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 4
    base_delay_s: float = 0.2
    max_delay_s: float = 2.0
    budget_s: float = 5.0        # total time for one logical call, retries and waits included

    def cap(self, retry_number: int) -> float:
        """Upper bound of the wait before retry ``retry_number`` (1 = first retry)."""
        return min(self.max_delay_s, self.base_delay_s * 2 ** (retry_number - 1))

    def delay(self, retry_number: int, rng: random.Random) -> float:
        return rng.uniform(0.0, self.cap(retry_number))
