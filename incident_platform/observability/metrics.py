"""The four required operational metrics.

1. Latency per task       (triage / planning / execution / whole incident)
2. Token consumption rate (tokens per second of wall time, and per incident)
3. Cache hit ratio        (semantic cache: L1 + L2 hits over all lookups)
4. Tool failure rate      (failed MCP tool calls over all attempted calls;
                           breaker-rejected calls are reported separately)
"""

from __future__ import annotations

import statistics
import time
from collections import defaultdict
from typing import Any


class MetricsCollector:
    def __init__(self, clock=time.perf_counter):
        self._clock = clock
        self._started = clock()
        self.task_latencies_ms: dict[str, list[float]] = defaultdict(list)
        self.tokens_total = 0
        self.incidents = 0
        self.cache_hits = 0
        self.cache_misses = 0
        self.tool_calls: dict[str, dict[str, int]] = defaultdict(
            lambda: {"ok": 0, "failed": 0, "rejected": 0}
        )

    # --- recording --------------------------------------------------------
    def record_latency(self, task: str, ms: float) -> None:
        self.task_latencies_ms[task].append(ms)

    def record_tokens(self, n: int) -> None:
        self.tokens_total += n

    def record_incident(self) -> None:
        self.incidents += 1

    def record_cache(self, hit: bool) -> None:
        if hit:
            self.cache_hits += 1
        else:
            self.cache_misses += 1

    def record_tool_call(self, tool: str, outcome: str) -> None:
        """outcome: 'ok' | 'failed' | 'rejected' (breaker open / guardrail)."""
        self.tool_calls[tool][outcome] += 1

    # --- derived ----------------------------------------------------------
    @property
    def cache_hit_ratio(self) -> float:
        total = self.cache_hits + self.cache_misses
        return self.cache_hits / total if total else 0.0

    @property
    def tool_failure_rate(self) -> float:
        attempted = sum(c["ok"] + c["failed"] for c in self.tool_calls.values())
        failed = sum(c["failed"] for c in self.tool_calls.values())
        return failed / attempted if attempted else 0.0

    def token_rate_per_s(self) -> float:
        elapsed = max(self._clock() - self._started, 1e-9)
        return self.tokens_total / elapsed

    def summary(self) -> dict[str, Any]:
        latency = {
            task: {
                "count": len(v),
                "mean_ms": round(statistics.fmean(v), 2),
                "max_ms": round(max(v), 2),
            }
            for task, v in sorted(self.task_latencies_ms.items())
        }
        return {
            "latency_per_task": latency,
            "tokens_total": self.tokens_total,
            "token_rate_per_s": round(self.token_rate_per_s(), 1),
            "tokens_per_incident": round(self.tokens_total / self.incidents, 1)
            if self.incidents
            else 0.0,
            "cache_hits": self.cache_hits,
            "cache_lookups": self.cache_hits + self.cache_misses,
            "cache_hit_ratio": round(self.cache_hit_ratio, 3),
            "tool_calls": {k: dict(v) for k, v in sorted(self.tool_calls.items())},
            "tool_failure_rate": round(self.tool_failure_rate, 3),
        }

    def render_summary(self) -> str:
        s = self.summary()
        lines = ["1) Latency per task"]
        for task, v in s["latency_per_task"].items():
            lines.append(
                f"     {task:<12} n={v['count']:<3} mean={v['mean_ms']:>8.2f} ms   max={v['max_ms']:>8.2f} ms"
            )
        lines.append(
            f"2) Token consumption   total={s['tokens_total']}  "
            f"rate={s['token_rate_per_s']}/s  per-incident={s['tokens_per_incident']}"
        )
        lines.append(
            f"3) Cache hit ratio     {s['cache_hits']}/{s['cache_lookups']} = {s['cache_hit_ratio']:.1%}"
        )
        lines.append(f"4) Tool failure rate   {s['tool_failure_rate']:.1%}")
        for tool, c in s["tool_calls"].items():
            lines.append(
                f"     {tool:<20} ok={c['ok']:<3} failed={c['failed']:<3} rejected={c['rejected']}"
            )
        return "\n".join(lines)
