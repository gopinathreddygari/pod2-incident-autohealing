"""Token estimation and cost accounting.

``estimate_tokens`` uses the common ~4-characters-per-token heuristic for
English and code. Real backends report exact usage; the mock uses the
estimate, so the cost numbers in the demo are realistic in magnitude.
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass

from config import ModelTier


def estimate_tokens(text: str) -> int:
    return max(1, math.ceil(len(text) / 4))


@dataclass
class UsageRecord:
    agent: str
    model: str
    tokens_in: int
    tokens_out: int
    cost_usd: float


class TokenProfiler:
    def __init__(self) -> None:
        self.records: list[UsageRecord] = []
        self.tokens_saved_by_cache = 0
        self.cost_saved_by_cache = 0.0

    @staticmethod
    def cost_of(tier: ModelTier, tokens_in: int, tokens_out: int) -> float:
        return tokens_in / 1000 * tier.input_cost_per_1k + tokens_out / 1000 * tier.output_cost_per_1k

    def record(self, agent: str, tier: ModelTier, tokens_in: int, tokens_out: int) -> UsageRecord:
        rec = UsageRecord(agent, tier.name, tokens_in, tokens_out, self.cost_of(tier, tokens_in, tokens_out))
        self.records.append(rec)
        return rec

    def record_cache_saving(self, tier: ModelTier, tokens_in: int, tokens_out: int) -> None:
        self.tokens_saved_by_cache += tokens_in + tokens_out
        self.cost_saved_by_cache += self.cost_of(tier, tokens_in, tokens_out)

    @property
    def total_tokens(self) -> int:
        return sum(r.tokens_in + r.tokens_out for r in self.records)

    @property
    def total_cost(self) -> float:
        return sum(r.cost_usd for r in self.records)

    def by_model(self) -> dict[str, dict[str, float]]:
        out: dict[str, dict[str, float]] = defaultdict(lambda: {"calls": 0, "tokens": 0, "cost_usd": 0.0})
        for r in self.records:
            m = out[r.model]
            m["calls"] += 1
            m["tokens"] += r.tokens_in + r.tokens_out
            m["cost_usd"] += r.cost_usd
        return dict(out)
