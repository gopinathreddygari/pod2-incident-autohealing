"""Two-tier model routing: accuracy vs. cost.

P1 incidents and high-complexity tasks go to the accuracy tier, because
a wrong root cause during an outage costs far more than the token difference.
Everything else goes to the cost tier. See ADR-03.
"""

from __future__ import annotations

from collections import Counter

from config import ModelTier


class ModelRouter:
    def __init__(self, accuracy_tier: ModelTier, cost_tier: ModelTier):
        self.accuracy_tier = accuracy_tier
        self.cost_tier = cost_tier
        self.decisions: Counter[str] = Counter()

    def route(self, severity: str, complexity: str = "normal", record: bool = True) -> ModelTier:
        tier = self.accuracy_tier if severity == "P1" or complexity == "high" else self.cost_tier
        if record:
            self.decisions[tier.name] += 1
        return tier
