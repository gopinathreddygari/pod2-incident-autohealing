"""Single source of runtime configuration.

Everything is read from the environment once, at import time. The real-LLM
flag defaults to False: the platform must run end-to-end with zero API keys
and zero third-party packages.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class ModelTier:
    """One tier of the two-tier model router, with its per-1K-token prices (USD)."""

    name: str
    input_cost_per_1k: float
    output_cost_per_1k: float


@dataclass
class Settings:
    # --- LLM provider -------------------------------------------------------
    # Real calls need BOTH this flag AND an API key (see llm_backend.get_backend).
    USE_REAL_LLM: bool = False
    OPENAI_API_KEY: str | None = None
    LLM_TIMEOUT_S: float = 20.0

    # --- Model routing (accuracy vs. cost) ---------------------------------
    ACCURACY_TIER: ModelTier = field(
        default_factory=lambda: ModelTier("gpt-4o", 0.0025, 0.0100)
    )
    COST_TIER: ModelTier = field(
        default_factory=lambda: ModelTier("gpt-4o-mini", 0.00015, 0.0006)
    )

    # --- Governance --------------------------------------------------------
    # Any plan whose triage confidence is below this goes to a human, even if
    # the action itself is non-destructive.
    MIN_AUTONOMOUS_CONFIDENCE: float = 0.75

    # PII detection: "off" (regex only), "heuristic" (regex + built-in name NER),
    # or "spacy" (regex + heuristic + spaCy NER, needs spaCy installed).
    PII_NER: str = "heuristic"

    # --- Semantic cache ----------------------------------------------------
    CACHE_SIMILARITY_THRESHOLD: float = 0.85
    CACHE_EMBEDDING_DIM: int = 512

    # --- Resilience --------------------------------------------------------
    BREAKER_FAILURE_THRESHOLD: int = 3
    BREAKER_RECOVERY_TIMEOUT_S: float = 30.0
    READ_TOOL_MAX_ATTEMPTS: int = 4

    # --- Observability -----------------------------------------------------
    AUDIT_LOG_PATH: str = "audit_log.jsonl"


def load_settings() -> Settings:
    return Settings(
        USE_REAL_LLM=_env_flag("INCIDENT_PLATFORM_USE_REAL_LLM"),
        OPENAI_API_KEY=os.environ.get("OPENAI_API_KEY") or None,
        PII_NER=os.environ.get("INCIDENT_PLATFORM_PII_NER", "heuristic").strip().lower(),
        AUDIT_LOG_PATH=os.environ.get("INCIDENT_PLATFORM_AUDIT_LOG", "audit_log.jsonl"),
    )


SETTINGS = load_settings()
