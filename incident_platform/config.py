"""Single source of runtime configuration.

Everything is read from the environment once, at import time. The real-LLM
flag defaults to False: the platform must run end-to-end with zero API keys
and zero third-party packages.

Settings may also come from ``incident_platform/.env`` (git-ignored; see
``.env.example``). Variables already set in the environment win over the file,
and ``INCIDENT_PLATFORM_LOAD_DOTENV=false`` skips the file entirely. Secret
values are never printed.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

ENV_FILE = Path(__file__).resolve().parent / ".env"


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

    # --- Fallback provider: Anthropic (used only if ANTHROPIC_API_KEY is set) --
    # Tier-for-tier with the OpenAI models above; prices are USD per 1K tokens.
    ANTHROPIC_API_KEY: str | None = None
    ANTHROPIC_ACCURACY_TIER: ModelTier = field(
        default_factory=lambda: ModelTier("claude-opus-5", 0.005, 0.025)
    )
    ANTHROPIC_COST_TIER: ModelTier = field(
        default_factory=lambda: ModelTier("claude-haiku-4-5", 0.001, 0.005)
    )
    # A provider that fails this many calls in a row is skipped for the recovery window.
    LLM_BREAKER_FAILURE_THRESHOLD: int = 3
    LLM_BREAKER_RECOVERY_TIMEOUT_S: float = 60.0

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
    BREAKER_MAX_RECOVERY_TIMEOUT_S: float = 240.0   # OPEN period doubles per failed trial, up to this
    READ_TOOL_MAX_ATTEMPTS: int = 4
    # Exponential backoff with full jitter between read-only retries (see state/retry.py).
    RETRY_BASE_DELAY_S: float = 0.2
    RETRY_MAX_DELAY_S: float = 2.0
    RETRY_BUDGET_S: float = 5.0

    # --- Observability -----------------------------------------------------
    AUDIT_LOG_PATH: str = "audit_log.jsonl"


def load_settings() -> Settings:
    defaults = Settings()
    # Model names can be overridden (e.g. if a model isn't available on your account).
    # Prices stay at the defaults, so costs for other models are approximate.
    accuracy = os.environ.get("INCIDENT_PLATFORM_ACCURACY_MODEL")
    cost = os.environ.get("INCIDENT_PLATFORM_COST_MODEL")
    a_accuracy = os.environ.get("INCIDENT_PLATFORM_ANTHROPIC_ACCURACY_MODEL")
    a_cost = os.environ.get("INCIDENT_PLATFORM_ANTHROPIC_COST_MODEL")
    return Settings(
        ACCURACY_TIER=ModelTier(accuracy, defaults.ACCURACY_TIER.input_cost_per_1k,
                                defaults.ACCURACY_TIER.output_cost_per_1k) if accuracy else defaults.ACCURACY_TIER,
        COST_TIER=ModelTier(cost, defaults.COST_TIER.input_cost_per_1k,
                            defaults.COST_TIER.output_cost_per_1k) if cost else defaults.COST_TIER,
        ANTHROPIC_ACCURACY_TIER=ModelTier(a_accuracy, defaults.ANTHROPIC_ACCURACY_TIER.input_cost_per_1k,
                                          defaults.ANTHROPIC_ACCURACY_TIER.output_cost_per_1k)
        if a_accuracy else defaults.ANTHROPIC_ACCURACY_TIER,
        ANTHROPIC_COST_TIER=ModelTier(a_cost, defaults.ANTHROPIC_COST_TIER.input_cost_per_1k,
                                      defaults.ANTHROPIC_COST_TIER.output_cost_per_1k)
        if a_cost else defaults.ANTHROPIC_COST_TIER,
        ANTHROPIC_API_KEY=os.environ.get("ANTHROPIC_API_KEY") or None,
        USE_REAL_LLM=_env_flag("INCIDENT_PLATFORM_USE_REAL_LLM"),
        OPENAI_API_KEY=os.environ.get("OPENAI_API_KEY") or None,
        PII_NER=os.environ.get("INCIDENT_PLATFORM_PII_NER", "heuristic").strip().lower(),
        AUDIT_LOG_PATH=os.environ.get("INCIDENT_PLATFORM_AUDIT_LOG", "audit_log.jsonl"),
    )


def load_dotenv(path: Path = ENV_FILE) -> list[str]:
    """Load ``KEY=VALUE`` lines into ``os.environ`` without overriding variables that are
    already set. Returns the names it set. Comments, blank lines, ``export`` prefixes and
    quoted values are handled; utf-8-sig tolerates a BOM from Notepad."""
    if not path.is_file():
        return []
    loaded = []
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        key, sep, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if not sep or not key.isidentifier():
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].rstrip()
        if key not in os.environ:
            os.environ[key] = value
            loaded.append(key)
    return loaded


def _load_env_file() -> str:
    if not _env_flag("INCIDENT_PLATFORM_LOAD_DOTENV", default=True):
        return "disabled (INCIDENT_PLATFORM_LOAD_DOTENV=false)"
    if not ENV_FILE.is_file():
        return "no .env file"
    return f"loaded .env ({len(load_dotenv())} settings)"


DOTENV_STATUS = _load_env_file()
SETTINGS = load_settings()
