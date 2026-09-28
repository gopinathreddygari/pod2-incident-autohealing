"""Shared agent machinery: the one path every LLM call goes through.

``think()`` runs, in order:
    redact PII -> input guardrail -> semantic cache -> model router -> backend
    -> token profiler -> cache store -> audit
all inside one tracer span. No agent calls a backend any other way, so none of
these controls can be skipped.

The ``cache_key`` parameter exists because of a real bug: keying the cache on
the full templated prompt made different incidents collide. Callers pass the
incident's *content* (title + symptoms) instead. See ADR-03.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from guardrails.guardrail_middleware import GuardrailViolation
from llm.llm_backend import parse_json_reply
from llm.token_profiler import estimate_tokens


@dataclass
class ThinkResult:
    data: dict[str, Any]
    cache_layer: str | None  # None = miss (tokens spent), "L1" / "L2" = hit
    similarity: float | None
    model: str | None
    tokens: int


class BaseAgent:
    name = "base"

    def __init__(self, platform):
        self.p = platform

    def think(self, incident, prompt: str, cache_key: str, complexity: str = "normal") -> ThinkResult:
        p = self.p
        with p.tracer.start_span(f"agent.{self.name}.think", {"incident.id": incident.incident_id, "agent": self.name}) as span:
            prompt, redactions, pii_sources = p.guardrails.redact_pii_detailed(prompt)
            cache_key, _ = p.guardrails.redact_pii(cache_key)
            if redactions:
                # pii_sources says which layer caught each item, e.g. {"PERSON/spacy-ner": 1}.
                span.set_attribute("pii.redactions", redactions)
                span.set_attribute("pii.sources", pii_sources)
                for note, counts in (("pii_redactions", redactions), ("pii_sources", pii_sources)):
                    seen = incident.notes.setdefault(note, {})
                    for key, n in counts.items():
                        seen[key] = seen.get(key, 0) + n

            verdict = p.guardrails.check_input(prompt)
            if not verdict.allowed:
                span.set_attribute("guardrail.blocked", True)
                p.audit.record(self.name, "guardrail_blocked_input", {
                    "incident_id": incident.incident_id, "reasons": verdict.reasons, "pii_redactions": redactions, "pii_sources": pii_sources,
                })
                raise GuardrailViolation("input", verdict.reasons)

            hit = p.cache.get(self.name, cache_key)
            p.metrics.record_cache(hit is not None)
            if hit is not None:
                # Estimate what this call would have cost, to report the saving.
                tier = p.router.route(incident.severity, complexity, record=False)
                p.profiler.record_cache_saving(tier, estimate_tokens(prompt), 60)
                span.set_attribute("cache.hit", hit.layer)
                span.set_attribute("cache.similarity", round(hit.similarity, 4))
                p.audit.record(self.name, "llm_cache_hit", {
                    "incident_id": incident.incident_id, "layer": hit.layer,
                    "similarity": round(hit.similarity, 4), "matched_key": hit.matched_key,
                })
                return ThinkResult(hit.value, hit.layer, hit.similarity, None, 0)

            tier = p.router.route(incident.severity, complexity)
            response = p.backend.complete(prompt, tier.name)
            answered_by = _billing_tier(p.settings, response.model, tier)  # a fallback bills at its own prices
            usage = p.profiler.record(self.name, answered_by, response.tokens_in, response.tokens_out)
            tokens = response.tokens_in + response.tokens_out
            p.metrics.record_tokens(tokens)
            span.set_attribute("llm.model", answered_by.name)
            span.set_attribute("llm.backend", response.backend)
            if response.fallback_error:
                span.set_attribute("llm.fallback_error", response.fallback_error)
            span.set_attribute("llm.tokens", tokens)

            data = parse_json_reply(response.text)
            p.cache.put(self.name, cache_key, data)
            p.audit.record(self.name, "llm_call", {
                "incident_id": incident.incident_id, "model": answered_by.name, "backend": response.backend,
                "routed_model": tier.name,
                "tokens_in": response.tokens_in, "tokens_out": response.tokens_out,
                "cost_usd": round(usage.cost_usd, 6), "pii_redactions": redactions, "pii_sources": pii_sources,
                **({"fallback_error": response.fallback_error} if response.fallback_error else {}),
            })
            return ThinkResult(data, None, None, answered_by.name, tokens)


def _billing_tier(settings, model: str | None, routed):
    """The priced tier for the model that actually answered (falls back to the routed tier)."""
    for tier in (settings.ACCURACY_TIER, settings.COST_TIER,
                 settings.ANTHROPIC_ACCURACY_TIER, settings.ANTHROPIC_COST_TIER):
        if model == tier.name:
            return tier
    return routed
