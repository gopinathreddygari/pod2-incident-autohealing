# ADR-05: LLM provider resilience (OpenAI -> Anthropic -> rules)

**Status:** Accepted
**Context:** Pod 2 Incident Remediation Platform

## Context

Every triage and planning step depends on an LLM. Provider outages, rate limits, retired models
and revoked keys all happen, and an incident platform is needed most during turbulent periods.
Two requirements pull in different directions:

- **Availability:** an LLM problem must never stop incident response (NFR: 99.9 % availability of
  the remediation plane).
- **Decision quality:** the deterministic mock knows only the patterns it was written for. Relying
  on it alone during an outage keeps the pipeline running but stops real automation.

## Decision

LLM calls go through a **fallback chain** (`FallbackChainBackend` in `llm/llm_backend.py`):

```
OpenAI (routed tier)  ->  Anthropic Claude (same tier)  ->  deterministic mock / rules  ->  (unknown -> escalate)
```

| Link | Accuracy tier (P1, hard tasks) | Cost tier (P2) | Enabled when |
|---|---|---|---|
| 1. OpenAI | `gpt-4o` | `gpt-4o-mini` | `OPENAI_API_KEY` set and `openai` installed |
| 2. Anthropic | `claude-opus-5` | `claude-haiku-4-5` | `ANTHROPIC_API_KEY` set and `anthropic` installed |
| 3. Mock | keyword rules | keyword rules | always (last link, cannot fail) |

All links require `INCIDENT_PLATFORM_USE_REAL_LLM=true`. Every model name is configurable in
`.env` (see `.env.example`).

1. **Different provider, not just a smaller model.** A second OpenAI model shares the same account,
   key, quota and control plane, so it fails in the same incidents. A second vendor covers
   provider-wide outages and account problems.
2. **Tier-for-tier mapping.** The router's choice (accuracy vs. cost) is preserved across providers,
   so a P2 incident does not suddenly run on the most expensive model.
3. **Any error moves to the next link.** That includes auth errors, because the next provider has
   its own key. Each provider sits behind its own **circuit breaker** (3 consecutive failures ->
   skipped for 60 s, then one trial call), so a dead provider costs one fast rejection per call
   instead of a timeout. Breaker changes are audited as `llm:<provider>`.
4. **Claude-specific safety.**
   - Replies must be a single JSON object, instructed in the system prompt; no assistant prefill.
   - `stop_reason` is checked first: a policy refusal raises, and the chain moves on.
   - On `claude-opus-5`, Anthropic's **server-side refusal fallback** (`fallbacks="default"`,
     beta `server-side-fallback-2026-07-01`) re-runs a declined request on Anthropic's recommended
     model inside the same call.
   - No sampling parameters are sent, because Opus 5 rejects them.
5. **Bill and label the model that actually answered.** Each `llm_call` audit entry records `model`
   (who answered), `routed_model` (what was asked for), `backend` and `fallback_error`, and costs
   use that model's prices. The dashboard shows `fallback -> Claude` on the incident card.
6. **Safety gates are provider-independent.** Risk classes, the HITL gate, guardrails, argument
   binding and verification apply exactly the same whichever model answered.

## Alternatives rejected

- **Mock-only fallback (previous design):** always available, but on novel incidents it only
  escalates, so automation silently stops during an OpenAI outage.
- **Same-provider model downgrade only (`gpt-4o -> gpt-4o-mini`):** no protection against
  provider-wide or account-level failures.
- **Active-active across providers:** doubles spend and makes behaviour non-deterministic between
  runs, with no benefit for an incident-rate workload.

## Consequences

- **Positive:**
  - An OpenAI outage no longer degrades decisions to keyword rules.
  - Fast failover through breakers.
  - Everything is visible in the audit log and dashboard.
- **Negative:**
  - A second vendor contract, key and data-processing agreement.
  - Prompts are shared, so answers can differ slightly between providers. Verification catches bad
    fixes regardless.
- **Degraded mode is explicit:** if both providers fail, the mock answers. Known patterns are still
  handled; **unknown incidents escalate to on-call** rather than guessing (NFR matrix).
- **Cost:** pay-per-use, so the standby provider costs almost nothing until it's used. The TCO
  model carries a small monthly line for monitoring/minimum usage (`standby_llm_cost_per_month`).
- **Not demoed:** the dashboard has no failover scenario. Failover is exercised by
  `tests/test_llm_fallback.py` with fake providers.
