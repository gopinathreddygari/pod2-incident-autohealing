# ADR-03: Cost & performance (routing, semantic cache, resilience)

**Status:** Accepted
**Context:** Pod 2 Incident Remediation Platform

## Context

Incidents cluster: the same failure recurs across regions and replicas within minutes. P1
incidents justify the most capable model, while P2s often do not. The LLM provider is also an
external dependency that can fail, and it must never make incident response slower than having
no AI at all.

## Decision

### 1. Two-tier model routing (`llm/model_router.py`)
- **Accuracy tier** (`gpt-4o`) for P1 incidents, and for any task marked high complexity
  (for example, triage on degraded evidence).
- **Cost tier** (`gpt-4o-mini`) for everything else. In the demo, INC-1003 (P2) is triaged and
  planned on the cost tier.

### 2. Two-level semantic cache (`llm/semantic_cache.py`), checked before every model call
- **L1:** exact SHA-256 of the normalised key.
- **L2:** cosine similarity of 512-dimension signed feature-hashing embeddings, with a
  0.85 threshold.
- Namespaced per agent, so triage answers are never served to the planner.
- INC-1004 (a repeat of INC-1001 in another region) gets an L2 hit for triage and an L1 hit
  for planning, and spends **zero tokens**. Tool arguments still bind to the new incident's own
  namespace and workload, because only the reasoning is cached, not the target.

### 3. Resilience
- `ResilientBackend` falls back to the deterministic mock on any provider error.
- Per-tool circuit breakers stop retry storms against a failing dependency.

### 4. Accounting (`llm/token_profiler.py`)
- Every call records tokens and cost per model.
- Cache hits record the tokens and cost *avoided*.
- `main.py` prints all of these, along with the four required metrics.

## The cache-key bug (found and fixed during build)

The first version embedded the **full templated prompt**. The template's shared boilerplate
(instructions, JSON schema, category list) outweighed the few tokens that actually described the
symptoms, so unrelated incidents looked alike. Measured with this repository's embedding and
triage template:

| Pair | Full prompt | Content key |
|---|---:|---:|
| INC-1001 crashloop vs INC-1003 latency | 0.542 | 0.038 |
| INC-1001 crashloop vs INC-1002 bad rollout | 0.513 | 0.000 |
| INC-1002 bad rollout vs INC-1006 disk pressure | 0.544 | -0.030 |
| INC-1001 vs INC-1004 (true repeat) | 0.989 | 0.979 |

With this short template the inflation stays below the 0.85 threshold. The effect grows with
template length, though, and production prompts (full tool catalogue, runbook excerpts, output
schema) are several times longer. The original build notes record 0.91 on an earlier,
longer-prompt version, enough to serve a crashloop diagnosis to a latency incident. Content keys separate true repeats
(0.98) from unrelated incidents (below 0.05) whatever the template length.

**Fix:** `BaseAgent.think()` takes a separate `cache_key`. `TriageAgent.cache_key()` builds it
from content only (title, alert name, symptom text) and deliberately excludes the template and
the namespace or pod names. The regression test is
`tests/test_llm_layer.py::test_regression_full_prompt_vs_content_key`. It asserts that the
content keys of those two incidents fall below the threshold, and that the full prompts score
higher than the content keys.

**Lesson:** for semantic caching, *what* you embed matters more than the similarity threshold.
Embed the part of the input that distinguishes one request from another.

## Consequences

- The hashing embedding is lexical, not semantic. "Pods keep restarting" will not match
  "CrashLoopBackOff". Production would swap `embed()` for a trained embedding model and store
  vectors in a vector DB; the interface stays the same.
- Cache staleness: a cached diagnosis could outlive a changed environment. Production should
  add a TTL and invalidate entries on deploy events. Execution is always re-verified against
  live telemetry, which limits the damage.
- See `docs/financial_nfr_workbook.md` for how LLM cost feeds the TCO model. Even at ten times
  the assumed LLM cost, ROI barely moves, so correctness, not token cost, is the constraint
  that matters.
