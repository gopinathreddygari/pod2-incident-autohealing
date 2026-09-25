# Financial & NFR Workbook

> **Generated file.** Produced by `python finance/tco_roi_calculator.py --write-workbook`.
> Edit the `Assumptions` dataclass in `finance/tco_roi_calculator.py`, not this file.
> All figures are illustrative planning assumptions, not measured data.

## 1. Three-year TCO / ROI

### Assumptions

| Assumption | Value |
|---|---|
| `p1_p2_incidents_per_month` | 40 |
| `annual_volume_growth` | 0.1 |
| `automation_coverage` | 0.45 |
| `baseline_mttr_min` | 95 |
| `automated_mttr_min` | 25 |
| `downtime_cost_per_min` | 25.0 |
| `responders_per_incident` | 2.5 |
| `engineer_hourly_cost` | 85.0 |
| `build_cost_one_time` | 180,000 |
| `infra_cost_per_month` | 3,500 |
| `llm_cost_per_incident` | 0.35 |
| `maintenance_fte` | 0.5 |
| `fte_annual_cost` | 160,000 |
| `years` | 3 |

### Year-by-year

| Year | Incidents | Remediated | Minutes saved | Downtime savings | Labour savings | Benefits | Build cost | Run cost | Net | Cumulative net |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 480 | 216 | 15,120 | $378,000 | $53,550 | $431,550 | $180,000 | $122,168 | $129,382 | $129,382 |
| 2 | 528 | 238 | 16,632 | $415,800 | $58,905 | $474,705 | $0 | $122,185 | $352,520 | $481,902 |
| 3 | 581 | 261 | 18,295 | $457,380 | $64,796 | $522,176 | $0 | $122,203 | $399,972 | $881,874 |

### 3-year summary

| Metric | Value |
|---|---|
| Total cost of ownership | $546,556 |
| Total benefits | $1,428,430 |
| Net benefit | $881,874 |
| ROI | 161% |
| Payback | month 7 |

**Reading the model.** Benefits come from two sources only: downtime minutes avoided on the
share of incidents the platform remediates, and responder hours freed on those same incidents.
It deliberately ignores harder-to-defend benefits (fewer repeat incidents, on-call attrition).

### Sensitivity (one assumption changed at a time)

| Scenario | 3-yr net | ROI | Payback |
|---|---:|---:|---:|
| Base case | $881,874 | 161% | month 7 |
| Downtime cost halved | $256,284 | 47% | month 17 |
| Automation coverage 0.45 -> 0.20 | $88,302 | 16% | month 27 |
| Build cost +50% | $791,874 | 124% | month 11 |
| Automated MTTR doubled (25 -> 50 min) | $371,721 | 68% | month 14 |
| LLM cost x10 | $876,870 | 159% | month 8 |

## 2. Non-functional requirements & SLA matrix

| NFR | Target (SLA/SLO) | How it is met | Where it is evidenced |
|---|---|---|---|
| Availability of the remediation plane | 99.9% monthly | Stateless agents; LLM outage falls back to mock/rules (`ResilientBackend`); per-tool circuit breakers | `llm/llm_backend.py`, `state/circuit_breaker.py` |
| Triage latency (p95, excluding human wait) | < 30 s real LLM; < 50 ms mock | Semantic cache before any model call; cost-tier routing for P2 | `metrics.py` latency-per-task, printed by `main.py` |
| MTTR for automatable P1/P2 | < 25 min (baseline 95) | Autonomous path for high-confidence, non-destructive actions | `main.py` INC-1001 / INC-1004 |
| Human approval SLA | Page within 1 min; decision within 15 min, else stays paused | HITL gate pauses in AWAITING_APPROVAL; unscripted/unanswered = reject | `hitl/hitl_gate.py` |
| Safety: gated risk classes (destructive, failover, config_patch) | 100% human-approved | `riskClass` on every tool spec + state machine has no bypass edge; unknown class = gated | `mcp_server/tool_server.py`, `hitl/hitl_gate.py`, ADR-04 |
| Safety: low-confidence actions | 100% human-approved below 0.75 | Confidence gate applies to every risk class | INC-1003 |
| Privilege escalation | 0 sudo/setuid/impersonation/cluster-admin/privileged/exec commands executed | Output, argument and script guardrails (FR4) | `guardrails/guardrail_middleware.py` |
| Prompt-injection resistance | 0 injected instructions reach the model | Input guardrail on all untrusted text before `think()` | INC-1005, `guardrails/` |
| PII handling | 0 raw emails/IPs/secrets to LLM or audit log | Redaction inside `BaseAgent.think()` | `tests/test_platform.py` |
| Audit integrity | 100% of actions logged; tampering detectable | Hash-chained JSONL, `verify_chain()` | `observability/audit_log.py` |
| Audit retention | 400 days (covers annual audit + buffer) | Ship JSONL to WORM object storage (production) | ADR-02 |
| LLM cost ceiling | < $1 per incident | Two-tier routing + cache; per-call cost accounting | `llm/token_profiler.py` |
| Traceability | Every stage in one trace per incident | OTel-shaped nested spans | `observability/tracer.py` |
