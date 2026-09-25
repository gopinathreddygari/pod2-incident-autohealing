"""3-year TCO / ROI model for the auto-healing platform.

    python finance/tco_roi_calculator.py                 # print the tables
    python finance/tco_roi_calculator.py --write-workbook # regenerate docs/financial_nfr_workbook.md

Every number in the workbook comes from the ``Assumptions`` dataclass below.
Change an assumption, re-run, and the workbook follows. The values are
illustrative planning figures for CloudScale Global Networks, not measured
data. Replace them with your own before a funding decision.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass
class Assumptions:
    # Incident volume
    p1_p2_incidents_per_month: float = 40
    annual_volume_growth: float = 0.10
    automation_coverage: float = 0.45       # share of incidents the platform remediates (auto or approved)

    # Response time (minutes)
    baseline_mttr_min: float = 95
    automated_mttr_min: float = 25

    # Cost of an incident minute
    downtime_cost_per_min: float = 25.0      # blended business impact of a P1/P2 minute (USD)
    responders_per_incident: float = 2.5
    engineer_hourly_cost: float = 85.0

    # Platform costs
    build_cost_one_time: float = 180_000     # design, build, security review, rollout
    infra_cost_per_month: float = 3_500      # runtime, vector store, observability
    llm_cost_per_incident: float = 0.35      # conservative; main.py's short demo prompts cost ~$0.001 per incident
    maintenance_fte: float = 0.5
    fte_annual_cost: float = 160_000

    years: int = 3


@dataclass
class YearResult:
    year: int
    incidents: float
    remediated: float
    minutes_saved: float
    downtime_savings: float
    labour_savings: float
    benefits: float
    build_cost: float
    run_cost: float
    costs: float
    net: float
    cumulative_net: float


def model(a: Assumptions) -> list[YearResult]:
    rows: list[YearResult] = []
    cumulative = 0.0
    saved_per_incident = a.baseline_mttr_min - a.automated_mttr_min
    for year in range(1, a.years + 1):
        incidents = a.p1_p2_incidents_per_month * 12 * (1 + a.annual_volume_growth) ** (year - 1)
        remediated = incidents * a.automation_coverage
        minutes_saved = remediated * saved_per_incident
        downtime = minutes_saved * a.downtime_cost_per_min
        labour = minutes_saved / 60 * a.responders_per_incident * a.engineer_hourly_cost
        build = a.build_cost_one_time if year == 1 else 0.0
        run = a.infra_cost_per_month * 12 + a.llm_cost_per_incident * incidents + a.maintenance_fte * a.fte_annual_cost
        benefits = downtime + labour
        costs = build + run
        cumulative += benefits - costs
        rows.append(YearResult(year, incidents, remediated, minutes_saved, downtime, labour, benefits,
                               build, run, costs, benefits - costs, cumulative))
    return rows


def payback_month(a: Assumptions, rows: list[YearResult]) -> int | None:
    """First month in which cumulative net benefit turns non-negative."""
    cumulative = -a.build_cost_one_time
    for r in rows:
        monthly = (r.benefits - r.run_cost) / 12
        for m in range(12):
            cumulative += monthly
            if cumulative >= 0:
                return (r.year - 1) * 12 + m + 1
    return None


def totals(a: Assumptions, rows: list[YearResult]) -> dict[str, float]:
    benefits = sum(r.benefits for r in rows)
    costs = sum(r.costs for r in rows)
    return {
        "tco": costs,
        "benefits": benefits,
        "net": benefits - costs,
        "roi_pct": (benefits - costs) / costs * 100 if costs else 0.0,
        "payback_month": payback_month(a, rows),
    }


def _usd(x: float) -> str:
    return f"${x:,.0f}"


def render_tables(a: Assumptions) -> str:
    rows = model(a)
    t = totals(a, rows)
    out = ["### Assumptions", "", "| Assumption | Value |", "|---|---|"]
    out += [f"| `{k}` | {v:,} |" if isinstance(v, (int, float)) else f"| `{k}` | {v} |" for k, v in asdict(a).items()]
    out += ["", "### Year-by-year", "",
            "| Year | Incidents | Remediated | Minutes saved | Downtime savings | Labour savings | "
            "Benefits | Build cost | Run cost | Net | Cumulative net |",
            "|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for r in rows:
        out.append(
            f"| {r.year} | {r.incidents:,.0f} | {r.remediated:,.0f} | {r.minutes_saved:,.0f} | "
            f"{_usd(r.downtime_savings)} | {_usd(r.labour_savings)} | {_usd(r.benefits)} | "
            f"{_usd(r.build_cost)} | {_usd(r.run_cost)} | {_usd(r.net)} | {_usd(r.cumulative_net)} |"
        )
    payback = f"month {t['payback_month']}" if t["payback_month"] else "not within horizon"
    out += ["", f"### {a.years}-year summary", "", "| Metric | Value |", "|---|---|",
            f"| Total cost of ownership | {_usd(t['tco'])} |",
            f"| Total benefits | {_usd(t['benefits'])} |",
            f"| Net benefit | {_usd(t['net'])} |",
            f"| ROI | {t['roi_pct']:.0f}% |",
            f"| Payback | {payback} |"]
    return "\n".join(out)


NFR_MATRIX = """| NFR | Target (SLA/SLO) | How it is met | Where it is evidenced |
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
"""


SENSITIVITIES: list[tuple[str, str, float]] = [
    ("downtime_cost_per_min", "Downtime cost halved", 0.5),
    ("automation_coverage", "Automation coverage 0.45 -> 0.20", 0.20 / 0.45),
    ("build_cost_one_time", "Build cost +50%", 1.5),
    ("automated_mttr_min", "Automated MTTR doubled (25 -> 50 min)", 2.0),
    ("llm_cost_per_incident", "LLM cost x10", 10.0),
]


def render_sensitivity(a: Assumptions) -> str:
    out = ["| Scenario | 3-yr net | ROI | Payback |", "|---|---:|---:|---:|"]
    base = totals(a, model(a))
    out.append(f"| Base case | {_usd(base['net'])} | {base['roi_pct']:.0f}% | month {base['payback_month']} |")
    for field_name, label, factor in SENSITIVITIES:
        varied = Assumptions(**{**asdict(a), field_name: getattr(a, field_name) * factor})
        t = totals(varied, model(varied))
        payback = f"month {t['payback_month']}" if t["payback_month"] else "none"
        out.append(f"| {label} | {_usd(t['net'])} | {t['roi_pct']:.0f}% | {payback} |")
    return "\n".join(out)


def render_workbook(a: Assumptions) -> str:
    return f"""# Financial & NFR Workbook

> **Generated file.** Produced by `python finance/tco_roi_calculator.py --write-workbook`.
> Edit the `Assumptions` dataclass in `finance/tco_roi_calculator.py`, not this file.
> All figures are illustrative planning assumptions, not measured data.

## 1. Three-year TCO / ROI

{render_tables(a)}

**Reading the model.** Benefits come from two sources only: downtime minutes avoided on the
share of incidents the platform remediates, and responder hours freed on those same incidents.
It deliberately ignores harder-to-defend benefits (fewer repeat incidents, on-call attrition).

### Sensitivity (one assumption changed at a time)

{render_sensitivity(a)}

## 2. Non-functional requirements & SLA matrix

{NFR_MATRIX}"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--write-workbook", action="store_true", help="regenerate docs/financial_nfr_workbook.md")
    args = parser.parse_args()
    a = Assumptions()
    if args.write_workbook:
        path = Path(__file__).resolve().parent.parent / "docs" / "financial_nfr_workbook.md"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render_workbook(a), encoding="utf-8")
        print(f"wrote {path}")
    else:
        print(render_tables(a))


if __name__ == "__main__":
    main()
