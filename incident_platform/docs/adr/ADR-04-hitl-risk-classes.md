# ADR-04: Gate human approval on tool risk classes

**Status:** Accepted (supersedes the boolean `destructive` gate described in earlier versions of ADR-02)
**Context:** Pod 2 Incident Remediation Platform

## Context

The first HITL gate asked one question: *is the tool destructive?* One bit is too coarse for
remediation actions:

- A rolling restart and a region failover are both "not a rollback", but they carry very
  different risk.
- A scale-out isn't destructive, yet it can starve a shared node pool or run up cost.
- A config patch rewrites a deployment's desired state even when nothing is deleted.

The requirement (FR3) is that low-risk resets run autonomously while anything that changes
desired state, withdraws a release or moves traffic always waits for an SRE.

## Decision

Every MCP tool declares a **risk class**, exposed as the `riskClass` annotation next to MCP's
`readOnlyHint`/`destructiveHint`. `HITLGate.evaluate(risk_class, confidence)` gates on it:

| Risk class | Meaning | Tools | Gate |
|---|---|---|---|
| `read_only` | observes only | fetch_k8s_logs, correlate_telemetry | autonomous |
| `safe_reset` | resets runtime state; desired state unchanged; self-healing if wrong | restart_service, clear_pod_cache | autonomous |
| `config_patch` | changes the desired-state spec | scale_deployment, apply_hotfix | **SRE approval** |
| `destructive` | withdraws a release or evicts workloads | rollback_deployment, drain_node | **SRE approval** |
| `failover` | moves a region's traffic to another cluster | failover_cluster | **SRE approval** |

Two rules sit on top of the table:

- **Low confidence always escalates.** If triage confidence is below `MIN_AUTONOMOUS_CONFIDENCE`
  (0.75), approval is required for *every* class, including read_only and safe_reset.
- **Unknown classes are gated.** An unknown or missing class yields `unclassified_action`. A new
  tool added without a class can't slip through as autonomous.

Each gated class has its own reason constant (`destructive_action`, `failover_action`,
`config_patch`, `unclassified_action`). The approval payload shows both the class and a
plain-English reason.

## Why `scale_deployment` is `config_patch`, not `safe_reset`

Scaling looks harmless, since nothing is deleted and replicas can be scaled back. It is still
classified as a config patch:

1. **It changes desired state.** `spec.replicas` is part of the deployment spec, and it persists
   until someone reverts it. A restart or cache flush changes only runtime state, and the system
   converges back to the same spec by itself.
2. **Its blast radius is shared.** Extra replicas consume capacity on node pools shared with other
   services. At peak (exactly when incidents happen) that can trigger evictions or pending pods
   elsewhere. The cost impact is also real and ongoing.
3. **It can mask the real fault.** Scaling out a memory leak (as in the INC-1010 OOM case) or a
   cache regression (INC-1003) buys time, but can hide the root cause. A human should choose
   between buying time and fixing the defect.
4. **It fights other controllers.** An HPA or GitOps controller may own `replicas`. A manual scale
   can be overwritten silently, or can conflict with the declared state in Git.
5. **Operational precedent.** Change-management policies usually treat capacity changes in
   production as standard changes that need a named approver, not as self-service resets.

The consequence is accepted: INC-1003 now pauses for `config_patch` even when its confidence is
above the threshold. The demo's scripted approval keeps it VERIFIED.

## Consequences

- **Positive:**
  - Autonomy is granted by *what an action does*, not by a single flag.
  - The table above is the policy, and it's testable (`tests/test_platform.py::HITLGateTests`).
  - Adding a tool forces an explicit classification decision.
- **Negative:**
  - More approvals than a destructive-only gate. That's mitigated by the step-through dashboard and
    by keeping resets autonomous.
- **Follow-up:** risk classes could become per-environment policy (e.g. `config_patch` autonomous in
  staging) loaded from config rather than code.
