# ADR-01: Hierarchical coordinator topology

**Status:** Accepted
**Context:** Pod 2 Incident Remediation Platform

## Context

The platform runs three specialist capabilities in sequence (triage, planning, execution
and verification). Each one needs a different tool scope and a different risk posture. An
incident response system is judged on correctness and auditability first, and latency second.
Operators must be able to answer "why did the system do that?" from a single place.

## Options considered

| Option | For | Against |
|---|---|---|
| **A. Hierarchical coordinator** (one orchestrator, specialist agents, no agent-to-agent calls) | Control flow readable in one method. A single owner of state transitions. Tool scopes are easy to restrict per agent. Deterministic tests | The coordinator is a central component to keep simple. Stages run sequentially |
| B. Peer-to-peer / swarm (agents hand off to each other) | Flexible, and emergent parallelism | Hard to prove the HITL gate cannot be bypassed. Non-deterministic paths. Audit reconstruction is hard |
| C. Single monolithic agent with all tools | Fewest moving parts | One prompt holds both read and destructive tools. No separation of duties. Hard to route cost per stage |

## Decision

**Option A.** `IncidentOrchestrator.handle()` is the coordinator. It owns the lifecycle and calls
`TriageAgent -> RemediationPlannerAgent -> ExecutionVerificationAgent`. Agents never call each
other.

- **Least privilege by stage:** triage uses only read-only tools, the planner uses no tools, and
  only the executor can call write tools, and only after the HITL gate.
- **One source of truth for state:** `IncidentStateStore` validates every transition against
  `VALID_TRANSITIONS`. The HITL gate is the only component that moves to APPROVED or REJECTED.
- **Dependency injection:** `IncidentPlatform` builds every shared component once (tracer,
  audit, cache, breakers, tool server) and injects them, so tests can swap any of them.

## Consequences

- Positive: the full control flow is about 40 lines in `orchestrator.py`. There is one trace
  per incident, and escalation policy (degraded evidence, guardrail block, no safe action) is
  centralised.
- Negative: stages are sequential. The evidence calls in triage could run in parallel later
  (`asyncio.gather`) without changing the topology.
- Risk: the coordinator could grow into a god object. Mitigation: it holds policy only, and
  all work lives in agents or supporting contexts.
