# Architecture Overview

CloudScale Global Networks -- Pod 2: IT Infrastructure Incident Remediation & Auto-Healing.

## 1. Purpose

Take a P1/P2 infrastructure incident from alert to verified fix, with minimal human effort and
**no unapproved destructive action**. The platform triages with read-only tools, proposes one
runbook action, pauses for a human whenever the action is destructive or the diagnosis is
uncertain, executes through a protected tool boundary, and verifies the result.

## 2. Domain-Driven Design: bounded contexts

| Context | Type | Responsibility | Code |
|---|---|---|---|
| **Incident Triage** | Core | Evidence gathering (read-only MCP tools), root cause, confidence, category | `agents/triage_agent.py` |
| **Remediation Planning** | Core | Choose one runbook action; bind arguments from validated incident data; render the command | `agents/remediation_planner_agent.py` |
| **Execution & Verification** | Core | Invoke the action; re-read telemetry to prove the fix | `agents/execution_verification_agent.py` |
| **Incident Lifecycle** | Core (shared kernel) | `IncidentState` graph; the only authority on legal transitions | `state/incident_state.py` |
| **Governance** | Supporting | HITL approval gate, guardrails (injection, shell, PII) | `hitl/`, `guardrails/` |
| **Tool Integration** | Supporting | MCP `list_tools`/`call_tool`, circuit breakers, mock cluster | `mcp_server/`, `state/circuit_breaker.py` |
| **LLM Operations** | Supporting | Backend selection, model routing, semantic cache, token/cost accounting | `llm/` |
| **Observability** | Generic | Tracing, hash-chained audit log, metrics | `observability/` |
| **Finance** | Generic | TCO/ROI model feeding the business case | `finance/` |

**Ubiquitous language.** *Incident* (the aggregate root), *Triage result*, *Remediation plan*,
*Approval request/decision*, *Tool* (MCP), *Blast radius*, *Degraded evidence*.

**Context map.** The Core contexts talk to Supporting contexts only through narrow ports:
- `BaseAgent.think()` is the single port into LLM Operations and Governance.
- `MCPToolServer.call_tool()` is the single port into Tool Integration.
- `HITLGate.request()` is the single port into approval.

Observability works as a conformist: every context writes to the same tracer and audit log
instances, which `IncidentPlatform` injects.

## 3. Component diagram (textual)

```
                         +--------------------------------------+
   alert / ticket  --->  |  IncidentOrchestrator (coordinator)  |  owns lifecycle, delegates stages
                         +---+--------------+---------------+---+
                             |              |               |
                    +--------v---+  +-------v--------+  +---v------------------------+
                    | Triage     |  | Remediation    |  | Execution & Verification   |
                    | Agent      |  | Planner Agent  |  | Agent  --> HITLGate        |
                    +--+------+--+  +---+--------+---+  +---+----------+-------------+
                       |      |         |        |          |          |
            think()    |      | call_tool (RO)   | think()  | call_tool| ApprovalChannel
                       v      v         v        v          v          v
   +-------------------------------+  +-------------------------------+  +-------------------+
   | BaseAgent.think()             |  | MCPToolServer                 |  | Console / Auto /  |
   |  PII redact -> input guard -> |  |  schema -> arg guardrail ->   |  | (Slack, PagerDuty)|
   |  cache L1/L2 -> router ->     |  |  circuit breaker -> handler   |  +-------------------+
   |  backend -> profiler -> audit |  |  9 tools, 5 risk classes      |
   +---------------+---------------+  +---------------+---------------+
                   |                                  |
                   v                                  v
        Mock / OpenAI (Resilient)            (Kubernetes / Prometheus seam)

   Cross-cutting (injected by IncidentPlatform): Tracer  AuditLog(hash chain)  MetricsCollector
                                                 IncidentStateStore  BreakerRegistry  Settings
```

See `diagrams/system_architecture.excalidraw` and `diagrams/agent_workflow_sequence.excalidraw`
for the drawn versions.

## 4. Tools, risk classes and the HITL rule

All tools are mocked against `MockCluster`, and every command template is a kubectl command.
**`correlate_telemetry` stands in for Prometheus and Datadog**, and `fetch_k8s_logs` for the Kubernetes log API. The seam is `MCPToolServer.call_tool()`,
so swapping in real clients doesn't change any agent code (ADR-02).

| Tool | Risk class | Gate |
|---|---|---|
| fetch_k8s_logs, correlate_telemetry | read_only | autonomous |
| restart_service, clear_pod_cache | safe_reset | autonomous |
| scale_deployment, apply_hotfix | config_patch | SRE approval |
| rollback_deployment, drain_node | destructive | SRE approval |
| failover_cluster | failover | SRE approval |

Independently of the class, **confidence below `MIN_AUTONOMOUS_CONFIDENCE` (0.75) always needs an
SRE**, and an unknown class is gated (fail-safe). ADR-04 records the reasoning, including why
`scale_deployment` is config_patch.

Every plan also carries an **IaC recovery draft**: Kubernetes YAML for hotfix/scale/rollback,
Ansible for restart/cache-flush/drain, and Terraform for failover. It's rendered from templates with
code-bound arguments, checked by the script guardrail, and shown to the approver. It is never
executed.

## 5. Control flow and safety invariants

1. **Nothing reaches a model unfiltered.** PII is redacted and injection patterns are checked
   inside `think()`. No agent has another way to call a backend.
2. **The model picks the action; code picks the target.** Tool arguments are bound from the
   incident's `target`, never from model output, and the rendered command must pass the output
   guardrail.
3. **Risky or uncertain means human.** `HITLGate.evaluate()` fires on a gated risk class
   (destructive, failover, config_patch) or on confidence below `MIN_AUTONOMOUS_CONFIDENCE`. The state graph has no edge from
   AWAITING_APPROVAL to EXECUTING except through APPROVED.
4. **Fail safe, not fail open.** Unknown approvals are rejected, degraded evidence escalates,
   provider errors fall back to the mock, and unexpected exceptions go to ESCALATED or FAILED.
5. **Everything is evidenced.** Each incident is one trace, and every decision is a
   hash-chained audit entry.

## 6. Deployment view (target production shape)

| Concern | Demo (this repo) | Production |
|---|---|---|
| MCP server | In-process class | Separate service behind stdio / streamable HTTP, per-tool RBAC service accounts |
| State store | In-memory dict | Redis (incident state) with the same get/put/transition surface |
| Semantic cache | In-memory list, hashed embeddings | Vector DB (pgvector/Redis) + trained embedding model |
| Audit log | Local JSONL | JSONL shipped to WORM object storage; head hash anchored externally |
| Tracing | OTel-shaped spans in memory | OpenTelemetry SDK -> collector -> Tempo/Jaeger/Datadog |
| Approval | Console / scripted / local web dashboard (`WebApprovalChannel`, blocks until a browser decision or the SLA timeout) | Slack or PagerDuty interactive message using the same `to_payload()` and the same blocking `ApprovalChannel` seam |
| LLM | Mock by default; opt-in OpenAI -> Anthropic -> mock chain | Same chain (ADR-05), keys from a secrets manager |
