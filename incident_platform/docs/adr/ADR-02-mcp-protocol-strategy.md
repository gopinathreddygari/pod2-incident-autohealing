# ADR-02: MCP as the tool boundary

**Status:** Accepted
**Context:** Pod 2 Incident Remediation Platform

## Context

Agents need to read cluster state (logs, metrics) and change it (restart, scale, roll back,
drain). The tool layer is where an LLM mistake turns into a production change, so it must be
the most defended boundary in the system. It must also be replaceable: today's mock handlers
will become Kubernetes, Prometheus and Terraform calls.

## Decision

Expose every capability through a **Model Context Protocol-shaped** server. It has two
methods, `list_tools()` (discovery) and `call_tool(name, arguments)` (invocation). Tool
errors come back as results with `isError: true` rather than exceptions, as in MCP's
`tools/call`.

1. **Nine tools, annotated.** Each tool carries MCP `readOnlyHint`/`destructiveHint` plus a
   `riskClass` annotation (read_only, safe_reset, config_patch, destructive, failover). The HITL
   gate reads the class, so classification lives with the tool and not in agent code. See
   **ADR-04** for the classes and the gating rule.
2. **Defence in depth inside `call_tool`**, in order:
   - JSON-schema validation (required, unknown and type-checked arguments)
   - an argument guardrail that rejects shell metacharacters in any string
   - a per-tool circuit breaker
   - an audit entry and a tracer span
3. **In-process for the demo.** The server is a Python class. Going out of process means
   putting the official `mcp` SDK transport (stdio or streamable HTTP) in front of the same
   class. No agent code changes, because agents only ever call these two methods.
4. **Arguments come from the incident, not the model.** The planner asks the model *which*
   tool to use. It binds arguments from the validated incident `target`. This closes the most
   common agent-to-tool injection path.

## Alternatives rejected

- **Direct SDK calls from agents** (kubernetes-client inside the agent): no single place to
  enforce validation, guardrails, breakers or audit.
- **A generic `run_shell(command)` tool:** unbounded blast radius, and its safety would depend
  entirely on string filtering.
- **Model-supplied free-form arguments:** makes prompt injection a remote-code path.

## Consequences

- Tool failure is data. Triage degrades gracefully when a read tool's breaker opens (INC-1010)
  and escalates rather than acting on partial evidence.
- **Production follow-ups:**
  - run the server out of process under a dedicated Kubernetes service account per tool
    (least privilege)
  - authenticate callers
  - ship the audit log to WORM storage with 400-day retention (NFR matrix)
- The guardrails are deterministic pattern matching: explainable and cheap, but not
  exhaustive. A classifier model could be added behind the same `GuardrailMiddleware`
  interface.
