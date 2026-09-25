# Pod 2 -- IT Infrastructure Incident Remediation & Auto-Healing Platform

**Enterprise Capstone -- AI for Technical Architects.** A working, runnable
implementation of the Pod 2 scenario for CloudScale Global Networks: a
hierarchical multi-agent pipeline that triages, plans, and executes remediation
for P1/P2 infrastructure incidents, with mandatory human approval on anything
destructive.

**Runs with zero dependencies and zero API keys by default** (Python 3.10+,
standard library only). Real OpenAI calls are supported, but they stay off
unless you explicitly opt in (see below).

```bash
cd incident_platform
python main.py        # use python3 on macOS/Linux
```

That single command runs 10 scripted incidents that exercise every required
capability, then prints a metrics/audit summary. Read the console output top
to bottom -- it *is* the demo. The exit code is 0 only if every incident reaches
its expected final state.

> **Windows note:** if `python` opens the Microsoft Store, the Store alias is
> shadowing your install. Either run it by full path
> (`& "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe" main.py`) or
> turn off *App execution aliases* for python in Windows Settings.

| Incident | Scenario | Demonstrates | Final state |
|---|---|---|---|
| INC-1001 | P1 CrashLoopBackOff | Autonomous remediation (non-destructive, confidence 0.93) | VERIFIED |
| INC-1002 | P1 bad rollout | HITL on a **destructive** action (approved); IP redacted by regex, a name by spaCy NER when enabled | VERIFIED |
| INC-1003 | P2 latency | HITL on risk class **config_patch** (scale) *and* **low confidence** (0.62 < 0.75); cost-tier model | VERIFIED |
| INC-1004 | P1 repeat of 1001 | **Semantic cache** (L2 triage, L1 plan): 0 tokens | VERIFIED |
| INC-1005 | P2 poisoned ticket | **Input guardrail** blocks prompt injection; email + IP redacted | ESCALATED |
| INC-1006 | P1 node DiskPressure | Destructive drain **rejected** by the SRE; nothing executes | REJECTED |
| INC-1007 | P2 stale cache | `clear_pod_cache` is **safe_reset**, so it runs **autonomously** and is verified | VERIFIED |
| INC-1008 | P1 bad config push | `apply_hotfix` (**config_patch**, vetted catalog patch `db-pool-size`) is approved and verified | VERIFIED |
| INC-1009 | P1 region outage | `failover_cluster` (**failover**) is **rejected** by the SRE; the failover never executes | REJECTED |
| INC-1010 | P1 OOMKilled | **Circuit breaker** opens on the log backend -> degraded triage -> escalate | ESCALATED |

---

## 1. What this is (and isn't)

This is a **teaching-scale reference implementation**. It demonstrates every
architectural pattern the Capstone brief asks for, with functioning code behind
each one; it is not a production deployment. Every external system
(Kubernetes, Prometheus/Datadog, the LLM provider) is mocked by default, with a
clearly marked seam for swapping in the real thing. Section 8, "Scope &
limitations", lists exactly what's mocked and why.

## 2. Project flow (what happens when you run `main.py`)

```
Incident arrives (title, severity, raw telemetry)
        |
        v
[TriageAgent]  --read-only MCP calls (fetch_k8s_logs, correlate_telemetry)-->
        |  LLM reasoning (mock or real) -> root cause + confidence + category
        v
[RemediationPlannerAgent]  -->  drafts one MCP action + steps
        |  output guardrail scans the drafted command
        v
   gated risk class OR low confidence?
        |                              \
       no                              yes
        |                               v
        |                        [HITL Gate] -- incident PAUSES
        |                        state -> AWAITING_APPROVAL
        |                        approval payload generated
        |                        SRE decides (approve/reject)
        |                        state -> APPROVED/REJECTED, RESUME
        |                               |
        v                               v (if approved)
[ExecutionVerificationAgent]  -->  MCP tool call (circuit-breaker + guardrail protected)
        |
        v
   verify post-remediation health -> VERIFIED or FAILED
```

Every LLM step checks the semantic cache before spending a token. Every step
writes a span to the tracer and an entry to the hash-chained audit log. See
`docs/diagrams/agent_workflow_sequence.excalidraw` for the full visual sequence,
and `docs/architecture_overview.md` for the Domain-Driven Design
bounded-context breakdown.

## 3. Enabling real OpenAI calls (disabled by default)

```bash
pip install -r requirements.txt          # after uncommenting the openai line
export INCIDENT_PLATFORM_USE_REAL_LLM=true
export OPENAI_API_KEY=sk-...
python main.py
```

(PowerShell: `$env:INCIDENT_PLATFORM_USE_REAL_LLM="true"; $env:OPENAI_API_KEY="sk-..."`)

Both the env var **and** a present API key are required (see
`llm/llm_backend.py:get_backend()`). If either is missing, you stay safely on
the mock backend. If a real call fails at runtime (bad key, rate limit,
network), `ResilientBackend` catches it and falls back to the mock rather than
crashing the incident pipeline -- an LLM provider outage should never become an
infrastructure-response outage.

## 3a. PII detection layers

Every prompt, cache key and audited free-text field (such as incident titles and state reasons) is
redacted before it leaves the process. See `guardrails/pii_detector.py`:

| Layer | Default | Catches |
|---|---|---|
| Regex rules | on | emails, IPv4/IPv6, phone numbers, Luhn-valid card numbers, API keys (OpenAI, AWS, GitHub, Slack, GitLab), JWTs, bearer tokens, private keys |
| Heuristic NER (stdlib) | on | person names after context cues ("reported by", "cc", "contact", "escalated to", …) or starting with a known first name ("Carlos Mendez") |
| spaCy NER | opt-in | statistical PERSON entities, including names with no cue |

To enable spaCy:

```bash
pip install spacy && python -m spacy download en_core_web_sm
export INCIDENT_PLATFORM_PII_NER=spacy      # or: off | heuristic (default)
```

If spaCy is requested but missing, a warning is printed and the regex and heuristic layers still
run. Findings from all layers are merged, so overlapping spans are redacted once.

spaCy's small model is noisy on ops text. Unfiltered, it tagged `Respond` and `JSON` in the prompt
template, `Cordon`, and `lookup inventory-db` as people, which would corrupt the prompt and strip
evidence. Its PERSON guesses are therefore accepted only when every token is name-shaped and not on
the stoplist, and a lone capitalised word at a sentence start must be a known first name.
`tests/test_pii.py` asserts zero spaCy false positives across all demo text.

**Which layer caught it?** Every finding carries its source: `regex`, `heuristic-ner` or `spacy-ner`.

- **Command line:** `python -m guardrails "noticed by Bartholomew Quigley, cc Wei Zhang" --ner spacy`
  lists each finding with its layer and character span.
- **Audit log:** every `llm_call` and `guardrail_blocked_input` entry includes
  `pii_sources`, e.g. `{"PERSON/spacy-ner": 1, "EMAIL/regex": 1}`.
- **Console demo:** the `detected by:` line under each `PII:` line.
- **Dashboard:** the incident's PII section has a *Detected by* table.

When two layers find the same text, it is redacted once and credited to the first layer that found
it (regex, then heuristic, then spaCy). So a `spacy-ner` credit means spaCy found something the
other layers missed.

On this machine spaCy lives in an isolated venv, so the default stays zero-dependency:

```powershell
$env:INCIDENT_PLATFORM_PII_NER="spacy"; .\.venv-ner\Scripts\python.exe ui_server.py
```

## 3b. MCP tools, risk classes and the HITL rule

Every tool is **mocked** and acts on the in-memory `MockCluster`. `correlate_telemetry` stands in for
the **Prometheus and Datadog** metrics backends, and `fetch_k8s_logs` for the Kubernetes log API.

| Tool | Risk class | `destructiveHint` | Executed command (kubectl) | Recovery draft |
|---|---|---|---|---|
| `fetch_k8s_logs` | read_only | no | `kubectl logs -l app=… --tail=50` | – |
| `correlate_telemetry` | read_only | no | `kubectl get --raw …/services/prometheus:9090/proxy/api/v1/query?query=up{…}` | – |
| `restart_service` | safe_reset | no | `kubectl rollout restart deployment/…` | ansible-yaml |
| `clear_pod_cache` | safe_reset | no | `kubectl annotate deployment/… cache.cloudscale.io/flush=now` | ansible-yaml |
| `scale_deployment` | config_patch | no | `kubectl scale deployment/… --replicas=N` | kubernetes-yaml |
| `apply_hotfix` | config_patch | yes | `kubectl patch deployment/… --type=strategic --patch-file=hotfixes/<id>.yaml` | kubernetes-yaml |
| `rollback_deployment` | destructive | yes | `kubectl rollout undo deployment/…` | kubernetes-yaml |
| `drain_node` | destructive | yes | `kubectl drain <node> --ignore-daemonsets` | ansible-yaml |
| `failover_cluster` | failover | yes | `kubectl annotate service/global-router … region=<region>` | terraform-hcl |

**HITL rule** (`hitl/hitl_gate.py`, rationale in ADR-04):

| Risk class | Confidence ≥ threshold (0.75) | Confidence < threshold |
|---|---|---|
| read_only | autonomous | SRE approval (`low_confidence`) |
| safe_reset | autonomous | SRE approval (`low_confidence`) |
| config_patch | SRE approval (`config_patch`) | SRE approval (`config_patch`, `low_confidence`) |
| destructive | SRE approval (`destructive_action`) | SRE approval (`destructive_action`, `low_confidence`) |
| failover | SRE approval (`failover_action`) | SRE approval (`failover_action`, `low_confidence`) |
| unknown class | SRE approval (`unclassified_action`), fail-safe | same |

Every template is a kubectl command, so all nine pass the output guardrail (a test renders and
checks each one). `apply_hotfix` takes a **catalog id**, not patch content. The id must match
`^[a-z0-9][a-z0-9-]{0,62}$` and exist in the mocked `HOTFIX_CATALOG` (`db-pool-size`, `hotfix-2141`),
otherwise the call fails with `invalid_arguments`. The reviewed patch file `hotfixes/<id>.yaml` is
what kubectl applies. In tool arguments, a bare Kubernetes name such as `su` or `sudo` (a valid
DNS-1123 name) is not treated as privilege escalation, because it can't execute anything. Commands
and script drafts still block those words.

The planner also renders an **IaC recovery-script draft** for every remediation (see the last column),
built from deterministic templates in `agents/recovery_scripts.py`. It's bound only to code-validated
arguments and checked by the script guardrail. It appears in the approval card and the dashboard,
but **only the kubectl command is ever executed**.

**Privilege-escalation guardrails** (FR4) block, in commands, tool arguments and script drafts:
`sudo`/`su`/`doas`, `chmod` setuid or world-writable modes, `chown root`, kubectl impersonation
(`--as=`, `--as-group=`), `clusterrolebinding`/`cluster-admin`, `--privileged`,
`hostPID`/`hostNetwork`, and `kubectl exec`.

## 3c. Live web dashboard (best for a live demo)

```bash
python ui_server.py            # opens http://127.0.0.1:8000
```

The dashboard runs the same ten scenarios on the same platform code, still with zero
dependencies (`http.server` plus one HTML file, no CDN, so it works offline). What it adds:

- **Paced state machine.** Each transition animates on the incident cards.
- **Per-incident Steps and Trace tabs.** *Steps* is a live, phase-grouped feed of that incident's audit entries (tool calls, LLM calls, cache hits, guardrail blocks, approvals, breaker changes). *Trace* is its span waterfall. Running spans are visible too, so the approval wait grows live.
- **Presenter-controlled pacing.** In step-through mode (the default), one incident runs, then the
  queue waits for **Next ▶**. *Run the rest* or *Auto* mode runs everything left without stopping.
  Approval cards open only for the incident you're viewing; others show as a header badge, so
  nothing takes over the screen while you're explaining something else.
- **Real human-in-the-loop.** The HITL gate uses `WebApprovalChannel`. The incident truly
  pauses until you click **Approve** or **Reject** on the Slack-style card. Unanswered
  requests reject after the 15-minute approval SLA.
- **Knobs.** The autonomy threshold, INC-1010's fault injection (tool and count), and the pace.
- **Custom incidents.** Presets include prompt injection, shell injection in a field, and a
  fix that doesn't work. Everything you type goes through the same guardrails.
- **Tamper button.** It edits one entry in a *copy* of the audit chain and shows where
  `verify_chain()` breaks. The real chain stays intact.
- **Live panels.** The four required metrics, breaker states, cost, and an audit event feed.

It binds to 127.0.0.1 only and has no authentication: it's a local demo, not a
deployable approval service. See `DEMO.md` for a presenter walkthrough.

## 4. Running the interactive HITL flow

`main.py` uses `AutoApprovalChannel` (scripted decisions), so the whole demo runs
non-interactively and reproducibly. To approve or reject for real from your
terminal:

```python
from hitl import ConsoleApprovalChannel
from orchestrator import IncidentOrchestrator, IncidentPlatform
from main import build_scenarios

platform = IncidentPlatform()
orchestrator = IncidentOrchestrator(platform, ConsoleApprovalChannel())
sc = build_scenarios()[1]                      # INC-1002, destructive rollback
platform.cluster.register_fault(sc.incident.target["service"], sc.incident.target["workload"],
                                sc.logs, sc.signals, sc.fixed_by)
print(orchestrator.handle(sc.incident))
```

This pauses execution, prints the approval payload (the same payload a
Slack/PagerDuty bot would render), and blocks on `input()` for your y/n.
EOF or Ctrl-C counts as a rejection.

## 5. Repository layout

```
incident_platform/
├── config.py                    # single source of runtime config; real-LLM flag defaults False
├── main.py                      # scripted demo runner (10 incidents, all required scenarios)
├── ui_server.py                 # live web dashboard (stdlib http.server) with browser approvals
├── ui/index.html                # the dashboard page (vanilla JS, no external requests)
├── DEMO.md                      # presenter walkthrough (dashboard + console)
├── orchestrator.py              # IncidentOrchestrator (Coordinator) + IncidentPlatform (DI container)
├── requirements.txt             # empty by default; openai only needed for real calls
│
├── agents/
│   ├── base_agent.py            # think(): PII redact -> guardrail -> cache -> route -> profile -> audit
│   ├── triage_agent.py          # RCA + confidence + category
│   ├── remediation_planner_agent.py  # drafts one MCP action + IaC draft; output/script guardrail checks
│   ├── recovery_scripts.py       # deterministic Kubernetes-YAML / Ansible / Terraform recovery drafts
│   └── execution_verification_agent.py  # HITL gate call -> tool execution -> health check
│
├── mcp_server/
│   └── tool_server.py           # MCPToolServer: list_tools()/call_tool(), 9 tools with risk classes, breaker+guardrail+audit
│
├── hitl/
│   ├── hitl_gate.py             # ApprovalRequest, ConsoleApprovalChannel, AutoApprovalChannel
│   └── web_approval_channel.py  # WebApprovalChannel: blocks until the browser decides (or SLA timeout)
│
├── guardrails/
│   ├── guardrail_middleware.py  # input (prompt injection) + output (shell injection) + PII redaction
│   └── pii_detector.py          # layered PII: regex rules + heuristic NER (+ optional spaCy NER)
│
├── llm/
│   ├── llm_backend.py           # MockLLMBackend (default), OpenAILLMBackend, ResilientBackend, get_backend()
│   ├── model_router.py          # 2-tier routing (accuracy vs. cost)
│   ├── semantic_cache.py        # L1 hash / L2 cosine-similarity cache
│   └── token_profiler.py        # token estimation + cost tracking
│
├── observability/
│   ├── tracer.py                # OTel-shaped spans, no SDK dependency
│   ├── audit_log.py             # hash-chained (tamper-evident) JSONL audit log
│   └── metrics.py               # latency/task, token rate, cache hit ratio, tool failure rate
│
├── state/
│   ├── incident_state.py        # IncidentState enum, valid-transition graph, IncidentStateStore
│   └── circuit_breaker.py       # CLOSED/OPEN/HALF_OPEN breaker per tool
│
├── finance/
│   └── tco_roi_calculator.py    # runnable 3-year TCO/ROI model (`python finance/tco_roi_calculator.py`)
│
├── tests/                       # 86 unittest cases incl. end-to-end runs via console and dashboard API
│
└── docs/
    ├── architecture_overview.md   # DDD bounded contexts + textual component diagram
    ├── financial_nfr_workbook.md  # generated output of the TCO/ROI calculator + NFR SLA matrix
    ├── adr/
    │   ├── ADR-01-topology-orchestration.md
    │   ├── ADR-02-mcp-protocol-strategy.md
    │   ├── ADR-03-cost-performance-strategy.md
    │   └── ADR-04-hitl-risk-classes.md
    └── diagrams/
        ├── generate_diagrams.py             # regenerates both .excalidraw files
        ├── system_architecture.excalidraw    # top-level cloud/runtime/security architecture
        └── agent_workflow_sequence.excalidraw # agent sequence + HITL approval boundary
```

Other commands:

```bash
python -m unittest discover -s tests -v               # test suite
python finance/tco_roi_calculator.py --write-workbook  # regenerate docs/financial_nfr_workbook.md
python docs/diagrams/generate_diagrams.py              # regenerate the .excalidraw files
```

## 6. How this maps to the evaluation rubric

| Rubric parameter | Where to look |
|---|---|
| **Core Integration Path** (topology, MCP, circuit breaker) | `orchestrator.py` (hierarchical coordinator), `mcp_server/tool_server.py` (9 tools with risk classes via `list_tools()`/`call_tool()`), `state/circuit_breaker.py`; rationale in ADR-01 and ADR-02 |
| **Telemetry & Audit** | `observability/tracer.py` (OTel-shaped spans), `observability/audit_log.py` (hash-chained, `verify_chain()`), `observability/metrics.py` (the four required metrics, printed at the end of `main.py`) |
| **Contract Compliance & Governance** | `hitl/hitl_gate.py` (risk-class + confidence-threshold gates), `guardrails/guardrail_middleware.py` (injection defense, PII redaction), `docs/architecture_overview.md` (DDD Core/Supporting mapping) |
| **Engineering Package Delivery** | This repository (functional code + tests), `docs/diagrams/*.excalidraw`, `docs/adr/ADR-0{1,2,3,4}-*.md`, `docs/financial_nfr_workbook.md` / `finance/tco_roi_calculator.py` |

## 7. Try these yourself

- **Trip the circuit breaker differently:** change `fail_injection={"fetch_k8s_logs": 5}`
  on INC-1010 in `main.py`. `{"fetch_k8s_logs": 2}` is absorbed by the read-tool
  retries, so the breaker never opens and the incident is VERIFIED.
  `{"correlate_telemetry": 5}` degrades triage through the other evidence source.
- **Change the HITL confidence threshold:** edit `MIN_AUTONOMOUS_CONFIDENCE` in `config.py`
  (currently 0.75). INC-1003's 0.62-confidence latency incident sits deliberately
  just under it, to demonstrate confidence-based escalation distinct from
  destructiveness-based escalation. Set it to 0.6 and INC-1003 runs autonomously.
- **Verify the audit log wasn't tampered with:** `platform.audit.verify_chain()`,
  or for the file on disk:
  `python -c "from observability import AuditLog; print(AuditLog.load('audit_log.jsonl').verify_chain())"`.
  Hand-edit any line in `audit_log.jsonl` and run it again -- the chain breaks.
- **Re-run the financial model with different assumptions:** edit the
  `Assumptions` dataclass in `finance/tco_roi_calculator.py` and re-run it.

## 8. Scope & limitations (read before a jury defense)

What's real engineering, and what's a placeholder:

- **Real:** the state machine and its transition validation, the circuit
  breaker, the hash-chained audit log, the guardrail pattern matching, the
  semantic cache (it genuinely computes cosine similarity over hashed
  embeddings), the HITL pause/resume cycle, and the token/cost accounting math.
- **Mocked, with a clear seam to make real:**
  - The MCP tool server's nine handlers act on an in-memory `MockCluster` instead
    of a real Kubernetes API, Prometheus, or Terraform. The docstring in
    `mcp_server/tool_server.py` explains why the `list_tools()`/`call_tool()`
    shape means swapping the transport doesn't require changing any calling code.
    The mock is stateful: applying the wrong remediation leaves the service
    unhealthy, so verification is a real check.
  - The mock LLM reasons by deterministic keyword rules over the evidence.
  - The mock embedding (`llm/semantic_cache.py`) is a hashing trick, not a
    trained model. It is a documented limitation.
  - The default name detector is heuristic (context cues plus a first-name list).
    It misses names with neither, and obfuscated PII ("jane dot doe at corp dot com").
    Enable spaCy NER, or put Presidio or a cloud DLP service behind the same
    `PIIDetector` interface, for production-grade recall.
- **Not implemented (explicitly out of scope for this deliverable):**
  - a real out-of-process MCP server (it is in-process for demo simplicity)
  - persistence to an actual Redis or vector DB (in-memory stand-ins with the
    same interface)
  - a real Slack/PagerDuty approval channel (console, scripted and local-web
    channels are provided instead; the web one shows the same blocking seam)
- **A bug worth knowing about (found and fixed during build):** an earlier
  version of the semantic cache matched two *different* incident types as
  duplicates, because it embedded the full templated LLM prompt and the shared
  boilerplate drowned out the actual symptom text. The fix caches on a
  distinct, content-focused key rather than the full prompt. See the
  `cache_key` parameter in `agents/base_agent.py` and ADR-03, which includes
  measured full-prompt vs. content-key similarities from this codebase.
  It is worth knowing because it is a realistic failure mode for anyone
  implementing semantic caching for the first time, not just a demo artifact.
