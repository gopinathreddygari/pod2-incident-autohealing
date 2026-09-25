# Requirements Validation — Incident Platform

As of 25 September 2026 (re-validated after the gap fixes and the minor fixes) · Scope: `incident_platform/` · Basis: demo with mocks accepted

## 1. Summary

With mocks accepted, all four functional requirements are now met. All 86 unit tests pass (1 skipped), up from 70. `python main.py` runs 10 incidents, each ending in its expected state, and exits with 0. The four minor issues from the previous check are resolved (section 6). The only integration gaps left are the ones accepted for a demo: Datadog and Prometheus are mocked, and MCP runs in-process.

**Evaluation basis.** Mocked integrations count as met when the mock follows the real interface and has real effects in the demo. `MockCluster` does both: a wrong remediation leaves the service unhealthy, so verification is genuine. Tool names, gating rules and guardrail patterns were checked as real logic, with no allowance for mocks.

| Req | Requirement | Before | Now | Evidence |
| --- | --- | --- | --- | --- |
| FR1a | Triage & Diagnosis agent (telemetry + logs → RCA) | Met | Met | `correlate_telemetry` is documented as standing in for Prometheus and Datadog |
| FR1b | Remediation Planner (Terraform / Ansible / K8s patches) | Partial | Met | `agents/recovery_scripts.py`: Kubernetes YAML, Ansible and Terraform drafts, checked by the script guardrail |
| FR1c | Execution & Verification agent | Met | Met | Unchanged; now gates on the tool's risk class |
| FR2 | MCP tools `fetch_k8s_logs`, `restart_service`, `apply_hotfix` | Partial | Met | All three exist; 9 tools with a `riskClass` annotation |
| FR3a | Read-only / non-destructive resets run autonomously | Mostly met | Met | `clear_pod_cache` (INC-1007) is verified with no approval request |
| FR3b | Destructive writes, failover, config patches pause for SRE | Partial | Met | `config_patch`, `destructive` and `failover` classes are always gated; unknown classes are gated too |
| FR4 | Zero-trust execution; block `rm -rf` and privilege escalation | Partial | Met | 8 new privilege-escalation patterns; all 14 of my attack probes were blocked |

## 2. FR1 — Multi-agent incident pipeline

**Met.** `IncidentOrchestrator` in `orchestrator.py` is the coordinator. It runs Triage → Planner → Execution & Verification; the agents never call each other (ADR-01). The planner now attaches a recovery-script draft to every plan, next to the executable `kubectl` command.

| Action | Draft format | Passes script guardrail |
| --- | --- | --- |
| `apply_hotfix` | Kubernetes YAML | Yes |
| `scale_deployment` | Kubernetes YAML | Yes |
| `rollback_deployment` | Kubernetes YAML | Yes |
| `restart_service` | Ansible | Yes |
| `clear_pod_cache` | Ansible | Yes |
| `drain_node` | Ansible | Yes |
| `failover_cluster` | Terraform (HCL) | Yes |

- Drafts use `string.Template` with arguments bound by code from the incident target, never from LLM text.
- Drafts are shown in the HITL approval payload but never executed. Only the `kubectl` command reaches the MCP server.
- A draft that fails `check_script()` escalates the incident (`test_fr1_blocked_draft_escalates`).
- Tests: `test_fr1_every_remediation_action_has_a_draft`, `test_fr1_plan_carries_draft_and_command_only_executes_kubectl`.

## 3. FR2 — MCP tool integration

**Met.** `mcp_server/tool_server.py` now exposes 9 mocked tools, including all three required names. Each one declares `readOnlyHint`, `destructiveHint` and the new `riskClass` annotation.

| Tool | Required? | Risk class | Approval at confidence 0.9 |
| --- | --- | --- | --- |
| `fetch_k8s_logs` | Yes | read_only | None |
| `restart_service` | Yes (renamed from `restart_pod`) | safe_reset | None |
| `apply_hotfix` | Yes (new; vetted patch catalog) | config_patch | Required |
| `correlate_telemetry` | Extra | read_only | None |
| `clear_pod_cache` | Extra (new) | safe_reset | None |
| `scale_deployment` | Extra | config_patch | Required |
| `rollback_deployment` | Extra | destructive | Required |
| `drain_node` | Extra | destructive | Required |
| `failover_cluster` | Extra (new) | failover | Required |

Tests: `test_fr2_restart_pod_is_renamed_restart_service`, `test_fr2_apply_hotfix_is_a_mocked_destructive_patch`. The server still runs in-process with no stdio or HTTP transport. That's accepted for the demo, and ADR-02 explains it.

## 4. FR3 — HITL gate rule

**Met.** `HITLGate.evaluate(risk_class, confidence)` in `hitl/hitl_gate.py` now gates on the tool's risk class. ADR-04 records the decision and why `scale_deployment` counts as a config patch.

| Requirement rule | Risk class | What I observed |
| --- | --- | --- |
| Read-only telemetry runs autonomously | read_only | No reasons returned |
| Non-destructive resets (e.g. clearing pod caches) run autonomously | safe_reset | No reasons; INC-1007 reaches VERIFIED with zero approval requests |
| Destructive writes pause for an SRE | destructive | `destructive_action`; INC-1002 approved, INC-1006 rejected (drain never runs) |
| Cluster failover pauses for an SRE | failover | `failover_action`; INC-1009 failover is rejected by the SRE and never runs |
| Configuration patch pauses for an SRE | config_patch | `config_patch`; INC-1003 scale-out and INC-1008 hotfix wait for approval, then reach VERIFIED |
| (fail-safe) Unknown tool class | anything else | `unclassified_action`, so it is gated |

The low-confidence trigger (below 0.75) still applies to every class, including safe resets. This is stricter than the requirement, and ADR-04 documents it.

Tests: `test_fr3_read_only_and_safe_reset_are_autonomous`, `test_fr3_config_patch_requires_approval`, `test_fr3_failover_requires_approval`, `test_fr3_destructive_requires_approval`, `test_fr3_new_safe_reset_and_failover_tools_are_mocked`.

## 5. FR4 — Security & guardrails

**Met.** `SHELL_PATTERNS` in `guardrails/guardrail_middleware.py` gained 8 privilege-escalation rules. They apply at three checkpoints: `check_output` (drafted command), `check_argument` (every MCP argument) and the new `check_script` (IaC drafts; only the newline rule is relaxed).

| Probe | Result |
| --- | --- |
| `sudo kubectl get pods`, `su -`, `doas id` | Blocked |
| `kubectl get pods --as=system:admin` | Blocked |
| `kubectl create clusterrolebinding x --clusterrole=cluster-admin` | Blocked |
| `kubectl run x --privileged`, `--overrides={hostPID:true}` | Blocked |
| `kubectl -n prod exec -it pod -- sh` | Blocked |
| `chmod 4755`, `chmod u+s`, `chmod 777`, `chown root:root` | Blocked |
| `kubectl get pods; rm -rf /`, `kubectl delete namespace prod` | Blocked |
| Arguments `sudo -i`, `su root`, `root; id`, `--as=admin` | Blocked |
| Bare-name arguments `su`, `sudo`, `doas`, `support-api` (valid Kubernetes names, cannot execute) | Allowed |
| All 9 tool command templates, read-only ones included | Allowed (no false positives) |

Tests: `test_fr4_no_tool_template_trips_guardrails`, `test_script_guardrail_allows_multiline_but_not_privilege`, plus the extended `test_output_guardrail` cases.

## 6. Minor issues — resolved

All four issues from the previous check are fixed and verified.

| Issue | Fix | Verified by |
| --- | --- | --- |
| `apply_hotfix` and `failover_cluster` missing from the live demo | INC-1008 (hotfix, approved) and INC-1009 (failover, rejected) added to `main.py` | Demo: INC-1008 VERIFIED with `apply_hotfix` ok=1; INC-1009 REJECTED with `failover_cluster` never called |
| `kubectl patch -p` given a patch id instead of JSON | `--patch-file=hotfixes/{patch}.yaml` plus `HOTFIX_CATALOG`; ids checked against a regex and the catalog | `nope`, `../../etc/passwd`, `HF-1` rejected as `invalid_arguments`; `db-pool-size` runs |
| `correlate_telemetry` template failed `check_output` | Now a `kubectl get --raw` Prometheus proxy query | All 9 rendered templates pass `check_output` |
| `su` rule blocked a resource named `su` | `check_argument` skips the word rule for valid DNS-1123 names only | `su`, `sudo`, `doas` allowed as names; `sudo -i`, `su root`, `Su` blocked; `sudo kubectl …` still blocked in `check_output` |

Still accepted for the demo, and not a gap: mocked telemetry backends and in-process MCP.

## 7. How to re-verify

Run these from `incident_platform/`:

```bash
python -m unittest discover -s tests
python main.py
```

Result on 25 September 2026: 86 tests pass (1 skipped, spaCy). The demo runs 10 incidents and ends with 6 VERIFIED, 2 ESCALATED and 2 REJECTED, all as expected; the audit chain is intact (116 entries).
