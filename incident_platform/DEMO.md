# Demo Script

A walkthrough that checks or presents every capability in about 10 minutes.
Run everything in **one PowerShell terminal**, from the `incident_platform` folder.

## 0. Setup

Python isn't on PATH on this machine (the Microsoft Store alias shadows it), so store its location in `$py`:

```powershell
cd C:\Users\Administrator\Desktop\capstone_project_v2\incident_platform; $py = "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe"
```

---

## A. Dashboard walkthrough (recommended for presenting)

**Restart helper.** `.\restart-dashboard.cmd` (in `incident_platform`) stops any running dashboard and
starts a fresh one with the right Python. Add `gpt` or `mock` to flip the `.env` switch first, e.g.
`.\restart-dashboard.cmd gpt`. Options: `-Port 8001`, `-Pii heuristic`, `-NoBrowser`, and `-NoRestart`
(flip the switch only).

```powershell
& $py ui_server.py
```

This opens http://127.0.0.1:8000 in your browser. Stop it with Ctrl+C in the terminal.

**You control the pace.** With *Pacing: Step-through* (the default), **↻ Start 10 scenarios** runs only
INC-1001, and the rest wait as QUEUED. When you've finished explaining an incident, click
**Next: INC-100x ▶** to run the next one. **Run the rest ⏩** runs everything left without stopping.
*Auto* mode runs all 10 back to back, as before.

**Narrate one incident at a time.** The detail panel has three tabs:
- **Summary**: the incident's details, as before.
- **Steps**: a live feed of just that incident, grouped by phase (Intake → Triage → Planning → Approval → Execution → Verification → Outcome), with timings. Every tool call, LLM call, cache hit, guardrail block and breaker change is shown.
- **Trace**: the OpenTelemetry-style span waterfall. While an incident waits for you, `hitl.approval` is shown running and growing. Afterwards the caption names the longest step, which is usually the human wait.

**Approvals never interrupt you.** The approval card opens only for the incident you're viewing. If
another incident is waiting (for example after *Run the rest*), a pulsing header badge says
"⏸ INC-1002 awaiting approval: view"; click it when you're ready. On the card,
**Review details first** (or Esc) closes it and the incident stays paused. The amber bar in its detail
panel reopens the card.

1. **Start the 10 scenarios** with the default knobs (threshold 0.75, `fetch_k8s_logs` × 5, pace 0.8 s).
   INC-1001 animates through the state machine. Click any card to see its details on the right.
   Click **Next** after each step below.
2. **INC-1001 and INC-1004.** INC-1001 runs straight through (badge: *autonomous*). INC-1004 shows
   *cache L2* and *plan cache L1*. The detail panel says "semantic cache L2 (similarity 0.979), 0 tokens",
   and the command still targets `payments-eu`.
3. **INC-1002 pauses.** The Slack-style card appears: *Why approval is required: destructive action*,
   plus the blast radius and the command. Click **Approve**, and it resumes and verifies.
   Its PII section shows the IP caught by `regex`. With spaCy on, it also shows *Bartholomew Quigley*
   caught by `spacy-ner`; with spaCy off, that name is not redacted, which is the argument for the NER layer.
4. **INC-1003 pauses for two reasons:** its scale-out is risk class **config_patch** (it changes the
   deployment's desired state, so it's always gated), *and* its confidence 0.62 is below 0.75. In the
   detail panel the confidence bar sits left of the threshold marker, and the plan shows a
   `kubernetes-yaml` recovery draft next to the kubectl command. **Approve**.
5. **INC-1005.** The red *input guardrail* badge appears, and the detail panel reads "Nothing was sent
   to the LLM". PII is redacted.
6. **INC-1006 pauses:** drain the node? Click **Reject**. The incident ends REJECTED, and
   `drain_node` shows 0 successful calls in the tools tile.
7. **INC-1007 runs without asking.** `clear_pod_cache` is risk class **safe_reset** (it resets runtime
   state, not desired state), so no approval card appears. Verification confirms it's healthy.
8. **INC-1008 pauses for a config patch.** A bad config push starved the DB pool; the plan is
   `apply_hotfix` with the vetted catalog patch `db-pool-size`. The approval card shows the
   `--patch-file=hotfixes/db-pool-size.yaml` command and the patch YAML itself. **Approve**, and it's VERIFIED.
9. **INC-1009 pauses for a failover.** A region outage plans `failover_cluster`, and the card shows
   the Terraform draft. **Reject**: it ends REJECTED, and `failover_cluster` has 0 calls in the tools tile.
10. **INC-1010.** In its **Steps** tab: a failure, "Retrying … after 0.1x s backoff", a second
   failure and retry (longer cap), the third failure, "Circuit breaker … CLOSED → OPEN for 30 s", then
   an instant `circuit_open` rejection with no more waiting. Its **Trace** tab shows the `retry.backoff`
   spans. The tools tile shows `fetch_k8s_logs` with 3 failures and the **OPEN** breaker
   badge, and the incident is escalated for incomplete evidence. It runs last on purpose: the breaker
   stays OPEN for its 30 s recovery window.
11. **Bottom panels.**
   - The four metric tiles: cache hit ratio **11.8%**, tool failure rate **8.8%**.
   - The audit chain reads **chain intact ✓**.
   - Click **Tamper with a copy**: the result is "broken at entry N", while the real chain is still intact.
12. **Knobs.** Set the threshold to **0.60** and the failure count to **2**, then run again.
   INC-1003 still asks for approval, but now *only* because of its risk class (the low-confidence reason
   is gone). INC-1010 recovers through retries, and its scale-out then needs approval too.
13. **+ Custom incident.** Pick a preset:
    - *PII-heavy ticket*: the detail panel's **PII redaction** section shows exactly what the model
      receives. Names, phone, email, IPv6 and the bearer token are all `[REDACTED_…]`, and the audit
      feed shows the title as "reported by [REDACTED_PERSON]". The *Detected by* table shows which
      layer caught each item. With spaCy on, "Bartholomew Quigley" is credited to `spacy-ner`,
      because no cue word or known first name precedes it.
      From a terminal: `& $py -m guardrails "noticed by Bartholomew Quigley, cc Wei Zhang"`
      (add `--ner spacy` and use `.venv-ner\Scripts\python.exe` to include spaCy).
    - *Known defect: vetted hotfix*: plans `apply_hotfix` (config_patch). The approval card shows the
      risk class and a `kubernetes-yaml` strategic-patch draft.
    - *Region outage*: plans `failover_cluster` (risk class failover). The approval card shows a
      `terraform-hcl` Route53 failover draft.
    - *Prompt injection in a ticket*: ESCALATED by the input guardrail.
    - *Shell injection in the namespace field*: the tool server's argument guardrail blocks every
      tool call, so the incident is ESCALATED.
    - *Verification catches a fix that didn't work*: approve the rollback, and post-remediation
      verification marks it **FAILED**, because the mock cluster only heals with a restart.

    Note: for about 30 s after a run, the `fetch_k8s_logs` breaker is still OPEN (its recovery window).
    A custom incident submitted then is escalated for that reason. Wait until the tools tile no longer
    shows OPEN; it passes through HALF_OPEN to CLOSED.

---

## 1. Main demo: all 10 incidents (console)

```powershell
& $py main.py
```

What to look for in each incident:

| Incident | Look for |
|---|---|
| INC-1001 | `restart_service [risk: safe_reset]`: state path goes straight to `EXECUTING -> VERIFIED`. No human was involved. |
| INC-1002 | `PAUSED -> AWAITING_APPROVAL`, then the Slack-style approval payload with blast radius and **Why approval is required: destructive action**. Also `PII: 1 IP` redacted. |
| INC-1003 | Paused for **config patch** *and* **confidence 0.62 < 0.75**. The payload shows `Risk class: config_patch` and the start of the YAML draft. Triage used `gpt-4o-mini`, the cheaper tier for P2. |
| INC-1004 | `cache L2 hit, similarity 0.979, 0 tokens`, then `plan ... (cache L1)`. The command still targets `payments-eu`, because only the reasoning is cached, not the target. |
| INC-1005 | `guardrail (input) blocked: instruction override`, plus an email and an IP redacted. The injected `kubectl delete ns production` never reaches the LLM. |
| INC-1006 | The SRE rejects the drain. The path ends at `REJECTED` and nothing executes. |
| INC-1007 | `clear_pod_cache [risk: safe_reset]`, no approval, VERIFIED. |
| INC-1008 | `apply_hotfix [risk: config_patch, destructiveHint]`, payload shows the catalog patch; APPROVED → VERIFIED. |
| INC-1009 | `failover_cluster [risk: failover, destructiveHint]`; REJECTED, and the failover never runs. |
| INC-1010 | `breakers={'fetch_k8s_logs': 'OPEN'...}`, then escalated: `incomplete evidence`. |

At the end, check the **Run summary**:
- 10 × `[ok]`
- the four metrics: cache hit ratio `2/17`, tool failure rate `8.8%`
- the cost per model
- `chain intact: True`

The process exits with code 0 only if every incident reaches its expected state.

## 2. Tests

```powershell
& $py -m unittest discover -s tests -v
```

Expected: `Ran 86 tests ... OK` (a few spaCy-only tests are skipped without spaCy). One `[llm] primary backend failed` line is normal; it comes from the fallback test.

## 3. Tamper with the audit log

This edits line 5 of a **copy** of the log (run step 1 first so `audit_log.jsonl` exists):

```powershell
Copy-Item audit_log.jsonl tampered.jsonl; & $py -c "import json;p='tampered.jsonl';L=open(p).read().splitlines();e=json.loads(L[4]);e['actor']='attacker';L[4]=json.dumps(e);open(p,'w').write('\n'.join(L)+'\n')"
```

Then verify both files:

```powershell
& $py -c "from observability import AuditLog as A; print('original:', A.load('audit_log.jsonl').verify_chain()); t=A.load('tampered.jsonl'); print('tampered:', t.verify_chain(), '-> first broken entry', t.first_broken_seq())"
```

Expected: `original: True`, then `tampered: False -> first broken entry 4`.

Clean up afterwards:

```powershell
Remove-Item tampered.jsonl
```

## 4. Change the HITL threshold

This lowers the autonomy threshold to 0.6 for one run. INC-1003 is no longer low-confidence, but its
scale-out is still gated by its risk class:

```powershell
& $py -c "import config,main; config.SETTINGS.MIN_AUTONOMOUS_CONFIDENCE=0.6; p,r=main.run_demo(audit_path=None,verbose=False); i=r[2][0].incident; print(i.incident_id, r[2][1].value, '| approval reasons:', i.notes['approval']['reasons'])"
```

Expected: `INC-1003 VERIFIED | approval reasons: ['config_patch']` (at 0.75 it is
`['config_patch', 'low_confidence']`).

## 5. Trip the circuit breaker differently

This runs with only 2 injected failures, which the read-tool retries absorb, so the breaker stays closed:

```powershell
& $py -c "import main; o=main.build_scenarios; main.build_scenarios=lambda: [s if s.incident.incident_id!='INC-1010' else (setattr(s,'fail_injection',{'fetch_k8s_logs':2}) or s) for s in o()]; p,r=main.run_demo(audit_path=None,verbose=False); print('INC-1010 ->', r[9][1].value, '| breakers:', p.breakers.snapshot()['fetch_k8s_logs'])"
```

Expected: `INC-1010 -> VERIFIED | breakers: CLOSED` (its scale-out goes to the scripted approval),
compared with ESCALATED/OPEN when there are 5 failures.

## 6. Approve or reject it yourself

This runs INC-1002 (the destructive rollback) and waits for your y/n:

```powershell
& $py -c "from hitl import ConsoleApprovalChannel; from orchestrator import *; from main import build_scenarios; p=IncidentPlatform(audit_path=None); o=IncidentOrchestrator(p, ConsoleApprovalChannel()); s=build_scenarios()[1]; t=s.incident.target; p.cluster.register_fault(t['service'],t['workload'],s.logs,s.signals,s.fixed_by); print(o.handle(s.incident))"
```

Type `y` to get `VERIFIED`, or `n` to get `REJECTED`. EOF or Ctrl-C also counts as a rejection.

## 7. Financial model

```powershell
& $py finance/tco_roi_calculator.py
```

Expected: 3-year TCO **$546,556**, ROI **161%**, payback in **month 7**. The full workbook with the sensitivity and NFR tables is in `docs/financial_nfr_workbook.md`.

## 8. Diagrams and docs

- Open https://excalidraw.com, choose menu → **Open**, and load `docs/diagrams/system_architecture.excalidraw`, then `agent_workflow_sequence.excalidraw`. The dashed red box marks the HITL approval boundary.
- To walk through the reasoning, use `docs/adr/ADR-01...03` and `docs/architecture_overview.md`.

## 9. Optional: real OpenAI calls

**With the `.env` file (recommended):** open `incident_platform\.env` (`notepad .env`), set
`INCIDENT_PLATFORM_USE_REAL_LLM=true` and `OPENAI_API_KEY=sk-...`, save, then run
`.\.venv-ner\Scripts\python.exe main.py` (that venv has the `openai` package). Set the switch back to
`false` to return to the mock. The run's second line confirms it: `config: loaded .env …; real LLM ON; OpenAI key set`.

**Or with terminal variables:**

This needs `pip install openai` and a key:

```powershell
$env:INCIDENT_PLATFORM_USE_REAL_LLM="true"; $env:OPENAI_API_KEY="sk-..."; & $py main.py
```

The header should show `LLM backend: openai->mock`. With a bad key, a warning prints and the run falls back to the mock without crashing.
Replies from a real model vary, so the final states may differ from the table in step 1.

To go back to the mock:

```powershell
Remove-Item Env:INCIDENT_PLATFORM_USE_REAL_LLM, Env:OPENAI_API_KEY
```
