# Pilot kit - running InkBlade on a real cluster

A pilot is a **bounded, authorized, read-first** assessment. This kit is the
checklist we use to keep it legal, reproducible and measurable. Copy it into your
own change record; do not run a pilot from memory.

Scope of this document: one cluster (or one namespace set), one assessment
window, 1-2 testers, 5-10 working days.

---

## 1. Roles

| Role | Owns | Must sign |
|---|---|---|
| Sponsor (platform owner) | budget, cluster access decision | authorization |
| Assessment lead | RoE, scope, level, reporting | RoE + final report |
| Tester / operator | execution, evidence integrity | run log |
| Observer (SRE/SecOps) | blast-radius veto, incident bridge | stop conditions |
| Legal / compliance | data handling, notification duties | retention + disclosure |

Two-person rule for anything above the `probe` level: at least one person who is
not operating the tool watches the run.

---

## 2. Authorization pack (before any execution)

InkBlade refuses to run without a pinned, signed RoE: the CLI exits with code
`91`, and the API returns `423 Locked` for run/execute routes. The RoE document
carries a SHA-256 of its canonical fields plus an HMAC bound to the workspace key,
so it cannot be edited after signing without failing verification.

### 2.1 Scope worksheet

Fill this in, attach it to the change record, and keep it identical to the RoE
fields you enter in the tool.

| Field | Example | Notes |
|---|---|---|
| Cluster / context | `prod-ml-eu1` | one context per RoE; multiple contexts = multiple records |
| Namespaces | `train, infer, ray-system` | explicit list; no wildcards |
| CIDRs | `10.20.0.0/16` | egress targets for probes; loopback-only is the default |
| Level | `只读侦察` (read-only recon) | see 2.2 |
| Window | `2026-11-03T08:00Z .. 2026-11-07T18:00Z` | UTC, single contiguous window |
| Client (authorizing party) | `ACME Platform Security` | named human or team, not a ticket number |
| Exclusions | `namespace: kube-system`, `node: gpu-a100-*` | written down even when empty |
| Data handling | evidence retained 90 days, then destroyed | matches your policy |

### 2.2 Levels and what they permit

| Level | Canonical value | Permitted activity | Write risk |
|---|---|---|---|
| Read-only recon | `只读侦察` | `kubectl get`, GET fingerprints, config export | none |
| Active probing | `主动探测` | benign probes, authentication attempts with lab accounts | low |
| Exploit verification | `利用验证` | proof-of-concept execution against in-scope targets | medium |
| Full impact demo | `全影响演示` | data-plane impact, e.g. weight tampering on a canary | high |

Level is a **ceiling**: the runner refuses modules whose `min_level` is above the
pinned RoE level. Raising it mid-pilot requires a new signed RoE.

### 2.3 Signing

```bash
# interactive: scope, level, users, authorization
inkblade quickstart

# or pin explicitly (JSON fields, same keys the quickstart writes)
inkblade --home ./pilot-home roe --workspace pilot
```

The resulting `consent.json` lives in the workspace next to `evidence.db`.
Archive it with the report: it is the proof that the assessment was authorized.

---

## 3. Runbook

### P0 - preparation (day 0)

1. Written authorization + scope worksheet approved by the sponsor.
2. Dedicated workspace, not a shared one: `--home ./pilot-home`.
3. Accounts: a `lead` (approves) and a `tester` (executes). Separate humans.
4. Backup/rollback owner named, even for read-only runs.
5. Baseline snapshot of the namespaces (GitOps state or `kubectl get -o yaml` of
   the resources you will touch) stored outside the tool.

### P1 - read-only inventory (day 1)

```bash
inkblade pilot --kubeconfig ./kubeconfig.yaml \
  --out reports/pilot --format both --workspace pilot
```

`pilot` only issues `kubectl get`/`list`/`watch`. Output:
`reports/pilot/pilot-report.md` + `.json` with context/cluster identity,
namespace inventory, RBAC surface, exposure map and a prioritised shortlist.

Review gate: the observer confirms the shortlist is in scope before P2.

### P2 - surface collection (day 1-2)

```bash
inkblade collect --kubeconfig ./kubeconfig.yaml --out ./pilot-home/collect
inkblade surfaces --profile ray-vllm --collect ./pilot-home/collect --json
```

Profiles: `bare-k8s-gpu`, `ray-vllm`, `managed-ack-tke`, `slurm-hpc`,
`airgapped`, `gpu-pooling`. The profile decides which modules are *runnable*:
modules whose declared surfaces are absent are skipped, not silently "PASS"ed.

### P3 - planning and dry-run (day 2)

Plans are produced with `execute`, which never touches a target in dry-run mode:

```bash
inkblade execute --chain <chain-id> --workspace pilot --dry-run
```

Dry-run prints the exact requests/commands and the per-step precondition verdict.
Nothing is sent and no evidence step is written. The lead reviews the plan and
writes the approval in the run log.

Single modules (`inkblade run --module <key>`) have no dry-run switch by design:
read-only modules (`writes: false`) are safe to execute, and write modules are
gated at execution time by the backup/rollback requirement below.

### P4 - execution (day 2-4)

Read-only and probe modules first:

```bash
inkblade run --module <key> --params @params.json --workspace pilot --actor tester --role tester
```

A finding is only `confirmed` when the evidence graph has the supporting
artefacts (request/response, timestamps, target identity). Modules that change
state require:

* a completed RoE at `利用验证` or above,
* `--allow-write` **and** a documented rollback (`backup_targets`) - the runner
  refuses write modules without it,
* the observer watching, and
* a canary namespace whenever the customer allows one.

### P5 - reporting and handover (day 4-5)

```bash
inkblade report --run <run-name> --kind pentest --workspace pilot
inkblade report --run <run-name> --kind remediation --workspace pilot
inkblade export --run <run-name> --format sarif --workspace pilot --out ./pilot-home/export.sarif
inkblade rules generate --out ./pilot-home/rules     # detections for the blue team
```

Deliverables: pentest report (bilingual), remediation report, SARIF/OCSF/VEX
export if requested, rules pack, evidence archive with `manifest.sha256`, and the
signed `consent.json`.

---

## 4. Metrics to record

Record these per pilot; they are what makes a go/no-go decision possible. Numbers
below are observed on lab-scale clusters - treat them as shape, not targets.

| Metric | Definition | How to capture |
|---|---|---|
| Coverage | runnable modules / modules in the selected profile | `inkblade surfaces --profile <p> --json` (`coverage_pct`) |
| Executed | modules actually run, split by level | run log (`steps/` per run) |
| Verified findings | findings backed by evidence artefacts / total findings | report front matter |
| High+ findings | confirmed `high` + `critical` | `reports/*/pentest-bi.md` summary |
| False positives | findings the customer refuted / total findings | FP/FN table (section 5) |
| False negatives | known-true issues InkBlade missed | FP/FN table (section 5) |
| Time to first finding | window start → first confirmed finding | run timestamps |
| Operator effort | person-hours, split lead/tester | timesheet |
| Blast radius | resources written, incidents raised | run log + observer notes |
| Evidence completeness | steps with `manifest.sha256` + artefacts | `inkblade export` / evidence index |
| Noise | findings per hour, review hours per 10 findings | derived |

### 4.1 Worked example (lab, one ray-vllm profile)

| Metric | Value |
|---|---|
| Coverage | 70.4% of profile modules runnable |
| Executed | 41 modules (read-only + probe) |
| Verified findings | 18 / 21 (3 refuted) |
| High+ | 7 |
| False positives | 3 / 21 = 14.3% |
| False negatives | 2 known (CVE applicability gap, see 5.2) |
| Time to first finding | 11 min |
| Operator effort | 6.5 person-hours |
| Blast radius | 0 writes |
| Evidence completeness | 21/21 steps with manifests |

---

## 5. False positive / false negative labelling

Every finding gets exactly one label from a human, not from the tool. Use this
table (CSV-compatible) and attach it to the pilot report.

### 5.1 Labelling table

| Column | Allowed values | Definition |
|---|---|---|
| `finding_id` | free text | id from the report (`F-001`, or module key + index) |
| `module_key` | registry key | producing module |
| `title` | free text | finding title as reported |
| `reported_sev` | critical/high/medium/low/info | as InkBlade reported |
| `label` | TP / FP / FN / inconclusive | adjudicated outcome |
| `reason` | short text | why (e.g. "control present but not detected", "test artefact") |
| `evidence_ref` | path or step id | artefact that decided the label |
| `customer_owner` | team | who can fix it |
| `adjudicated_by` | name | human, not the tool |
| `adjudicated_at` | ISO-8601 | timestamp |

Rules:

* `FP` requires a **refutation artefact** (config dump, denied request, patched
  version) - "looks wrong" is `inconclusive`.
* `FN` is recorded against the module that *should* have caught it, so the gap
  becomes a regression test, not an anecdote.
* A finding with a missing evidence artefact is `inconclusive`, never `TP`.

### 5.2 Known FN sources at the time of writing

| Source | Effect | Mitigation |
|---|---|---|
| Static-only CVE cases | registry keeps them `static-only`; not weaponizable without a full stack | read the `static_blocker` field before reporting absence |
| Managed control planes | node/kubelet surfaces not reachable | use `managed-ack-tke` profile, report as coverage gap |
| Hardware-only modules | need BMC/switch/NVLink access | declare `hardware-only` scope explicitly |
| Quarantined modules | disabled by default, excluded from the coverage denominator | list them in the report appendix |

---

## 6. Exit criteria

The pilot ends when **all** of these are true:

1. Every module in the approved profile is either executed, skipped with a
   recorded reason (surface absent), or explicitly excluded by the customer.
2. Every finding carries an evidence reference and a human label.
3. The report, remediation list, rules pack and evidence archive are delivered
   and acknowledged.
4. Rollback is confirmed (for any write activity: state restored, no leftovers).
5. Data handling obligations are executed (retention or destruction).
6. A retrospective is written: what worked, what produced noise, what to fund.

### Go/no-go for production adoption

| Criterion | Threshold |
|---|---|
| High+ verified findings in the pilot | any count is fine; the question is whether they were actionable |
| False positives | <= 20%, all with refutation artefacts |
| Evidence completeness | 100% of confirmed findings |
| Incidents caused | 0 |
| Operator effort per finding | <= 1 person-hour per confirmed high+ |
| Coverage of the customer's critical surfaces | >= 60%, or gaps accepted in writing |

If any row fails, the outcome is "pilot again with scoped changes", not "adopt".

---

## 7. Stop conditions (observer can halt immediately)

* A write lands outside the declared namespaces/CIDRs.
* A finding suggests the tool reached data it should not have (model weights,
  customer PII, secrets) - stop, preserve evidence, notify.
* Control-plane or GPU-operator health degrades during a run.
* The RoE window expires while a run is active (the runner refuses new steps;
  finish the current step and export).
* Any participant is unsure whether the activity is authorized. Stop first.

Incident path: observer → sponsor → (if data exposure) legal/DPO. Preserve
`evidence.db` and `steps/` before any cleanup.

---

## 8. Offboarding

1. Archive the evidence bundle (`inkblade export`), record its SHA-256 in the
   handover ticket.
2. Destroy the workspace copy after the retention period stated in the RoE.
3. Rotate any credentials used during the pilot (lab accounts, service tokens).
4. Remove the tool's ServiceAccount/RBAC and the Helm release.
5. Confirm deletion in writing; attach the confirmation to the report.

---

## 9. Command cheat sheet

```bash
inkblade trial                                  # 5-minute offline check
inkblade doctor --mode cluster --kubeconfig K   # environment + cluster readiness
inkblade pilot --kubeconfig K --out reports/pilot
inkblade collect --kubeconfig K --out ./collect
inkblade surfaces --profile ray-vllm --collect ./collect --json
inkblade execute --chain C --workspace pilot --dry-run
inkblade run --module M --params @p.json --actor tester --role tester
inkblade report --run R --kind pentest --workspace pilot
inkblade export --run R --format sarif --workspace pilot --out export.sarif
inkblade rules generate --out ./rules
```

Full CLI reference: `inkblade --help` and `inkblade <cmd> --help`.
