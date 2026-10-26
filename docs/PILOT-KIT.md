# Pilot kit - running InkBlade on a real cluster

A pilot is bounded, authorized and read-first. Scope: one cluster (or one namespace set), one
window, 1–2 testers, 5–10 working days. Copy this into your change record; do not run from memory.

## 1. Roles

| Role | Owns | Signs |
|---|---|---|
| Sponsor (platform owner) | budget, cluster access decision | authorization |
| Assessment lead | RoE, scope, level, reporting | RoE + final report |
| Tester / operator | execution, evidence integrity | run log |
| Observer (SRE/SecOps) | blast-radius veto, incident bridge | stop conditions |
| Legal / compliance | data handling, notification duties | retention + publication |

Two-person rule above `probe`: someone who is not driving watches the run.

## 2. Authorization pack

Without a pinned, signed RoE the CLI exits `91` and the API returns `423 Locked`. The RoE carries
a SHA-256 of its canonical fields plus an HMAC bound to the workspace key.

### 2.1 Scope worksheet

| Field | Example | Notes |
|---|---|---|
| Cluster / context | `prod-ml-eu1` | one context per RoE |
| Namespaces | `train, infer, ray-system` | explicit list, no wildcards |
| CIDRs | `10.20.0.0/16` | egress targets; loopback-only by default |
| Level | `只读侦察` | see 2.2 |
| Window | `2026-11-03T08:00Z .. 2026-11-07T18:00Z` | UTC, contiguous |
| Client | `ACME Platform Security` | named team, not a ticket number |
| Exclusions | `namespace: kube-system` | written down even when empty |
| Data handling | 90-day retention, then destroy | matches your policy |

### 2.2 Levels

| Level | Canonical value | Permitted activity | Write risk |
|---|---|---|---|
| Read-only recon | `只读侦察` | `kubectl get`, GET fingerprints, config export | none |
| Active probing | `主动探测` | benign probes, auth attempts with test accounts | low |
| Exploit verification | `利用验证` | PoC execution against in-scope targets | medium |
| Full impact demo | `全影响演示` | data-plane impact, e.g. canary weight tampering | high |

Level is a ceiling: modules with a higher `min_level` refuse to run, and raising it needs a new
signed RoE.

### 2.3 Signing

```bash
inkblade quickstart                       # interactive: scope, level, users, signature
inkblade --home ./pilot-home roe --workspace pilot
```

`consent.json` lands next to `evidence.db`. Archive it with the report.

## 3. Runbook

| Step | Day | Commands | Gate |
|---|---|---|---|
| P0 prep | 0 | `--home ./pilot-home`, accounts, baseline snapshot outside the tool | sponsor approved 2.1 |
| P1 inventory | 1 | `pilot --kubeconfig K --out reports/pilot --format both --workspace pilot` | observer confirms scope |
| P2 surfaces | 1–2 | `collect --kubeconfig K --out ./pilot-home/collect` then `surfaces --profile P --collect ./pilot-home/collect --json` | profile chosen, gaps recorded |
| P3 planning | 2 | `execute --chain C --workspace pilot --dry-run` | lead writes approval in the run log |
| P4 execution | 2–4 | `run --module M --params @p.json --actor tester --role tester` | writes need RoE `利用验证`, `--allow-write`, rollback |
| P5 handover | 4–5 | `report`, `export --format sarif`, `rules generate` | deliverables acknowledged |

```bash
# P5, in full
inkblade report --run R --kind pentest --workspace pilot
inkblade report --run R --kind remediation --workspace pilot
inkblade export --run R --format sarif --workspace pilot --out ./pilot-home/export.sarif
inkblade rules generate --out ./pilot-home/rules
```

Profiles: `bare-k8s-gpu`, `ray-vllm`, `managed-ack-tke`, `slurm-hpc`, `airgapped`, `gpu-pooling`.
Absent surfaces are skipped, never marked PASS. `run --module` has no dry-run switch; writes are
gated at execution.

## 4. Metrics

| Metric | Definition | Capture |
|---|---|---|
| Coverage | runnable / profile modules | `surfaces --json` (`coverage_pct`) |
| Executed | modules run, by level | `steps/` |
| Verified findings | evidenced / total | report front matter |
| High+ | confirmed high + critical | `pentest-bi.md` |
| False positives | refuted / total | section 5 |
| False negatives | known-true issues missed | section 5 |
| Time to first finding | window start → first confirmed | run timestamps |
| Operator effort | person-hours by role | timesheet |
| Blast radius | resources written, incidents | run log + observer notes |
| Evidence completeness | steps with manifest + artefacts | `export` |
| Noise | findings/hour, review hours per 10 | derived |

### 4.1 Worked example

| Metric | Value |
|---|---|
| Coverage | 70.4% |
| Executed | 41 modules (read-only + probe) |
| Verified findings | 18 / 21 |
| High+ | 7 |
| False positives | 3 / 21 = 14.3% |
| Time to first finding | 11 min |
| Operator effort | 6.5 person-hours |
| Blast radius | 0 writes |
| Evidence completeness | 21 / 21 |

## 5. Labelling

| Column | Values | Definition |
|---|---|---|
| `finding_id` | free text | `F-001` or module key + index |
| `module_key` | registry key | producing module |
| `reported_sev` | critical/high/medium/low/info | as reported |
| `label` | TP / FP / FN / inconclusive | human adjudication |
| `reason` | short text | why |
| `evidence_ref` | path or step id | artefact that decided it |
| `customer_owner` | team | who can fix it |
| `adjudicated_by` / `_at` | name / ISO-8601 | human, timestamp |

`FP` needs a refutation artefact; a missing artefact is `inconclusive`, never `TP`. `FN` is
recorded against the module that should have caught it, so the gap becomes a regression test.

### 5.1 Known FN sources

| Source | Effect | Mitigation |
|---|---|---|
| Static-only CVE cases | not weaponisable without a full stack | read `static_blocker` before reporting absence |
| Managed control planes | node/kubelet surfaces unreachable | `managed-ack-tke` profile, report as gap |
| Hardware-only modules | need BMC/switch/NVLink | declare `hardware-only` scope |
| Quarantined modules | excluded from the denominator | list them in the appendix |

## 6. Exit criteria

| # | Criterion |
|---|---|
| 1 | every approved module executed, skipped with a recorded reason, or excluded by the customer |
| 2 | every finding has an evidence reference and a human label |
| 3 | report, remediation list, rules pack and archive delivered and acknowledged |
| 4 | rollback confirmed for any write activity |
| 5 | data handling executed (retention or destruction) |
| 6 | retrospective written |

### 6.1 Go / no-go

| Criterion | Threshold |
|---|---|
| False positives | ≤ 20%, all with refutation artefacts |
| Evidence completeness | 100% of confirmed findings |
| Incidents caused | 0 |
| Operator effort | ≤ 1 person-hour per confirmed high+ |
| Critical-surface coverage | ≥ 60%, or gaps accepted in writing |

Any failed row means "pilot again with scoped changes", not "adopt".

## 7. Stop conditions

| Trigger | Action |
|---|---|
| A write lands outside declared namespaces/CIDRs | stop, preserve evidence, notify |
| A finding suggests data outside scope (weights, PII, secrets) | stop, preserve, notify |
| Control-plane or GPU-operator health degrades | stop |
| RoE window expires mid-run | finish the current step, export, re-sign |
| Anyone is unsure the activity is authorized | stop |

Incident path: observer → sponsor → legal/DPO. Preserve `evidence.db` and `steps/` before cleanup.

## 8. Offboarding

| # | Step |
|---|---|
| 1 | `export` the evidence bundle, record its SHA-256 in the handover ticket |
| 2 | destroy the workspace copy after the RoE retention period |
| 3 | rotate credentials used during the pilot |
| 4 | remove the ServiceAccount/RBAC and the Helm release |
| 5 | confirm deletion in writing, attach it to the report |

## 9. Cheat sheet

```bash
inkblade pilot --dry-run                         # offline rehearsal, no cluster contact
inkblade doctor --mode cluster --kubeconfig K    # environment + cluster readiness
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
