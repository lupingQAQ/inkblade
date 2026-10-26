# Trial guide - 5 minutes, no cluster

This is the shortest path from "cloned the repo" to "I have seen InkBlade work
and I know what it produced". Everything here runs offline: a synthetic mock
lab bound to loopback, no kubeconfig, no LLM key, no network egress.

If you only have Docker, jump to [Container trial](#container-trial).

---

## 0. Prerequisites

| Requirement | Notes |
|---|---|
| Python 3.10 - 3.13 | `python --version`; on Windows `py -3.12` is fine |
| ~200 MB free disk | demo workspace + reports + vendored UI |
| No cluster | the demo refuses to contact anything outside 127.0.0.1 |

```bash
git clone https://github.com/inkblade/inkblade.git
cd inkblade
python -m pip install -e .
```

Verify the console script resolves:

```bash
inkblade --help
```

If `inkblade` is not on `PATH`, every command below also works as
`python -m inkblade ...`.

---

## 1. One command: `inkblade trial`

```bash
inkblade trial
```

It runs the offline demo, then prints a card like this (timings from a Windows 11
/ Python 3.12 laptop; the demo is CPU-bound, expect 5-10 s):

```text
InkBlade trial (offline demo)
==============================================================
version   : 0.2.0  python 3.12.15  Windows-11-10.0.26300-SP0
mode      : offline-demo
chain     : flat-network-admin-plane-weight-poison (1.2s)
findings  : 10 total {'high': 8, 'medium': 2}
elapsed   : 7.3s (mock lab on 127.0.0.1)

Artifacts
  [ok     ] pentest report       <out>/reports/pentest-bi.md
  [ok     ] remediation report   <out>/reports/remediation-bi.md
  [ok     ] demo summary         <out>/reports/summary.json
  [ok     ] rules pack           <out>/rules-pack
  [ok     ] static UI            <out>/webui/index.html
  [ok     ] evidence workspace   <out>/workspace
  [ok     ] trial report         <out>/reports/trial-report.json
```

Where `<out>` defaults to `./demo-trial`. Options:

| Flag | Effect |
|---|---|
| `--out DIR` | output directory (default `./demo-trial`) |
| `--no-demo` | environment check only; artifacts are listed as `plan` |
| `--kubeconfig PATH` | adds the read-only pilot step to "next steps" (does not connect) |
| `--json` | machine-readable trial report on stdout |

### Expected artifacts

| Path | What "good" looks like |
|---|---|
| `reports/pentest-bi.md` | bilingual report: executive summary, chain narrative, findings with severity, evidence references |
| `reports/remediation-bi.md` | per-finding remediation with owner/priority |
| `reports/summary.json` | machine summary: chain id, step statuses, severity histogram |
| `reports/trial-report.json` | this run's trial card as JSON (`schema: inkblade-trial/1`) |
| `rules-pack/` | converted detections (Kyverno / Gatekeeper / Sigma / Falco families) plus an index |
| `webui/index.html` | self-contained static UI (no external CDN) |
| `workspace/` | evidence store: `evidence.db`, `consent.json`, per-run `steps/` with `manifest.sha256` |

The demo is deterministic: same chain, same 10 findings. If the count or the
chain differs, you are not running the code in this repository - stop and
report it (see [FEEDBACK.md](FEEDBACK.md)).

---

## 2. Self-check: `inkblade doctor`

```bash
inkblade doctor --mode mock --json
```

The contract is: **no `FAIL` item** (exit code `0`). `WARN` is normal in mock
mode because the environment legitimately lacks cluster pieces:

| Item | Mock-mode result | Why |
|---|---|---|
| `python` | PASS | 3.10+ required |
| `write` / `disk` / `port` / `clock` | PASS | workspace writability, free space, port, clock skew |
| `mock` | PASS | mock lab imports and the module registry loads (275 modules) |
| `bash` | PASS (Windows: optional) | `bash` present or not, mock mode does not need it |
| `entry` | WARN | console script not on `PATH` (use `python -m inkblade`) |
| `kubeconfig` / `kubectl` | WARN | no cluster in the 5-minute trial |
| `consent` | WARN | no RoE signed yet - the demo signs its own scope |
| `optional` | WARN | optional extras (`zstandard`, `cryptography`) absent |

Typical failure and fix:

| Symptom | Fix |
|---|---|
| `port ... in use` | `inkblade doctor --port 8899` |
| module registry empty | run from the repository root, or reinstall with `pip install -e .` |
| console encoding errors on Windows | `set PYTHONIOENCODING=utf-8` |

---

## 3. Guided setup: `inkblade quickstart`

```bash
inkblade quickstart --yes
```

Five questions (scope/level/users/authorization) with defaults, then it writes a
workspace under `./inkblade-workspace` and prints the exact dry-run command to
execute next. Nothing is executed against a cluster: `--yes` uses the synthetic
defaults.

Then run the dry-run it printed:

```bash
python -m inkblade --home ./inkblade-workspace execute \
  --workspace local-lab \
  --chain flat-network-admin-plane-weight-poison --dry-run
```

A dry-run must print the plan and write no evidence steps.

---

## 4. Look at the UI

Open the static export (no server):

```text
demo-trial/webui/index.html
```

Or start the local console (read-only until a RoE is signed):

```bash
inkblade --home ./demo-trial/workspace ui --port 8765
# http://127.0.0.1:8765
```

Demo credentials are printed by the demo and are fixed for reproducibility:
`demo-lead` (lead role) and `demo-tester` (tester role), password `demo-pass`.
**They exist only inside the demo workspace** and are never valid anywhere else.

---

## Container trial

```bash
docker build -t inkblade:trial .
docker run --rm -v inkblade-data:/data inkblade:trial trial --out /data/trial
docker run --rm --entrypoint id inkblade:trial -u     # 10001, not root
```

Mounting `/data` keeps the evidence; without it the container is ephemeral by
design. The image runs as uid 10001 with a read-only root filesystem in
Kubernetes (see `deploy/helm/inkblade`).

---

## Kubernetes trial (optional)

Only for a cluster you own and may assess:

```bash
helm install inkblade deploy/helm/inkblade -n inkblade --create-namespace
kubectl -n inkblade rollout status deploy/inkblade-inkblade
kubectl -n inkblade port-forward svc/inkblade-inkblade 8765:80
```

`helm install` prints the account bootstrap, the RoE gate and the teardown
steps. Defaults are read-only: the ServiceAccount receives `get/list/watch`
only, write verbs need both `readOnly=false` and `rbac.allowWrite=true`, and a
signed RoE is still required per workspace.

---

## What this trial does not prove

Be precise when you report results internally:

* The mock lab is synthetic. Findings demonstrate pipeline behaviour, not a real
  cluster's exposure.
* No real credentials, no real CVE exploitation, no network egress.
* Performance numbers are laptop-scale; a pilot on a real cluster produces
  different timings (see `docs/PILOT-KIT.md` for the metrics we ask you to
  record).
* Coverage numbers in reports are computed against the module registry; they are
  not a proof of detection quality. False-positive/false-negative labelling is a
  pilot activity.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `DemoRefused: output dir ... not empty` | `demo`/`trial` refuses to write into a non-demo directory | use a new `--out DIR` |
| `ModuleNotFoundError: inkblade` | running from another directory without install | `pip install -e .` or run from the repo root |
| `inkblade` not found | script not on `PATH` (user-level scripts dir) | `python -m inkblade ...` |
| UI port already used | previous run still bound | `--port 8899` |
| Reports show `?` for CJK text | console codepage | `chcp 65001` / `set PYTHONIOENCODING=utf-8` |

---

## Next steps

1. Read the pilot kit: [PILOT-KIT.md](PILOT-KIT.md) - RoE, scope, metrics,
   FP/FN labelling, exit criteria.
2. Write a plugin: [PLUGIN-SDK.md](PLUGIN-SDK.md) - `inkblade sdk new`.
3. Review the security posture: [AUDIT-PACKAGE.md](AUDIT-PACKAGE.md).
4. Tell us what broke: [FEEDBACK.md](FEEDBACK.md).
