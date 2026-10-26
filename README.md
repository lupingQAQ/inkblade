# InkBlade (墨刃零)

**Training & Inference Cluster Penetration Testing Platform**

`v0.2.0 preview` · Apache-2.0 · Python 3.10 – 3.13 · no runtime dependencies · offline by default

> Authorized use only. Consent pinning, technical-level gates, a mandatory backup gate for write
> modules, and per-action auditing are enforced in code. Without a signed record, the CLI and the
> HTTP API both refuse to execute. There is no override flag.

Preview note. The scan, evidence and report paths are usable for pilots. The in-pod collector is
mid-migration to the static Rust probe; the Python snapshot parser in `core/inpod.py` stays the
reference until that migration closes.

## Why it exists

We wrote InkBlade after a run of the same conversation. A dashboard was "only on the VPN". It was
not. It sat on a NodePort with no auth, and the proxy that used to front it had been deleted two
releases before. The runbook still had the old diagram.

The clusters we test are rarely broken in one place. They are assembled: managed control plane
here, GPU operator there, an inference gateway pointed at the shared storage, a training job that
loads whatever checkpoint it is given. Each decision was reasonable at the time. The path between
them was never reviewed by anyone.

InkBlade inventories, quietly. It will not run a module without a signed scope. It records every
step with a hash and an archive, which is what makes a finding survive review.

## What you get

| Layer | What it does |
|---|---|
| Consent | Signed records, four cumulative technical levels, four roles, no override |
| Orchestration | Ordered chains, dry-run plan, dependency topology, backup gate, rollback |
| Modules | 286 manifests in 8 families; 275 enabled, 11 quarantined for missing surfaces |
| Evidence | Context journal, SQLite audit tables, per-step archive with a SHA-256 manifest |
| Reporting | PTES narrative and remediation checklist, bilingual, CVSS 3.1, NIST / GB-T 20984 |
| Console | Six-view local SPA; static export opens from the filesystem |
| Defence | Admission, network, detection and convergence packs, replayed per chain |
| Probe | Static Rust collector for in-pod facts: caps, seccomp, mounts, GPU/RDMA, token presence |

## Start

```bash
python -m inkblade doctor            # interpreter, write access, port, optional deps
python -m inkblade pilot --dry-run   # offline rehearsal: empty profile + plan, no cluster contact
python -m inkblade ui                # local console on 127.0.0.1:8765
python -m inkblade exploit --list    # weapon packs with their deployment requirement
```

`pilot --dry-run` writes a profile, a plan and an approval list. It opens no connections. When you
have a cluster you may read:

```bash
python -m inkblade pilot --kubeconfig ~/.kube/config --out reports/pilot
python -m inkblade run --module <key> --params '{"target": "..."}'   # needs a signed scope
```

Container path, if you prefer it:

```bash
docker build -t inkblade:0.2.0 .
docker run --rm -v inkblade-data:/data inkblade:0.2.0 doctor
helm install inkblade deploy/helm/inkblade --namespace inkblade --create-namespace
```

## Command map

| Task | Command |
|---|---|
| Environment check | `inkblade doctor` |
| Offline rehearsal | `inkblade pilot --dry-run` |
| Signed scope wizard | `inkblade quickstart` |
| Accounts and roles | `inkblade user add <name> <password> <role>` |
| Module inventory | `inkblade module list` |
| Read-only cluster inventory | `inkblade pilot --kubeconfig <path>` |
| Collection / discovery | `inkblade collect` · `inkblade discover` |
| Single module | `inkblade run --module <key>` |
| Chain (plan / run) | `inkblade execute --chain <id> --dry-run` · `execute --chain <id>` |
| Weapon packs | `inkblade exploit --list` · `exploit <id> --real --backup-target <dir>` |
| Undo | `inkblade rollback --run <id> --step <n>` · `inkblade abort` |
| Reports and exports | `inkblade report --run <id> --lang bi` · `export --format sarif` |
| Defence rules | `inkblade rules generate` · `rules validate` |
| Retest / CI | `inkblade schedule run-due` · `ci-gate --fail-on high --new-only` |
| In-pod probe | `inkblade-probe --emit probes` (see `probe/`) |
| Embedding | `inkblade mcp` · `inkblade sdk list` |
| Optional model | `inkblade llm-pool status` · `llm-pool add` (off by default) |
| Bounded autonomy | `inkblade autonomy grant` · `explore autonomy --autonomy L3` |

## Vulnerability coverage

41 verified primitives across 24 components. A row enters the table after dynamic reproduction on a
pinned upstream version and a novelty check that found no matching public advisory.

The table lists component, class, affected versions and verification shape. No reproduction steps,
no payloads, no target list.

Read the coverage table in [`VULNERABILITY-COVERAGE.md`](docs/VULNERABILITY-COVERAGE.md).

## Documentation

| Document | What is in it |
|---|---|
| [Usage guide](docs/USAGE.md) | Command guide, workspace layout, troubleshooting |
| [Install guide](docs/INSTALL.md) | Wheel, checkout, container, Helm, air-gapped |
| [Features](docs/FEATURES.md) | Capability inventory with verified / simulated / gap states |
| [Workflow](docs/WORKFLOW.md) | The eleven stages, gate by gate |
| [Modules](docs/MODULES.md) | Module families, levels, chains, manifest contract |
| [Architecture](docs/ARCHITECTURE.md) | Ten coverage layers, seven runtime layers, component probe |
| [Agent & LLM](docs/AGENT-LLM.md) | Optional model pool, L3 preconditions, data boundary |
| [FAQ](docs/FAQ.md) | Short answers, including the uncomfortable ones |
| [Versioning](docs/VERSIONING.md) | Pre-1.0 versioning policy |
| [Security policy](SECURITY.md) | Vulnerability reporting and support window |

The site is generated from these files and published from `docs/`
([site notes](docs/README-SITE.md)).

## Limits

- Coverage is uneven: 60–71% on Kubernetes profiles, 25% on Slurm. Missing modules are listed.
- Verification is partial: 37 of 152 catalogue entries. The rest are hypotheses with a blocker.
- A coverage row is a lead. It was reproduced on one commit and one config.
- Autonomy is bounded. The default is propose-and-wait; L3 needs a lead grant with a TTL, an
  allowlist and budget caps.
- Pre-1.0. Pin a version for a regulated pilot.

It is not a SaaS. It is not an agent with standing write access. It does not scan without
configuration.

## AI-assisted writing

Parts of this README and the docs were drafted with AI assistance and then edited by a human who
ran the commands and checked the numbers. Detectors disagree with each other; if a number here is
wrong, that is a bug.

## License and security

Apache-2.0. Keep the notices, including `NOTICE`. The licence does not grant trademark rights.
Security issues: use the hosting platform's private reporting, 90-day coordination target, no
public issue with exploit detail. Supported line: 0.2.x.

---

中文版：[`README.zh-CN.md`](README.zh-CN.md)
