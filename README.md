# InkBlade (墨刃零)

**Training & Inference Cluster Penetration Testing Platform**

`v0.2.0` · Apache-2.0 · Python 3.10 – 3.13 · no runtime dependencies · offline by default

> Authorized use only. Consent pinning, technical-level gates, a mandatory backup gate for write
> modules, and per-action auditing are enforced in code. Without a signed record, the CLI and the
> HTTP API both refuse to execute. There is no override flag.

## Why it exists

We built this after the fourth time a platform team told us the dashboard was only on the VPN.

It was not on the VPN. It was on a NodePort, the NodePort had no auth, and the proxy in front of
it had been removed two releases earlier while the runbook kept describing the old topology.

That is the shape of most of what we find. Not a clever exploit — a seam between two things that
were each individually fine. A service account that can read the model registry. An admission
webhook that fails open. A weight-sync endpoint with no auth. A checkpoint loader nobody expected
to see untrusted input.

So the tool does three things. It inventories, read-only, and says "unknown" instead of guessing.
It waits for a signature before it runs anything. And it keeps receipts: every step gets a hash and
an archive, so a challenged finding is replayed, not argued about.

## What you get

| Layer | What it does |
|---|---|
| Consent | Signed records, four cumulative technical levels, four roles, no override |
| Orchestration | Ordered chains, dry-run plan, dependency topology, backup gate, rollback |
| Modules | 286 manifests across 8 families; 275 enabled, 11 quarantined for missing surfaces |
| Evidence | Context journal, SQLite audit tables, per-step archive with SHA-256 manifest |
| Reporting | PTES narrative + remediation checklist, bilingual, CVSS 3.1, NIST / GB-T 20984 |
| Console | Six-view local SPA, static export that opens from the filesystem |
| Defence | Admission, network, detection and convergence packs, replayed per chain |
| Probe | Static Rust collector for in-pod facts: caps, seccomp, mounts, GPU/RDMA, token presence |

## Start

```bash
python -m inkblade doctor            # interpreter, write access, port, optional deps
python -m inkblade pilot --dry-run   # offline rehearsal: empty profile + plan, no cluster contact
python -m inkblade ui                # local console on 127.0.0.1:8765
python -m inkblade exploit --list    # weapon packs with their deployment requirement
```

`pilot --dry-run` writes a profile, a plan and an approval list, and never opens a connection.
When you have a cluster you are allowed to read:

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

## Vulnerability coverage

41 verified primitives, 24 components. The rule for the table: reproduced dynamically on a pinned
upstream version, and the novelty check found no matching public advisory.

Component, class, affected versions, verification shape. No reproduction steps, no payloads, no
target list.

[`docs/VULNERABILITY-COVERAGE.md`](docs/VULNERABILITY-COVERAGE.md)

## Documentation

| Document | What's in it |
|---|---|
| [`docs/USAGE.md`](docs/USAGE.md) | Command guide, workspace layout, troubleshooting |
| [`docs/INSTALL.md`](docs/INSTALL.md) | Wheel, checkout, container, Helm, air-gapped |
| [`docs/FEATURES.md`](docs/FEATURES.md) | Capability inventory with verified / simulated / gap states |
| [`docs/WORKFLOW.md`](docs/WORKFLOW.md) | The eleven stages, gate by gate |
| [`docs/MODULES.md`](docs/MODULES.md) | Module families, levels, chains, manifest contract |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Seven layers, component probe, runtime boundaries |
| [`docs/FAQ.md`](docs/FAQ.md) | Short answers, including the uncomfortable ones |
| [`SECURITY.md`](SECURITY.md) | Vulnerability reporting and support window |
| [`docs/VERSIONING.md`](docs/VERSIONING.md) | Pre-1.0 versioning policy |

The site is generated from these files and published from `docs/`
([`docs/README-SITE.md`](docs/README-SITE.md)).

## Limits

- Coverage is uneven. 60–71% on Kubernetes profiles, 25% on Slurm. The missing modules are listed.
- Verification is partial: 37 of 152 catalogue entries, the rest are hypotheses with a blocker.
- A coverage row is a lead, not a verdict — one commit, one config.
- Autonomy is bounded. The default stops at "propose and wait".
- Pre-1.0. Pin a version for a regulated pilot.

Not a SaaS, not an agent with standing write access, not a zero-configuration scanner.

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
