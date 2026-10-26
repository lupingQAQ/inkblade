# InkBlade

**Probe-centric penetration testing for training and inference clusters**

`v0.2.0` · Apache-2.0 · Python 3.10–3.13 controller · static Rust probe · read-only by default

> **Authorized use only.** Point InkBlade at assets you have written authorization for. Consent and
> ROE records are hash-pinned. Scope, level and time window are enforced in code. Writes need a
> backup receipt. No signed record, no probe — and no flag skips it.

## Why a Pod-side probe

A cluster scanner can tell you that a namespace is privileged or an image has a CVE. It cannot tell
you what the inference Pod actually sees: its service-account token, mounted weights, RDMA
interfaces, GPU device nodes, cgroup limits, or the neighbours reachable from its network namespace.

InkBlade puts a single static Rust binary inside the target Pod. Templates are JSON data. The probe
is the only target-side execution logic. No Python, shell, or module code is shipped into the target.

```
foothold → Rust probe → framed channel → in-pod tasks → child probes → evidence
```

The Python controller owns authorization, scope, template selection, budgets, evidence storage,
reporting and rule generation. It never executes target-side logic.

## Ten layers

The first nine describe where ML infrastructure differs from ordinary Kubernetes. The tenth
describes whether the defenders can see it.

| Layer | What we look for | Representative template keys |
|---|---|---|
| 1. Architecture | Rail/multi-plane mismatch, PD-split KV channels, IMEX domains, MoE/EP collectives, long-context KV lifetime, federation | `rail-mismatch-forcing`, `prefill-decode-kv-channel-unauth`, `nvlink-imex-isolation`, `nccl-collective-join` |
| 2. Product / framework | Plugin routes, admin fail-open, dev modes, RL control planes, WebUI, checkpoint loaders | `vllm-plugin-auth-bypass`, `sglang-admin-failopen`, `verl-prime-code-exec`, `msswift-trust-remote-code` |
| 3. Component / operator | Ray and LWS control, GPU Operator, DRA, CSI, BMC/Redfish, DPU | `ray-dashboard-job`, `gpu-operator-driver-audit`, `gpu-dra-mig-policy`, `redfish-default-credentials` |
| 4. Network / fabric | Policy bypass on hostNetwork/SR-IOV/macvlan, dual CNI, IB SM, RoCE PFC/ECN, SHARP, NCCL bootstrap | `multus-sriov-rdma-bypass`, `ib-sm-partition-audit`, `roce-pfc-storm`, `sharp-in-network-poison` |
| 5. Data / weights | Checkpoint and optimizer shards, dataset pipelines, HF cache, weight buckets, model registry | `checkpoint-shard-poison`, `skyrl-fetch-weights-traversal`, `model-registry-exposure` |
| 6. Tenant / isolation | MIG and MPS residue, GPU pooling schedulers, `cache_salt`, routing metric leakage | `gpu-tenant-residue`, `hami-scheduler-auth-gap`, `cache-salt-policy-audit` |
| 7. Supply chain / identity | `trust_remote_code`, revision pinning, signatures/attestation, SBOM, IRSA wildcards, IMDS | `trust-remote-code-supply-chain`, `gpu-cc-attestation-chain`, `cloud-irsa-trust-wildcard` |
| 8. Cache security | Cross-tenant prefix cache, semantic false hits, eviction residue, remote KV pools, EPP metrics, TTFT timing | `prefix-cache-cross-tenant-leak`, `similarity-cache-false-hit`, `remote-kv-pool-isolation`, `cache-timing-sidechannel` |
| 9. Cross-combination | Findings that only exist when two or three components meet; reported once, at the combination | `vllm-plugin-auth-bypass` + `sglang-weight-exfil`, `imex-computedomain-gpu-memory-crossing`, `long-context-cache-leak` |
| 10. Defense bypass | Whether HIDS, runtime policy, admission, image scan, host agents, WAF and flow visibility see benign authorized activity | `defense-bypass-elkeid`, `defense-bypass-falco`, `defense-bypass-admission`, `defense-bypass-waf-inference` |

Full four-column tables for layers 1–9: [`docs/DETECTION-LAYERS.md`](docs/DETECTION-LAYERS.md).
Layer 10, including the eleven defense-bypass modules: [`docs/PRODUCT.md`](docs/PRODUCT.md).

## Defense bypass and detection coverage

This is a product capability, not an add-on. Eleven `defense-bypass-*` modules are being
migrated to run through the Rust probe; each uses benign markers only and returns three kinds of
output for every technique: **detected**, **blind spot**, and **hardening advice**. They do not carry
malware, persist, disable security products, or provide evasion instructions.

| Product family | Module | What is measured |
|---|---|---|
| Elkeid HIDS | `defense-bypass-elkeid` | agent/driver fingerprint, whitelisted paths, renamed tools, driver-not-loaded degradation, rule blind spots |
| AgentSmith-HIDS | `defense-bypass-agentsmith` | `smith.ko` presence, rule coverage gaps, renamed exec, benign DNS |
| veinmind container scan | `defense-bypass-veinmind` | layered images, renamed tools, compressed samples, whitelist names |
| Falco | `defense-bypass-falco` | no-driver degradation, rule gaps, ephemeral containers, renamed exec |
| Tetragon / eBPF | `defense-bypass-tetragon` | policy not mounted in a namespace, short-lived processes, hostNetwork |
| KubeArmor | `defense-bypass-kubearmor` | namespace posture, default-allow, hostNetwork coverage |
| Kyverno / Gatekeeper | `defense-bypass-admission` | exemptions, Audit mode, mutation order, subresources |
| Trivy / grype image scan | `defense-bypass-imagescan` | deep layers, renamed tools, compressed samples, whitelist names |
| Wazuh / Osquery host agents | `defense-bypass-hostagent` | agent offline window, rule gaps, renamed exec |
| ModSecurity / Coraza / SafeLine WAF | `defense-bypass-waf-inference` | encoding, chunked, Unicode and oversized request variants |
| Cilium Hubble / Calico flows | `defense-bypass-netobserv` | hostNetwork, multi-NIC, short-lived flows |

Blind spots feed rule packs directly: Kyverno/Gatekeeper for admission, Sigma for process/file/DNS
telemetry, Falco/Tetragon for runtime, Suricata/WAF for network and request normalization. The
product ships the rules and the replay matrix, not just a warning that a product was bypassed.

## What you get

- **One execution path.** Foothold, Rust probe, framed channel, in-pod template execution, child
  probes, evidence. Paths outside this diagram are not supported.
- **Zero target-side interpreter.** The probe is static; templates are data. A distroless or
  scratch-based inference image runs the same templates as a Python image.
- **Probe trees.** `probe_id` / `parent_id`, per-child tokens, stricter inheritance, depth/fan-out
  limits, child-first cleanup.
- **Read-only by default.** Writes need authorization, `--allow-write`, `meta.writes`,
  `backup-write` mode and a backup receipt.
- **Evidence at the boundary.** Per-task results, step logs, artifacts, SHA-256 manifests, probe
  identity, cleanup receipts.
- **Ten detection layers.** 287 module directories, 29 chains, 11 defense-bypass modules.
- **Rules you can replay.** Admission, runtime and network packs with blocked/detected/missed
  matrices.
- **No telemetry.** No account, no cloud key, no licence server.

## Maturity / 成熟度

| Tier | Scope | Status |
|---|---|---|
| demo | Mock range and offline reports | Not offered in the probe architecture. A mock run is template validation, not a customer result. |
| 试点 / pilot | Authorized, read-only: one namespace, one Pod, one template, then layer scan | Recommended first engagement. Evidence and limits are explicit. |
| 生产 / production | Full chains, enterprise integrations, HA, on-call | Not recommended yet. There is no vendor SLA or certification. |

禁止宣称 / prohibited claims: no “zero false positives”, no “full coverage”, no “production-certified”, no “undetectable”. Every number needs a task set, a version and a date.

## Quick start

The product path is `doctor → session → probe → exec/scan → report`.

```bash
python -m pip install -e .

# 1. Environment and probe binary
python -m inkblade doctor

# 2. Authorized session
python -m inkblade session start \
  --name pilot-01 --workspace ./work \
  --kubeconfig ~/.kube/config \
  --scope namespace:ml-team --level read-only

# 3. Deploy the probe
python -m inkblade probe deploy \
  --session pilot-01 --target ml-team/infer-0 \
  --method kubectl-exec --binary ./inkblade-probe-linux-amd64

# 4. Run one template, or a layer scan
python -m inkblade exec --session pilot-01 --probe p-7f3a1c9e \
  --template service-account-token-exposure
python -m inkblade scan --session pilot-01 --profile ray-vllm --layers 1,3,5

# 5. Report
python -m inkblade report --session pilot-01 --lang bi
```

There is no demo or trial path: a session requires an authorized target and a signed consent record.
The 2026-10 probe migration is in its final window; `doctor` reports the command surface that is
actually available. Current completion is tracked in [`docs/DYNAMIC-VERIFICATION.md`](docs/DYNAMIC-VERIFICATION.md).

## Command map

| Task | Command |
|---|---|
| Environment check | `inkblade doctor` |
| Session | `inkblade session start|list|show|close` |
| Probe deployment | `inkblade probe deploy|list|show|collect|spawn|tree|cleanup` |
| One template | `inkblade exec --template <key>` |
| Layer scan | `inkblade scan --profile <name> --layers <n,n>` |
| Dry run | `inkblade scan ... --dry-run` |
| Report | `inkblade report --session <id> --lang bi` |
| Export | `inkblade export --format sarif|ocsf|vex` |
| Rule packs | `inkblade rules generate|validate` |
| Template check | `inkblade template lint|validate` |

## Documentation

| Document | Purpose |
|---|---|
| [`docs/PRODUCT.md`](docs/PRODUCT.md) | Positioning, audiences, ten-layer detection tables, defense-bypass outputs |
| [`docs/ARCHITECTURE-PROBE.md`](docs/ARCHITECTURE-PROBE.md) | The single execution path, probe tree, runtime operations, controller boundary |
| [`docs/PROBE-PROTOCOL.md`](docs/PROBE-PROTOCOL.md) | Framing, auth, tasks/results, budgets, file chunks, cleanup, error codes |
| [`docs/PROBE-DEPLOY.md`](docs/PROBE-DEPLOY.md) | RCE/memfd, kubectl, EphemeralContainer, shared volumes, release binaries, write gates |
| [`docs/DYNAMIC-VERIFICATION.md`](docs/DYNAMIC-VERIFICATION.md) | Two-state mock verification standard, evidence format, coverage fields, current status |
| [`docs/INSTALL.md`](docs/INSTALL.md) | Controller and probe installation, air-gapped, workspace layout |
| [`docs/USAGE.md`](docs/USAGE.md) | Five-step workflow, scenarios, output reading, exit codes |
| [`docs/FAQ.md`](docs/FAQ.md) | Boundaries, migration status, writes, detection, licensing |
| [`docs/DOC-INDEX.md`](docs/DOC-INDEX.md) | Complete documentation index |
| [`docs/HOW-TO-DESIGN-COMMERCIAL-AGENT.md`](docs/HOW-TO-DESIGN-COMMERCIAL-AGENT.md) | Engineering handbook, including the probe-centric revision |

## English / 中文

This README is the English entry point. The Chinese version is
[`README.zh-CN.md`](README.zh-CN.md); both describe the same architecture and the same limits.

## 证据 / 限制

**Evidence**

- Probe runtime: `probe/src/{http,net,exec,fsops,k8s,spawn,collect,protocol}.rs`.
- Template schema: `probe/schema/probe-template.schema.json`; reference evaluator:
  `inkblade/tpl/engine.py` (mock/CI only, refuses to run unless explicitly enabled).
- Defense-bypass assessment: `inkblade/core/defenseprobe.py` and 11 `inkblade/modules/defense-bypass-*`
  modules.
- Current counts: 287 module directories (286 templates plus one bootstrap), 29 chains, 11
  defense-bypass modules. Migration window: 286 legacy `run.py` files remain and must be removed
  before release; the registry already ignores them.
- Rust-runtime dynamic verification is still 0. The 286/286 two-state results in the coverage
  report use `runtime=reference`; they are useful for template logic, not for probe evidence.

**Limits**

- The 2026-10 migration is in its final window. The probe CLI and the `session/probe/exec/scan`
  surface are still being finished; this README describes the target contract and marks the current
  state.
- The defense-bypass modules still use the Python reference assessment; they are not yet counted as
  Rust template coverage.
- Vendor blind spots are version- and configuration-specific. A blind spot is not a claim that the
  product can be bypassed in general.
- Benign markers prove visibility, not invisibility of malicious behaviour. The product does not
  ship malware, persistence, or evasion instructions.
- Some detection points need privileged Pods, hostNetwork, GPU devices or node access; without that
  surface the template returns `skipped` or `blocked`, never `verified`.

## AI assistance statement

Parts of this README and the documentation were drafted with AI assistance, then edited by a human
maintainer who ran the commands, checked the numbers against code and generated reports, and cut
claims that would not reproduce.

Detectors disagree with each other and with people, so no detection rate is claimed. If a sentence
reads like a machine wrote it, it probably started that way. Numbers that look wrong are bugs.

Code, manifests, rule packs and evidence artefacts come from the software; this statement covers
prose.
