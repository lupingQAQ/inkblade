# InkBlade

**Probe-centric penetration testing for training and inference clusters.**

InkBlade places a static Rust probe inside an authorized Pod, runs declarative detection templates across ten layers of ML infrastructure, and turns the evidence into a bilingual report, replayable rule packs and a live console. The controller stays outside the cluster; the target Pod needs no Python, shell, curl or module code.

> **Authorized use only.** Point InkBlade at assets you have written authorization for. Consent and ROE records are hash-pinned; scope, level and time window are enforced in code. A write needs a backup receipt. No signed record, no probe — and no flag skips the gate.

## Core capabilities

### Ten detection layers

Each layer is a set of templates you can run on its own. A template declares its inputs, steps, checks, findings and artifacts; the probe executes it and returns evidence.

| Layer | What you can do | Representative templates |
|---|---|---|
| 1. Architecture | Audit rail and multi-plane alignment, PD-split KV channels, IMEX/ComputeDomain boundaries, MoE/EP collective membership, long-context KV lifetime, multi-cluster federation | `rail-mismatch-forcing`, `prefill-decode-kv-channel-unauth`, `nvlink-imex-isolation`, `nccl-collective-join` |
| 2. Product / framework | Enumerate admin and control surfaces of vLLM, SGLang, TRL, verl, AReaL, SkyRL, OpenRLHF, slime, LLaMA-Factory, ms-swift, Megatron-LM, DeepSpeed, transformers, inference gateways and agent platforms; check plugin routes, dev modes, deserialization sinks and weight export paths | `vllm-plugin-auth-bypass`, `sglang-admin-failopen`, `verl-prime-code-exec`, `msswift-trust-remote-code` |
| 3. Component / operator | Inspect Ray and LWS control planes, GPU Operator and driver containers, DRA device policy, CSI node plugins, BMC/Redfish endpoints and DPU offload | `ray-dashboard-job`, `gpu-operator-driver-audit`, `gpu-dra-mig-policy`, `redfish-default-credentials` |
| 4. Network / fabric | Test policy bypass on hostNetwork, SR-IOV and macvlan, dual CNI control planes, IB subnet manager and partitions, RoCE PFC/ECN, SHARP aggregation, NCCL bootstrap and DNS discovery | `multus-sriov-rdma-bypass`, `ib-sm-partition-audit`, `roce-pfc-storm`, `sharp-in-network-poison` |
| 5. Data / weights | Check checkpoint and optimizer shards, dataset pipelines, Hugging Face cache, weight buckets, model registries and KV/prefix cache entries | `checkpoint-shard-poison`, `skyrl-fetch-weights-traversal`, `model-registry-exposure` |
| 6. Tenant / isolation | Measure MIG and MPS residue, GPU pooling schedulers, `cache_salt` policy and routing metric leakage | `gpu-tenant-residue`, `hami-scheduler-auth-gap`, `cache-salt-policy-audit` |
| 7. Supply chain / identity | Verify `trust_remote_code`, revision pinning, attestation chains, SBOM, IRSA and workload identity, IMDS reachability and credential exposure | `trust-remote-code-supply-chain`, `gpu-cc-attestation-chain`, `cloud-irsa-trust-wildcard` |
| 8. Cache security | Test cross-tenant prefix cache, semantic false hits, eviction residue, remote KV pools, EPP metrics and TTFT timing | `prefix-cache-cross-tenant-leak`, `similarity-cache-false-hit`, `remote-kv-pool-isolation`, `cache-timing-sidechannel` |
| 9. Cross-combination | Report findings that only exist when two or three components meet, once at the combination, with the component notes folded in | `vllm-plugin-auth-bypass` + `sglang-weight-exfil`, `imex-computedomain-gpu-memory-crossing`, `long-context-cache-leak` |
| 10. Defense bypass | Measure whether HIDS, runtime eBPF, admission control, image scanning, host agents, WAF and flow telemetry see benign authorized activity; every technique returns detected / blind spot / hardening and feeds a rule pack | `defense-bypass-elkeid`, `defense-bypass-falco`, `defense-bypass-admission`, `defense-bypass-waf-inference` |

Layer 10 is a product capability, not an add-on. Eleven `defense-bypass-*` modules cover Elkeid, AgentSmith-HIDS, veinmind, Falco, Tetragon, KubeArmor, Kyverno/Gatekeeper, Trivy/grype, Wazuh/Osquery, ModSecurity/Coraza/SafeLine and Cilium Hubble/Calico. They use benign markers, do not persist, do not disable security products and do not ship evasion instructions.

### Platform capabilities

- **One execution path.** Foothold → Rust probe → framed channel → in-pod task → child probe → evidence. Detection, escape and lateral movement all run through that path.
- **Zero target-side interpreter.** The probe is a static binary; templates are JSON data. A distroless or scratch inference image runs the same templates as a Python image.
- **Probe trees.** `probe_id` and `parent_id` give every probe a place in the tree; children inherit a stricter budget and allow-list, depth and fan-out are bounded, cleanup is child-first.
- **Agent runtime.** A budgeted planner executes the objective graph, records every observation and decision, and can resume from a durable journal or replay without executing.
- **Cross-cluster relay.** Relays carry the same framed protocol between clusters so one engagement can cover several clusters and record a coverage proof.
- **Evidence at the boundary.** Per-task results, step logs, artifacts, SHA-256 manifests, traffic tables, probe identity and cleanup receipts.
- **Rules you can replay.** Admission, runtime and network packs with blocked / detected / missed matrices.
- **Report and console.** Bilingual pentest and remediation reports, SARIF / OCSF / VEX export, and a local web console for findings, graphs and timelines.
- **No telemetry.** No account, no cloud key, no licence server, no outbound call unless you configure one.

## Workflow

| # | Stage | What happens | Artifact |
|---:|---|---|---|
| 1 | Foothold | A session records the entry vector: `kubeconfig`, `external` or `foothold`, with target, namespace, Pod and credential fingerprint | session record, audit trail |
| 2 | Rust probe | The static probe is delivered by `kubectl`, ServiceAccount token, shared volume, EphemeralContainer or an authorized RCE callback | probe identity, SHA-256 |
| 3 | Channel | The controller speaks an HMAC-authenticated, length-prefixed JSON protocol over the probe's stdio; the channel can expose loopback SOCKS5 and port forwards | channel state, task log |
| 4 | Detection | Templates run inside the Pod across the ten layers; each result carries steps, checks, findings and artifacts | findings, evidence anchors |
| 5 | Escape | Container and node boundaries are tested through the operator, driver, CSI, runtime and kernel surfaces in scope | escape path, proof |
| 6 | Lateral | Service-to-service, control-plane, gateway and fabric reachability is mapped from the probe's network namespace | reachability graph, pivots |
| 7 | Multi-probe | Child probes extend the tree to further Pods and namespaces; each child keeps its own token and stricter budget | probe tree, lineage |
| 8 | Cross-cluster | `agent relay` connects clusters; `agent coverage` records which objective nodes were closed and which were not reachable | relay status, coverage proof |
| 9 | Report / rules / visualization | Bilingual reports, SARIF/OCSF/VEX exports, replayable rule packs and the local console | report, rule packs, console |

## Quick start

Run against an environment you are authorized to test.

```bash
# 1. Install the controller
python -m pip install -e .

# 2. Open the onboarding wizard: workspace, authorization, kubeconfig
python -m inkblade up

# 3. Sign the authorization record: target, scope, level, time window
python -m inkblade quickstart

# 4. Import the kubeconfig and open an authorized session
python -m inkblade session open \
  --mode kubeconfig \
  --workspace ./work \
  --kubeconfig ~/.kube/config \
  --namespace ml-team \
  --pod infer-0

# 5. Deliver the probe into the target Pod
python -m inkblade probe deploy \
  --session <session-id> \
  --via kubectl \
  --binary ./inkblade-probe-linux-amd64 \
  --namespace ml-team \
  --pod infer-0 \
  --allow-write

# 6. Run the agent against the probe
python -m inkblade agent run \
  --probe <probe-id> \
  --objective read-only-recon \
  --workspace ./work

# 7. Render the report
python -m inkblade report --run <run-id> --lang bi
```

`inkblade up` creates the workspace, checks the authorization record and walks through kubeconfig import. `quickstart` writes the signed record that binds scope, level and window. `probe deploy` is a plan without `--allow-write`; with it, the probe is delivered and registered. `agent run` prints the `run_id` that `report` consumes.

## Command map

| Task | Command |
|---|---|
| Onboarding | `inkblade up` |
| Authorization record | `inkblade quickstart`, `inkblade roe` |
| Session | `inkblade session open` / `status` / `close` / `run` |
| Probe delivery | `inkblade probe deploy` / `list` / `collect` / `exec` / `read-file` / `list-files` / `upload` / `download` / `spawn` / `cleanup` |
| Channel | `inkblade channel start` / `status` / `stop` |
| One template | `inkblade session run --id <session> --module <key>` or `inkblade run --module <key>` |
| Chain execution | `inkblade execute --chain <id> --dry-run` then `inkblade execute --chain <id>` |
| Agent | `inkblade agent run` / `status` / `trace` / `resume` / `replay` / `stop` |
| Cross-cluster | `inkblade agent relay add\|list\|status`, `inkblade agent coverage status\|proof` |
| Report | `inkblade report --run <id> --lang bi --kind pentest\|remediation` |
| Export | `inkblade export --run <id> --format sarif\|ocsf\|vex` |
| Rule packs | `inkblade rules generate`, `inkblade rules validate` |
| Console | `inkblade ui` |
| Templates | `inkblade template list` / `get` / `plan` / `validate` |

## Deployment

**Wheel**

```bash
python -m pip wheel . --no-deps -w dist/
python -m pip install --no-index --find-links dist/ inkblade
```

**Docker**

```bash
docker build -t inkblade:0.2.0 .
docker run --rm -v inkblade-data:/data inkblade:0.2.0 up
```

**Helm**

```bash
helm install inkblade deploy/helm/inkblade \
  --namespace inkblade --create-namespace
```

The chart runs as uid 10001 with a read-only root filesystem and a PVC for evidence. Read verbs are granted by default; write verbs require both `readOnly=false` and `rbac.allowWrite=true`, plus a signed record in the workspace. Uninstalling keeps the PVC so evidence outlives the release.

## Security and authorization

- **RoE first.** `quickstart` writes a consent record with target, scope, level, time window and emergency contact. The record is hashed and the hash travels with every run; an expired or out-of-scope run is refused with exit code 91.
- **Read-only by default.** Collection, HTTP/TCP probes, file reads, read-only commands and read-only templates work without extra flags. Writes need all five gates: session level, `--allow-write`, `meta.writes`, `backup-write` mode and a backup receipt.
- **Backup and rollback.** A write module snapshots first, executes second and records both. `inkblade rollback --run <id> --step <n>` restores one step and prints a receipt; an unrestorable step is reported as a finding.
- **Audit and evidence.** Every probe action, file read, exec call and task result is written to the evidence store with a SHA-256 manifest. Reports anchor every finding to a task, step, artifact, probe or manifest hash.
- **Kill switch.** `inkblade abort` sets a workspace-level stop; runs refuse until it is cleared.
- **No telemetry.** The controller makes no outbound call unless you enable an integration. There is no account system, licence server or usage upload.

## License

Apache-2.0. Commercial use, forks and embedding are permitted; keep `LICENSE` and `NOTICE`. The `NOTICE` file records the clean-room boundary: functional parity was derived from public descriptions and observable behaviour, and InkBlade is not linked with or derived from AGPL projects. Documentation index: [`docs/DOC-INDEX.md`](docs/DOC-INDEX.md).
