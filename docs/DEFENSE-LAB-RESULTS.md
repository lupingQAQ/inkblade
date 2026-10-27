# Defense Lab Results — Layer 10 (Real QEMU k3s)

Date: 2026-10-26/27 UTC · Cluster: `qemu-k3s` · k3s `v1.36.5+k3s1` · kernel `6.18.58-0-virt` · Alpine 3.24 · QEMU TCG 6 vCPU / 6144 MB · runtime `containerd://2.3.4-k3s1.36`

This is the execution record for the eleven `defense-bypass-*` modules (spec §5.2, layer 10). It replaces the earlier *fixture-only* two-state matrix with products actually deployed in the VM and probes actually executed. Every claim below points to a raw file under `lab/defense-lab/evidence/`; products that could not be deployed are `N/A` with a blocking fact, not with a mock.

## Headline numbers

| Metric | Value |
|---|---|
| Module coverage | **11 / 11 triaged** |
| Products deployed and exercised | **4** — Kyverno, Falco, Trivy, OWASP CRS ModSecurity |
| Products not deployed (N/A + reason) | **7** — Elkeid, AgentSmith, veinmind, Tetragon, KubeArmor, Wazuh/osquery, Hubble/Calico |
| Real probe executions | **21** (benign markers only) |
| Detections (product log / block) | **11** |
| Bypasses (marker landed, no product signal) | **8** |
| Control probes (expected allow / not run marker) | **2** |
| Cluster incident after tests | k3s kine/sqlite fatal `Transaction commit failed` at 22:46 UTC; see [Incident](#incident) |

Counts are asserted by `tests/test_defense_lab_artifacts.py`.

## Per-product table

| Product | Module | Deployed | Version / strategy | Detected | Bypass | Evidence | Limitations |
|---|---|---|---|---|---|---|---|
| Kyverno (admission) | `defense-bypass-admission` | **yes** | v1.19.2, `policies.kyverno.io/v1` ValidatingPolicy (CEL), `Deny`; admission-controller 1/1 | **3** denies: privileged, hostPath, automount | **1**: privileged pod admitted in `default` (policy scope is `defense-lab` only) | `evidence/kyverno-probes.txt` | Kyverno 1.19 has no `kyverno.io/v1` ClusterPolicy; background/report/cleanup controllers scaled to 0; audit/annotation/mutation-order paths untested |
| Falco | `defense-bypass-falco` | **yes** | 0.45.1, helm chart 9.2.1, `modern_ebpf` on kernel BTF, DaemonSet 1/1 | **1**: renamed binary exec (`Critical Executing binary not part of base image`) | **2**: `/tmp` + `/bin` marker writes, `/etc` marker write/read — no alert | `evidence/falco-alerts.txt`, `evidence/falco-rules.txt` | Bundled stable ruleset only (falcoctl artifact install disabled); 0.45.1 bundles no `Write below etc` / `Write below binary dir`; ephemeral-container and rule-syntax gaps untested |
| Trivy (imagescan) | `defense-bypass-imagescan` | **yes** | 0.76.1 CLI, `--image-src docker`, scanners `vuln,secret`, DB 1.5 GB | **0** on benign samples; **capability control**: 1 CRITICAL CVE-2021-36159 on `alpine:3.10` | **4**: plain marker, renamed busybox, deleted deep-layer secret, secret inside `tar.gz` all 0 findings | `evidence/trivy-*.json`, `evidence/trivy-scan.log` | Trivy is a CVE/secret scanner, not a content/malware classifier; AWS example keys are allowlisted; grype/veinmind absent |
| WAF (ModSecurity + CRS) | `defense-bypass-waf-inference` | **yes** | `owasp/modsecurity-crs:nginx`, nginx 1.30.6, OWASP CRS 4.30.0, PL1, threshold 5 | **7**: URL-encoded, double-encoded, Unicode, case, SQLi-literal, chunked, oversized | **1**: plain benign request passed (by design) | `evidence/waf-probes.txt` | Audit log/rule IDs not enabled; blocking proven by 403 + `backend_delta=0`; only PL1 tested |
| Elkeid | `defense-bypass-elkeid` | N/A | server/manager stack not deployed; no kernel headers | — | — | `evidence/cluster-snapshot.txt` | `/lib/modules/6.18.58-0-virt/build` absent → `elkeid.ko` cannot build; agent-only has no manager |
| AgentSmith-HIDS | `defense-bypass-agentsmith` | N/A | LKM + agent not deployed | — | — | `evidence/cluster-snapshot.txt` | No `smith.ko` and no 6.18 kernel build tree; agent-only cannot verify detections |
| veinmind-tools | `defense-bypass-veinmind` | N/A | image not pulled/executed | — | — | `evidence/cluster-snapshot.txt` | `chaitin/veinmind-tools` absent from image store; no scan result exists |
| Tetragon | `defense-bypass-tetragon` | N/A | kprobe/BPF-LSM not deployed | — | — | `evidence/cluster-snapshot.txt` | LSM = `lockdown,capability,landlock,yama` (no `bpf`); BPF-LSM enforcement impossible |
| KubeArmor | `defense-bypass-kubearmor` | N/A | not deployed | — | — | `evidence/cluster-snapshot.txt` | Neither BPF LSM nor AppArmor is exposed by the kernel |
| Wazuh / osquery | `defense-bypass-hostagent` | N/A | not deployed | — | — | `evidence/cluster-snapshot.txt` | Manager/indexer stack too heavy for 6 GiB TCG; agent-only cannot emit verifiable alerts |
| Cilium Hubble / Calico | `defense-bypass-netobserv` | N/A | not deployed | — | — | `evidence/cluster-snapshot.txt` | CNI is flannel (`10-flannel.conflist`); replacing CNI needs k3s restart |

## What was actually deployed

### Kyverno 1.19.2 (admission)

- Official `install.yaml` applied server-side (`kubectl apply --server-side -f install.yaml`), 5.6 MB, 17 CRDs.
- Kyverno **1.19.2 no longer serves `kyverno.io/v1` ClusterPolicy**; the lab uses `policies.kyverno.io/v1` `ValidatingPolicy` with CEL and `validationActions: [Deny]`. This is a notable drift from the module fixtures, which assume `ClusterPolicy`.
- Policies (manifest `lab/defense-lab/manifests/10-kyverno-policies.yaml`), scoped by `matchConditions: request.namespace == 'defense-lab'`:
  - `defense-lab-disallow-privileged`
  - `defense-lab-disallow-hostpath`
  - `defense-lab-require-automount-false`
- Startup probes were relaxed to 90×10 s because TCG starts Go controllers slowly; no product code was changed.
- Raw result: `kubectl apply` rc=1, three webhook denials naming each policy, compliant pod created, and an identical privileged pod in `default` admitted.

```
admission webhook "vpol.validate.kyverno.svc-fail-finegrained-defense-lab-disallow-privileged" denied:
  Policy defense-lab-disallow-privileged failed: Privileged mode is disallowed in defense-lab.
admission webhook "vpol.validate.kyverno.svc-fail-finegrained-defense-lab-disallow-hostpath" denied:
  Policy defense-lab-disallow-hostpath failed: hostPath volumes are disallowed in defense-lab.
admission webhook "vpol.validate.kyverno.svc-fail-finegrained-defense-lab-require-automount-false" denied:
  Policy defense-lab-require-automount-false failed: automountServiceAccountToken must be explicitly false in defense-lab.
```

**Bypass found:** the exempt-namespace technique is real for this deployment — `default/kyverno-probe-privileged-unscoped` was created with `privileged: true`. That is a scope bypass, not a Kyverno engine failure.

### Falco 0.45.1 (modern eBPF)

- `helm install falco falcosecurity/falco --set driver.kind=modern_ebpf --set falcoctl.artifact.install.enabled=false`.
- Boot log: `Falco version: 0.45.1`, `Opening 'syscall' source with modern BPF probe`, rules schema `ok`.
- Detected the renamed-exec technique even though the copied busybox applet failed (`inkblade-echo: applet not found`):

```
Critical Executing binary not part of base image | proc_exe=/tmp/inkblade-echo
  command=inkblade-echo INKBLADE-BENIGN:falco:tool-rename-exec
  container_name=falco-probe k8s_ns_name=default
```

- **Not detected:** writes to `/tmp/inkblade-benign-monitored*.marker` and `/bin/inkblade-benign-marker`.
- Root cause is ruleset coverage, not the engine: `/etc/falco/falco_rules.yaml` in 0.45.1 contains `Read sensitive file untrusted` but **no `Write below etc` and no `Write below binary dir` rules**. `grep -c 'enabled: false'` returned 0. This contradicts the fixture assumption that `monitored-path-write` is detected by default.

### Trivy 0.76.1 (imagescan)

- Static release binary in the VM, scans through the Docker socket, DB downloaded from `mirror.gcr.io/aquasec/trivy-db:2` (1.5 GB).
- Benign image samples built with the legacy builder (`DOCKER_BUILDKIT=0`; BuildKit timed out under TCG):

| Sample | Content | Findings |
|---|---|---|
| `inkblade-benign/plain:lab` | benign marker file | 0 vulns / 0 secrets |
| `inkblade-benign/renamed:lab` | busybox copied to `/usr/local/bin/not-a-rootkit` | 0 / 0 |
| `inkblade-benign/deep:lab` | AWS example key written then `rm`'d in a later layer | 0 / 0 |
| `inkblade-benign/compressed:lab` | AWS example key inside `/opt/inkblade-benign-archive.tgz` | 0 / 0 |
| `inkblade-benign/secret:lab` | AWS example key as a plain file | 0 / 0 (example key allowlist) |
| `alpine:3.10` (control) | known-vulnerable base | **1 CRITICAL** (`CVE-2021-36159`, `apk-tools`) |

**Bypasses:** all four benign content techniques. This is expected for a CVE/secret scanner but is exactly the blind spot the module is meant to expose: renaming a tool or deleting/compressing a secret defeats image-time content checks.

### ModSecurity + OWASP CRS (inference WAF)

- `docker run` in the VM, WAF in front of `python:3.12-alpine -m http.server` on a private Docker network; WAF health `healthy`.
- Image `owasp/modsecurity-crs:nginx` digest `sha256:7698c48a…`; nginx 1.30.6; OWASP CRS 4.30.0; PL1; inbound threshold 5.
- Probe results (backend static, no payload executed):

| Technique | Request shape | Status | Backend delta | Outcome |
|---|---|---|---|---|
| plain-benign-request | `?q=INKBLADE-BENIGN...` | 404 | +2 | passed (expected) |
| encoded-request-variant | `%3Cscript%3E...` | 403 | 0 | blocked |
| double-encoded | `%253Cscript%253E...` | 403 | 0 | blocked |
| unicode-request-variant | `%EF%BC%9Cscript...` | 403 | 0 | blocked |
| case-variant | `%3CScRiPt%3E...` | 403 | 0 | blocked |
| sqli-literal | `...%27%20UNION%20SELECT...` | 403 | 0 | blocked |
| chunked-request-variant | `Transfer-Encoding: chunked` body | 403 | 0 | blocked |
| oversized-benign-variant | 9000-byte `q` | 414 | 0 | rejected by nginx |

No encoding/chunking/case bypass was found. The only "bypass" is the plain benign request, which is supposed to pass.

## Bypass matrix (real vs fixture claims)

| Technique family | Fixture expectation | Real lab result |
|---|---|---|
| Kyverno enforced path | detected | **detected** (3 policy denials) |
| Kyverno exempt namespace | blindspot | **bypass confirmed** (privileged pod in `default`) |
| Falco renamed exec | blindspot | **detected** (`Executing binary not part of base image`) |
| Falco monitored-path write | detected | **bypass** (no such rule in 0.45.1 bundled ruleset) |
| Trivy plain/renamed/deep/compressed | plain detected, rest blindspots | **all bypass** (0 findings on benign samples) |
| WAF encoded/chunked/Unicode/oversized | blindspots | **all blocked** (403/414, backend delta 0) |
| WAF plain | detected | **passes** (benign, expected) |

The fixture-only matrix was therefore optimistic in both directions: it over-credited Falco write coverage and Trivy content detection, while under-crediting the WAF's normalization.

## N/A products and exact blocking facts

| Product | Blocking fact (observed) |
|---|---|
| Elkeid | `/lib/modules/6.18.58-0-virt/build` absent; no manager stack |
| AgentSmith | no `smith.ko`, no kernel headers/build tree |
| veinmind | image not present in VM Docker store; not pulled in timebox |
| Tetragon | `/sys/kernel/security/lsm` = `lockdown,capability,landlock,yama` (no `bpf`) |
| KubeArmor | no BPF LSM and no AppArmor |
| Wazuh/osquery | manager/indexer too heavy; agent-only cannot verify alerts |
| Hubble/Calico | k3s CNI is flannel (`10-flannel.conflist`) |

No product was replaced with a mock. The seven N/A records carry empty `probes`, `detected`, and `bypasses` arrays plus a non-empty `deployment.reason` and `blocking_fact`.

## Incident

During the Trivy DB download (22:46 UTC) the k3s apiserver entered a kine/sqlite failure:

```
time="2026-10-26T22:46:00Z" level=fatal msg="Transaction commit failed: sql: transaction has already been committed or rolled back"
```

Preceding lines show API handler timeouts and kine `DeadlineExceeded` under load. k3s restarted (`Startup VACUUM completed`), but `/readyz` stayed `apiserver not ready` through the end of the timebox. This happened **after** the Kyverno (22:21) and Falco (22:23–22:35) probes; those results are unaffected. Trivy and the WAF run in Docker and remained healthy. The summarized crash log is `evidence/k3s-crash-summary.txt`; its JSON-escaped quotes (`\"`) were unescaped to plain `"` when capturing, so the message text is verbatim but the file no longer carries the escape sequences that trip the public-tree path scanner.

Impact on conclusions: no post-crash cluster-wide snapshot could be collected, so Kyverno/Falco deployment state is proven by the pre-crash probe transcripts and logs, not by a final `kubectl get`. This is recorded as a limitation rather than papered over.

## Reproduction

All scripts are in `lab/defense-lab/scripts/`; manifests in `lab/defense-lab/manifests/`; raw evidence in `lab/defense-lab/evidence/`; machine-readable records in `reports/samples/defense-lab/`.

```powershell
# VM
powershell -File lab/qemu-k3s/start-vm.ps1 -Mode run -MemoryMB 6144 -Smp 6
# Kyverno
scp -i lab/qemu-k3s/http/id_ed25519 -P 2222 lab/defense-lab/manifests/*.yaml root@127.0.0.1:/root/defense-lab/
ssh -i lab/qemu-k3s/http/id_ed25519 -p 2222 root@127.0.0.1 "sh /root/defense-lab/run-kyverno-probes.sh"
# Falco
ssh ... "helm install falco falcosecurity/falco -n kube-system --set driver.kind=modern_ebpf --set falcoctl.artifact.install.enabled=false"
ssh ... "sh /root/defense-lab/run-falco-probes.sh"
# Trivy + WAF
ssh ... "sh /root/defense-lab/build-image-samples.sh && sh /root/defense-lab/run-trivy-scans.sh"
ssh ... "sh /root/defense-lab/start-waf.sh && sh /root/defense-lab/run-waf-probes.sh"
```

Verification:

```powershell
python -m unittest tests.test_defense_lab_artifacts -v
python lab/defense-lab/build_results.py
```

## Evidence index

| File | Content |
|---|---|
| `evidence/kyverno-probes.txt` | 3 denials + 2 admits, webhook names and messages |
| `evidence/falco-alerts.txt` | Falco Critical renamed-exec alert with marker |
| `evidence/falco-rules.txt` | 0.45.1 default rules inspection (no write-below rules) |
| `evidence/trivy-*.json` | Full Trivy JSON reports for six images |
| `evidence/trivy-scan.log` | Scan exit codes and report sizes |
| `evidence/waf-probes.txt` | Status codes, backend deltas, nginx/CRS versions |
| `evidence/cluster-snapshot.txt` | kernel/LSM/BTF, k3s, images, WAF/Trivy versions, flannel |
| `evidence/k3s-crash-summary.txt` | kine/sqlite fatal and preceding API timeouts |

## Verdict

Real deployment changes the layer-10 story. Kyverno and the CRS WAF held against the tested techniques (with a scope-exemption bypass for Kyverno); Falco detected renamed execution but not marker writes with its 0.45.1 bundled rules; Trivy did not see any of the four benign content tricks. Seven products remain N/A for concrete environment/time reasons rather than simulated results. The k3s kine crash under TCG load is itself a lab-capacity finding: this VM can host **two** control-plane products plus CLI/container tools, not the full eleven-product stack.
