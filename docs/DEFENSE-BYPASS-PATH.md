# Defense-Aware Bypass Execution Path

Date: 2026-10-27 UTC · Cluster: `qemu-k3s` · k3s `v1.36.5+k3s1` · Kyverno `v1.19.2` · Falco `0.45.1` (modern eBPF)

This document records the change from "a bypass probe that reports a product is
bypassable" to "the agent execution path selects and runs a bypass variant
before an exploit/privesc intent".  The behavior was exercised end-to-end on the
real Kyverno + Falco VM described in [`DEFENSE-LAB-RESULTS.md`](DEFENSE-LAB-RESULTS.md).

## 1. What changed

| Layer | Before | After |
|---|---|---|
| Probe collection | process/mount/SA snapshot | adds `security_posture`: agent processes, kernel modules, agent directories, admission policies, runtime sensor, ruleset fingerprint |
| Agent graph | findings only | `Fact` with claim `defense:<product>` (`fact_kind="defense"`), evidence-gated |
| Policy | RoE / scope / write gate | `core/defense_policy.py`: product → available techniques → risk/success ranking; explicit stop when no primitive exists |
| Execution | free-form exploit intent | scheduler refuses offensive intents without a `bypass.technique_id`; probe tasks carry the selected plan |
| Evidence | probe archive | additionally records detected product, technique id, alerts and denials observed in the phase window |

## 2. Security posture (probe collect)

`inkblade-probe collect` now returns a `security_posture` object (read-only, no
new process and no write):

```json
{
  "schema": "inkblade-security-posture/1",
  "namespace": "trident-bypass",
  "processes": [{"pid": 4267, "comm": "falco", "matched": ["falco"]}],
  "kernel_modules": ["...", "kvm"],
  "agent_dirs": [{"path": "/etc/falco", "product": "falco", "present": false}],
  "admission": {
    "kyverno": {"available": true, "count": 3,
                "items": [{"name": "defense-lab-disallow-privileged",
                           "scope": "[request.namespace == 'defense-lab']"}]}
  },
  "runtime_sensor": {"falco": {"running": true, "btf": true,
                               "kernel_module": false,
                               "driver": "modern_ebpf_inferred"}},
  "rulesets": [{"product": "falco", "rule_count": 25,
                "interesting_rules": ["terminal-shell", "k8s-api-contact", "drop-execute"]}],
  "products": [{"product": "falco", "version": "falcosecurity/falco:0.45.1"},
               {"product": "kyverno", "version": "reg.kyverno.io/kyverno/kyverno:v1.19.2"}],
  "no_exec": true, "no_write": true
}
```

The observer parses the object into graph facts; a confirmed fact requires the
collect archive SHA-256, the same evidence gate as every other finding:

```
defense:falco      attrs={version, ruleset, sensor, available_techniques}
defense:admission  attrs={policies, namespace, available_techniques}
```

## 3. Bypass policy engine

`inkblade/core/defense_policy.py` has one catalog entry per Rust primitive.  The
ranking is a heuristic, not a promise:

```
score = success_rate * (1 - detection_risk)
```

| Technique id | Product domain | Primitive | Risk | Success | Score |
|---|---|---|---|---|---|
| `namespace-scope-evasion` | admission, kubearmor | namespace outside policy match scope | 0.05 | 0.95 | 0.9025 |
| `sa-permission-selection` | admission, falco, kubearmor | SelfSubjectAccessReview; select an already-authorized SA | 0.10 | 0.85 | 0.7650 |
| `path-evasion` | runtime sensors | writable workspace outside monitored set | 0.15 | 0.75 | 0.6375 |
| `command-split-env-clean` | runtime sensors | per-line commands + `env_clear` | 0.30 | 0.60 | 0.4200 |
| `fileless-memfd-exec` | runtime sensors | `memfd_create` + `/proc/self/fd` exec | 0.45 | 0.55 | 0.3025 |
| `existing-binary-exec` | runtime sensors | `/bin/sh` or busybox already in the image | 0.55 | 0.45 | 0.2025 |

Product → technique map:

| Product | Techniques | Behaviour |
|---|---|---|
| `admission` (Kyverno/Gatekeeper) | namespace-scope-evasion, sa-permission-selection | select a namespace outside `matchConditions`, or an SA with the required verb |
| `falco` | fileless-memfd-exec, existing-binary-exec, path-evasion, command-split-env-clean | rank by score; path-evasion is the default |
| `elkeid`, `agentsmith`, `tetragon` | memfd, existing-binary, path, split | same runtime primitives |
| `kubearmor` | namespace-scope-evasion, existing-binary, path | admission-style + runtime |
| `hostagent` | path, split | host file/command coverage only |
| `imagescan`, `veinmind`, `waf-inference`, `netobserv` | **none** | return `no-technique`, `stop=true`, status `policy-refused`; the intent is not executed |

The stop path is deliberately not "try harder": if a detected product has no
implemented primitive, the engine reports
`该产品/规则下不可绕过（无已实现原语）` and the scheduler blocks the intent.

## 4. Execution-path wiring

`TaskScheduler.claim_next()` runs the normal RoE/policy gate first, then the
defense gate:

1. read confirmed/hypothesis `defense:<product>` facts from the graph;
2. classify the intent as offensive (`role=exploit`, or module/tag contains
   `exploit/privesc/lateral/escape/takeover/bypass/credential/...`);
3. require `params.bypass.technique_id` that is available for a detected
   product;
4. on failure: block the intent, emit `defense.refused`, `policy.refused`,
   optionally `defense.stopped`, and increment `SchedulerStatus.defense_refused`;
5. on success: attach `defense_bypass` to the claimed intent and emit
   `defense.bypass.selected` with the technique id.

Probe tasks carry the same object:

```json
{
  "bypass": {
    "technique_id": "path-evasion",
    "techniques": ["path-evasion", "existing-binary-exec"],
    "product": "falco",
    "plan": {
      "techniques": ["path-evasion", "existing-binary-exec"],
      "script": "…benign marker…",
      "workdir": "/dev/shm",
      "monitored_paths": ["/tmp", "/var/tmp"],
      "clean_env": true
    }
  }
}
```

The template dialect accepts `op: "bypass"` natively (validated in
`inkblade/tpl/schema.py`, passed through by `inkblade/tpl/lower.py`, executed by
`probe/src/template.rs`).  A bypass step has no host fallback.

## 5. End-to-end run (real products)

Environment:

- VM: QEMU TCG, 4 vCPU / 4096 MB, Alpine 3.24, kernel `6.18.58-0-virt`.
- Kyverno `v1.19.2`, 3 `ValidatingPolicy` objects scoped to `defense-lab`.
- Falco `0.45.1`, modern eBPF; the running rules file used 25 top-level
  `- rule:` entries and contains no `Write below etc` / `Write below binary
  dir` rule.
- Probe: `inkblade-probe` Linux amd64, built in the VM.

### 5.1 Kyverno scope → privileged Pod → node marker

- A control Pod with `privileged: true` and `hostPath: /` was submitted to
  `defense-lab`: **denied** by `defense-lab-disallow-hostpath`; a second
  control with only `privileged: true` (no hostPath) was **denied** by
  `defense-lab-disallow-privileged`. Both denials are in
  `logs/kyverno-control-apply.log`.
- The same manifest in `default` (outside the policy's `matchConditions`) was
  admitted; inside it, the probe recorded `uid=0`, full `CapEff`, host PID 1,
  and wrote a marker to `/host/root/inkblade-bypass-node.marker`.
- Node read-back confirms the marker.

This is a **scope bypass**, not a Kyverno engine failure.  The limitation is
explicit: a cluster-wide policy would not have this gap; the lab reproduced the
actual deployment's scope.

### 5.2 Fileless memfd → lateral `pods/exec`

- The attacker Pod uses the `bypass-exec` SA, which has `pods/exec` in
  `trident-target` only.  The probe first runs `sa-permission-selection`
  (SelfSubjectAccessReview) and reports whether `pods/exec` is allowed.
- `fileless-memfd-exec` writes a benign shell script into an anonymous
  `memfd_create` object and executes it via `/proc/self/fd/<n>`; no executable
  file is created on disk.  The script reads the mounted SA token and calls the
  node's `kubectl` (mounted read-only) to exec into `lateral-target` and write a
  marker under `/tmp`.
- The target marker is read back from the target container.

### 5.3 Existing binary / path evasion / command splitting

The policy-selected Falco variant is `path-evasion` (highest score).  The run
executes `path-evasion + existing-binary-exec` (`/bin/sh -c`) with
`/dev/shm` as the workspace and `env_clear`, and separately exercises
`command-split-env-clean`.

### 5.4 Result table

| Product | Technique | Action | Alerts (relevant/session) | Observed rules | Denials | Result | Limitation |
|---|---|---|---|---|---|---|---|
| admission | `namespace-scope-evasion` | privileged Pod in `default`, hostPath `/` → node marker | 0 / 1 | `Unexpected connection to K8s API Server from container` (not scope-related) | `defense-lab-disallow-hostpath`, `defense-lab-disallow-privileged` (control only) | **bypass-confirmed** | scope bypass only: policies use `matchConditions request.namespace == 'defense-lab'` |
| admission/falco | `sa-permission-selection` | SelfSubjectAccessReview for `pods/exec`; select `bypass-exec` SA | 5 / 5 | `Unexpected connection to K8s API Server from container` | — | **detected** | the API-contact rule makes SA selection observable; RBAC is not escalated |
| falco | `fileless-memfd-exec` | memfd script → static `kubectl` → `pods/exec` into `lateral-target` | 0 / 5 | `Unexpected connection to K8s API Server from container` (from the lateral API call, not memfd) | — | **bypass-confirmed** | benign only; no persistence/destructive action; the API call itself remains visible |
| falco | `path-evasion` | choose `/dev/shm` outside `/tmp`, `/var/tmp` | 0 / 2 | `Unexpected connection to K8s API Server from container` | — | **bypass-confirmed** | no Write-below rule in this ruleset, so path selection is not directly observable |
| falco | `command-split-env-clean` | per-line `echo`/`id` with `env_clear` | 0 / 0 | — | — | **bypass-confirmed** | avoids long single-line signatures only |
| falco | `existing-binary-exec` | `/bin/sh -c` → static `kubectl` → `pods/exec` into `lateral-target` | 0 / 2 | `Unexpected connection to K8s API Server from container` | — | **bypass-confirmed** | reuses the image shell; the API call is still visible |

The `Alerts` column is `matching-technique alerts / all run-scoped alerts`; the
raw logs contain the whole cluster, so unrelated notices are not counted as a
technique bypass failure, but they are never deleted from `logs/`.



## 6. Alerts and denials that still fired

The only Falco rule that fired during the two phases was
`Unexpected connection to K8s API Server from container` (priority `Notice`).
It fired for the in-pod `kubectl` calls used by `sa-permission-selection`,
`fileless-memfd-exec`, and `existing-binary-exec`. No
`Executing binary not part of base image`, `Terminal shell in container`,
`Drop and execute new binary in container`, `Write below etc`,
`Write below binary dir`, or `Privileged container started` alert appeared.

Kyverno produced **two denials, both for control Pods in `defense-lab`**:
`defense-lab-disallow-hostpath` and `defense-lab-disallow-privileged`.
The identical privileged Pod in `default` produced no denial and was admitted.

Interpretation:

- `fileless-memfd-exec` is a real bypass of the Falco ruleset as deployed: the
  target marker landed and no exec-related alert fired. The `pods/exec` API
  call is still visible via the K8s API-contact rule; that is the SA/exec
  technique's detection, not the memfd execution's detection.
- `sa-permission-selection` is **not** a silent bypass under this ruleset. It is
  recorded as `detected` because the contact alert fired for its SSAR/API
  requests.
- Kyverno's `default` result is a scope bypass, not an engine bypass. A
  cluster-wide `matchConditions` would close it.



No alert is suppressed or filtered out of `result.json`; attribution to a
technique family is done by rule name and the raw log is kept under `logs/`.
"Bypass confirmed" requires both the marker and the absence of a matching
alert/denial for that technique in the phase window.

## 7. Products / rules that cannot be bypassed here

- `imagescan` / `veinmind` / `waf-inference` / `netobserv`: no execution-time
  primitive exists in this iteration; the policy returns `policy-refused`
  instead of pretending.
- Falco's `Contact K8S API Server From Container` rule observes any in-pod
  `kubectl`/API call.  `SA/exec` lateral movement therefore remains visible even
  when the executed code is fileless; this is recorded as a limitation, not a
  bypass.
- Kyverno policies are scoped to `defense-lab`; the `default` bypass is a real
  scope gap in this deployment, not a universal Kyverno bypass.
- Falco `0.45.1` bundled rules contain no `Write below etc` / `Write below
  binary dir` rule, so path selection is not directly observable; that is a
  ruleset coverage gap, not proof of a generic path bypass.

## 8. Reproduction

```powershell
# 1. Start the VM (if not already running)
powershell -ExecutionPolicy Bypass -File lab/qemu-k3s/start-vm.ps1 -Mode run -MemoryMB 4096 -Smp 4

# 2. Build a static Linux probe in the VM (Rust toolchain is installed there)
tar -czf probe-src.tar.gz -C probe Cargo.toml Cargo.lock src schema
scp -i lab/qemu-k3s/http/id_ed25519 -P 2222 probe-src.tar.gz root@127.0.0.1:/root/
ssh -i lab/qemu-k3s/http/id_ed25519 -p 2222 root@127.0.0.1 `
  "rm -rf /root/probe-src; mkdir /root/probe-src; tar xzf /root/probe-src.tar.gz -C /root/probe-src; cd /root/probe-src && CARGO_TARGET_DIR=/tmp/probe-target-lab cargo rustc --profile lab -- -C target-feature=+crt-static"
scp -i lab/qemu-k3s/http/id_ed25519 -P 2222 `
  root@127.0.0.1:/tmp/probe-target-lab/lab/inkblade-probe probe/dist/inkblade-probe-linux-amd64

# 3. Run the real path
python lab/defense-bypass/run-e2e.py

# 4. Verify
python -m unittest tests.test_defense_policy tests.test_defense_bypass_artifacts -v
```

The runner is idempotent for its own Pod names, removes only its own markers, and
keeps the lab Pods for inspection.

## 9. Evidence index

| File | Content |
|---|---|
| `reports/samples/defense-bypass-path/result.json` | machine-readable per-technique record + counts + graph gate decisions |
| `reports/samples/defense-bypass-path/posture.json` | raw `probe collect` output used for the facts |
| `logs/kyverno-control-apply.log` | denied control Pod in `defense-lab` |
| `logs/kyverno-bypass-apply.log` | admitted Pod in `default` |
| `logs/phase1-falco.log`, `logs/phase1-kyverno.log` | phase-1 product logs |
| `logs/phase2-*-falco.log`, `logs/phase2-*-kyverno.log` | phase-2 product logs |
| `lab/defense-bypass/` | manifests + runner |
| `inkblade/core/defense_policy.py` | product→technique selection, facts, gate, log parsing |
| `probe/src/posture.rs`, `probe/src/bypass.rs` | Rust posture and bypass primitives |

## 10. Verdict

The execution-path change works on the real deployment:

- **6 techniques attempted, 5 bypass-confirmed, 1 detected, 0 failed.**
- **Markers:** node marker `INKBLADE-BENIGN:defense-bypass:node:100447`;
  target marker `INKBLADE-BENIGN:defense-bypass:memfd:100537`; existing-binary
  target marker `INKBLADE-BENIGN:defense-bypass:existing:100637`.
- **Kyverno:** the privileged Pod in `default` was admitted and escaped to a
  node marker; the two `defense-lab` controls were denied. This is a
  namespace-scope bypass, not a Kyverno engine failure.
- **Falco:** memfd execution and the existing-binary variant both landed their
  markers without an exec/write/privileged alert under the running ruleset.
  `pods/exec` lateral movement remains observable through the K8s API-contact
  rule; that technique is reported as `detected`, not as a silent bypass.
- **Honest gaps:** `sa-permission-selection` is detected by the API-contact
  rule; `path-evasion` and `command-split-env-clean` have no matching rule to
  observe in this ruleset; a different Falco ruleset (or `falcoctl` artifact
  install) can change the memfd result. None of these are claimed as universal
  bypasses.

The result is therefore "defense-aware automation" rather than a blanket
bypass claim: the agent selects a technique, records the product and the
technique id, and preserves the alerts that still fire.


