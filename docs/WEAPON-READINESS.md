# Weapon readiness — exposure classification, verification and one-click packs

Generated: `2026-10-26T22:42:20+00:00`. Sources: `inkblade/core/exploit-registry.json` (152 catalog/mining entries), `inkblade/core/zeroday-registry.json` (47 reserve entries), `inkblade/core/data/weapon-packs.json` (reserve packs) and `inkblade/core/data/version-matrix.json` (payload variants).

> **Rules.** `deployment_requirement` is independent of `status`. `default-exposed` means reachable with the vendor's default bind/config (evidence names the address/flag/file:line). `verified` still requires a dynamic reproduction with a proof marker. An exposure-only finding is never promoted to RCE.

## 1. Catalog + mining registry (152 entries)

Counts: `default-exposed`=11, `needs-config`=27, `function-level`=91, `hardware-only`=23; one-click module-backed: **84/152**; payload variants: **150**.

| Component | total | verified | default-exposed | needs-config | function-level | payload variants | one-click |
|---|---:|---:|---:|---:|---:|---:|---:|
| `bmc` | 4 | 0 | 0 | 0 | 0 | 6 | 3/4 |
| `cephcsi` | 2 | 1 | 2 | 0 | 0 | 2 | 1/2 |
| `cgpu` | 1 | 0 | 0 | 0 | 0 | 2 | 1/1 |
| `containerd` | 1 | 0 | 0 | 0 | 0 | 2 | 1/1 |
| `cumulus` | 2 | 0 | 0 | 0 | 0 | 4 | 2/2 |
| `deepspeed` | 15 | 6 | 0 | 0 | 15 | 12 | 6/15 |
| `dify` | 3 | 0 | 0 | 3 | 0 | 6 | 3/3 |
| `dradriver` | 1 | 0 | 0 | 1 | 0 | 0 | 0/1 |
| `gpuoperator` | 2 | 0 | 0 | 2 | 0 | 0 | 0/2 |
| `hami` | 1 | 0 | 0 | 0 | 1 | 2 | 1/1 |
| `juicefscsi` | 1 | 1 | 1 | 0 | 0 | 0 | 1/1 |
| `kuberay` | 1 | 0 | 0 | 1 | 0 | 2 | 1/1 |
| `kubernetes` | 2 | 0 | 0 | 2 | 0 | 4 | 2/2 |
| `kueue` | 1 | 1 | 1 | 0 | 0 | 0 | 1/1 |
| `linux-kernel` | 1 | 0 | 0 | 0 | 0 | 2 | 1/1 |
| `litellm` | 6 | 2 | 0 | 6 | 0 | 12 | 6/6 |
| `llamafactory` | 25 | 4 | 6 | 0 | 19 | 8 | 10/25 |
| `lws` | 1 | 0 | 0 | 1 | 0 | 2 | 1/1 |
| `megatron` | 7 | 2 | 0 | 2 | 5 | 8 | 4/7 |
| `mlflow` | 3 | 2 | 0 | 0 | 3 | 6 | 3/3 |
| `msswift` | 13 | 6 | 0 | 0 | 13 | 12 | 6/13 |
| `nccl` | 1 | 0 | 0 | 0 | 0 | 0 | 0/1 |
| `nvidia` | 4 | 0 | 0 | 0 | 0 | 8 | 4/4 |
| `open-webui` | 3 | 0 | 0 | 3 | 0 | 6 | 3/3 |
| `pytorch` | 1 | 1 | 0 | 0 | 1 | 2 | 1/1 |
| `ray` | 3 | 2 | 0 | 3 | 0 | 6 | 3/3 |
| `runc` | 2 | 0 | 0 | 0 | 0 | 4 | 2/2 |
| `sglang` | 6 | 3 | 1 | 2 | 2 | 12 | 6/6 |
| `sonic` | 3 | 0 | 0 | 0 | 0 | 6 | 3/3 |
| `sonicrestapi` | 1 | 0 | 0 | 0 | 0 | 0 | 0/1 |
| `transformers` | 2 | 2 | 0 | 0 | 2 | 4 | 2/2 |
| `trl` | 25 | 0 | 0 | 0 | 25 | 0 | 0/25 |
| `ucx` | 1 | 0 | 0 | 0 | 0 | 0 | 0/1 |
| `ucxpy` | 1 | 0 | 0 | 0 | 1 | 0 | 0/1 |
| `vllm` | 4 | 3 | 0 | 0 | 3 | 8 | 4/4 |
| `volcano` | 1 | 1 | 0 | 1 | 0 | 0 | 1/1 |
| `wandb` | 1 | 0 | 0 | 0 | 1 | 2 | 1/1 |
| **Total** | **152** | **37** | **11** | **27** | **91** | **150** | **84/152** |

`one-click` = the entry owns a module directory (`module.json` + `template.json`); `inkblade exploit <id> --dry-run` resolves it (reserve packs win, catalog entries are synthesised on demand). Entries without a module stay classified but are not one-click runnable; that is the honest gap, not a hidden failure.

## 2. 0day reserve (novelty-checked entries, all weaponised)

Counts: `default-exposed`=5, `needs-config`=20, `function-level`=21, `hardware-only`=1; modules: **33**; payload variants: **99**; one-click: **47/47**. Note: `zeroday-registry.json` summary reports `reserve`=46 (reserve-eligible) and `reserve_unique`=39 (dedupe-keys); this section counts the 47 entries in state `novelty-checked`, which is the pack-building denominator.

| Component | total | verified | default-exposed | needs-config | function-level | payload variants | one-click |
|---|---:|---:|---:|---:|---:|---:|---:|
| `areal` | 4 | 4 | 0 | 2 | 1 | 9 | 4/4 |
| `cephcsi` | 1 | 1 | 1 | 0 | 0 | 2 | 1/1 |
| `deepspeed` | 6 | 6 | 0 | 0 | 6 | 12 | 6/6 |
| `dify` | 4 | 4 | 1 | 3 | 0 | 8 | 4/4 |
| `djev` | 1 | 1 | 1 | 0 | 0 | 2 | 1/1 |
| `llamafactory` | 2 | 2 | 0 | 0 | 2 | 4 | 2/2 |
| `llm2jev` | 1 | 1 | 0 | 1 | 0 | 2 | 1/1 |
| `megatron` | 1 | 1 | 0 | 0 | 1 | 2 | 1/1 |
| `msswift` | 9 | 9 | 1 | 0 | 8 | 18 | 9/9 |
| `onejev` | 1 | 1 | 0 | 1 | 0 | 2 | 1/1 |
| `open-webui` | 1 | 1 | 0 | 1 | 0 | 2 | 1/1 |
| `openjev` | 1 | 1 | 0 | 1 | 0 | 2 | 1/1 |
| `openrlhf` | 2 | 2 | 0 | 2 | 0 | 4 | 2/2 |
| `sglang-omni` | 1 | 1 | 1 | 0 | 0 | 2 | 1/1 |
| `siliconlab` | 1 | 1 | 0 | 1 | 0 | 2 | 1/1 |
| `skyrl` | 3 | 3 | 0 | 3 | 0 | 6 | 3/3 |
| `slime` | 2 | 2 | 0 | 1 | 1 | 4 | 2/2 |
| `trl` | 1 | 1 | 0 | 1 | 0 | 2 | 1/1 |
| `verl` | 3 | 3 | 0 | 1 | 2 | 6 | 3/3 |
| `vllm` | 1 | 1 | 0 | 1 | 0 | 4 | 1/1 |
| `vllm-jev` | 1 | 1 | 0 | 1 | 0 | 4 | 1/1 |
| **Total** | **47** | **47** | **5** | **20** | **21** | **99** | **47/47** |

Every reserve entry has: one module (11 created in this pass: openrlhf-serve-rm, msswift-trust-remote-code, verl-prime-code-exec, skyrl-fetch-weights-traversal, openrlhf-vllm-env-force, openjev-clef-release-module, msswift-eval-escape, onejev-ssrf, llm2jev-file-read, siliconlab-credential-exfil, msswift-media-local-read), a version-matrix row, >=2 payload variants, a deployment verdict with evidence, and an `inkblade exploit <id>` entry (dry-run + `--real`, backup gate for write modules).

## 3. Default-exposed: the “默认可打” list

These are reachable without a non-default setting. The impact column separates a verified primitive from an exposure-only finding.

| ID | Component | Status | Impact | Evidence |
|---|---|---|---|---|
| `cephcsi-cephcsi-go-bind-all-l255-regex` | `cephcsi` | static-only | exposure only (bind/auth posture; no RCE verified) | cmd/cephcsi.go:255 sets conf.MetricsIP = "0.0.0.0" for the default CSI metrics/pprof mux; no auth middleware is installed on that listener. |
| `cephcsi-httpserver-go-pprof-exposed-l37-regex` | `cephcsi` | verified | verified dynamic primitive | internal/util/httpserver.go:37 registers net/http/pprof on the CSI metrics mux; cmd/cephcsi.go:255 defaults MetricsIP to 0.0.0.0 and the mux has no auth - live GET /debug/pprof/ and /metrics returned 200 without Authorization. |
| `dify-shellctl-unauth-rce` | `dify` | verified | verified reserve primitive | dify-agent/docker/docker-compose.yaml:559 shellctl listens on 0.0.0.0:5004 with no token; POST /v1/jobs/run executes commands and reads tenant homes. |
| `djev-open-proxy` | `djev` | verified | verified reserve primitive | djev/structured_server.py do_POST/do_GET serve 0.0.0.0:8011; API_KEY is optional and the GET management routes never check it. |
| `juicefscsi-controller-manager-go-go-bind-all-l71-regex` | `juicefscsi` | verified | verified dynamic primitive | cmd/app/controller_manager.go:71 BindAddress: "0.0.0.0:8084" and controller-runtime logs secure=false; unauthenticated GET /metrics returned 200 on eth0. |
| `kueue-server-go-pprof-exposed-l30-regex` | `kueue` | verified | verified dynamic primitive | cmd/kueueviz/backend/config/server.go:30 imports net/http/pprof; KUEUEVIZ_AUTH_MODE unset defaults to Disabled and the listener is :::18080 - unauthenticated GET /api/pod/<name> returned 200 with the canary env value. |
| `llamafactory-app-py-bind-all-interfaces-l130-regex` | `llamafactory` | exposure-verified | exposure-verified (bind/auth, no RCE) | src/llamafactory/api/app.py:130 api_host = os.getenv("API_HOST", "0.0.0.0"); the FastAPI app installs no authentication dependency, so the default launch is reachable from every interface. |
| `llamafactory-app-py-go-bind-all-l130-regex` | `llamafactory` | exposure-verified | exposure-verified (bind/auth, no RCE) | src/llamafactory/api/app.py:130 api_host = os.getenv("API_HOST", "0.0.0.0"); default run binds 0.0.0.0 with no auth dependency. |
| `llamafactory-interface-py-bind-all-interfaces-l103-regex` | `llamafactory` | exposure-verified | exposure-verified (bind/auth, no RCE) | src/llamafactory/webui/interface.py:103 server_name = os.getenv("GRADIO_SERVER_NAME", "0.0.0.0"); gradio launch() has no auth by default. |
| `llamafactory-interface-py-bind-all-interfaces-l94-regex` | `llamafactory` | exposure-verified | exposure-verified (bind/auth, no RCE) | src/llamafactory/webui/interface.py:94 server_name = os.getenv("GRADIO_SERVER_NAME", "0.0.0.0"); gradio launch() has no auth by default. |
| `llamafactory-interface-py-go-bind-all-l103-regex` | `llamafactory` | exposure-verified | exposure-verified (bind/auth, no RCE) | src/llamafactory/webui/interface.py:103 binds the web UI to 0.0.0.0 when GRADIO_SERVER_NAME is unset (the vendor default). |
| `llamafactory-interface-py-go-bind-all-l94-regex` | `llamafactory` | exposure-verified | exposure-verified (bind/auth, no RCE) | src/llamafactory/webui/interface.py:94 binds the web UI to 0.0.0.0 when GRADIO_SERVER_NAME is unset (the vendor default). |
| `msswift-media-local-read` | `msswift` | verified | verified reserve primitive | swift/infer_engine/protocol.py:275 opens a request-supplied media path when SWIFT_MEDIA_ALLOWED_DIRS is unset (the default allow-all); served by the normal inference deployment. |
| `CVE-2026-92972` | `sglang` | verified | verified dynamic primitive | sglang/srt/disaggregation/common/conn.py:738 registers PUT /route, /register_dp_rank and /query_dp_ranks on the PD bootstrap aiohttp app with no auth dependency (TCPSite host=self.host); a live unauthenticated PUT /route returned 200 and rewrote prefill_port_table (KV peer redirection). |
| `sglang-omni-admin-failopen` | `sglang-omni` | verified | verified reserve primitive | sglang_omni/http/admin_auth.py:28 returns _no_auth when SGLANG_OMNI_ADMIN_KEY is unset; POST /start_profile accepts event_dir and writes JSONL under it. |

Reading the list:

- **CVE-2026-92972** — unauthenticated PD bootstrap `PUT /route` poisons `prefill_port_table`; the live reproduction returned 200 without credentials.
- **kueueviz / ceph-csi pprof / JuiceFS metrics** — unauthenticated read/exposure on a default listener (`0.0.0.0` or `::`); these are information-disclosure primitives, not code execution.
- **LLaMA-Factory (6 cases)** — `GRADIO_SERVER_NAME`/`API_HOST` default to `0.0.0.0` and the web UI/API have no auth. The real app was launched with the vendor defaults and served an unauthenticated request from a non-loopback address; no RCE is claimed.
- **djev / SGLang-Omni / dify-shellctl / ms-swift media** — reserve entries whose default config omits the key/token or allows the path; verified dynamically for the reserve cohort.

## 4. Verified status and gaps

- Catalog/mining: **37/152 verified RCE** plus **6 exposure-verified** (LLaMA-Factory default bind, no RCE claimed); 87 static-only and 22 unsupported (BMC/switch/DPU/kernel/runtime hardware paths).
- Reserve: **47/47 verified**; all 47 are module-backed and one-click runnable.
- Static-only blockers (catalog/mining): `hygiene-not-exploitable`=26, `pattern-false-positive`=17, `dependency-default-blocks`=16, `requires-full-stack`=12, `requires-k8s`=5, `host-toolchain-missing`=4, `claim-refuted`=3, `advisory-unresolved`=1, `deployment-misconfig`=1, `by-design`=1, `catalog-data-error`=1.
- Verification target `>=50/152` is **not met**: 37 dynamic + 6 exposure = 43. The exact blockers are recorded in each manifest (`static_blocker.category/reason`) and must not be papered over.

Why the remaining static cases did not become verified:

- `requires-full-stack` (12): Dify needs API+DB+sandbox, LiteLLM needs Postgres + a DB-backed virtual key, Open WebUI needs the FastAPI server + DB + session, Megatron is advisory-only, vLLM/SGLang need a GPU model server.
- `host-toolchain-missing` (4): ceph-csi needs librbd/libceph, SonIC REST needs swsscommon/Redis, the DRA driver/GPU operator exec sinks are operator-configured with no tenant input. Three Go cases (kueueviz, Volcano, JuiceFS CSI) were promoted earlier and are counted in the 37.
- `exposure-only` (6): LLaMA-Factory bind defaults were promoted to `exposure-verified` — the real web UI/API listened on `0.0.0.0` and served an unauthenticated request from a non-loopback address. They are counted separately from the 37 RCE-verified entries and never claimed as RCE.
- `requires-k8s` (5): a live API server/kubelet/CRD and pod-create rights are required; the QEMU k3s VM can host a cluster but not the vulnerable historical versions.

## 5. One-click usage

```powershell
inkblade exploit --list                     # readiness table (reserve + registry)
inkblade exploit djev-open-proxy            # dry-run plan: variants, evidence, marker template
inkblade exploit CVE-2026-92972 --real --target http://127.0.0.1:30000
inkblade exploit skyrl-tinker-api --real --target http://127.0.0.1:8000 `
    --backup-target /var/lib/skyrl/checkpoints
```

- `--real` goes through `run_module`, so RoE scope, the surface gate and the backup gate all apply. A write module without `--backup-target` exits **91** before acting.
- Marker proof: every real run writes `exploit-marker.txt` in the run directory (`INKBLADE-<run>` + SHA256). The dry-run prints the marker template and never writes.
- Payload variants are listed in the dry-run output; they are request mutations (`path_suffix`, `path_dotseg`, `method`, `query`, `body_merge`) or file/param payloads for function-level packs.

## 6. Method notes

- Deployment evidence is validated by `inkblade/core/deployment.py::validate_evidence` and by `tools/verify-exploits.py`; empty/generic evidence fails the gate.
- `tools/classify-deployment.py --write` regenerates the two registries; `tools/build-weapon-packs.py --write` regenerates packs + version-matrix rows; this document is rendered by `tools/render-weapon-readiness.py`.
