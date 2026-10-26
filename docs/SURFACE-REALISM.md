# Surface realism — 真实部署面与模块可测性

Generated from `trident/profiles/*.json`, `trident/profiles/surface-map.json` and each module's `surfaces` declaration. Re-run: `python tools/render-surface-docs.py`.

> **Rule.** A module is `production-testable` only when every required surface is present in the profile/collection; `conditional` when some required surface is missing or unverified; `no-surface` when no required surface exists. `unknown` at runtime requires an explicit `--probe`. The matrix below uses **profile declarations** (synthetic deployment facts), not a live cluster; `trident surfaces --collect <dir>` recomputes it against real collection output.

## 1. Profile coverage

| Profile | Platform | Default modules | production-testable | conditional | no-surface | Production coverage | Operable coverage | Default-exploitable PoCs |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| `airgapped` | Air-gapped self-managed Kubernetes: local registry, SPIRE id | 249 | 191 | 46 | 12 | **76.71%** | 95.18% | 1 |
| `bare-k8s-gpu` | Self-managed Kubernetes with GPU worker nodes, direct vLLM s | 249 | 182 | 33 | 34 | **73.09%** | 86.35% | 1 |
| `gpu-pooling` | Kubernetes GPU pooling with HAMi/cGPU sharing, SGLang PD dis | 249 | 161 | 43 | 45 | **64.66%** | 81.93% | 2 |
| `managed-ack-tke` | Managed ACK/TKE control plane: no direct etcd or node BMC ac | 249 | 183 | 33 | 33 | **73.49%** | 86.75% | 0 |
| `ray-vllm` | KubeRay control plane with vLLM/SGLang inference, LWS multi- | 249 | 185 | 33 | 31 | **74.3%** | 87.55% | 2 |
| `slurm-hpc` | Bare-metal Slurm HPC cluster: no Kubernetes API, BMC/IB swit | 249 | 44 | 62 | 143 | **17.67%** | 42.57% | 0 |

Production coverage = `default_production_testable / default_enabled`. Quarantined modules (`default_enabled=false`) are excluded from the denominator.

## 2. Quarantined by default (`default_enabled=false`)

| Module | Required surfaces | No-surface in all profiles | Reason |
|---|---|---|---|
| `cxl-memory-security` | config-file:cxl/inventory.json | yes | C 级前瞻项：六个主流画像均无 CXL 面；仅客户实际部署 CXL 时显式启用，默认关闭，不计入芯片渗透能力。 |
| `federated-learning-audit` | http-endpoint:/fl; k8s-object:Deployment/nvflare; k8s-object:Deployment/flower | yes | Component not present in the six mainstream deployment profiles; kept for customers that actually deploy it. |
| `model-watermark-backdoor-audit` | http-endpoint:/watermark; model-file:watermark | yes | Component not present in the six mainstream deployment profiles; kept for customers that actually deploy it. |
| `nvlink-imex-isolation` | config-file:nvswitch/imex.json | no | C 级前瞻项：NVLink/IMEX 仅 GB200/NVL 多节点客户需要；默认关闭，不计入芯片渗透能力。 |
| `post-quantum-tls-audit` | http-endpoint:/tls | yes | Component not present in the six mainstream deployment profiles; kept for customers that actually deploy it. |
| `spdm-pcie-doe` | config-file:spdm/device-export.json | no | C 级前瞻项：SPDM 细项仅在 GB200/NVL 或明确部署 CMA/SPDM 的客户环境启用；默认关闭，不计入芯片渗透能力。 |
| `wasm-runtime-audit` | k8s-object:RuntimeClass/wasm; runtime-agent:wasmtime | yes | Component not present in the six mainstream deployment profiles; kept for customers that actually deploy it. |

### No-surface rows not yet quarantined

| Module | Required surfaces | Owner note |
|---|---|---|
| `data-provenance-audit` | http-endpoint:/provenance/attestation | No surface in all six profiles; kept enabled by a parallel workstream pending its owner's quarantine decision. It is still `no-surface` and cannot run when the surface gate is enabled. |
| `post-quantum-tls-posture` | http-endpoint:/tls | No surface in all six profiles; kept enabled by a parallel workstream pending its owner's quarantine decision. It is still `no-surface` and cannot run when the surface gate is enabled. |
| `wasm-workload-surface` | k8s-object:RuntimeClass/wasm; runtime-agent:wasmtime | No surface in all six profiles; kept enabled by a parallel workstream pending its owner's quarantine decision. It is still `no-surface` and cannot run when the surface gate is enabled. |

Global no-surface rows: **8**; explicitly quarantined: **7**.


These modules remain callable explicitly (`trident run --module ... --probe` or with a real `--collect` / `--profile`). They are excluded from the default chain and from the default coverage denominator, so a green default report no longer implies coverage of an undeployed component. Other `no-surface` rows owned by parallel workstreams remain enabled until their owner applies the same quarantine; their verdict is still `no-surface` and they cannot execute when the surface gate is on.

## 3. Module × profile verdict matrix

Legend: **production-testable** = execute against this profile without extra confirmation; **conditional** = present but missing a required surface or needs collection; **no-surface** = not deployed (skipped, no finding, not counted).

| Module | Required surfaces | `airgapped` | `bare-k8s-gpu` | `gpu-pooling` | `managed-ack-tke` | `ray-vllm` | `slurm-hpc` |
|---|---|---|---|---|---|---|---|
| `admission-crd-subresource-gap` | k8s-object:ValidatingWebhookConfiguration; http-endpoint:/validate | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `admission-gatekeeper-semantics` | k8s-object:ValidatingWebhookConfiguration; http-endpoint:/validate | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `admission-kyverno-semantics` | k8s-object:ValidatingWebhookConfiguration; http-endpoint:/validate | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `admission-webhook-write` | k8s-object:ValidatingWebhookConfiguration; http-endpoint:/validate | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `aigateway-auth-bypass` | http-endpoint:/v1/models; config-file:litellm | conditional | production-testable | conditional | production-testable | production-testable | conditional |
| `aigateway-cache-cross-tenant` | http-endpoint:/v1/models; config-file:litellm; http-endpoint:/v1/chat/completions; k8s-object:Pod | conditional | production-testable | conditional | production-testable | production-testable | conditional |
| `aigateway-fingerprint` | http-endpoint:/v1/models; config-file:litellm | conditional | production-testable | conditional | production-testable | production-testable | conditional |
| `aigateway-guardrail-bypass` | http-endpoint:/v1/models; config-file:litellm | conditional | production-testable | conditional | production-testable | production-testable | conditional |
| `aigateway-log-pii-leak` | http-endpoint:/v1/models; config-file:litellm | conditional | production-testable | conditional | production-testable | production-testable | conditional |
| `aigateway-quota-bypass` | http-endpoint:/v1/models; config-file:litellm | conditional | production-testable | conditional | production-testable | production-testable | conditional |
| `aigateway-route-hijack` | http-endpoint:/v1/models; config-file:litellm | conditional | production-testable | conditional | production-testable | production-testable | conditional |
| `aigateway-upstream-key-exfil` | http-endpoint:/v1/models; config-file:litellm | conditional | production-testable | conditional | production-testable | production-testable | conditional |
| `ambient-mesh-audit` | k8s-object:DaemonSet/ztunnel; runtime-agent:ztunnel; http-endpoint:/healthz/ready | no-surface | no-surface | no-surface | production-testable | no-surface | no-surface |
| `api-server-flood-surface` | k8s-object:APIService; k8s-object:Pod; http-endpoint:/healthz | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `apiservice-hijack` | k8s-object:APIService; http-endpoint:/healthz | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `areal-awex-nccl-injection` | config-file:train; model-file:checkpoint; k8s-object:Pod; runtime-agent:nccl | production-testable | production-testable | production-testable | production-testable | production-testable | conditional |
| `areal-load-pickle` | config-file:train; model-file:checkpoint | production-testable | production-testable | production-testable | production-testable | production-testable | production-testable |
| `areal-setenv-engine-rce` | config-file:train; model-file:checkpoint | production-testable | production-testable | production-testable | production-testable | production-testable | production-testable |
| `attack-path-ranking` | k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `auth-gap-detection` | k8s-object:Pod; http-endpoint:/healthz | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `bmc-ipmi-exposure` | bmc:bmc/redfish | production-testable | production-testable | no-surface | no-surface | no-surface | production-testable |
| `cache-eviction-residue` | http-endpoint:/v1/chat/completions; k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `cache-poison-persistence` | http-endpoint:/v1/chat/completions; k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `cache-salt-policy-audit` | http-endpoint:/v1/chat/completions; k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `cache-timing-sidechannel` | http-endpoint:/v1/chat/completions; k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `cdk-persistence-detect` | k8s-object:APIService; http-endpoint:/healthz; k8s-object:ValidatingWebhookConfiguration; http-endpoint:/validate | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `cdk-techniques` | k8s-object:Pod; http-endpoint:/healthz | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `cert-manager-webhook-tls` | k8s-object:ValidatingWebhookConfiguration; http-endpoint:/validate | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `cgpu-isolation-audit` | k8s-object:DaemonSet/hami-device-plugin; http-endpoint:/metrics; k8s-object:Node; runtime-agent:nvidia-device-plugin | conditional | conditional | production-testable | conditional | conditional | conditional |
| `checkpoint-io-storm` | config-file:train; model-file:checkpoint | production-testable | production-testable | production-testable | production-testable | production-testable | production-testable |
| `checkpoint-optimizer-state-poison` | config-file:train; model-file:checkpoint | production-testable | production-testable | production-testable | production-testable | production-testable | production-testable |
| `checkpoint-shard-poison` | config-file:train; model-file:checkpoint | production-testable | production-testable | production-testable | production-testable | production-testable | production-testable |
| `cis-benchmark-audit` | k8s-object:Node; http-endpoint:/healthz; k8s-object:Pod; http-endpoint::2379; http-endpoint:/v1/models; config-file:vllm; config-file:sglang; config-file:kubelet | production-testable | production-testable | production-testable | production-testable | production-testable | conditional |
| `cloud-bucket-cross-tenant` | http-endpoint:metadata; k8s-object:Pod; config-file:train; model-file:checkpoint | conditional | conditional | conditional | production-testable | conditional | conditional |
| `cloud-integration-fingerprint` | http-endpoint:metadata; k8s-object:Pod; k8s-object:CSIDriver; runtime-agent:csi | conditional | conditional | conditional | conditional | conditional | no-surface |
| `cloud-irsa-trust-wildcard` | http-endpoint:metadata; k8s-object:Pod | conditional | conditional | conditional | production-testable | conditional | no-surface |
| `cloud-role-overprivilege` | http-endpoint:metadata; k8s-object:Pod; config-file:train; model-file:checkpoint | conditional | conditional | conditional | production-testable | conditional | conditional |
| `cloud-sg-imds-exposure` | http-endpoint:metadata; k8s-object:Pod | conditional | conditional | conditional | production-testable | conditional | no-surface |
| `cloud-snapshot-share` | http-endpoint:metadata; k8s-object:Pod | conditional | conditional | conditional | production-testable | conditional | no-surface |
| `cloud-token-harvest` | http-endpoint:metadata; k8s-object:Pod | conditional | conditional | conditional | production-testable | conditional | no-surface |
| `cni-aware-reachability-graph` | k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `cni-plugin-exec` | k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `cni-stack-capability` | k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `collective-communication-surface` | k8s-object:Pod; runtime-agent:nccl | production-testable | production-testable | production-testable | production-testable | production-testable | conditional |
| `combo-signature-static` | k8s-object:Pod; http-endpoint:/healthz | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `confidential-containers-attestation` | k8s-object:RuntimeClass/kata-cc; runtime-agent:kata; config-file:kata; bmc:tpm; config-file:attest | production-testable | production-testable | no-surface | conditional | no-surface | conditional |
| `confidential-containers-audit` | k8s-object:RuntimeClass/kata-cc; runtime-agent:kata; config-file:kata | production-testable | production-testable | no-surface | production-testable | no-surface | no-surface |
| `containerd-shim-escape-detect` | k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `context-limit-bypass` | k8s-object:Pod; http-endpoint:/healthz | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `crd-conversion-webhook` | k8s-object:ValidatingWebhookConfiguration; http-endpoint:/validate | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `csi-node-plugin-escape` | k8s-object:Node; http-endpoint:/healthz; k8s-object:CSIDriver; runtime-agent:csi; k8s-object:Pod | production-testable | production-testable | production-testable | conditional | production-testable | no-surface |
| `csr-approve` | k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `cumulus-nvue-injection` | switch:switch/sonic | production-testable | no-surface | no-surface | no-surface | no-surface | production-testable |
| `cxl-memory-security` | config-file:cxl/inventory.json | no-surface | no-surface | no-surface | no-surface | no-surface | no-surface |
| `data-pipeline-poison` | config-file:train; model-file:checkpoint | production-testable | production-testable | production-testable | production-testable | production-testable | production-testable |
| `data-provenance-audit` | http-endpoint:/provenance/attestation | no-surface | no-surface | no-surface | no-surface | no-surface | no-surface |
| `deepspeed-checkpoint-rce` | config-file:train; model-file:checkpoint | production-testable | production-testable | production-testable | production-testable | production-testable | production-testable |
| `defense-bypass-admission` | k8s-object:ValidatingWebhookConfiguration; http-endpoint:/validate; runtime-agent:runtime-agent; k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | conditional |
| `defense-bypass-agentsmith` | runtime-agent:runtime-agent; k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | conditional |
| `defense-bypass-elkeid` | runtime-agent:runtime-agent; k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | conditional |
| `defense-bypass-falco` | runtime-agent:runtime-agent; k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | conditional |
| `defense-bypass-hostagent` | runtime-agent:runtime-agent; k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | conditional |
| `defense-bypass-imagescan` | runtime-agent:runtime-agent; k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | conditional |
| `defense-bypass-kubearmor` | runtime-agent:runtime-agent; k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | conditional |
| `defense-bypass-netobserv` | runtime-agent:runtime-agent; k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | conditional |
| `defense-bypass-tetragon` | runtime-agent:runtime-agent; k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | conditional |
| `defense-bypass-veinmind` | runtime-agent:runtime-agent; k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | conditional |
| `defense-bypass-waf-inference` | runtime-agent:runtime-agent; k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | conditional |
| `dify-code-node-escape` | http-endpoint:/api; config-file:app | conditional | no-surface | no-surface | conditional | conditional | no-surface |
| `dify-control-plane-failopen` | http-endpoint:/api; config-file:app | conditional | no-surface | no-surface | conditional | conditional | no-surface |
| `dify-local-sandbox-unauth-rce` | http-endpoint:/api; config-file:app | conditional | no-surface | no-surface | conditional | conditional | no-surface |
| `dify-snapshot-cross-tenant-theft` | http-endpoint:/api; config-file:app | conditional | no-surface | no-surface | conditional | conditional | no-surface |
| `dify-stub-token-forgery` | http-endpoint:/api; config-file:app | conditional | no-surface | no-surface | conditional | conditional | no-surface |
| `djev-open-proxy` | k8s-object:Pod; http-endpoint:/healthz | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `dns-service-discovery` | k8s-object:RayCluster; http-endpoint:/dashboard | no-surface | no-surface | no-surface | no-surface | production-testable | no-surface |
| `dpu-ipu-offload` | http-endpoint:/dpu; bmc:bmc/dpu; k8s-object:Node; config-file:iommu | conditional | production-testable | conditional | conditional | conditional | conditional |
| `dpu-smartnic-surface` | http-endpoint:/dpu; bmc:bmc/dpu | no-surface | production-testable | no-surface | no-surface | no-surface | production-testable |
| `driver-reset-trigger` | k8s-object:Node; runtime-agent:nvidia-device-plugin | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `ebpf-runtime-coverage-gap` | k8s-object:Pod; http-endpoint:/healthz | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `escape-primitives` | k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `etcd-direct-access` | k8s-object:Pod; http-endpoint::2379 | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `experiment-tracker-exposure` | http-endpoint:/api; model-file:model | production-testable | conditional | conditional | production-testable | production-testable | conditional |
| `exposure-mapping` | k8s-object:Pod; http-endpoint:/healthz | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `fabric-telemetry-exposure` | switch:switch/fabric | production-testable | no-surface | no-surface | no-surface | no-surface | production-testable |
| `fabric-topology-isolation` | switch:switch/fabric | production-testable | no-surface | no-surface | no-surface | no-surface | production-testable |
| `federated-learning-audit` | http-endpoint:/fl; k8s-object:Deployment/nvflare; k8s-object:Deployment/flower | no-surface | no-surface | no-surface | no-surface | no-surface | no-surface |
| `federated-learning-surface` | http-endpoint:/fl; k8s-object:Deployment | conditional | conditional | conditional | conditional | conditional | no-surface |
| `firmware-signature-inventory` | config-file:firmware/vendor-inventory.json | production-testable | production-testable | no-surface | no-surface | no-surface | production-testable |
| `framework-port-matching` | k8s-object:Pod; http-endpoint:/healthz | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `gang-scheduler-abuse` | k8s-object:Pod; config-file:scheduler | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `gateway-api-ambient-mesh` | k8s-object:DaemonSet/ztunnel; runtime-agent:ztunnel; http-endpoint:/healthz/ready | no-surface | no-surface | no-surface | production-testable | no-surface | no-surface |
| `gitops-secret-read` | k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `gitops-supply-chain` | k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `gpu-cc-attestation-chain` | k8s-object:Node/gpu-0; config-file:attest/gpu-cc.json | production-testable | production-testable | conditional | conditional | conditional | no-surface |
| `gpu-device-cross-namespace` | k8s-object:Node; runtime-agent:nvidia-device-plugin | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `gpu-dra-mig-policy` | k8s-object:Node; runtime-agent:nvidia-device-plugin | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `gpu-driver-firmware-surface` | k8s-object:Node; runtime-agent:nvidia-device-plugin | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `gpu-memory-residue-isolation` | k8s-object:Node/gpu-0; config-file:gpu/sharing.json | conditional | conditional | production-testable | conditional | conditional | no-surface |
| `gpu-metrics-tenant-leak` | k8s-object:Node; runtime-agent:nvidia-device-plugin | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `gpu-network-operator-posture` | switch:switch/fabric; k8s-object:Node; http-endpoint:/healthz; runtime-agent:nvidia-device-plugin | production-testable | conditional | conditional | conditional | conditional | conditional |
| `gpu-operator-config-depth` | k8s-object:Node; runtime-agent:nvidia-device-plugin; k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `gpu-operator-driver-audit` | k8s-object:Node; runtime-agent:nvidia-device-plugin | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `gpu-operator-driver-escape` | k8s-object:Node; runtime-agent:nvidia-device-plugin; k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `gpu-pool-scheduler-unauth` | k8s-object:DaemonSet/hami-device-plugin; http-endpoint:/metrics; k8s-object:Node; runtime-agent:nvidia-device-plugin; k8s-object:Pod; config-file:scheduler | conditional | conditional | production-testable | conditional | conditional | conditional |
| `gpu-tenant-residue` | k8s-object:Node; runtime-agent:nvidia-device-plugin | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `hami-scheduler-auth-gap` | k8s-object:DaemonSet/hami-device-plugin; http-endpoint:/metrics; k8s-object:Pod; config-file:scheduler | conditional | conditional | production-testable | conditional | conditional | conditional |
| `hardware-supply-chain` | k8s-object:Pod; http-endpoint:/healthz | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `hybrid-cloud-egress-pivot` | http-endpoint:metadata; k8s-object:Pod | conditional | conditional | conditional | production-testable | conditional | no-surface |
| `ib-sm-partition-audit` | switch:switch/fabric | production-testable | no-surface | no-surface | no-surface | no-surface | production-testable |
| `ib-subnet-manager-hijack` | switch:switch/fabric | production-testable | no-surface | no-surface | no-surface | no-surface | production-testable |
| `identity-federation-trust-matrix` | k8s-object:Pod; http-endpoint:/healthz | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `image-pull-secret-theft` | k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `impersonate-abuse` | k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `inference-gateway-pd` | k8s-object:LeaderWorkerSet; http-endpoint:/healthz; http-endpoint:/v1/chat/completions; k8s-object:Pod | conditional | conditional | conditional | conditional | production-testable | no-surface |
| `iommu-smmu-config` | config-file:iommu/kernel-cmdline.txt | production-testable | production-testable | no-surface | no-surface | no-surface | production-testable |
| `ipmi-cipher-zero-bypass` | bmc:bmc/redfish | production-testable | production-testable | no-surface | no-surface | no-surface | production-testable |
| `kdigger-admission` | k8s-object:ValidatingWebhookConfiguration; http-endpoint:/validate; k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `kdigger-buckets` | k8s-object:ValidatingWebhookConfiguration; http-endpoint:/validate; k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `kernel-lpe-audit` | config-file:train; model-file:checkpoint; k8s-object:Pod; config-file:audit | production-testable | production-testable | production-testable | production-testable | production-testable | conditional |
| `kube-audit-trail-analysis` | k8s-object:APIService; http-endpoint:/healthz; k8s-object:RayCluster; http-endpoint:/dashboard; k8s-object:CSIDriver; runtime-agent:csi; k8s-object:Pod; config-file:audit | conditional | conditional | conditional | conditional | production-testable | no-surface |
| `kube-bench-cis` | k8s-object:Node; http-endpoint:/healthz; k8s-object:Pod; http-endpoint::2379; config-file:kubelet; config-file:scheduler | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `kubehound-edges` | k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `kubehound-token-edges` | k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `kubehunter-checks` | k8s-object:Node; http-endpoint:/healthz; k8s-object:Pod; http-endpoint::2379 | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `kubelet-10250-exec` | k8s-object:Node; http-endpoint:/healthz | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `kubelet-api-surface` | k8s-object:Node; http-endpoint:/healthz | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `kubelet-gitrepo-exec-detect` | k8s-object:Node; http-endpoint:/healthz | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `kubelet-surface` | k8s-object:Node; http-endpoint:/healthz | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `kuberay-operator-escalation` | k8s-object:RayCluster; http-endpoint:/dashboard | no-surface | no-surface | no-surface | no-surface | production-testable | no-surface |
| `kubernetes-cve-catalog` | k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `kubetrail-collector` | k8s-object:Pod; config-file:audit | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `kubetrail-lpe` | k8s-object:Pod; config-file:audit | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `kubetrail-manifest-secrets` | k8s-object:Pod; config-file:audit | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `kubetrail-persistence` | k8s-object:ValidatingWebhookConfiguration; http-endpoint:/validate; k8s-object:Pod; config-file:audit | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `kubetrail-token-audit` | k8s-object:Pod; config-file:audit | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `kubiscan-risky` | k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `kv-cache-integrity-poison` | http-endpoint:/v1/chat/completions; k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `kv-oom-bomb` | http-endpoint:/v1/chat/completions; k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `litellm-config-update-rce` | http-endpoint:/v1/models; config-file:litellm | conditional | production-testable | conditional | production-testable | production-testable | conditional |
| `litellm-default-key-exfil` | http-endpoint:/v1/models; config-file:litellm | conditional | production-testable | conditional | production-testable | production-testable | conditional |
| `llamafactory-checkpoint-rce` | config-file:train; model-file:checkpoint | production-testable | production-testable | production-testable | production-testable | production-testable | production-testable |
| `long-context-memory-amplification` | http-endpoint:/v1/chat/completions; k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `long-context-training-collective-surface` | config-file:train; model-file:checkpoint; k8s-object:Pod; runtime-agent:nccl | production-testable | production-testable | production-testable | production-testable | production-testable | conditional |
| `long-context-window-exhaustion` | k8s-object:Pod; http-endpoint:/healthz | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `lora-adapter-injection` | k8s-object:Pod; http-endpoint:/healthz | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `lws-leader-endpoint-audit` | k8s-object:LeaderWorkerSet; http-endpoint:/healthz | conditional | conditional | conditional | conditional | production-testable | no-surface |
| `lws-secrets-lateral` | k8s-object:LeaderWorkerSet; http-endpoint:/healthz | conditional | conditional | conditional | conditional | production-testable | no-surface |
| `megatron-checkpoint-rce` | config-file:train; model-file:checkpoint | production-testable | production-testable | production-testable | production-testable | production-testable | production-testable |
| `megatron-deepspeed-config-surface` | config-file:train; model-file:checkpoint | production-testable | production-testable | production-testable | production-testable | production-testable | production-testable |
| `metadata-egress` | http-endpoint:metadata; k8s-object:Pod | conditional | conditional | conditional | production-testable | conditional | no-surface |
| `mig-profile-mismatch` | k8s-object:Node; runtime-agent:nvidia-device-plugin | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `mlflow-model-rce` | http-endpoint:/api; model-file:model | production-testable | conditional | conditional | production-testable | production-testable | conditional |
| `mlflow-trace-write` | http-endpoint:/api; model-file:model | production-testable | conditional | conditional | production-testable | production-testable | conditional |
| `model-registry-exposure` | http-endpoint:/api; model-file:model | production-testable | conditional | conditional | production-testable | production-testable | conditional |
| `model-watermark-backdoor-audit` | http-endpoint:/watermark; model-file:watermark | no-surface | no-surface | no-surface | no-surface | no-surface | no-surface |
| `model-watermark-backdoor-detect` | http-endpoint:/watermark; model-file:model | conditional | conditional | conditional | conditional | conditional | conditional |
| `mps-context-shared` | k8s-object:Node; runtime-agent:nvidia-device-plugin | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `msswift-dataset-pickle-rce` | http-endpoint:/v1/chat/completions; k8s-object:Pod; config-file:train; model-file:checkpoint | production-testable | production-testable | production-testable | production-testable | production-testable | conditional |
| `multi-cloud-imds-credentials` | http-endpoint:metadata; k8s-object:Pod | conditional | conditional | conditional | production-testable | conditional | no-surface |
| `multi-cluster-federation` | k8s-object:Pod; http-endpoint:/healthz | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `multus-sriov-rdma-bypass` | k8s-object:Pod; http-endpoint:/healthz | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `nccl-collective-join` | config-file:train; model-file:checkpoint; k8s-object:Pod; runtime-agent:nccl | production-testable | production-testable | production-testable | production-testable | production-testable | conditional |
| `nccl-port-exhaustion` | k8s-object:Pod; runtime-agent:nccl | production-testable | production-testable | production-testable | production-testable | production-testable | conditional |
| `nccl-straggler-injection` | http-endpoint:/dpu; bmc:bmc/dpu; k8s-object:Pod; runtime-agent:nccl | conditional | production-testable | conditional | conditional | conditional | conditional |
| `network-policy-coverage` | k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `nvidia-toolkit-escape-detect` | k8s-object:Node; runtime-agent:nvidia-device-plugin; k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `nvlink-imex-isolation` | config-file:nvswitch/imex.json | production-testable | production-testable | no-surface | no-surface | no-surface | production-testable |
| `nvswitch-nvlink-topology` | k8s-object:Pod; http-endpoint:/healthz | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `observability-exposure` | http-endpoint:/api; model-file:model; http-endpoint:/metrics; k8s-object:Pod | production-testable | conditional | conditional | production-testable | production-testable | conditional |
| `oidc-issuer-confusion` | k8s-object:Pod; http-endpoint:/healthz | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `open-webui-code-execute-rce` | http-endpoint:/api; config-file:app | conditional | no-surface | no-surface | conditional | conditional | no-surface |
| `open-webui-file-overwrite` | http-endpoint:/api; config-file:app | conditional | no-surface | no-surface | conditional | conditional | no-surface |
| `open-webui-indirect-injection-exec` | http-endpoint:/api; config-file:app | conditional | no-surface | no-surface | conditional | conditional | no-surface |
| `outbound-ssrf` | http-endpoint:metadata; k8s-object:Pod | conditional | conditional | conditional | production-testable | conditional | no-surface |
| `overprivileged-sa-escalation` | k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `pcie-iommu-audit` | k8s-object:Node; config-file:iommu | production-testable | production-testable | conditional | conditional | conditional | conditional |
| `pcie-iommu-dma` | k8s-object:Node; config-file:iommu | production-testable | production-testable | conditional | conditional | conditional | conditional |
| `peirates-primitives` | k8s-object:Node; http-endpoint:/healthz; k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `post-quantum-tls-audit` | http-endpoint:/tls | no-surface | no-surface | no-surface | no-surface | no-surface | no-surface |
| `post-quantum-tls-posture` | http-endpoint:/tls | no-surface | no-surface | no-surface | no-surface | no-surface | no-surface |
| `prefill-decode-kv-channel-unauth` | http-endpoint:/v1/chat/completions; k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `prefix-cache-cross-tenant-leak` | http-endpoint:/v1/chat/completions; k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `pretrain-job-escape` | k8s-object:RayCluster; http-endpoint:/dashboard; config-file:train; model-file:checkpoint; k8s-object:Pod | conditional | conditional | conditional | conditional | production-testable | conditional |
| `privileged-gpu-pod-escape` | k8s-object:Node; runtime-agent:nvidia-device-plugin; k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `privileged-workloads` | k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `python-dangerous-sinks` | k8s-object:Pod; http-endpoint:/healthz | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `rag-vector-injection` | k8s-object:Pod; http-endpoint:/healthz | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `rail-mismatch-forcing` | switch:switch/fabric | production-testable | no-surface | no-surface | no-surface | no-surface | production-testable |
| `ray-control-plane` | k8s-object:RayCluster; http-endpoint:/dashboard | no-surface | no-surface | no-surface | no-surface | production-testable | no-surface |
| `ray-dashboard-job` | k8s-object:RayCluster; http-endpoint:/dashboard | no-surface | no-surface | no-surface | no-surface | production-testable | no-surface |
| `ray-job-marker-rce` | k8s-object:RayCluster; http-endpoint:/dashboard | no-surface | no-surface | no-surface | no-surface | production-testable | no-surface |
| `rbac-bind-verb` | k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `rbac-escalate-verb` | k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `rbac-mapping` | k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `redfish-default-credentials` | bmc:bmc/redfish | production-testable | production-testable | no-surface | no-surface | no-surface | production-testable |
| `remote-kv-pool-isolation` | http-endpoint:/v1/chat/completions; k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `reverse-rbac-lookup` | k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `reward-hacking-detect` | config-file:train; model-file:checkpoint | production-testable | production-testable | production-testable | production-testable | production-testable | production-testable |
| `reward-model-abuse` | config-file:train; model-file:checkpoint | production-testable | production-testable | production-testable | production-testable | production-testable | production-testable |
| `rl-rollout-buffer-poison` | config-file:train; model-file:checkpoint | production-testable | production-testable | production-testable | production-testable | production-testable | production-testable |
| `roce-pfc-storm` | switch:switch/fabric | production-testable | no-surface | no-surface | no-surface | no-surface | production-testable |
| `router-cache-metrics-leak` | http-endpoint:/v1/models; config-file:vllm; http-endpoint:/v1/chat/completions; k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | conditional |
| `runc-escape-detect` | k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `runtime-socket-escape` | k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `sa-token-request` | k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `sandbox-runtime-surface` | k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `scheduler-network-semantics` | k8s-object:Pod; config-file:scheduler | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `secret-scanner` | k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `secure-boot-chain` | bmc:tpm/tpm2; config-file:attest/tpm.json | production-testable | production-testable | no-surface | no-surface | no-surface | production-testable |
| `sft-framework-surface` | config-file:train; model-file:checkpoint | production-testable | production-testable | production-testable | production-testable | production-testable | production-testable |
| `sglang-admin-failopen` | http-endpoint:/admin; config-file:sglang | conditional | conditional | conditional | production-testable | production-testable | no-surface |
| `sglang-omni-profiler-write` | http-endpoint:/v1/models; config-file:sglang | production-testable | production-testable | production-testable | production-testable | production-testable | conditional |
| `sglang-route-poison` | http-endpoint:/route; http-endpoint:/register_dp_rank; config-file:sglang | conditional | conditional | production-testable | conditional | production-testable | no-surface |
| `sglang-weight-exfil` | http-endpoint:/v1/models; model-file:model | production-testable | production-testable | production-testable | production-testable | production-testable | production-testable |
| `sglang-zmq-pickle-rce` | http-endpoint:/v1/models; config-file:sglang | production-testable | production-testable | production-testable | production-testable | production-testable | conditional |
| `shared-volume-weight-copy` | k8s-object:Pod; http-endpoint:/healthz | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `sharp-collective-config` | switch:switch/fabric; k8s-object:Pod; runtime-agent:nccl | production-testable | conditional | conditional | conditional | conditional | conditional |
| `sharp-in-network-poison` | switch:switch/fabric | production-testable | no-surface | no-surface | no-surface | no-surface | production-testable |
| `sharp-session-trust-audit` | switch:switch/fabric | production-testable | no-surface | no-surface | no-surface | no-surface | production-testable |
| `similarity-cache-false-hit` | http-endpoint:/v1/chat/completions; k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `skyrl-dev-pickle-rce` | config-file:train; model-file:checkpoint | production-testable | production-testable | production-testable | production-testable | production-testable | production-testable |
| `skyrl-tinker-hijack` | config-file:train; model-file:checkpoint | production-testable | production-testable | production-testable | production-testable | production-testable | production-testable |
| `slime-weight-pull-poison` | config-file:train; model-file:checkpoint | production-testable | production-testable | production-testable | production-testable | production-testable | production-testable |
| `sonic-config-plane-write` | switch:switch/sonic | production-testable | no-surface | no-surface | no-surface | no-surface | production-testable |
| `sonic-fabric-config-audit` | switch:switch/sonic; switch:switch/fabric | production-testable | no-surface | no-surface | no-surface | no-surface | production-testable |
| `sonic-rsyslog-injection` | switch:switch/sonic | production-testable | no-surface | no-surface | no-surface | no-surface | production-testable |
| `spdm-pcie-doe` | config-file:spdm/device-export.json | production-testable | production-testable | no-surface | no-surface | no-surface | production-testable |
| `spiffe-spire-audit` | k8s-object:Deployment/spire-server; runtime-agent:spire-agent; config-file:spire | production-testable | no-surface | no-surface | no-surface | no-surface | no-surface |
| `spiffe-spire-surface` | k8s-object:Deployment/spire-server; runtime-agent:spire-agent; config-file:spire | production-testable | no-surface | no-surface | no-surface | no-surface | no-surface |
| `ssrf-imds-credential` | http-endpoint:metadata; k8s-object:Pod | conditional | conditional | conditional | production-testable | conditional | no-surface |
| `storage-protocol-csi` | k8s-object:CSIDriver; runtime-agent:csi | production-testable | production-testable | production-testable | conditional | production-testable | no-surface |
| `storage-sharing` | config-file:train; model-file:checkpoint; k8s-object:CSIDriver; runtime-agent:csi | production-testable | production-testable | production-testable | conditional | production-testable | conditional |
| `supply-chain-credential-theft` | k8s-object:Pod; http-endpoint:/healthz | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `supply-chain-pinning` | k8s-object:Pod; http-endpoint:/healthz | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `switch-os-config-surface` | switch:switch/sonic | production-testable | no-surface | no-surface | no-surface | no-surface | production-testable |
| `tokenizer-template-injection` | config-file:train; model-file:checkpoint | production-testable | production-testable | production-testable | production-testable | production-testable | production-testable |
| `torch-weights-bypass-rce` | k8s-object:Pod; http-endpoint:/healthz | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `torchrun-elastic-surface` | k8s-object:Pod; http-endpoint::2379; config-file:train; model-file:checkpoint | production-testable | production-testable | production-testable | production-testable | production-testable | conditional |
| `tpm-attestation-audit` | bmc:tpm; config-file:attest | production-testable | production-testable | no-surface | no-surface | no-surface | production-testable |
| `tpm-measured-boot` | bmc:tpm; config-file:attest | production-testable | production-testable | no-surface | no-surface | no-surface | production-testable |
| `training-data-leak` | config-file:train; model-file:checkpoint | production-testable | production-testable | production-testable | production-testable | production-testable | production-testable |
| `training-silent-corruption` | config-file:train; model-file:checkpoint | production-testable | production-testable | production-testable | production-testable | production-testable | production-testable |
| `trl-serve-dev-mode` | http-endpoint:/v1/models; config-file:vllm; config-file:train; model-file:checkpoint | production-testable | production-testable | production-testable | production-testable | production-testable | conditional |
| `trust-remote-code-supply-chain` | http-endpoint:/v1/models; config-file:vllm | production-testable | production-testable | production-testable | production-testable | production-testable | conditional |
| `unlimited-query-distillation` | k8s-object:Pod; http-endpoint:/healthz | production-testable | production-testable | production-testable | production-testable | production-testable | no-surface |
| `vector-db-exposure` | http-endpoint:/collections | no-surface | no-surface | no-surface | no-surface | production-testable | no-surface |
| `verl-checkpoint-pickle` | config-file:train; model-file:checkpoint | production-testable | production-testable | production-testable | production-testable | production-testable | production-testable |
| `verl-hdfs-command-injection` | k8s-object:RayCluster; http-endpoint:/dashboard; config-file:train; model-file:checkpoint | conditional | conditional | conditional | conditional | production-testable | conditional |
| `vllm-operator-rbac-escalation` | http-endpoint:/v1/models; config-file:vllm; k8s-object:Pod | production-testable | production-testable | production-testable | production-testable | production-testable | conditional |
| `vllm-pickle-pipe-rce` | config-file:vllm; model-file:model | production-testable | production-testable | production-testable | production-testable | production-testable | conditional |
| `vllm-plugin-auth-bypass` | http-endpoint:/v1/models; config-file:vllm | production-testable | production-testable | production-testable | production-testable | production-testable | conditional |
| `vllm-sglang-patch-matrix` | http-endpoint:/v1/models; config-file:vllm; config-file:sglang | production-testable | production-testable | production-testable | production-testable | production-testable | conditional |
| `vllm-surface-fuzz` | http-endpoint:/v1/models; config-file:vllm | production-testable | production-testable | production-testable | production-testable | production-testable | conditional |
| `vllm-timing-oracle` | http-endpoint:/v1/models; config-file:vllm | production-testable | production-testable | production-testable | production-testable | production-testable | conditional |
| `wasm-runtime-audit` | k8s-object:RuntimeClass/wasm; runtime-agent:wasmtime | no-surface | no-surface | no-surface | no-surface | no-surface | no-surface |
| `wasm-workload-surface` | k8s-object:RuntimeClass/wasm; runtime-agent:wasmtime | no-surface | no-surface | no-surface | no-surface | no-surface | no-surface |

## 4. Default-exposed exploit PoCs by profile

`deployment_requirement=default-exposed` means a verified exploit reachable without a non-default setting. Per-profile counts additionally require the owning module to be `production-testable` in that profile.

| Profile | Default-exposed PoCs | IDs |
|---|---:|---|
| `airgapped` | 1 | `cephcsi-httpserver-go-pprof-exposed-l37-regex` |
| `bare-k8s-gpu` | 1 | `cephcsi-httpserver-go-pprof-exposed-l37-regex` |
| `gpu-pooling` | 2 | `CVE-2026-92972`, `cephcsi-httpserver-go-pprof-exposed-l37-regex` |
| `managed-ack-tke` | 0 | — |
| `ray-vllm` | 2 | `CVE-2026-92972`, `cephcsi-httpserver-go-pprof-exposed-l37-regex` |
| `slurm-hpc` | 0 | — |

Global registry counts: `default-exposed`=2, `function-level`=28, `hardware-only`=24, `needs-config`=98. Only `default-exposed` entries enter the “默认可利用” number; `function-level` and `hardware-only` paths are explicitly not service exposure.

## 5. Collect and verify

```powershell
trident collect --profile ray-vllm --kubeconfig .kube/config --target http://127.0.0.1:8000/v1/models --files .\export --hardware .\hw-export
trident surfaces --profile ray-vllm --collect collection
trident run --module sglang-route-poison --profile ray-vllm --collect collection
```

Fixture mode is explicit: `trident collect --fixture --profile ray-vllm`.
Every fixture collection and report section is stamped **FIXTURE DATA — not a production verdict**; fixture mode never counts toward a customer production report.

## 6. Accelerator chip posture (A/B/C boundary)

A/B/C/D necessity tiers are defined in [`CHIP-SECURITY-SCOPE.md`](CHIP-SECURITY-SCOPE.md). Only A (real attack path) counts as chip pentest capability; B is assurance detection; C is research-only and default-disabled; D (silicon lab, physical fault injection, Rowhammer/microarchitectural exploitation) is explicitly out of scope. **C/D are never counted as chip pentest capability.**

A2 (BMC/DPU/IPMI out-of-band takeover) is covered by existing `bmc-ipmi-exposure`, `dpu-smartnic-surface`, `redfish-default-credentials` and `ipmi-cipher-zero-bypass`; this workstream adds the Redfish UpdateService / FirmwareInventory read-only face.

| Module | Tier | Default | Research-only | Required surfaces | `airgapped` | `bare-k8s-gpu` | `gpu-pooling` | `managed-ack-tke` | `ray-vllm` | `slurm-hpc` |
|---|---|---|---|---|---|---|---|---|---|---|
| `cxl-memory-security` | C | off | yes | config-file:cxl/inventory.json | no-surface | no-surface | no-surface | no-surface | no-surface | no-surface |
| `firmware-signature-inventory` | B | on | no | config-file:firmware/vendor-inventory.json | production-testable | production-testable | no-surface | no-surface | no-surface | production-testable |
| `gpu-cc-attestation-chain` | B | on | no | k8s-object:Node/gpu-0; config-file:attest/gpu-cc.json | production-testable | production-testable | conditional | conditional | conditional | no-surface |
| `gpu-memory-residue-isolation` | A | on | no | k8s-object:Node/gpu-0; config-file:gpu/sharing.json | conditional | conditional | production-testable | conditional | conditional | no-surface |
| `iommu-smmu-config` | A | on | no | config-file:iommu/kernel-cmdline.txt | production-testable | production-testable | no-surface | no-surface | no-surface | production-testable |
| `nvlink-imex-isolation` | C | off | yes | config-file:nvswitch/imex.json | production-testable | production-testable | no-surface | no-surface | no-surface | production-testable |
| `secure-boot-chain` | B | on | no | bmc:tpm/tpm2; config-file:attest/tpm.json | production-testable | production-testable | no-surface | no-surface | no-surface | production-testable |
| `spdm-pcie-doe` | C | off | yes | config-file:spdm/device-export.json | production-testable | production-testable | no-surface | no-surface | no-surface | production-testable |

C-tier rows remain callable only with an explicit `--probe` / customer profile; their presence in this matrix is not a claim of production chip coverage.

Snapshot: 256 modules, 6 profiles, 7 quarantined modules, 8 globally no-surface.
