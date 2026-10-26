# Detection layers / 检测分层

[English](#english) · [中文](#中文)

A generic Kubernetes scanner asks: is this namespace privileged, is that API anonymous, does this
image have a CVE? Useful questions. They miss the parts that make a training cluster a training
cluster.

InkBlade is organised around nine layers where ML infrastructure differs from ordinary Kubernetes:
GPU fabric and collectives, weights and checkpoints, KV caches, tenant residue, and the
combinations that only exist when a framework, an operator and a network plugin meet.

The rule for the last layer: a finding that needs two components to be true is reported once, at
the combination, not twice as two low-severity notes.

---

## English

### 1. Architecture layer

Ten-thousand-GPU topologies, rail alignment, PD-split KV channels, IMEX domains, long-context
windows.

| Detection point | Why it is specific to training/inference clusters | Module keys / chains | Evidence produced |
|---|---|---|---|
| Rail and multi-plane mismatch | GPUs and NICs are cabled per rail; a mismatch silently moves collective traffic onto the wrong plane | `rail-mismatch-forcing`, `fabric-topology-isolation`, `fabric-exhaustion-chain` | Topology snapshot with rail mapping, mismatch finding |
| Prefill/decode KV channel | PD disaggregation sends KV blocks between nodes, often with no auth | `prefill-decode-kv-channel-unauth`, `inference-gateway-pd`, `pd-kv-poison` | Channel reachability, before/after block diff |
| IMEX / ComputeDomain | Cross-node GPU memory sharing by design, outside the process boundary | `nvlink-imex-isolation`, `imex-computedomain-gpu-memory-crossing` | Domain membership and permission snapshot |
| MoE / expert-parallel collectives | Joining an EP group is trust by default; expert shards can be swapped | `nccl-collective-join`, `nccl-straggler-injection` (MoE routing itself is a documented gap) | Group-join record, gradient delta |
| Long-context KV lifetime | Longer windows mean longer residency; eviction policy sets the leak window | `remote-kv-pool-isolation`, `kv-oom-bomb`, `cache-eviction-residue` | Residency samples, eviction residue |
| Multi-cluster federation | Federation trusts across cluster boundaries for identity and weights | `multi-cluster-federation`, `federated-learning-surface` | Federation trust graph |

### 2. Product and framework layer

The framework table is explicit on purpose. Every stack brings its own control plane, its own
serialization choices and its own defaults. A generic Kubernetes check sees none of that.

| Framework | Distinctive detection points | Module keys / chains | Evidence |
|---|---|---|---|
| vLLM | Plugin routes outside the `--api-key` guard; RL control router mounted at `/`; dev-mode weight and cache endpoints; prefix-cache timing oracle | `vllm-plugin-auth-bypass`, `vllm-pickle-pipe-rce`, `vllm-timing-oracle`, `vllm-surface-fuzz` | Route/auth matrix, dev endpoint responses, TTFT samples |
| SGLang | Admin dependency fail-open; profiler `event_dir` write; ZMQ pickle RCE; weight export path | `sglang-admin-failopen`, `sglang-omni-profiler-write`, `sglang-zmq-pickle-rce`, `sglang-weight-exfil` | Endpoint responses, written file hash, export trace |
| TRL | `vllm-serve` binds 0.0.0.0 with dev mode forced and no API key | `trl-serve-dev-mode` | Bind address, unauthenticated dev responses |
| verl | `prime_math` evals model output; `prime_code` execs generated code; checkpoint `recv_pyobj`; HDFS path in `os.system`; vLLM/Ray/KubeRay dev-mode exposure | `verl-prime-code-exec`, `verl-checkpoint-pickle`, `verl-hdfs-command-injection`, `ray-dashboard-job` | Exec marker, loader trace, command echo |
| AReaL | `/set_env` → `/create_engine` → `/call` chain; `/load` with `torch.load(weights_only=False)`; `/awex` arbitrary save plus NCCL join | `areal-setenv-engine-rce`, `areal-load-pickle`, `areal-awex-nccl-injection` | Chain transcript, marker hash, group-join record |
| SkyRL | dev-mode `/update_weights` pickle; `/fetch_weights` traversal; Tinker control plane; r2egym `docker.sock` (signature declared, module pending) | `skyrl-dev-pickle-rce`, `skyrl-fetch-weights-traversal`, `skyrl-tinker-hijack` | Loader trace, write proof, control-plane map |
| OpenRLHF | `serve_rm` unauthenticated reward scoring; `vllm_engine` forces insecure serialization | `openrlhf-serve-rm`, `openrlhf-vllm-env-force` | Scoring response, environment inventory |
| slime | `pull_weights` patch stack writes weights across tenants; debug/resume `torch.load` | `slime-weight-pull-poison` | Weight diff, path resolution |
| LLaMA-Factory | Checkpoint `torch.load`; WebUI exposure | `llamafactory-checkpoint-rce` | Loader trace, HTTP posture |
| ms-swift | `trust_remote_code` default; eval escape via `device_groups`; dataset pickle; media local read | `msswift-trust-remote-code`, `msswift-eval-escape`, `msswift-dataset-pickle-rce`, `msswift-media-local-read` | Import trace, file read proof |
| Megatron-LM | checkpointing `torch.load`; config surface; optimizer shard trust | `megatron-checkpoint-rce`, `megatron-deepspeed-config-surface`, `checkpoint-optimizer-state-poison` | Loader trace, shard diff |
| DeepSpeed | stage3 `torch.load` sinks; AutoEP unsafe conversion | `deepspeed-checkpoint-rce`, `checkpoint-shard-poison` | Loader reachability, conversion trace |
| transformers | `trust_remote_code` dynamic module import; revision drift | `trust-remote-code-supply-chain` | Import trace, revision diff |
| djev / vllm-jev | Open proxy relay; plugin route bypass of the API key | `djev-open-proxy`, `vllm-plugin-auth-bypass` | Relay transcript, auth matrix |
| Agent platforms (Dify, Open WebUI) | Sandbox escape; auth fail-open; default JWE key; cross-tenant snapshot; code-interpreter bypass | `dify-local-sandbox-unauth-rce`, `dify-control-plane-failopen`, `dify-stub-token-forgery`, `dify-snapshot-cross-tenant-theft`, `open-webui-code-execute-rce` | Sandbox probe, forged token, snapshot read |
| Gateways (LiteLLM, Higress, Envoy AI) | Default key exfiltration; config-update RCE; upstream key leakage; cross-tenant cache; guardrail bypass | `litellm-default-key-exfil`, `litellm-config-update-rce`, `aigateway-upstream-key-exfil`, `aigateway-cache-cross-tenant`, `aigateway-guardrail-bypass` | Config diff, key scope, cache hit record |

Gaps stay visible: r2egym is a signature without a module, Higress and Envoy AI are covered by the
generic gateway family rather than per-vendor handlers, and MoE routing has no dedicated check yet.

### 3. Component and operator layer

KubeRay, LWS, Volcano, Kueue, GPU Operator, DRA, CSI, BMC, DPU — the machinery that grants GPU and
storage access.

| Detection point | Why it is specific | Module keys / chains | Evidence |
|---|---|---|---|
| Ray / LWS control | Ray dashboard and LWS leader endpoints run jobs beside training workloads | `ray-dashboard-job`, `ray-control-plane`, `lws-leader-endpoint-audit`, `lws-secrets-lateral` | Job submission record, secret diff |
| GPU Operator and driver | Driver containers and device plugins run privileged on every GPU node | `gpu-operator-driver-audit`, `gpu-operator-driver-escape`, `gpu-operator-config-depth` | DaemonSet and mount audit |
| DRA | Device requests now carry policy, including MIG profiles | `gpu-dra-mig-policy` | ResourceClaim policy snapshot |
| CSI | Model weights and checkpoints live on Ceph or JuiceFS volumes | `csi-node-plugin-escape`, `storage-protocol-csi` | Volume mount graph |
| BMC / Redfish | Node management is a separate plane with separate credentials | `bmc-ipmi-exposure`, `redfish-default-credentials`, `ipmi-cipher-zero-bypass` | Endpoint posture, credential check |
| DPU / SmartNIC | Offload moves policy enforcement onto hardware you may not manage | `dpu-ipu-offload`, `dpu-smartnic-surface` | Offload inventory |

### 4. Network and fabric layer

Policy bypass on non-standard interfaces, dual CNI control planes, InfiniBand and RoCE specifics,
in-network aggregation, collective bootstrap.

| Detection point | Why it is specific | Module keys / chains | Evidence |
|---|---|---|---|
| NetworkPolicy bypass | hostNetwork, SR-IOV and macvlan traffic never reaches the policy hook | `multus-sriov-rdma-bypass`, `network-policy-coverage` | Interface inventory, reachability proof |
| CNI dual control plane | Managed clouds run VPC routing and cluster policy as two systems that drift | `cni-stack-capability`, `cni-aware-reachability-graph`, `vpc-cni-dual-control-plane-lateral` | Reachability graph, drift list |
| IB subnet manager / partitions | The SM is a separate trust domain from Kubernetes | `ib-sm-partition-audit`, `ib-subnet-manager-hijack`, `ib-rdma-collective-injection` | Partition table, membership proof |
| RoCE PFC / ECN | Lossless configuration is global; one bad queue stalls the fabric | `roce-pfc-storm`, `fabric-telemetry-exposure` | PFC counters, queue telemetry |
| SHARP in-network aggregation | Aggregation happens on switches, outside host policy | `sharp-collective-config`, `sharp-in-network-poison`, `sharp-session-trust-audit` | Session table, config diff |
| NCCL bootstrap / straggler | Collective bootstrap is unauthenticated by design | `nccl-collective-join`, `nccl-straggler-injection`, `nccl-port-exhaustion` | Join record, timing skew |
| IMEX / ComputeDomain | Memory sharing across nodes has no policy equivalent | `nvlink-imex-isolation` | Domain scope |
| DNS | Service discovery is the map an attacker needs first | `dns-service-discovery` | Zone and endpoint map |

### 5. Data and weights layer

Checkpoints, optimizer shards, dataset pipelines, HF cache, weight storage, registries.

| Detection point | Why it is specific | Module keys / chains | Evidence |
|---|---|---|---|
| Checkpoint and optimizer shards | Training state is huge, writable and trusted at load time | `checkpoint-shard-poison`, `checkpoint-optimizer-state-poison`, `flat-network-admin-plane-weight-poison` | Shard diff, loader trace |
| Dataset pipelines | webdataset/Arrow parsing is code execution adjacent and rarely reviewed | `msswift-dataset-pickle-rce` (webdataset/Arrow parsers are a documented gap) | Pipeline config, load result |
| HF cache | Shared caches are written by one tenant and read by another | `cache-poison-persistence`, `shared-pvc-supply-chain-poison` | Cache write path, read-back proof |
| Weight storage | Weight buckets are cloud objects with cloud IAM | `skyrl-fetch-weights-traversal`, `sglang-weight-exfil`, `cloud-bucket-cross-tenant` | Object ACL, fetch transcript |
| Model registry | The registry is the last trust gate before deployment | `model-registry-exposure`, `data-provenance-audit` | Registry exposure, signer chain |
| KV and prefix caches | Inference state is data, and data crosses tenants | `prefix-cache-cross-tenant-leak`, `similarity-cache-false-hit`, `remote-kv-pool-isolation` | Cache key scope, hit samples |

### 6. Tenant and isolation layer

MIG and MPS residue, GPU pooling schedulers, cache salt policy, routing metric leakage.

| Detection point | Why it is specific | Module keys / chains | Evidence |
|---|---|---|---|
| MIG / MPS residue | Partitioning is not zeroisation; memory and context can survive | `mig-profile-mismatch`, `mps-context-shared`, `gpu-tenant-residue` | Residue probe, profile map |
| GPU pooling schedulers | HAMi and cGPU schedulers make isolation decisions outside Kubernetes RBAC | `hami-scheduler-auth-gap`, `cgpu-isolation-audit`, `gpu-pool-scheduler-unauth` | Scheduler API posture |
| cache_salt | Per-tenant salt is the only thing separating cache entries | `cache-salt-policy-audit`, `approx-cache-cross-tenant-chain` | Salt config, collision test |
| Routing metric leakage | Router and EPP metrics expose queue depth and cache hit patterns | `router-cache-metrics-leak`, `gpu-metrics-tenant-leak` | Metric scrape, inference |

### 7. Supply chain and identity layer

trust_remote_code, revision pinning, signatures and attestation, SBOM, IRSA/workload identity, IMDS.

| Detection point | Why it is specific | Module keys / chains | Evidence |
|---|---|---|---|
| trust_remote_code | Model loading imports code from the model repo by default | `trust-remote-code-supply-chain`, `msswift-trust-remote-code` | Load trace, imported module |
| Revision pinning | Floating revisions turn a model upgrade into a supply-chain event | `supply-chain-pinning` | Manifest diff |
| Signatures and attestation | TDX/SEV/NVIDIA CC claims gate confidential inference | `gpu-cc-attestation-chain`, `confidential-containers-attestation`, `tpm-attestation-audit` | Verified claim chain |
| SBOM | ML bills of materials are still maturing; most clusters have none | `hardware-supply-chain`, `firmware-signature-inventory` | SBOM export |
| IRSA / workload identity wildcard | A wildcard trust policy turns any pod into a cloud principal | `cloud-irsa-trust-wildcard`, `cloud-cross-tenant-role-assume` | Trust policy graph |
| IMDS | Node metadata is one request away from cloud credentials | `ssrf-imds-credential`, `multi-cloud-imds-credentials`, `cloud-sg-imds-exposure` | Reachability and credential scope |

### 8. Cache security layer

Prefix caches, approximate and semantic caches, salt policy, eviction residue, remote KV pools,
PD channels, router metrics, TTFT side channels.

| Detection point | Why it is specific | Module keys / chains | Evidence |
|---|---|---|---|
| Cross-tenant prefix cache | The same prefix from two tenants may resolve to one entry | `prefix-cache-cross-tenant-leak`, `long-context-cache-leak` | Hit samples, tenant key scope |
| Approximate / semantic cache false hit | Similarity thresholds are tuned for hit rate, not isolation | `similarity-cache-false-hit`, `approx-cache-cross-tenant-chain` | Threshold sweep, leaked fragment |
| cache_salt policy | Salt is per deployment or per tenant; the difference is the whole control | `cache-salt-policy-audit` | Config, collision test |
| Eviction residue | Eviction frees the index, not necessarily the memory | `cache-eviction-residue`, `kv-cache-integrity-poison` | Residue read after eviction |
| Remote KV pool namespace | Mooncake/LMCache pools share namespaces across workloads | `remote-kv-pool-isolation` | Namespace map |
| PD KV channel | Disaggregated serving moves KV blocks between trust domains | `prefill-decode-kv-channel-unauth`, `prefill-decode-kv-inference-manipulation` | Channel auth posture |
| Router (EPP) cache metrics | Hit-rate metrics leak what other tenants asked | `router-cache-metrics-leak` | Scrape and inference |
| TTFT timing side channel | Time-to-first-token shifts when a prefix is already cached | `cache-timing-sidechannel`, `cache-sidechannel-chain` | p95 TTFT, matched prompt pairs |

TTFT judgement rule: same token count, same batch size, alternating prompts, at least 30 samples
per arm. Report only when the p95 difference exceeds the run-to-run noise band and correlates with
cache-hit counters. Otherwise it is load noise, not a finding.

### 9. Cross-combination layer

Single components look fine. The combination is the finding. Fourteen signatures are currently
declared; the runner reports the combination once and suppresses the two component notes.

| Combination | Why it only exists in combination | Module keys / chains | Evidence |
|---|---|---|---|
| vLLM + vllm-jev | The plugin route is fine alone; with the gateway it bypasses API-key auth | `vllm-plugin-auth-bypass` | Route + auth matrix |
| SGLang + slime pull_weights | The patch stack turns weight sync into an unauthenticated write | `sglang-weight-exfil` | Patch inventory, write proof |
| SGLang + LWS PD | Leader routing and the PD KV channel compose into inference manipulation | `inference-gateway-pd`, `lws-leader-endpoint-audit` | Topology + channel test |
| verl/SkyRL + KubeRay | Training actors and Ray dashboard share a flat network | `ray-dashboard-job`, `verl-checkpoint-pickle` | Job record, loader trace |
| vLLM + production-stack operator | Operator RBAC amplifies the vLLM surface | `vllm-operator-rbac-escalation` | Role graph |
| AReaL/SGLang + NCCL/RDMA | Reachable control plane plus trusted collective join | `areal-awex-nccl-injection`, `nccl-collective-join` | Join record, gradient delta |
| Shared PVC + HF cache | Writable cache plus trusted model load | `cache-poison-persistence`, `shared-pvc-supply-chain-poison` | Cache write, load marker |
| Multus + SR-IOV + RDMA | Policy bypass plus direct memory access | `multus-sriov-rdma-bypass` | Interface map |
| llm-d/vLLM PD + NIXL | KV transfer library exposure across trust domains | `prefill-decode-kv-channel-unauth`, `remote-kv-pool-isolation` | Transfer trace |
| EKS VPC-CNI + security groups | Two control planes, one drift | `vpc-cni-dual-control-plane-lateral` | Drift list |
| InferencePool fail-open | Gateway fails open and tenant baseline is missing | `gateway-api-ambient-mesh`, `inference-tenant-isolation-baseline` | Fail-open test |
| GB200 + DRA/IMEX | New hardware defaults to memory sharing | `gpu-dra-mig-policy`, `nvlink-imex-isolation` | Policy + domain |
| Long context + KV reuse | Longer context means more cache reuse across requests | `prefix-cache-cross-tenant-leak`, `long-context-cache-leak` | Reuse samples |
| GPU pooling + MIG residue | Placement plus leftover memory | `gpu-tenant-residue`, `gpu-tenant-residue-chain` | Residue probe |

Deduplication: each combination has a signature. If the combination fires, the component findings it
explains are folded into it. If it does not fire, the component findings stand on their own.

---

## 中文

通用 Kubernetes 扫描器问的是：这个命名空间是不是 privileged，那个 API 是不是匿名可读，这个镜像有没有 CVE。
这些问题有用，但漏掉了训练集群之所以是训练集群的部分。

InkBlade 按九层组织，这九层是 ML 基础设施与普通 Kubernetes 的差异所在：GPU fabric 与集合通信、权重与 checkpoint、
KV 缓存、租户残留，以及只有框架、Operator 与网络插件凑在一起才成立的组合。

最后一层的规则：需要两个组件同时成立才算问题的，只报一次，报在组合上，不拆成两条低危。

### 1. 架构层

万卡拓扑、rail 对齐、PD 分离 KV 通道、IMEX 域、长上下文窗口。

| 检测点 | 为什么训练/推理集群独有 | 模块键 / 链 | 证据产出 |
|---|---|---|---|
| Rail 与多平面错配 | GPU 与网卡按 rail 布线；错配会把集合通信悄悄挤到错误平面 | `rail-mismatch-forcing`、`fabric-topology-isolation`、`fabric-exhaustion-chain` | 带 rail 映射的拓扑快照、错配发现 |
| Prefill/decode KV 通道 | PD 分离要在节点间搬 KV 块，通常没有鉴权 | `prefill-decode-kv-channel-unauth`、`inference-gateway-pd`、`pd-kv-poison` | 通道可达性、篡改前后块差异 |
| IMEX / ComputeDomain | 设计上就允许跨节点共享 GPU 内存，绕过进程边界 | `nvlink-imex-isolation`、`imex-computedomain-gpu-memory-crossing` | 域成员与权限快照 |
| MoE / EP 集合通信 | 加入 EP 组默认被信任；专家分片可被替换 | `nccl-collective-join`、`nccl-straggler-injection`（MoE 路由本身是已记录缺口） | 组加入记录、梯度差异 |
| 长上下文 KV 生命周期 | 窗口越长驻留越久，逐出策略决定泄露窗口 | `remote-kv-pool-isolation`、`kv-oom-bomb`、`cache-eviction-residue` | 驻留采样、逐出残留 |
| 多集群联邦 | 联邦跨集群信任身份与权重 | `multi-cluster-federation`、`federated-learning-surface` | 联邦信任图 |

### 2. 产品 / 框架层

框架这张表是刻意列全的。每个栈有自己的控制面、自己的序列化选择、自己的默认值。通用 Kubernetes 检查一个都看不见。

| 框架 | 特有检测点 | 模块键 / 链 | 证据 |
|---|---|---|---|
| vLLM | 插件路由不在 `--api-key` 保护前缀内；RL 控制路由挂在 `/`；dev-mode 权重与缓存端点；前缀缓存时序侧信道 | `vllm-plugin-auth-bypass`、`vllm-pickle-pipe-rce`、`vllm-timing-oracle`、`vllm-surface-fuzz` | 路由/鉴权矩阵、dev 端点响应、TTFT 采样 |
| SGLang | 管理依赖 fail-open；profiler `event_dir` 写入；ZMQ pickle RCE；权重导出路径 | `sglang-admin-failopen`、`sglang-omni-profiler-write`、`sglang-zmq-pickle-rce`、`sglang-weight-exfil` | 端点响应、写入文件哈希、导出轨迹 |
| TRL | `vllm-serve` 绑 0.0.0.0，强制 dev 模式且无 API key | `trl-serve-dev-mode` | 绑定地址、未鉴权 dev 响应 |
| verl | `prime_math` 对模型输出 eval；`prime_code` 对生成代码 exec；checkpoint `recv_pyobj`；HDFS 路径进 `os.system`；与 vLLM/Ray/KubeRay 组合的 dev-mode 暴露 | `verl-prime-code-exec`、`verl-checkpoint-pickle`、`verl-hdfs-command-injection`、`ray-dashboard-job` | 执行标记、loader 轨迹、命令回显 |
| AReaL | `/set_env` → `/create_engine` → `/call` 链式 RCE；`/load` 走 `torch.load(weights_only=False)`；`/awex` 任意保存 + NCCL 入组 | `areal-setenv-engine-rce`、`areal-load-pickle`、`areal-awex-nccl-injection` | 链路记录、标记哈希、入组记录 |
| SkyRL | dev-mode `/update_weights` 反序列化；`/fetch_weights` 路径穿越；Tinker 控制面；r2egym `docker.sock`（签名已声明，模块待补） | `skyrl-dev-pickle-rce`、`skyrl-fetch-weights-traversal`、`skyrl-tinker-hijack` | loader 轨迹、写入证明、控制面映射 |
| OpenRLHF | `serve_rm` 无鉴权打分；`vllm_engine` 强制不安全序列化 | `openrlhf-serve-rm`、`openrlhf-vllm-env-force` | 打分响应、环境清单 |
| slime | `pull_weights` 补丁栈跨租户写权重；debug/resume `torch.load` | `slime-weight-pull-poison` | 权重差异、路径解析 |
| LLaMA-Factory | checkpoint `torch.load`；WebUI 暴露面 | `llamafactory-checkpoint-rce` | loader 轨迹、HTTP 姿态 |
| ms-swift | 默认 `trust_remote_code`；`device_groups` 触发 eval 逃逸；数据集 pickle；media 本地读 | `msswift-trust-remote-code`、`msswift-eval-escape`、`msswift-dataset-pickle-rce`、`msswift-media-local-read` | 导入轨迹、文件读取证明 |
| Megatron-LM | checkpointing `torch.load`；config 面；优化器分片被信任 | `megatron-checkpoint-rce`、`megatron-deepspeed-config-surface`、`checkpoint-optimizer-state-poison` | loader 轨迹、分片差异 |
| DeepSpeed | stage3 `torch.load` 系列 sink；AutoEP 不安全转换 | `deepspeed-checkpoint-rce`、`checkpoint-shard-poison` | loader 可达性、转换轨迹 |
| transformers | `trust_remote_code` 动态模块导入；revision 漂移 | `trust-remote-code-supply-chain` | 导入轨迹、revision 差异 |
| djev / vllm-jev | 开放代理中继；插件路由绕过 API key | `djev-open-proxy`、`vllm-plugin-auth-bypass` | 中继记录、鉴权矩阵 |
| 智能体平台（Dify、Open WebUI） | 沙箱逃逸；鉴权 fail-open；默认 JWE 密钥；跨租户快照；代码解释器绕过 | `dify-local-sandbox-unauth-rce`、`dify-control-plane-failopen`、`dify-stub-token-forgery`、`dify-snapshot-cross-tenant-theft`、`open-webui-code-execute-rce` | 沙箱探测、伪造令牌、快照读取 |
| 网关（LiteLLM、Higress、Envoy AI） | 默认密钥外泄；配置更新 RCE；上游密钥泄露；跨租户缓存；护栏绕过 | `litellm-default-key-exfil`、`litellm-config-update-rce`、`aigateway-upstream-key-exfil`、`aigateway-cache-cross-tenant`、`aigateway-guardrail-bypass` | 配置差异、密钥范围、缓存命中记录 |

缺口照旧写出来：r2egym 只有签名没有模块；Higress 与 Envoy AI 由通用网关族覆盖，没有逐厂商处理；MoE 路由还没有专门检查。

### 3. 组件 / Operator 层

KubeRay、LWS、Volcano、Kueue、GPU Operator、DRA、CSI、BMC、DPU——发放 GPU 与存储权限的机械部分。

| 检测点 | 为什么独有 | 模块键 / 链 | 证据 |
|---|---|---|---|
| Ray / LWS 控制面 | Ray dashboard 与 LWS leader 端点就在训练负载旁边跑任务 | `ray-dashboard-job`、`ray-control-plane`、`lws-leader-endpoint-audit`、`lws-secrets-lateral` | 任务提交记录、Secret 差异 |
| GPU Operator 与驱动 | 驱动容器与 device plugin 在每个 GPU 节点上以特权运行 | `gpu-operator-driver-audit`、`gpu-operator-driver-escape`、`gpu-operator-config-depth` | DaemonSet 与挂载审计 |
| DRA | 设备请求开始承载策略，包括 MIG profile | `gpu-dra-mig-policy` | ResourceClaim 策略快照 |
| CSI | 权重与 checkpoint 放在 Ceph 或 JuiceFS 卷上 | `csi-node-plugin-escape`、`storage-protocol-csi` | 卷挂载图 |
| BMC / Redfish | 节点管理是另一个平面，另一套凭据 | `bmc-ipmi-exposure`、`redfish-default-credentials`、`ipmi-cipher-zero-bypass` | 端点姿态、凭据检查 |
| DPU / SmartNIC | Offload 把策略执行搬到你不一定管的硬件上 | `dpu-ipu-offload`、`dpu-smartnic-surface` | offload 清单 |

### 4. 网络 / fabric 层

非标准接口上的策略旁路、CNI 双控制面、IB 与 RoCE、在网聚合、集合通信 bootstrap。

| 检测点 | 为什么独有 | 模块键 / 链 | 证据 |
|---|---|---|---|
| NetworkPolicy 旁路 | hostNetwork、SR-IOV、macvlan 流量根本到不了策略钩子 | `multus-sriov-rdma-bypass`、`network-policy-coverage` | 网卡清单、可达性证明 |
| CNI 双控制面 | 托管云把 VPC 路由与集群策略分成两套系统，会漂移 | `cni-stack-capability`、`cni-aware-reachability-graph`、`vpc-cni-dual-control-plane-lateral` | 可达图、漂移清单 |
| IB SM / Partition | SM 是独立于 Kubernetes 的信任域 | `ib-sm-partition-audit`、`ib-subnet-manager-hijack`、`ib-rdma-collective-injection` | Partition 表、成员证明 |
| RoCE PFC / ECN | 无损配置是全局的，一个坏队列能拖住整个 fabric | `roce-pfc-storm`、`fabric-telemetry-exposure` | PFC 计数、队列遥测 |
| SHARP 在网聚合 | 聚合发生在交换机上，主机策略管不到 | `sharp-collective-config`、`sharp-in-network-poison`、`sharp-session-trust-audit` | 会话表、配置差异 |
| NCCL bootstrap / straggler | 集合通信 bootstrap 设计上不鉴权 | `nccl-collective-join`、`nccl-straggler-injection`、`nccl-port-exhaustion` | 加入记录、时序偏差 |
| IMEX / ComputeDomain | 跨节点内存共享没有对应的策略抽象 | `nvlink-imex-isolation` | 域范围 |
| DNS | 服务发现是攻击者最想先拿到的那张图 | `dns-service-discovery` | 区域与端点图 |

### 5. 数据 / 权重层

checkpoint、优化器分片、数据集管道、HF 缓存、权重存储、模型注册表。

| 检测点 | 为什么独有 | 模块键 / 链 | 证据 |
|---|---|---|---|
| Checkpoint 与优化器分片 | 训练状态体量大、可写，而且加载时被信任 | `checkpoint-shard-poison`、`checkpoint-optimizer-state-poison`、`flat-network-admin-plane-weight-poison` | 分片差异、loader 轨迹 |
| 数据集管道 | webdataset/Arrow 解析紧邻代码执行，且少有人审 | `msswift-dataset-pickle-rce`（webdataset/Arrow 解析器是已记录缺口） | 管道配置、加载结果 |
| HF 缓存 | 共享缓存由一个租户写、另一个租户读 | `cache-poison-persistence`、`shared-pvc-supply-chain-poison` | 缓存写入路径、读回证明 |
| 权重存储 | 权重桶是云对象，归云 IAM 管 | `skyrl-fetch-weights-traversal`、`sglang-weight-exfil`、`cloud-bucket-cross-tenant` | 对象 ACL、拉取记录 |
| 模型注册表 | 注册表是部署前最后一道信任闸门 | `model-registry-exposure`、`data-provenance-audit` | 注册表暴露面、签名链 |
| KV 与前缀缓存 | 推理状态就是数据，而数据会跨租户 | `prefix-cache-cross-tenant-leak`、`similarity-cache-false-hit`、`remote-kv-pool-isolation` | 缓存键范围、命中样本 |

### 6. 租户 / 隔离层

MIG 与 MPS 残留、GPU 池化调度器、cache_salt 策略、路由指标泄露。

| 检测点 | 为什么独有 | 模块键 / 链 | 证据 |
|---|---|---|---|
| MIG / MPS 残留 | 分区不等于清零，显存与上下文会留下来 | `mig-profile-mismatch`、`mps-context-shared`、`gpu-tenant-residue` | 残留探测、profile 映射 |
| GPU 池化调度器 | HAMi 与 cGPU 把隔离决策放在 Kubernetes RBAC 之外 | `hami-scheduler-auth-gap`、`cgpu-isolation-audit`、`gpu-pool-scheduler-unauth` | 调度器 API 姿态 |
| cache_salt | 每租户 salt 是缓存条目之间唯一的隔断 | `cache-salt-policy-audit`、`approx-cache-cross-tenant-chain` | salt 配置、碰撞测试 |
| 路由指标泄露 | 路由与 EPP 指标暴露队列深度和缓存命中模式 | `router-cache-metrics-leak`、`gpu-metrics-tenant-leak` | 指标抓取、推断链 |

### 7. 供应链 / 身份层

trust_remote_code、revision 固定、签名与证明、SBOM、IRSA/工作负载身份、IMDS。

| 检测点 | 为什么独有 | 模块键 / 链 | 证据 |
|---|---|---|---|
| trust_remote_code | 加载模型默认会执行模型仓库里的代码 | `trust-remote-code-supply-chain`、`msswift-trust-remote-code` | 加载轨迹、导入模块 |
| revision 固定 | 浮动 revision 让一次模型升级变成供应链事件 | `supply-chain-pinning` | manifest 差异 |
| 签名与证明 | TDX/SEV/NVIDIA CC 声明决定机密推理能不能开 | `gpu-cc-attestation-chain`、`confidential-containers-attestation`、`tpm-attestation-audit` | 校验过的声明链 |
| SBOM | ML 物料清单还在成熟期，多数集群根本没有 | `hardware-supply-chain`、`firmware-signature-inventory` | SBOM 导出 |
| IRSA / 工作负载身份通配 | 通配信任策略能把任意 Pod 变成云主体 | `cloud-irsa-trust-wildcard`、`cloud-cross-tenant-role-assume` | 信任策略图 |
| IMDS | 节点元数据离云凭据只差一个请求 | `ssrf-imds-credential`、`multi-cloud-imds-credentials`、`cloud-sg-imds-exposure` | 可达性与凭据范围 |

### 8. 缓存安全层

前缀缓存、近似与语义缓存、salt 策略、逐出残留、远程 KV 池、PD 通道、路由指标、TTFT 侧信道。

| 检测点 | 为什么独有 | 模块键 / 链 | 证据 |
|---|---|---|---|
| 跨租户前缀缓存 | 两个租户的相同前缀可能命中同一条目 | `prefix-cache-cross-tenant-leak`、`long-context-cache-leak` | 命中样本、租户键范围 |
| 近似 / 语义缓存误命中 | 相似度阈值是按命中率调的，不是按隔离调的 | `similarity-cache-false-hit`、`approx-cache-cross-tenant-chain` | 阈值扫描、泄露片段 |
| cache_salt 策略 | salt 可以按部署或按租户，差别就是整个控制点 | `cache-salt-policy-audit` | 配置、碰撞测试 |
| 逐出残留 | 逐出释放的是索引，不一定是内存 | `cache-eviction-residue`、`kv-cache-integrity-poison` | 逐出后读残留 |
| 远程 KV 池命名空间 | Mooncake/LMCache 池在不同工作负载间共用命名空间 | `remote-kv-pool-isolation` | 命名空间映射 |
| PD KV 通道 | 分离式推理在信任域之间搬 KV 块 | `prefill-decode-kv-channel-unauth`、`prefill-decode-kv-inference-manipulation` | 通道鉴权姿态 |
| 路由（EPP）缓存指标 | 命中率指标会泄露别的租户问过什么 | `router-cache-metrics-leak` | 抓取与推断 |
| TTFT 时序侧信道 | 前缀已缓存时，首 token 时间会变 | `cache-timing-sidechannel`、`cache-sidechannel-chain` | p95 TTFT、配对提示 |

TTFT 判定口径：同样 token 数、同样 batch、交替发送，每组至少 30 个样本。只有当 p95 差异超过同批噪声带、且与缓存命中计数相关时才报。
否则那是负载噪声，不是发现。

### 9. 跨组合层

单个组件看起来都没问题。组合才是发现。当前声明 14 组签名；runner 只报组合一次，并抑制被它解释的两条组件级记录。

| 组合 | 为何只有组合成立 | 模块键 / 链 | 证据 |
|---|---|---|---|
| vLLM + vllm-jev | 插件路由单看没问题，与网关一起就绕过了 API key | `vllm-plugin-auth-bypass` | 路由 + 鉴权矩阵 |
| SGLang + slime pull_weights | 补丁栈把权重同步变成无鉴权写 | `sglang-weight-exfil` | 补丁清单、写入证明 |
| SGLang + LWS PD | leader 路由与 PD KV 通道叠加成推理操纵 | `inference-gateway-pd`、`lws-leader-endpoint-audit` | 拓扑 + 通道测试 |
| verl/SkyRL + KubeRay | 训练 actor 与 Ray dashboard 共享扁平网络 | `ray-dashboard-job`、`verl-checkpoint-pickle` | 任务记录、loader 轨迹 |
| vLLM + production-stack operator | Operator RBAC 放大 vLLM 面 | `vllm-operator-rbac-escalation` | 角色图 |
| AReaL/SGLang + NCCL/RDMA | 控制面可达 + 集合通信被信任 | `areal-awex-nccl-injection`、`nccl-collective-join` | 加入记录、梯度差异 |
| 共享 PVC + HF 缓存 | 缓存可写 + 模型加载被信任 | `cache-poison-persistence`、`shared-pvc-supply-chain-poison` | 缓存写入、加载标记 |
| Multus + SR-IOV + RDMA | 策略旁路 + 直接内存访问 | `multus-sriov-rdma-bypass` | 网卡映射 |
| llm-d/vLLM PD + NIXL | KV 传输库跨信任域暴露 | `prefill-decode-kv-channel-unauth`、`remote-kv-pool-isolation` | 传输记录 |
| EKS VPC-CNI + 安全组 | 两套控制面，一次漂移 | `vpc-cni-dual-control-plane-lateral` | 漂移清单 |
| InferencePool 失败放行 | 网关 fail-open 叠加租户隔离基线缺失 | `gateway-api-ambient-mesh`、`inference-tenant-isolation-baseline` | fail-open 测试 |
| GB200 + DRA/IMEX | 新硬件路线默认开内存共享 | `gpu-dra-mig-policy`、`nvlink-imex-isolation` | 策略 + 域 |
| 长上下文 + KV 复用 | 上下文越长，跨请求复用越多 | `prefix-cache-cross-tenant-leak`、`long-context-cache-leak` | 复用样本 |
| GPU 池化 + MIG 残留 | 放置策略 + 残留显存 | `gpu-tenant-residue`、`gpu-tenant-residue-chain` | 残留探测 |

去重：每组组合有签名。组合成立时，被它解释的组件级发现并入组合；组合不成立时，组件级发现各自独立。
