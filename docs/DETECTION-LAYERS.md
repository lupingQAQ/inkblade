# Detection layers / 检测分层

[English](#english) · [中文](#中文)

A generic Kubernetes scanner asks: is this namespace privileged, is that API anonymous, does this image have a CVE? Useful questions. They miss the parts that make a training cluster a training cluster: GPU fabric and collectives, weights and checkpoints, KV caches, tenant residue, and the combinations that only exist when a framework, an operator and a network plugin meet.

InkBlade is organised around ten layers. Each layer is a set of templates you can run on its own; each template declares what it does, what it looks for and what it produces. The rule for the combination layer: a finding that needs two components to be true is reported once, at the combination, not twice as two low-severity notes.

---

## English

### 1. Architecture layer

**What you can do.** Audit ten-thousand-GPU topologies, verify rail alignment and PD-split channels, map IMEX domains, test collective membership and measure long-context KV lifetime.

**What it detects.** Rail and multi-plane mismatch, unauthenticated prefill/decode KV channels, cross-node GPU memory sharing outside the process boundary, EP group trust by default, KV residency and eviction windows, federation identity and weight trust.

**What it produces.** Topology snapshot with rail mapping, channel reachability and before/after block differences, domain membership and permission snapshots, group-join records and timing skew, residency samples, federation trust graph.

Representative templates: `rail-mismatch-forcing`, `fabric-topology-isolation`, `prefill-decode-kv-channel-unauth`, `pd-kv-poison`, `nvlink-imex-isolation`, `imex-computedomain-gpu-memory-crossing`, `nccl-collective-join`, `nccl-straggler-injection`, `remote-kv-pool-isolation`, `kv-oom-bomb`, `cache-eviction-residue`, `multi-cluster-federation`, `federated-learning-surface`.

### 2. Product and framework layer

**What you can do.** Enumerate the admin and control surfaces of inference frameworks, training frameworks, RL control planes, inference gateways and agent platforms, then test plugin routes, development modes, deserialization sinks and weight export paths.

**What it detects.** vLLM plugin routes outside the `--api-key` guard, the RL control router at `/`, dev-mode weight and cache endpoints and prefix-cache timing; SGLang admin fail-open, profiler `event_dir` writes, ZMQ pickle and weight export; TRL `vllm-serve` on `0.0.0.0`; verl `prime_math` evaluation, `prime_code` execution, checkpoint `recv_pyobj` and HDFS command injection; AReaL `/set_env` → `/create_engine` → `/call`, unsafe `/load` and `/awex` NCCL join; SkyRL dev-mode `/update_weights`, `/fetch_weights` traversal and the Tinker control plane; OpenRLHF unauthenticated `serve_rm` and forced insecure serialization; slime `pull_weights` cross-tenant writes; LLaMA-Factory, Megatron-LM and DeepSpeed checkpoint loaders; ms-swift `trust_remote_code`; transformers dynamic module import; djev / vllm-jev open relay; LiteLLM, Higress and Envoy AI key and config surfaces; Dify and Open WebUI sandboxes and default keys.

**What it produces.** Route and auth matrices, endpoint responses, loader traces, execution markers, written-file hashes, configuration diffs, key scope, cache hit records.

| Framework | Distinctive detection points | Representative keys |
|---|---|---|
| vLLM | Plugin route bypass, RL router, dev endpoints, prefix timing | `vllm-plugin-auth-bypass`, `vllm-pickle-pipe-rce`, `vllm-timing-oracle` |
| SGLang | Admin fail-open, profiler write, ZMQ pickle, weight export | `sglang-admin-failopen`, `sglang-omni-profiler-write`, `sglang-zmq-pickle-rce`, `sglang-weight-exfil` |
| TRL | `vllm-serve` dev mode on 0.0.0.0 | `trl-serve-dev-mode` |
| verl | `prime_math` eval, `prime_code` exec, checkpoint `recv_pyobj`, HDFS injection | `verl-prime-code-exec`, `verl-checkpoint-pickle`, `verl-hdfs-command-injection` |
| AReaL | `set_env` to `create_engine` to `call`, unsafe `/load`, `/awex` NCCL join | `areal-setenv-engine-rce`, `areal-load-pickle`, `areal-awex-nccl-injection` |
| SkyRL | Dev-mode weights, fetch traversal, Tinker control plane | `skyrl-dev-pickle-rce`, `skyrl-fetch-weights-traversal`, `skyrl-tinker-hijack` |
| OpenRLHF | Unauthenticated `serve_rm`, forced insecure serialization | `openrlhf-serve-rm`, `openrlhf-vllm-env-force` |
| slime | Cross-tenant `pull_weights`, debug/resume load | `slime-weight-pull-poison` |
| LLaMA-Factory | Checkpoint load, WebUI exposure | `llamafactory-checkpoint-rce` |
| ms-swift | `trust_remote_code`, eval escape, dataset pickle, media read | `msswift-trust-remote-code`, `msswift-eval-escape`, `msswift-dataset-pickle-rce` |
| Megatron-LM | Checkpointing load, config surface, optimizer shard trust | `megatron-checkpoint-rce`, `megatron-deepspeed-config-surface` |
| DeepSpeed | Stage3 load sinks, AutoEP conversion | `deepspeed-checkpoint-rce`, `checkpoint-shard-poison` |
| transformers | Dynamic module import, revision drift | `trust-remote-code-supply-chain` |
| djev / vllm-jev | Open relay, plugin route bypass | `djev-open-proxy`, `vllm-plugin-auth-bypass` |
| Dify / Open WebUI | Sandbox escape, fail-open auth, default JWE key, cross-tenant snapshot | `dify-local-sandbox-unauth-rce`, `dify-stub-token-forgery`, `open-webui-code-execute-rce` |
| LiteLLM / Higress / Envoy AI | Default key, config RCE, upstream key, cache isolation | `litellm-default-key-exfil`, `litellm-config-update-rce`, `aigateway-upstream-key-exfil` |

### 3. Component and operator layer

**What you can do.** Inspect the machinery that grants GPU and storage access: KubeRay, LWS, GPU Operator, DRA, CSI, BMC and DPU.

**What it detects.** Ray dashboard and LWS leader endpoints that run jobs beside training workloads, privileged driver containers and device plugins, DRA device policy including MIG profiles, CSI node plugin permissions, BMC/Redfish default credentials and IPMI cipher 0, DPU offload that moves policy enforcement off-cluster.

**What it produces.** Job submission records, secret diffs, DaemonSet and mount audits, ResourceClaim policy snapshots, volume mount graphs, endpoint posture, credential checks, offload inventories.

Representative templates: `ray-dashboard-job`, `ray-control-plane`, `lws-leader-endpoint-audit`, `lws-secrets-lateral`, `gpu-operator-driver-audit`, `gpu-operator-driver-escape`, `gpu-dra-mig-policy`, `csi-node-plugin-escape`, `storage-protocol-csi`, `bmc-ipmi-exposure`, `redfish-default-credentials`, `ipmi-cipher-zero-bypass`, `dpu-ipu-offload`, `dpu-smartnic-surface`.

### 4. Network and fabric layer

**What you can do.** Test policy bypass on non-standard interfaces, map dual CNI control planes, and probe InfiniBand, RoCE, SHARP and collective bootstrap.

**What it detects.** hostNetwork, SR-IOV and macvlan traffic that never reaches the policy hook; VPC routing and cluster policy drift; IB subnet manager partitions; RoCE PFC/ECN lossless configuration; SHARP in-network aggregation and session trust; NCCL bootstrap and straggler injection; DNS service discovery.

**What it produces.** Interface inventory, reachability proofs, reachability graphs and drift lists, partition tables and membership proofs, PFC counters and queue telemetry, session tables and config diffs, join records and timing skew.

Representative templates: `multus-sriov-rdma-bypass`, `network-policy-coverage`, `cni-aware-reachability-graph`, `vpc-cni-dual-control-plane-lateral`, `ib-sm-partition-audit`, `ib-subnet-manager-hijack`, `ib-rdma-collective-injection`, `roce-pfc-storm`, `fabric-telemetry-exposure`, `sharp-in-network-poison`, `sharp-session-trust-audit`, `nccl-collective-join`, `nccl-port-exhaustion`, `dns-service-discovery`.

### 5. Data and weights layer

**What you can do.** Check the trust boundary around training state, dataset pipelines, model caches, weight storage and registries.

**What it detects.** Checkpoint and optimizer shards trusted at load time, dataset pickle parsing, shared HF caches written by one tenant and read by another, weight buckets governed by cloud IAM, model registry exposure, KV and prefix cache entries crossing tenants.

**What it produces.** Shard diffs and loader traces, pipeline configuration and load results, cache write paths and read-back proofs, object ACLs and fetch transcripts, signer chains, cache key scope and hit samples.

Representative templates: `checkpoint-shard-poison`, `checkpoint-optimizer-state-poison`, `flat-network-admin-plane-weight-poison`, `msswift-dataset-pickle-rce`, `cache-poison-persistence`, `shared-pvc-supply-chain-poison`, `skyrl-fetch-weights-traversal`, `sglang-weight-exfil`, `cloud-bucket-cross-tenant`, `model-registry-exposure`, `data-provenance-audit`, `prefix-cache-cross-tenant-leak`, `similarity-cache-false-hit`, `remote-kv-pool-isolation`.

### 6. Tenant and isolation layer

**What you can do.** Measure how well GPU partitioning and pooling schedulers isolate tenants, and check cache salt and routing metrics.

**What it detects.** MIG and MPS residue in memory and context, HAMi and cGPU isolation decisions outside Kubernetes RBAC, missing or deployment-wide `cache_salt`, router and EPP metrics that expose queue depth and hit patterns.

**What it produces.** Residue samples, profile maps, scheduler API posture, salt configuration and collision tests, metric scrapes and inference results.

Representative templates: `mig-profile-mismatch`, `mps-context-shared`, `gpu-tenant-residue`, `hami-scheduler-auth-gap`, `cgpu-isolation-audit`, `gpu-pool-scheduler-unauth`, `cache-salt-policy-audit`, `approx-cache-cross-tenant-chain`, `router-cache-metrics-leak`, `gpu-metrics-tenant-leak`.

### 7. Supply chain and identity layer

**What you can do.** Verify model-code trust, revision pinning, attestation chains, bills of materials and cloud identity.

**What it detects.** `trust_remote_code` and custom modeling files that execute at load time, floating revisions, TDX/SEV/NVIDIA CC claims, ML SBOM coverage, IRSA and workload identity wildcards, IMDS reachability, credentials that coexist inside a Pod.

**What it produces.** Import traces and file hashes, commit/revision comparison, verified claim chains and policy assertions, material lists and missing items, trust policy graphs, IMDS reachability and credential scope.

Representative templates: `trust-remote-code-supply-chain`, `msswift-trust-remote-code`, `supply-chain-pinning`, `gpu-cc-attestation-chain`, `confidential-containers-attestation`, `tpm-attestation-audit`, `ml-bom-coverage`, `image-sbom-provenance`, `cloud-irsa-trust-wildcard`, `imds-credential-reachability`, `service-account-token-exposure`, `cloud-credential-in-pod`.

### 8. Cache security layer

**What you can do.** Test tenant isolation, hit boundaries and eviction behaviour of inference caches, and measure timing side channels.

**What it detects.** Cross-tenant prefix cache reuse, approximate and semantic cache false hits, eviction residue, remote KV pool namespaces, PD KV channels, EPP cache metrics, TTFT timing.

**What it produces.** Cache keys and hit samples, similarity scores and response differences, reads before and after eviction, pool endpoints and tenant labels, timing samples and statistical deviation.

Representative templates: `prefix-cache-cross-tenant-leak`, `long-context-cache-leak`, `similarity-cache-false-hit`, `approx-cache-cross-tenant-chain`, `cache-salt-policy-audit`, `cache-eviction-residue`, `kv-cache-integrity-poison`, `remote-kv-pool-isolation`, `prefill-decode-kv-channel-unauth`, `router-cache-metrics-leak`, `cache-timing-sidechannel`, `cache-sidechannel-chain`.

TTFT judgement rule: same token count, same batch size, alternating prompts, at least 30 samples per arm. Report only when the p95 difference exceeds the run-to-run noise band and correlates with cache-hit counters.

### 9. Cross-combination layer

**What you can do.** Assemble findings that only exist when two or three components meet, attach preconditions and keep one record per combination.

**What it detects.** Fourteen declared signatures, including plugin auth plus weight export, IMEX plus ComputeDomain plus GPU memory, long context plus prefix reuse, GPU tenant residue plus node escape, network bypass plus control plane, cloud identity plus weight bucket.

**What it produces.** The combination chain, one evidence anchor per step, preconditions, and a fix order that removes the root cause instead of adding another control.

| Combination | Why it only exists in combination | Representative keys |
|---|---|---|
| vLLM + vllm-jev | The plugin route is fine alone; with the gateway it bypasses API-key auth | `vllm-plugin-auth-bypass` |
| SGLang + slime `pull_weights` | The patch stack turns weight sync into an unauthenticated write | `sglang-weight-exfil` |
| SGLang + LWS PD | Leader routing and the PD KV channel compose into inference manipulation | `inference-gateway-pd`, `lws-leader-endpoint-audit` |
| verl/SkyRL + KubeRay | Training actors and the Ray dashboard share a flat network | `ray-dashboard-job`, `verl-checkpoint-pickle` |
| vLLM + production-stack operator | Operator RBAC amplifies the vLLM surface | `vllm-operator-rbac-escalation` |
| AReaL/SGLang + NCCL/RDMA | Reachable control plane plus trusted collective join | `areal-awex-nccl-injection`, `nccl-collective-join` |
| Shared PVC + HF cache | Writable cache plus trusted model load | `cache-poison-persistence`, `shared-pvc-supply-chain-poison` |
| Multus + SR-IOV + RDMA | Policy bypass plus direct memory access | `multus-sriov-rdma-bypass` |
| llm-d/vLLM PD + NIXL | KV transfer library exposed across trust domains | `prefill-decode-kv-channel-unauth`, `remote-kv-pool-isolation` |
| EKS VPC-CNI + security groups | Two control planes, one drift | `vpc-cni-dual-control-plane-lateral` |
| InferencePool fail-open | Gateway fails open and the tenant baseline is missing | `gateway-api-ambient-mesh`, `inference-tenant-isolation-baseline` |
| GB200 + DRA/IMEX | New hardware defaults to memory sharing | `gpu-dra-mig-policy`, `nvlink-imex-isolation` |
| Long context + KV reuse | Longer context means more cache reuse across requests | `prefix-cache-cross-tenant-leak`, `long-context-cache-leak` |
| GPU pooling + MIG residue | Placement plus leftover memory | `gpu-tenant-residue`, `gpu-tenant-residue-chain` |

Deduplication: each combination has a signature. If the combination fires, the component findings it explains are folded into it. If it does not fire, the component findings stand on their own.

### 10. Defense bypass layer

**What you can do.** Measure whether the defender sees benign authorized activity, then turn the result into rules, configuration changes and replay cases.

**What it detects.** HIDS agent and driver fingerprints, runtime policy degradation, admission exemptions and mutation order, image-scan layer coverage, host-agent offline windows, WAF normalization differences, network visibility sampling gaps.

**What it produces.** For every technique: **detected**, **blind spot** and **hardening advice**, plus a rule pack the defender can load and replay.

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

Blind spots feed rule packs directly: Kyverno/Gatekeeper for admission, Sigma for process/file/DNS telemetry, Falco/Tetragon for runtime, Suricata/WAF for network and request normalization. The modules use benign markers only; they do not carry malware, persist, disable security products or provide evasion instructions.

---

## 中文

通用 Kubernetes 扫描器问的是：这个命名空间是不是 privileged，那个 API 是不是匿名可读，这个镜像有没有 CVE。这些问题有用，但漏掉了训练集群之所以是训练集群的部分：GPU fabric 与集合通信、权重与 checkpoint、KV 缓存、租户残留，以及只有框架、Operator 与网络插件凑在一起才成立的组合。

InkBlade 的检测模型共十层。每一层都是一组可独立执行的模板；每个模板都声明自己做什么、检测什么、产出什么。组合层的规则：需要两个组件同时成立才算问题的，只报一次，报在组合上，不拆成两条低危。

### 1. 架构层

**能做什么。** 审计万卡拓扑，验证 rail 对齐与 PD 分离通道，测绘 IMEX 域，测试集合通信入组，度量长上下文 KV 生命周期。

**检测什么。** rail 与多平面错配、无鉴权的 prefill/decode KV 通道、跨节点 GPU 内存共享越过进程边界、EP 组默认信任、KV 驻留与逐出窗口、联邦身份与权重信任。

**产出什么。** 带 rail 映射的拓扑快照、通道可达性与篡改前后块差异、域成员与权限快照、组加入记录与时序偏差、驻留采样、联邦信任图。

代表模板：`rail-mismatch-forcing`、`fabric-topology-isolation`、`prefill-decode-kv-channel-unauth`、`pd-kv-poison`、`nvlink-imex-isolation`、`imex-computedomain-gpu-memory-crossing`、`nccl-collective-join`、`nccl-straggler-injection`、`remote-kv-pool-isolation`、`kv-oom-bomb`、`cache-eviction-residue`、`multi-cluster-federation`、`federated-learning-surface`。

### 2. 产品 / 框架层

**能做什么。** 枚举推理框架、训练框架、RL 控制面、推理网关与 Agent 平台的管理面，测试插件路由、开发模式、反序列化 sink 与权重导出路径。

**检测什么。** vLLM 插件路由在 `--api-key` 保护之外、RL 控制路由挂在 `/`、dev-mode 权重与缓存端点、前缀缓存时序；SGLang 管理面 fail-open、profiler `event_dir` 写入、ZMQ pickle、权重导出；TRL `vllm-serve` 绑 `0.0.0.0`；verl 的 `prime_math` eval、`prime_code` exec、checkpoint `recv_pyobj`、HDFS 命令注入；AReaL 的 `/set_env` → `/create_engine` → `/call`、不安全 `/load`、`/awex` NCCL 入组；SkyRL dev-mode `/update_weights`、`/fetch_weights` 穿越、Tinker 控制面；OpenRLHF 无鉴权 `serve_rm` 与强制不安全序列化；slime `pull_weights` 跨租户写入；LLaMA-Factory、Megatron-LM、DeepSpeed 的 checkpoint loader；ms-swift 的 `trust_remote_code`；transformers 动态模块导入；djev / vllm-jev 开放中继；LiteLLM、Higress、Envoy AI 的密钥与配置面；Dify 与 Open WebUI 的沙箱和默认密钥。

**产出什么。** 路由与鉴权矩阵、端点响应、loader 轨迹、执行 marker、写入文件哈希、配置差异、密钥作用域、缓存命中记录。

| 框架 | 特有检测点 | 代表模板 |
|---|---|---|
| vLLM | 插件路由绕过、RL 路由、dev 端点、前缀时序 | `vllm-plugin-auth-bypass`、`vllm-pickle-pipe-rce`、`vllm-timing-oracle` |
| SGLang | 管理面 fail-open、profiler 写入、ZMQ pickle、权重导出 | `sglang-admin-failopen`、`sglang-omni-profiler-write`、`sglang-zmq-pickle-rce`、`sglang-weight-exfil` |
| TRL | `vllm-serve` 在 0.0.0.0 上开 dev | `trl-serve-dev-mode` |
| verl | `prime_math` eval、`prime_code` exec、checkpoint `recv_pyobj`、HDFS 注入 | `verl-prime-code-exec`、`verl-checkpoint-pickle`、`verl-hdfs-command-injection` |
| AReaL | `set_env` 到 `create_engine` 到 `call`、不安全 `/load`、`/awex` NCCL 入组 | `areal-setenv-engine-rce`、`areal-load-pickle`、`areal-awex-nccl-injection` |
| SkyRL | dev 权重、fetch 穿越、Tinker 控制面 | `skyrl-dev-pickle-rce`、`skyrl-fetch-weights-traversal`、`skyrl-tinker-hijack` |
| OpenRLHF | 无鉴权 `serve_rm`、强制不安全序列化 | `openrlhf-serve-rm`、`openrlhf-vllm-env-force` |
| slime | 跨租户 `pull_weights`、debug/resume 加载 | `slime-weight-pull-poison` |
| LLaMA-Factory | checkpoint 加载、WebUI 暴露 | `llamafactory-checkpoint-rce` |
| ms-swift | `trust_remote_code`、eval 逃逸、数据集 pickle、media 读取 | `msswift-trust-remote-code`、`msswift-eval-escape`、`msswift-dataset-pickle-rce` |
| Megatron-LM | checkpointing 加载、config 面、优化器分片信任 | `megatron-checkpoint-rce`、`megatron-deepspeed-config-surface` |
| DeepSpeed | stage3 加载 sink、AutoEP 转换 | `deepspeed-checkpoint-rce`、`checkpoint-shard-poison` |
| transformers | 动态模块导入、revision 漂移 | `trust-remote-code-supply-chain` |
| djev / vllm-jev | 开放中继、插件路由绕过 | `djev-open-proxy`、`vllm-plugin-auth-bypass` |
| Dify / Open WebUI | 沙箱逃逸、fail-open 鉴权、默认 JWE 密钥、跨租户快照 | `dify-local-sandbox-unauth-rce`、`dify-stub-token-forgery`、`open-webui-code-execute-rce` |
| LiteLLM / Higress / Envoy AI | 默认密钥、配置 RCE、上游密钥、缓存隔离 | `litellm-default-key-exfil`、`litellm-config-update-rce`、`aigateway-upstream-key-exfil` |

### 3. 组件 / Operator 层

**能做什么。** 检查发放 GPU 与存储权限的机械部分：KubeRay、LWS、GPU Operator、DRA、CSI、BMC 与 DPU。

**检测什么。** Ray dashboard 与 LWS leader 端点在训练负载旁边跑任务、特权驱动容器与 device plugin、DRA 设备策略（含 MIG profile）、CSI 节点插件权限、BMC/Redfish 默认凭据与 IPMI cipher 0、DPU offload 把策略执行移出集群。

**产出什么。** 任务提交记录、Secret 差异、DaemonSet 与挂载审计、ResourceClaim 策略快照、卷挂载图、端点态势、凭据检查、offload 清单。

代表模板：`ray-dashboard-job`、`ray-control-plane`、`lws-leader-endpoint-audit`、`lws-secrets-lateral`、`gpu-operator-driver-audit`、`gpu-operator-driver-escape`、`gpu-dra-mig-policy`、`csi-node-plugin-escape`、`storage-protocol-csi`、`bmc-ipmi-exposure`、`redfish-default-credentials`、`ipmi-cipher-zero-bypass`、`dpu-ipu-offload`、`dpu-smartnic-surface`。

### 4. 网络 / fabric 层

**能做什么。** 测试非标准接口上的策略旁路，测绘双 CNI 控制面，探测 InfiniBand、RoCE、SHARP 与集合通信 bootstrap。

**检测什么。** hostNetwork、SR-IOV、macvlan 流量绕过策略钩子；VPC 路由与集群策略漂移；IB 子网管理器分区；RoCE PFC/ECN 无损配置；SHARP 在网聚合与会话信任；NCCL bootstrap 与 straggler 注入；DNS 服务发现。

**产出什么。** 接口清单、可达性证明、可达图与漂移清单、分区表与成员证明、PFC 计数与队列遥测、会话表与配置差异、入组记录与时序偏斜。

代表模板：`multus-sriov-rdma-bypass`、`network-policy-coverage`、`cni-aware-reachability-graph`、`vpc-cni-dual-control-plane-lateral`、`ib-sm-partition-audit`、`ib-subnet-manager-hijack`、`ib-rdma-collective-injection`、`roce-pfc-storm`、`fabric-telemetry-exposure`、`sharp-in-network-poison`、`sharp-session-trust-audit`、`nccl-collective-join`、`nccl-port-exhaustion`、`dns-service-discovery`。

### 5. 数据 / 权重层

**能做什么。** 检查训练状态、数据集管道、模型缓存、权重存储与注册表的信任边界。

**检测什么。** checkpoint 与优化器分片在加载时被信任、数据集 pickle 解析、共享 HF 缓存被一个租户写另一个租户读、权重桶由云 IAM 管理、模型注册表暴露面、KV 与前缀缓存跨租户。

**产出什么。** 分片差异与 loader 轨迹、管道配置与加载结果、缓存写入路径与读回证明、对象 ACL 与拉取转录、签名链、缓存键作用域与命中样本。

代表模板：`checkpoint-shard-poison`、`checkpoint-optimizer-state-poison`、`flat-network-admin-plane-weight-poison`、`msswift-dataset-pickle-rce`、`cache-poison-persistence`、`shared-pvc-supply-chain-poison`、`skyrl-fetch-weights-traversal`、`sglang-weight-exfil`、`cloud-bucket-cross-tenant`、`model-registry-exposure`、`data-provenance-audit`、`prefix-cache-cross-tenant-leak`、`similarity-cache-false-hit`、`remote-kv-pool-isolation`。

### 6. 租户 / 隔离层

**能做什么。** 度量 GPU 分区与池化调度器的隔离效果，检查缓存 salt 与路由指标。

**检测什么。** MIG 与 MPS 在显存和上下文中的残留、HAMi 与 cGPU 在 Kubernetes RBAC 之外的隔离决策、`cache_salt` 缺失或按部署复用、Router 与 EPP 指标暴露队列深度和命中模式。

**产出什么。** 残留样本、profile 映射、调度器 API 态势、salt 配置与碰撞测试、指标抓取与推断结果。

代表模板：`mig-profile-mismatch`、`mps-context-shared`、`gpu-tenant-residue`、`hami-scheduler-auth-gap`、`cgpu-isolation-audit`、`gpu-pool-scheduler-unauth`、`cache-salt-policy-audit`、`approx-cache-cross-tenant-chain`、`router-cache-metrics-leak`、`gpu-metrics-tenant-leak`。

### 7. 供应链 / 身份层

**能做什么。** 核验模型代码信任、revision 固定、证明链、物料清单与云身份。

**检测什么。** `trust_remote_code` 与自定义 modeling 文件在加载时执行、浮动 revision、TDX/SEV/NVIDIA CC 声明、ML SBOM 覆盖、IRSA 与工作负载身份通配、IMDS 可达性、Pod 内并存的凭据。

**产出什么。** 导入轨迹与文件哈希、commit/revision 对照、已校验的证明链与策略断言、物料清单与缺失项、信任策略图、IMDS 可达性与凭据作用域。

代表模板：`trust-remote-code-supply-chain`、`msswift-trust-remote-code`、`supply-chain-pinning`、`gpu-cc-attestation-chain`、`confidential-containers-attestation`、`tpm-attestation-audit`、`ml-bom-coverage`、`image-sbom-provenance`、`cloud-irsa-trust-wildcard`、`imds-credential-reachability`、`service-account-token-exposure`、`cloud-credential-in-pod`。

### 8. 缓存安全层

**能做什么。** 测试推理缓存的租户隔离、命中边界与逐出行为，测量时序侧信道。

**检测什么。** 跨租户前缀缓存复用、近似与语义缓存误命中、逐出残留、远程 KV 池命名空间、PD KV 通道、EPP 缓存指标、TTFT 时序。

**产出什么。** 缓存键与命中样本、相似度分数与响应差异、逐出前后读取结果、池端点与租户标签、时序样本与统计偏差。

代表模板：`prefix-cache-cross-tenant-leak`、`long-context-cache-leak`、`similarity-cache-false-hit`、`approx-cache-cross-tenant-chain`、`cache-salt-policy-audit`、`cache-eviction-residue`、`kv-cache-integrity-poison`、`remote-kv-pool-isolation`、`prefill-decode-kv-channel-unauth`、`router-cache-metrics-leak`、`cache-timing-sidechannel`、`cache-sidechannel-chain`。

TTFT 判定口径：同样 token 数、同样 batch、交替发送，每组至少 30 个样本。只有当 p95 差异超过同批噪声带、且与缓存命中计数相关时才报。

### 9. 跨组合层

**能做什么。** 把只在组合下成立的发现装配成一条链，标注前置条件，每个组合只保留一条记录。

**检测什么。** 14 组已声明签名，包括插件鉴权 + 权重导出、IMEX + ComputeDomain + GPU 内存、长上下文 + 前缀复用、GPU 租户残留 + 节点逃逸、网络旁路 + 控制面、云身份 + 权重桶。

**产出什么。** 组合链、每步一个证据锚、前置条件，以及移除根因而非叠加另一个控制的修复顺序。

| 组合 | 为何只有组合成立 | 代表模板 |
|---|---|---|
| vLLM + vllm-jev | 插件路由单看没问题，与网关一起就绕过 API key | `vllm-plugin-auth-bypass` |
| SGLang + slime `pull_weights` | 补丁栈把权重同步变成无鉴权写 | `sglang-weight-exfil` |
| SGLang + LWS PD | leader 路由与 PD KV 通道叠加成推理操纵 | `inference-gateway-pd`、`lws-leader-endpoint-audit` |
| verl/SkyRL + KubeRay | 训练 actor 与 Ray dashboard 共享扁平网络 | `ray-dashboard-job`、`verl-checkpoint-pickle` |
| vLLM + production-stack operator | Operator RBAC 放大 vLLM 面 | `vllm-operator-rbac-escalation` |
| AReaL/SGLang + NCCL/RDMA | 控制面可达 + 集合通信被信任 | `areal-awex-nccl-injection`、`nccl-collective-join` |
| 共享 PVC + HF 缓存 | 缓存可写 + 模型加载被信任 | `cache-poison-persistence`、`shared-pvc-supply-chain-poison` |
| Multus + SR-IOV + RDMA | 策略旁路 + 直接内存访问 | `multus-sriov-rdma-bypass` |
| llm-d/vLLM PD + NIXL | KV 传输库跨信任域暴露 | `prefill-decode-kv-channel-unauth`、`remote-kv-pool-isolation` |
| EKS VPC-CNI + 安全组 | 两套控制面，一次漂移 | `vpc-cni-dual-control-plane-lateral` |
| InferencePool 失败放行 | 网关 fail-open 叠加租户隔离基线缺失 | `gateway-api-ambient-mesh`、`inference-tenant-isolation-baseline` |
| GB200 + DRA/IMEX | 新硬件路线默认开内存共享 | `gpu-dra-mig-policy`、`nvlink-imex-isolation` |
| 长上下文 + KV 复用 | 上下文越长，跨请求复用越多 | `prefix-cache-cross-tenant-leak`、`long-context-cache-leak` |
| GPU 池化 + MIG 残留 | 放置策略 + 残留显存 | `gpu-tenant-residue`、`gpu-tenant-residue-chain` |

去重：每组组合有签名。组合成立时，被它解释的组件级发现并入组合；组合不成立时，组件级发现各自独立。

### 10. 防护绕过层

**能做什么。** 度量防守方是否看得见良性授权行为，并把结果转成规则、配置修改与重放用例。

**检测什么。** HIDS agent 与 driver 指纹、运行时策略降级、准入豁免与 mutation 顺序、镜像扫描分层覆盖、主机代理离线窗口、WAF 归一化差异、网络可视化采样缺口。

**产出什么。** 每类技术固定输出 **检测（detected）**、**盲区（blind spot）**、**硬化建议（hardening）**，以及防守方可以直接加载和重放的规则包。

| 产品族 | 模块 | 测什么 |
|---|---|---|
| Elkeid HIDS | `defense-bypass-elkeid` | agent/driver 指纹、白名单路径、工具改名、driver 未加载降级、规则盲区 |
| AgentSmith-HIDS | `defense-bypass-agentsmith` | `smith.ko` 是否存在、规则覆盖缺口、改名执行、良性 DNS |
| veinmind 容器扫描 | `defense-bypass-veinmind` | 分层镜像、改名工具、压缩样本、白名单样本名 |
| Falco | `defense-bypass-falco` | 无 driver 降级、规则缺口、ephemeral 容器、改名执行 |
| Tetragon / eBPF | `defense-bypass-tetragon` | 策略未挂载命名空间、短生命周期进程、hostNetwork |
| KubeArmor | `defense-bypass-kubearmor` | namespace posture、默认放行、hostNetwork 覆盖 |
| Kyverno / Gatekeeper | `defense-bypass-admission` | 豁免、Audit 模式、mutation 顺序、子资源 |
| Trivy / grype 镜像扫描 | `defense-bypass-imagescan` | 深层覆盖、改名工具、压缩样本、白名单样本名 |
| Wazuh / Osquery 主机代理 | `defense-bypass-hostagent` | agent 离线窗口、规则缺口、改名执行 |
| ModSecurity / Coraza / 雷池 WAF | `defense-bypass-waf-inference` | 编码、分块、Unicode、超长请求变体 |
| Cilium Hubble / Calico flows | `defense-bypass-netobserv` | hostNetwork、多网卡、短生命周期流 |

盲区直接反哺规则包：Kyverno/Gatekeeper 管准入，Sigma 管进程/文件/DNS，Falco/Tetragon 管运行时，Suricata/WAF 管网络与请求归一化。模块只使用良性 marker，不携带恶意载荷、不做持久化、不关闭安全产品、不提供规避执法的话术。
