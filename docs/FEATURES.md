# Features / 特性

[English](#english) · [中文](#中文)

InkBlade is a probe-centric testing product for training and inference clusters. This page lists what the product does: the ten detection layers, the in-pod execution substrate, the framework handlers, the platform features and the outputs.

---

## English

### Ten layers, one product

A generic cluster scanner checks RBAC, admission, exposed APIs and image CVEs. Useful, but it does not know that GPUs are wired per rail, that weights are writable at load time, that KV cache is data crossing tenants, or that a collective trusts whoever joins it. Each InkBlade layer is a set of templates that answer those questions.

| Layer | What the product does | Detail |
|---|---|---|
| 1. Architecture | Audits rail and multi-plane alignment, PD-split KV channels, IMEX domains, MoE/EP collectives, long-context KV lifetime and federation | `DETECTION-LAYERS.md` |
| 2. Product / framework | Enumerates admin and control surfaces of vLLM, SGLang, TRL, verl, AReaL, SkyRL, OpenRLHF, slime, LLaMA-Factory, ms-swift, Megatron-LM, DeepSpeed, transformers, inference gateways and agent platforms | `DETECTION-LAYERS.md` |
| 3. Component / operator | Inspects Ray, LWS, GPU Operator, DRA, CSI, BMC/Redfish and DPU | `MODULES.md` |
| 4. Network / fabric | Tests policy bypass, dual CNI control planes, IB subnet manager, RoCE PFC/ECN, SHARP, NCCL bootstrap and DNS | `DETECTION-LAYERS.md` |
| 5. Data / weights | Checks checkpoint and optimizer shards, dataset pipelines, HF cache, weight buckets, registries and KV caches | `DETECTION-LAYERS.md` |
| 6. Tenant / isolation | Measures MIG/MPS residue, GPU pooling schedulers, `cache_salt` and routing metrics | `DETECTION-LAYERS.md` |
| 7. Supply chain / identity | Verifies `trust_remote_code`, revision pinning, attestation chains, SBOM, IRSA/workload identity and IMDS | `VULNERABILITY-LAYERS.md` |
| 8. Cache security | Tests prefix cache, semantic cache, salt policy, eviction residue, remote KV pools, EPP metrics and TTFT timing | `DETECTION-LAYERS.md` |
| 9. Cross-combination | Reports findings that only exist when two or three components meet, once per combination | `DETECTION-LAYERS.md` |
| 10. Defense bypass | Measures whether HIDS, runtime eBPF, admission, image scan, host agents, WAF and flow telemetry see benign authorized activity | `PRODUCT.md` |

### In-pod probe / channel

The component layer has a native execution substrate, not just checks. A single static Rust binary is delivered into a target Pod through a foothold — `kubectl exec`, a ServiceAccount token, a shared volume, an EphemeralContainer or an authorized RCE callback — and speaks an authenticated length-prefixed JSON protocol over the probe channel (reverse or stdio). It provides `collect`, `exec` with an argv allow-list, `dial` for SOCKS5 and port forwarding, chunked `upload`/`download` with SHA-256, `spawn` for parent/child probes and declarative `http`, `tcp`, `exec`, `fs`, `k8s` and `socks` tasks. Read-only is the default; no Python or shell interpreter is placed in the Pod. SOCKS and forward listeners bind `127.0.0.1` only.

Entry and session logic is explicit and probe-first: `foothold` (an existing Pod shell, ServiceAccount token or authorized RCE) and `external` (a bounded reachability proof, then an authorized RCE or callback) need no kubeconfig. `kubeconfig` is the optional batch bootstrap for several Pods. Host kubectl is used only for that optional bootstrap; afterwards every module action goes through a probe channel and is audited. See [`PROBE-CHANNEL.md`](PROBE-CHANNEL.md) and [`PROBE-PROTOCOL.md`](PROBE-PROTOCOL.md).

### Framework matrix

| Framework | Distinctive checks | Representative modules |
|---|---|---|
| vLLM | Plugin route bypass, RL router, dev-mode endpoints, prefix-cache timing | `vllm-plugin-auth-bypass`, `vllm-timing-oracle` |
| SGLang | Admin fail-open, profiler write, ZMQ pickle, weight export | `sglang-admin-failopen`, `sglang-zmq-pickle-rce` |
| TRL | `vllm-serve` dev mode on 0.0.0.0 | `trl-serve-dev-mode` |
| verl | `prime_math` eval, `prime_code` exec, checkpoint `recv_pyobj`, HDFS injection | `verl-prime-code-exec`, `verl-checkpoint-pickle` |
| AReaL | `/set_env` → `/create_engine` → `/call`, unsafe `/load`, `/awex` NCCL join | `areal-setenv-engine-rce`, `areal-awex-nccl-injection` |
| SkyRL | Dev-mode weights, fetch traversal, Tinker control plane | `skyrl-dev-pickle-rce`, `skyrl-tinker-hijack` |
| OpenRLHF | Unauthenticated reward scoring, forced insecure serialization | `openrlhf-serve-rm`, `openrlhf-vllm-env-force` |
| slime | Cross-tenant weight pull, debug/resume load | `slime-weight-pull-poison` |
| LLaMA-Factory | Checkpoint load, WebUI exposure | `llamafactory-checkpoint-rce` |
| ms-swift | `trust_remote_code`, eval escape, dataset pickle, media read | `msswift-trust-remote-code`, `msswift-eval-escape` |
| Megatron-LM | Checkpointing load, config surface, optimizer shard trust | `megatron-checkpoint-rce` |
| DeepSpeed | Stage3 load sinks, AutoEP conversion | `deepspeed-checkpoint-rce` |
| transformers | Dynamic module import, revision drift | `trust-remote-code-supply-chain` |
| djev / vllm-jev | Open relay, plugin route bypass | `djev-open-proxy`, `vllm-plugin-auth-bypass` |
| Dify / Open WebUI | Sandbox escape, fail-open auth, default JWE key, cross-tenant snapshot | `dify-local-sandbox-unauth-rce`, `open-webui-code-execute-rce` |
| LiteLLM / Higress / Envoy AI | Default key, config RCE, upstream key, cache isolation | `litellm-default-key-exfil`, `aigateway-upstream-key-exfil` |

### Platform features

- **Session and authorization.** `session open` records the entry vector, namespace, Pod, container, credential fingerprint and evidence root. Scope, level and window come from the signed record.
- **Probe lifecycle.** `probe deploy`, `list`, `collect`, `exec`, `read-file`, `list-files`, `upload`, `download`, `spawn` and `cleanup`; every action is registered and audited.
- **Channel.** The default reverse channel has the controller listen (`channel listen`) and the probe connect back from the Pod; a stdio channel (`channel start`) is available when a local command transport exists. `status` and `stop` manage the process.
- **Templates.** Declarative JSON with inputs, steps, computed state, checks, findings, artifacts, version matrix and boundaries. `template list`, `get`, `plan` and `validate` cover authoring.
- **Agent.** `agent run` executes a budgeted objective graph; `resume` restores from a journal, `replay` re-renders without executing, `trace` shows decisions, `stop` is the kill switch.
- **Cross-cluster.** `agent relay` registers relays between clusters; `agent coverage` records the closure proof for the objective graph.
- **Rule packs.** `rules generate` writes admission, runtime and network packs; `rules validate` replays them and produces a blocked / detected / missed matrix.
- **Reporting.** PTES-style pentest report plus a remediation checklist, bilingual output, `--redact` before external release, and SARIF / OCSF / VEX export.
- **Console.** `inkblade ui` serves a local console for findings, probe trees, graphs and timelines.
- **Audit.** Every exec, file read, list and task result lands in the evidence store with a SHA-256 manifest and a unified timeline.

### Optional integrations

LLM pool, notifications, SIEM/ITSM adapters and the autonomous planner are off until configured. An air-gapped run is the normal case.

---

## 中文

### 十层，一个产品

通用集群扫描器查 RBAC、准入、暴露 API、镜像 CVE。有用，但不够。它不知道 GPU 按 rail 布线，不知道权重在加载时可写，不知道 KV 缓存是会跨租户的数据，也不知道集合通信默认信任加入者。InkBlade 的每一层都是一组回答这些问题的模板。

| 层 | 产品做什么 | 详情 |
|---|---|---|
| 1. 架构层 | 审计 rail 与多平面错配、PD 分离 KV 通道、IMEX 域、MoE/EP 集合通信、长上下文 KV 生命周期与联邦 | `DETECTION-LAYERS.md` |
| 2. 产品 / 框架层 | 枚举 vLLM、SGLang、TRL、verl、AReaL、SkyRL、OpenRLHF、slime、LLaMA-Factory、ms-swift、Megatron-LM、DeepSpeed、transformers、推理网关与 Agent 平台的管理面与控制面 | `DETECTION-LAYERS.md` |
| 3. 组件 / Operator 层 | 检查 Ray、LWS、GPU Operator、DRA、CSI、BMC/Redfish 与 DPU | `MODULES.md` |
| 4. 网络 / fabric 层 | 测试策略旁路、CNI 双控制面、IB 子网管理器、RoCE PFC/ECN、SHARP、NCCL bootstrap 与 DNS | `DETECTION-LAYERS.md` |
| 5. 数据 / 权重层 | 检查 checkpoint 与优化器分片、数据集管道、HF 缓存、权重桶、注册表与 KV 缓存 | `DETECTION-LAYERS.md` |
| 6. 租户 / 隔离层 | 度量 MIG/MPS 残留、GPU 池化调度器、`cache_salt` 与路由指标 | `DETECTION-LAYERS.md` |
| 7. 供应链 / 身份层 | 核验 `trust_remote_code`、revision 固定、证明链、SBOM、IRSA/工作负载身份与 IMDS | `VULNERABILITY-LAYERS.md` |
| 8. 缓存安全层 | 测试前缀缓存、语义缓存、salt 策略、逐出残留、远程 KV 池、EPP 指标与 TTFT 时序 | `DETECTION-LAYERS.md` |
| 9. 跨组合层 | 只在两个或三个组件相遇时才成立的发现，每个组合只报一次 | `DETECTION-LAYERS.md` |
| 10. 防护绕过层 | 度量 HIDS、运行时 eBPF、准入、镜像扫描、主机代理、WAF 与流量可视化是否看得见良性授权行为 | `PRODUCT.md` |

### 组件层内置 in-pod 探针 / 通道

组件层不只有检查项，还有原生执行底座：单个静态 Rust 探针经立足点进入目标 Pod —— `kubectl exec`、ServiceAccount token、共享卷、EphemeralContainer 或授权 RCE 回调 —— 使用带认证的长度前缀 JSON 协议，提供 `collect`、带 argv 白名单的 `exec`、SOCKS5/端口转发 `dial`、分块且带 SHA-256 的 `upload`/`download`、父子 `spawn`，以及声明式 `http`、`tcp`、`exec`、`fs`、`k8s`、`socks` 任务。默认只读；目标 Pod 内没有 Python/shell 解释器；SOCKS 与转发只监听 `127.0.0.1`。

入口是探针优先的：`foothold`（已有 Pod shell、ServiceAccount token 或授权 RCE）与 `external`（有界可达性证明，再经授权 RCE 或回调投放）都不需要 kubeconfig；`kubeconfig` 只是可选的批量 bootstrap。host kubectl 仅用于该可选路径；之后每个模块动作都经探针通道并留审计。详见 [`PROBE-CHANNEL.md`](PROBE-CHANNEL.md) 与 [`PROBE-PROTOCOL.md`](PROBE-PROTOCOL.md)。

### 框架矩阵

| 框架 | 特有检查 | 代表模块 |
|---|---|---|
| vLLM | 插件路由绕过、RL 路由、dev 端点、前缀缓存时序 | `vllm-plugin-auth-bypass`、`vllm-timing-oracle` |
| SGLang | 管理面 fail-open、profiler 写入、ZMQ pickle、权重导出 | `sglang-admin-failopen`、`sglang-zmq-pickle-rce` |
| TRL | `vllm-serve` 在 0.0.0.0 上开 dev | `trl-serve-dev-mode` |
| verl | `prime_math` eval、`prime_code` exec、checkpoint `recv_pyobj`、HDFS 注入 | `verl-prime-code-exec`、`verl-checkpoint-pickle` |
| AReaL | `/set_env` → `/create_engine` → `/call`、不安全 `/load`、`/awex` NCCL 入组 | `areal-setenv-engine-rce`、`areal-awex-nccl-injection` |
| SkyRL | dev 权重、fetch 穿越、Tinker 控制面 | `skyrl-dev-pickle-rce`、`skyrl-tinker-hijack` |
| OpenRLHF | 无鉴权打分、强制不安全序列化 | `openrlhf-serve-rm`、`openrlhf-vllm-env-force` |
| slime | 跨租户权重拉取、debug/resume 加载 | `slime-weight-pull-poison` |
| LLaMA-Factory | checkpoint 加载、WebUI 暴露 | `llamafactory-checkpoint-rce` |
| ms-swift | `trust_remote_code`、eval 逃逸、数据集 pickle、media 读取 | `msswift-trust-remote-code`、`msswift-eval-escape` |
| Megatron-LM | checkpointing 加载、config 面、优化器分片信任 | `megatron-checkpoint-rce` |
| DeepSpeed | stage3 加载 sink、AutoEP 转换 | `deepspeed-checkpoint-rce` |
| transformers | 动态模块导入、revision 漂移 | `trust-remote-code-supply-chain` |
| djev / vllm-jev | 开放中继、插件路由绕过 | `djev-open-proxy`、`vllm-plugin-auth-bypass` |
| Dify / Open WebUI | 沙箱逃逸、fail-open 鉴权、默认 JWE 密钥、跨租户快照 | `dify-local-sandbox-unauth-rce`、`open-webui-code-execute-rce` |
| LiteLLM / Higress / Envoy AI | 默认密钥、配置 RCE、上游密钥、缓存隔离 | `litellm-default-key-exfil`、`aigateway-upstream-key-exfil` |

### 平台功能

- **会话与授权。** `session open` 记录入口方式、命名空间、Pod、容器、凭据指纹与证据根；范围、级别和时间窗来自签署记录。
- **探针生命周期。** `probe deploy`、`list`、`collect`、`exec`、`read-file`、`list-files`、`upload`、`download`、`spawn`、`cleanup`；每个动作都登记并留审计。
- **通道。** 默认是反向通道：控制端 `channel listen`，探针从 Pod 内主动回连；存在本地命令通道时可用 stdio 通道（`channel start`）。`status`、`stop` 管理进程。
- **模板。** 声明式 JSON，含输入、步骤、computed 状态、检查项、发现、产物、版本矩阵与边界；`template list`、`get`、`plan`、`validate` 覆盖编写与校验。
- **Agent。** `agent run` 执行带预算的目标图；`resume` 从 journal 恢复，`replay` 零执行回放，`trace` 查看决策，`stop` 是急停开关。
- **跨集群。** `agent relay` 注册集群间中继；`agent coverage` 记录目标图的闭合证明。
- **规则包。** `rules generate` 生成准入、运行时、网络三类规则；`rules validate` 重放并输出拦截 / 检出 / 漏过矩阵。
- **报告。** PTES 结构渗透报告 + 修复清单，双语输出，外发前 `--redact`，支持 SARIF / OCSF / VEX 导出。
- **控制台。** `inkblade ui` 提供本地控制台，展示发现、探针树、图与时间线。
- **审计。** 每次 exec、文件读取、目录列举与任务结果都进入证据库，带 SHA-256 manifest 与统一时间线。

### 可选集成

LLM 池、通知、SIEM/ITSM 适配器与自主规划器都要配置后才启用。离线运行是常态。
