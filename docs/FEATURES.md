# Features / 特性

[English](#english) · [中文](#中文)

This page lists what is built, what is simulated, and what is missing. The organising idea is the
nine detection layers: each one is a place where ML infrastructure differs from ordinary Kubernetes,
and each row says how far the coverage actually goes.

---

## English

### Nine layers, one product

A generic cluster scanner checks RBAC, admission, exposed APIs, image CVEs. Useful. Not enough. It
does not know that GPUs are wired per rail, that weights are writable at load time, that KV cache is
data crossing tenants, or that a collective trusts whoever joins it.

| Layer | What is covered | State | Detail |
|---|---|---|---|
| 1. Architecture | Rail / multi-plane mismatch, PD-split KV channel, IMEX domains, MoE/EP collectives, long-context KV lifetime, federation | Modules verified; MoE routing itself is a gap | `DETECTION-LAYERS.md` |
| 2. Product / framework | 16 stacks: vLLM, SGLang, TRL, verl, AReaL, SkyRL, OpenRLHF, slime, LLaMA-Factory, ms-swift, Megatron-LM, DeepSpeed, transformers, djev/vllm-jev, agent platforms, gateways | Handlers verified against fixtures and lab builds; r2egym docker.sock still a gap | `DETECTION-LAYERS.md` |
| 3. Component / operator | Ray, LWS, GPU Operator, DRA, CSI, BMC/Redfish, DPU | Verified, read-only or gated; Volcano/Kueue coverage is partial | `MODULES.md` |
| 4. Network / fabric | Policy bypass, dual CNI control planes, IB SM, RoCE PFC/ECN, SHARP, NCCL bootstrap, DNS | Verified with fixtures and simulations; no real switch ASIC lab | `HARDWARE-SWITCH-COVERAGE.md` |
| 5. Data / weights | Checkpoint and optimizer shards, dataset pipelines, HF cache, weight buckets, registries | Verified; webdataset/Arrow parsers are a gap | `DETECTION-LAYERS.md` |
| 6. Tenant / isolation | MIG/MPS residue, GPU pooling, `cache_salt`, routing metrics | Verified; pooling scheduler variants move fast | `DETECTION-LAYERS.md` |
| 7. Supply chain / identity | `trust_remote_code`, revision pinning, signatures/attestation, SBOM, IRSA wildcard, IMDS | Verified, with online TEE checks in a separate track | `KEYLESS-VERIFICATION.md` |
| 8. Cache security | Prefix cache, semantic cache, salt, eviction residue, remote KV pools, PD channel, EPP metrics, TTFT timing | Verified with timing and collision tests | `DETECTION-LAYERS.md` |
| 9. Cross-combination | 14 declared signatures, deduplicated against component findings | Declared and tested; r2egym signature has no module yet | `DETECTION-LAYERS.md` |

### In-pod probe / channel (component layer)

The component layer has a native execution substrate, not just checks. A single
static Rust binary is injected into a target Pod and speaks an authenticated
length-prefixed JSON protocol over `kubectl exec -i` (or an RCE callback). It
provides `collect`, `exec` (argv allow-list), `dial` (SOCKS5/port-forward),
`upload`/`download` (chunked + SHA-256), `spawn` (parent/child probes) and
declarative `http/tcp/exec/fs/k8s/socks` tasks. Read-only is the default; no
Python or shell interpreter is placed in the Pod. SOCKS and forward listeners
bind `127.0.0.1` only.

Entry and session logic is explicit: `kubeconfig`, `external` and `foothold`
modes; external must prove reachability and a vulnerable version/route before
any exploit, and no foothold means read-only recon. Host kubectl is used only
for the first bootstrap; thereafter every module action goes through a probe
and is audited. See [`PROBE-CHANNEL.md`](PROBE-CHANNEL.md) and
[`PROBE-PROTOCOL.md`](PROBE-PROTOCOL.md).

组件层现在有原生执行底座：单个静态 Rust 探针经 `kubectl exec -i`（或 RCE
回调）进入目标 Pod，提供 collect/exec/dial/upload/download/spawn 与声明式
http/tcp/exec/fs/k8s/socks 任务；默认只读，Pod 内无 Python/解释器；SOCKS 与
端口转发只监听回环。入口分 kubeconfig/external/foothold 三种，external 必须
先证明可达与脆弱版本/路由，未取得 foothold 只允许只读侦察；host kubectl
仅用于首次 bootstrap，之后所有模块动作都经探针并留审计。

### Framework matrix

| Framework | Distinctive checks | Modules | State |
|---|---|---:|---|
| vLLM | Plugin route bypass, RL router, dev-mode endpoints, prefix-cache timing | 4 | Verified |
| SGLang | Admin fail-open, profiler write, ZMQ pickle, weight export | 4 | Verified |
| TRL | `vllm-serve` dev mode on 0.0.0.0 | 1 | Verified |
| verl | `prime_math` eval, `prime_code` exec, checkpoint `recv_pyobj`, HDFS injection | 3 | Verified |
| AReaL | `/set_env`→`/create_engine`→`/call`, `/load` unsafe load, `/awex` NCCL join | 3 | Verified |
| SkyRL | Dev-mode weights, fetch traversal, Tinker control plane | 3 | Verified; r2egym gap |
| OpenRLHF | Unauthenticated reward scoring, forced insecure serialization | 2 | Verified |
| slime | Cross-tenant weight pull, debug/resume load | 1 | Verified |
| LLaMA-Factory | Checkpoint load, WebUI exposure | 1 | Verified |
| ms-swift | `trust_remote_code`, eval escape, dataset pickle, media read | 4 | Verified |
| Megatron-LM | Checkpointing load, config surface, optimizer shard trust | 2 | Verified |
| DeepSpeed | Stage3 load sinks, AutoEP conversion | 1 | Verified (variants in reserve) |
| transformers | Dynamic module import, revision drift | 1 | Verified as a trust edge |
| djev / vllm-jev | Open relay, plugin route bypass | 2 | Verified |
| Agent platforms (Dify, Open WebUI) | Sandbox escape, fail-open auth, default JWE key, cross-tenant snapshot | 5 | Verified |
| Gateways (LiteLLM, Higress, Envoy AI) | Default key, config RCE, upstream key, cache isolation | 5 | Verified (vendor-agnostic) |

### Numbers that keep us honest

| Number | Value | Note |
|---|---:|---|
| Modules | 286 | 275 default, 11 quarantined for missing surfaces |
| Chains | 29 / 71 steps | Five families, including fabric and cache chains |
| Offline tests | 1,900+ | No cluster, no network, no key |
| Catalogue verification | 37 / 152 | Plus 6 exposure-verified |
| Production coverage | 60–71% | Kubernetes profiles; Slurm is 25% |
| Zero-day reserve | 39 unique | 21 components, 47 confirmed-unpublished rows |

### What we do not claim

- **Production readiness.** Pre-1.0. No HA design, no SLA, no certification.
- **Full framework coverage.** 16 stacks have handlers; the long tail does not.
- **Real hardware validation everywhere.** Switch ASIC and some DPU paths are simulated.
- **Zero false positives.** Evidence-backed findings reduce them; they do not vanish.
- **Autonomy.** Default stops at “propose and wait”.

### Optional integrations stay off

LLM pool, notifications, SIEM/ITSM adapters and the agent planner are disabled until configured. An
air-gapped run is the normal case.

---

## 中文

### 十层，一个产品

通用集群扫描器查 RBAC、准入、暴露 API、镜像 CVE。有用，但不够。它不知道 GPU 按 rail 布线，
不知道权重在加载时可写，不知道 KV 缓存是会跨租户的数据，也不知道集合通信默认信任加入者。

| 层 | 覆盖内容 | 状态 | 详情 |
|---|---|---|---|
| 1. 架构层 | rail / 多平面错配、PD 分离 KV 通道、IMEX 域、MoE/EP 集合通信、长上下文 KV 生命周期、联邦 | 模块已验证；MoE 路由本身是缺口 | `DETECTION-LAYERS.md` |
| 2. 产品 / 框架层 | 16 个栈：vLLM、SGLang、TRL、verl、AReaL、SkyRL、OpenRLHF、slime、LLaMA-Factory、ms-swift、Megatron-LM、DeepSpeed、transformers、djev/vllm-jev、智能体平台、网关 | 处理器在 fixture 与实验构建上验证；r2egym docker.sock 仍是缺口 | `DETECTION-LAYERS.md` |
| 3. 组件 / Operator 层 | Ray、LWS、GPU Operator、DRA、CSI、BMC/Redfish、DPU | 已验证，只读或过闸门；Volcano/Kueue 覆盖部分 | `MODULES.md` |
| 4. 网络 / fabric 层 | 策略旁路、CNI 双控制面、IB SM、RoCE PFC/ECN、SHARP、NCCL bootstrap、DNS | fixture 与模拟验证；没有真实交换芯片实验台 | `HARDWARE-SWITCH-COVERAGE.md` |
| 5. 数据 / 权重层 | checkpoint 与优化器分片、数据集管道、HF 缓存、权重桶、注册表 | 已验证；webdataset/Arrow 解析器是缺口 | `DETECTION-LAYERS.md` |
| 6. 租户 / 隔离层 | MIG/MPS 残留、GPU 池化、`cache_salt`、路由指标 | 已验证；池化调度器变体变化快 | `DETECTION-LAYERS.md` |
| 7. 供应链 / 身份层 | `trust_remote_code`、revision 固定、签名与证明、SBOM、IRSA 通配、IMDS | 已验证，TEE 在线校验单独跟踪 | `KEYLESS-VERIFICATION.md` |
| 8. 缓存安全层 | 前缀缓存、语义缓存、salt、逐出残留、远程 KV 池、PD 通道、EPP 指标、TTFT 时序 | 已用计时与碰撞测试验证 | `DETECTION-LAYERS.md` |
| 9. 跨组合层 | 14 条已声明签名，与组件级发现去重 | 已声明并测试；r2egym 签名尚无模块 | `DETECTION-LAYERS.md` |

### 组件层内置 in-pod 探针 / 通道

组件层不只有检查项，还有原生执行底座：单个静态 Rust 探针经
`kubectl exec -i`（或 RCE 回调）进入目标 Pod，提供 collect/exec（argv
白名单）/dial（SOCKS5/端口转发）/upload/download（分块 + SHA256）/spawn
（父子探针）与声明式 http/tcp/exec/fs/k8s/socks 任务。默认只读；目标 Pod
内没有 Python/解释器；SOCKS 与转发只监听 `127.0.0.1`。

入口分 `kubeconfig`、`external`、`foothold` 三种会话；external 必须先证明
可达与脆弱版本/路由，未取得 foothold 只允许只读侦察。host kubectl 仅用于
首次 bootstrap；之后每个模块动作都经探针并留审计。详见
[`PROBE-CHANNEL.md`](PROBE-CHANNEL.md) 与 [`PROBE-PROTOCOL.md`](PROBE-PROTOCOL.md)。

### 框架矩阵

| 框架 | 特有检查 | 模块数 | 状态 |
|---|---|---:|---|
| vLLM | 插件路由绕过、RL 路由、dev 端点、前缀缓存时序 | 4 | 已验证 |
| SGLang | 管理面 fail-open、profiler 写入、ZMQ pickle、权重导出 | 4 | 已验证 |
| TRL | `vllm-serve` 在 0.0.0.0 上开 dev | 1 | 已验证 |
| verl | `prime_math` eval、`prime_code` exec、checkpoint `recv_pyobj`、HDFS 注入 | 3 | 已验证 |
| AReaL | `/set_env`→`/create_engine`→`/call`、`/load` 不安全加载、`/awex` NCCL 入组 | 3 | 已验证 |
| SkyRL | dev 权重、fetch 穿越、Tinker 控制面 | 3 | 已验证；r2egym 缺口 |
| OpenRLHF | 无鉴权打分、强制不安全序列化 | 2 | 已验证 |
| slime | 跨租户权重拉取、debug/resume 加载 | 1 | 已验证 |
| LLaMA-Factory | checkpoint 加载、WebUI 暴露 | 1 | 已验证 |
| ms-swift | `trust_remote_code`、eval 逃逸、数据集 pickle、media 读取 | 4 | 已验证 |
| Megatron-LM | checkpointing 加载、config 面、优化器分片信任 | 2 | 已验证 |
| DeepSpeed | stage3 加载 sink、AutoEP 转换 | 1 | 已验证（变体在储备里） |
| transformers | 动态模块导入、revision 漂移 | 1 | 作为信任边验证 |
| djev / vllm-jev | 开放中继、插件路由绕过 | 2 | 已验证 |
| 智能体平台（Dify、Open WebUI） | 沙箱逃逸、fail-open 鉴权、默认 JWE 密钥、跨租户快照 | 5 | 已验证 |
| 网关（LiteLLM、Higress、Envoy AI） | 默认密钥、配置 RCE、上游密钥、缓存隔离 | 5 | 已验证（厂商无关） |

### 让数字自己说话

| 数字 | 值 | 说明 |
|---|---:|---|
| 模块 | 286 | 默认 275，隔离 11 |
| 链 | 29 / 71 步 | 五族，含 fabric 与缓存链 |
| 离线测试 | 1,900+ | 不要集群、网络、密钥 |
| 目录验证 | 37 / 152 | 另有 6 条暴露面验证 |
| 生产可测覆盖 | 60–71% | Kubernetes 画像；Slurm 25% |
| 零日储备 | 39 条独立原语 | 21 个组件，确认未公开 47 行 |

### 我们不宣称

- **生产就绪。** pre-1.0。没有 HA 设计、没有 SLA、没有认证。
- **框架全覆盖。** 16 个栈有处理器，长尾没有。
- **所有硬件都真机验证。** 交换芯片与部分 DPU 路径是模拟。
- **零误报。** 带证据的发现能减少误报，不能消除。
- **自治。** 默认停在“提议并等待”。

### 可选集成默认关闭

LLM 池、通知、SIEM/ITSM 适配器、Agent 规划器都要配置后才启用。离线运行是常态。
