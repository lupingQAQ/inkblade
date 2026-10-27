# InkBlade（墨刃零）

**面向训练与推理集群的探针式渗透测试产品。**

InkBlade 把一个静态链接的 Rust 探针放进已授权的 Pod，用声明式模板覆盖 ML 基础设施的十层检测，并把证据整理成双语报告、可重放规则包和本地控制台。控制端留在集群之外；目标 Pod 不需要 Python、shell、curl，也不需要下发模块代码。

> **仅限授权使用。** 只对你有书面授权的资产使用 InkBlade。consent 与 ROE 记录哈希钉存，范围、级别、时间窗由代码强制执行；写操作必须有备份回执。没有签署记录就不投放探针，也没有跳过闸门的开关。

## 核心能力

### 十层检测

每一层都是一组可独立执行的模板。模板声明输入、步骤、检查项、发现和产物；探针执行模板并回传证据。

| 层 | 能做什么 | 代表模板 |
|---|---|---|
| 1. 架构层 | 审计 rail 与多平面错配、PD 分离 KV 通道、IMEX/ComputeDomain 边界、MoE/EP 集合通信入组、长上下文 KV 生命周期、多集群联邦 | `rail-mismatch-forcing`、`prefill-decode-kv-channel-unauth`、`nvlink-imex-isolation`、`nccl-collective-join` |
| 2. 产品 / 框架层 | 枚举 vLLM、SGLang、TRL、verl、AReaL、SkyRL、OpenRLHF、slime、LLaMA-Factory、ms-swift、Megatron-LM、DeepSpeed、transformers、推理网关与 Agent 平台的管理面；检查插件路由、dev 模式、反序列化 sink 与权重导出路径 | `vllm-plugin-auth-bypass`、`sglang-admin-failopen`、`verl-prime-code-exec`、`msswift-trust-remote-code` |
| 3. 组件 / Operator 层 | 检查 Ray 与 LWS 控制面、GPU Operator 与驱动容器、DRA 设备策略、CSI 节点插件、BMC/Redfish 端点与 DPU offload | `ray-dashboard-job`、`gpu-operator-driver-audit`、`gpu-dra-mig-policy`、`redfish-default-credentials` |
| 4. 网络 / fabric 层 | 验证 hostNetwork、SR-IOV、macvlan 上的策略旁路，CNI 双控制面，IB 子网管理器与分区，RoCE PFC/ECN，SHARP 在网聚合，NCCL bootstrap 与 DNS 发现 | `multus-sriov-rdma-bypass`、`ib-sm-partition-audit`、`roce-pfc-storm`、`sharp-in-network-poison` |
| 5. 数据 / 权重层 | 检查 checkpoint 与优化器分片、数据集管道、Hugging Face 缓存、权重桶、模型注册表与 KV/前缀缓存条目 | `checkpoint-shard-poison`、`skyrl-fetch-weights-traversal`、`model-registry-exposure` |
| 6. 租户 / 隔离层 | 度量 MIG 与 MPS 残留、GPU 池化调度器、`cache_salt` 策略与路由指标泄露 | `gpu-tenant-residue`、`hami-scheduler-auth-gap`、`cache-salt-policy-audit` |
| 7. 供应链 / 身份层 | 核验 `trust_remote_code`、revision 固定、证明链、SBOM、IRSA 与工作负载身份、IMDS 可达性与凭据暴露 | `trust-remote-code-supply-chain`、`gpu-cc-attestation-chain`、`cloud-irsa-trust-wildcard` |
| 8. 缓存安全层 | 测试跨租户前缀缓存、语义缓存误命中、逐出残留、远程 KV 池、EPP 指标与 TTFT 时序 | `prefix-cache-cross-tenant-leak`、`similarity-cache-false-hit`、`remote-kv-pool-isolation`、`cache-timing-sidechannel` |
| 9. 跨组合层 | 只在两个或三个组件相遇时才成立的发现，只报一次，并把组件级记录并入组合 | `vllm-plugin-auth-bypass` + `sglang-weight-exfil`、`imex-computedomain-gpu-memory-crossing`、`long-context-cache-leak` |
| 10. 防护绕过层 | 度量 HIDS、运行时 eBPF、准入控制、镜像扫描、主机代理、WAF 与流量可视化是否看得见良性授权行为；每类技术固定输出检测 / 盲区 / 硬化建议，并反哺规则包 | `defense-bypass-elkeid`、`defense-bypass-falco`、`defense-bypass-admission`、`defense-bypass-waf-inference` |

第 10 层是产品能力，不是附加演示。11 个 `defense-bypass-*` 模块覆盖 Elkeid、AgentSmith-HIDS、veinmind、Falco、Tetragon、KubeArmor、Kyverno/Gatekeeper、Trivy/grype、Wazuh/Osquery、ModSecurity/Coraza/雷池与 Cilium Hubble/Calico。它们只使用良性 marker，不做持久化、不关闭安全产品、不提供规避执法的话术。

### 平台能力

- **一条执行路径。** 立足 → Rust 探针 → 帧通道 → Pod 内任务 → 子探针 → 证据。检测、逃逸和横向都走这条路径。
- **目标侧零解释器。** 探针是静态二进制，模板是 JSON 数据。distroless 或 scratch 推理镜像与 Python 镜像跑同一套模板。
- **探针树。** `probe_id` 与 `parent_id` 记录每颗探针的位置；子探针继承更严格的预算与白名单，深度与扇出有上限，清理先子后父。
- **Agent 运行时。** 带预算的规划器执行目标图，记录每次观察与决策，可从持久 journal 恢复，也可零执行回放。
- **跨集群中继。** 中继用同一套帧协议连接集群，让一次项目覆盖多个集群并留下覆盖证明。
- **证据在边界产生。** 任务结果、步骤日志、产物、SHA-256 manifest、流量表、探针身份与清理回执。
- **规则可重放。** 准入、运行时、网络三类规则包，输出拦截 / 检出 / 漏过矩阵。
- **报告与控制台。** 双语渗透报告与修复报告，SARIF / OCSF / VEX 导出，本地 Web 控制台展示发现、图与时间线。
- **无遥测。** 不要账号、不要云密钥、没有许可服务器；不配置集成就没有外发调用。

## 工作流

| # | 阶段 | 发生什么 | 产物 |
|---:|---|---|---|
| 1 | 立足 | 会话记录入口方式：`kubeconfig`、`external` 或 `foothold`，以及目标、命名空间、Pod 与凭据指纹 | 会话记录、审计轨迹 |
| 2 | Rust 探针 | 静态探针经 `kubectl`、ServiceAccount token、共享卷、EphemeralContainer 或授权 RCE 回调投放 | 探针身份、SHA-256 |
| 3 | 通道 | 控制端通过探针 stdio 使用 HMAC 认证、长度前缀的 JSON 协议；通道可在回环上开 SOCKS5 与端口转发 | 通道状态、任务日志 |
| 4 | 检测 | 模板在 Pod 内按十层执行；每个结果带步骤、检查项、发现与产物 | 发现、证据锚 |
| 5 | 逃逸 | 通过范围内的 Operator、驱动、CSI、运行时与内核面测试容器与节点边界 | 逃逸路径、证明 |
| 6 | 横向 | 从探针所在网络命名空间测绘服务、控制面、网关与 fabric 可达性 | 可达图、跳板 |
| 7 | 多探针 | 子探针把探针树扩展到更多 Pod 与命名空间；每个子探针有独立 token 和更严格的预算 | 探针树、血缘 |
| 8 | 跨集群 | `agent relay` 连接多个集群；`agent coverage` 记录目标图里哪些节点已闭合、哪些不可达 | 中继状态、覆盖证明 |
| 9 | 报告 / 规则 / 可视化 | 双语报告、SARIF/OCSF/VEX 导出、可重放规则包与本地控制台 | 报告、规则包、控制台 |

## 快速开始

在你有权测试的环境中运行。

```bash
# 1. 安装控制端
python -m pip install -e .

# 2. 打开接入向导：工作区、授权、kubeconfig
python -m inkblade up

# 3. 签授权记录：目标、范围、级别、时间窗
python -m inkblade quickstart

# 4. 导入 kubeconfig 并打开授权会话
python -m inkblade session open \
  --mode kubeconfig \
  --workspace ./work \
  --kubeconfig ~/.kube/config \
  --namespace ml-team \
  --pod infer-0

# 5. 把探针投放进目标 Pod
python -m inkblade probe deploy \
  --session <session-id> \
  --via kubectl \
  --binary ./inkblade-probe-linux-amd64 \
  --namespace ml-team \
  --pod infer-0 \
  --allow-write

# 6. 用 Agent 驱动探针
python -m inkblade agent run \
  --probe <probe-id> \
  --objective read-only-recon \
  --workspace ./work

# 7. 出报告
python -m inkblade report --run <run-id> --lang bi
```

`inkblade up` 创建工作区、检查授权记录并引导导入 kubeconfig；`quickstart` 写出绑定范围、级别与时间窗的签署记录；`probe deploy` 不带 `--allow-write` 时只出投放计划，带上后才真正投放并注册探针；`agent run` 打印 `report` 需要的 `run_id`。

## 命令表

| 任务 | 命令 |
|---|---|
| 接入向导 | `inkblade up` |
| 授权记录 | `inkblade quickstart`、`inkblade roe` |
| 会话 | `inkblade session open` / `status` / `close` / `run` |
| 探针投放 | `inkblade probe deploy` / `list` / `collect` / `exec` / `read-file` / `list-files` / `upload` / `download` / `spawn` / `cleanup` |
| 通道 | `inkblade channel start` / `status` / `stop` |
| 单模板 | `inkblade session run --id <session> --module <key>` 或 `inkblade run --module <key>` |
| 链执行 | `inkblade execute --chain <id> --dry-run`，确认后 `inkblade execute --chain <id>` |
| Agent | `inkblade agent run` / `status` / `trace` / `resume` / `replay` / `stop` |
| 跨集群 | `inkblade agent relay add\|list\|status`、`inkblade agent coverage status\|proof` |
| 报告 | `inkblade report --run <id> --lang bi --kind pentest\|remediation` |
| 导出 | `inkblade export --run <id> --format sarif\|ocsf\|vex` |
| 规则包 | `inkblade rules generate`、`inkblade rules validate` |
| 控制台 | `inkblade ui` |
| 模板 | `inkblade template list` / `get` / `plan` / `validate` |

## 部署

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

Chart 以 uid 10001 运行，根文件系统只读，证据落在 PVC。默认只授予读动词；写动词要同时打开 `readOnly=false` 与 `rbac.allowWrite=true`，并且工作区里有签署记录。卸载不删除 PVC，证据要比 release 活得久。

## 安全与授权

- **先有 RoE。** `quickstart` 写出 consent 记录：目标、范围、级别、时间窗与应急联系人。记录做哈希，哈希跟着每一次 run 走；过期或越界的 run 以退出码 91 拒绝。
- **默认只读。** 采集、HTTP/TCP 探测、读文件、只读命令与只读模板不需要额外开关。写操作要过五道闸门：会话级别、`--allow-write`、`meta.writes`、`backup-write` 模式与备份回执。
- **备份与回滚。** 写模块先快照、再执行、两者都记录。`inkblade rollback --run <id> --step <n>` 恢复单步并打印回执；恢复不了的步骤作为发现报出。
- **审计与证据。** 每次探针动作、文件读取、exec 调用与任务结果都写入证据库，并带 SHA-256 manifest。报告把每条发现锚定到 task、step、artifact、probe 或 manifest 哈希。
- **急停。** `inkblade abort` 置位工作区停止开关，解除前所有 run 拒绝执行。
- **无遥测。** 不启用集成时控制端不发起外发调用；没有账号体系、许可服务器或使用数据上传。

## 许可

Apache-2.0。允许商用、fork 与嵌入服务；保留 `LICENSE` 与 `NOTICE`。`NOTICE` 记录 clean-room 边界：功能对标只依据公开描述与可观察行为，InkBlade 不与 AGPL 项目链接或派生。文档索引：[`docs/DOC-INDEX.md`](docs/DOC-INDEX.md)。
