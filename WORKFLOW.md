# Workflow / 工作流

[English](#english) · [中文](#中文)

The order matters. Each stage leaves behind something the next stage can check, and any stage can refuse. The workflow starts at a foothold, runs every action through the probe, extends the probe tree, and ends with a report, rule packs and a console view.

---

## English

### The nine stages

| # | Stage | Command | Gate | Artifact |
|---:|---|---|---|---|
| 1 | Foothold | `session open --mode foothold\|external` (optional `kubeconfig`) | Signed consent, target, window | session record, audit trail |
| 2 | Rust probe | `probe deploy --via sa-token\|rce` (optional `kubectl`) | `--allow-write` plus session level | probe identity, SHA-256 |
| 3 | Channel | `channel listen` (probe reverse), `channel start` for stdio | loopback bind policy | channel state, task log |
| 4 | Detection | `session run --module`, `run --module`, `agent run` | scope, level, surface | findings, evidence anchors |
| 5 | Escape | `execute --chain`, `exploit` | chain preconditions, backup gate | escape path, proof |
| 6 | Lateral | channel forwards, `probe upload` + `probe spawn`, `agent run` | scope coverage | reachability graph, pivots |
| 7 | Multi-probe | `probe spawn`, `probe list` | parent token, nesting depth, concurrent child probes | probe tree, lineage |
| 8 | Cross-cluster | `agent relay add`, `agent coverage status` | relay token, per-cluster consent | relay status, coverage proof |
| 9 | Report / rules / console | `report`, `export`, `rules generate`, `ui` | `--redact` before release | report, rule packs, console |

### Stage 1 — foothold

`session open` binds the engagement to the entry you already hold. `foothold` starts from a Pod shell, a ServiceAccount token or an authorized RCE and needs no kubeconfig; `external` starts from a reachable service, requires a bounded proof object before anything beyond read-only recon, and places the probe through an authorized RCE or callback. `kubeconfig` is the optional batch bootstrap for several Pods. The record stores the credential SHA-256 fingerprint, never the credential itself.

### Stage 2 — Rust probe

`probe deploy` delivers the static binary. Without `--allow-write` it prints the deployment plan. With it, the probe lands through the foothold — a ServiceAccount token or an authorized RCE — or through the optional `kubectl` path, and registers its `probe_id`, architecture and hash.

When a probe already exists, skip stages 1 and 2: `probe list` finds it in the workspace, the controller listens with `channel listen`, and the probe connects back with `inkblade-probe reverse`.

### Stage 3 — channel

The default channel is initiated by the probe: the controller listens with `channel listen` and the probe connects back from the Pod with `inkblade-probe reverse`. No Pod-side listening port is required, so the default least-privilege foothold needs outbound TCP only. When a local command transport exists, the stdio channel is available: `channel start` exposes loopback SOCKS5 and `--forward LOCAL:HOST:PORT` pairs, `channel status` reports state, and `channel stop` closes them. Child probes are delivered with `probe upload` + `probe spawn` and call back the same way.

### Stage 4 — detection

Detection is template execution. `session run --id <session> --module <key>` runs one template through the probe; `run --module <key>` runs it through the controller; `agent run` plans and executes a set of them against the objective graph. Every result carries steps, checks, findings, artifacts and a runtime marker.

### Stage 5 — escape

`execute --chain <id> --dry-run` resolves the chain graph and prints every write. Confirmed chains run with `execute --chain <id>`. A write step needs the backup gate: a receipt is created before the step and referenced afterwards. `exploit <id>` is the one-shot entry for a prepared exploit package; `--real` enables the RoE, backup and surface gates.

### Stage 6 — lateral

Lateral movement uses the same probe. Channel forwards (reverse or stdio) reach internal services through the Pod network namespace; `probe upload` + `probe spawn` starts a child probe on another Pod and it calls back the controller; `agent run` records each pivot as a graph edge with the evidence that proves it.

### Stage 7 — multi-probe

Every probe has a `probe_id` and a `parent_id`. A child inherits the parent's read-only state, command allow-list and budget, and can only be stricter. Depth is capped, fan-out is capped, and cleanup is child-first so no orphan keeps a token alive.

### Stage 8 — cross-cluster

`agent relay add` registers a relay to another cluster; `agent coverage status` shows which objective nodes are complete, which are reachable but unproven, and which have no path. `agent coverage proof` writes the completion proof that ships with the report.

### Stage 9 — report, rules and console

`report --run <id> --lang bi` renders the pentest narrative and the remediation checklist from the same evidence. `export --format sarif|ocsf|vex` produces machine-readable output. `rules generate` writes admission, runtime and network packs; `rules validate` replays them and prints the intercepted / detected / missed matrix. `inkblade ui` serves the local console with findings, probe trees, graphs and timelines.

### Write-permission checks

| Situation | What happens | What to do |
|---|---|---|
| Consent record expired | Every run exits 91 | Re-sign with a new window; old evidence stays valid |
| Out-of-scope target | Run refused before execution | Fix the scope or drop the target |
| Chain precondition false | Step skipped, the rest continues where possible | Run the prerequisite module first |
| Write step without backup target | Step refused, exit 91 | Provide a backup target |
| Rollback cannot restore a step | Exit 3, run marked | Treat the un-restored step as a finding and report it |

---

## 中文

### 九个阶段

| # | 阶段 | 命令 | 校验 | 产物 |
|---:|---|---|---|---|
| 1 | 立足 | `session open --mode foothold\|external`（可选 `kubeconfig`） | 签署授权、目标、时间窗 | 会话记录、审计轨迹 |
| 2 | Rust 探针 | `probe deploy --via sa-token\|rce`（可选 `kubectl`） | `--allow-write` 与会话级别 | 探针身份、SHA-256 |
| 3 | 通道 | `channel listen`（探针 reverse），`channel start` 用 stdio | 回环绑定策略 | 通道状态、任务日志 |
| 4 | 检测 | `session run --module`、`run --module`、`agent run` | 范围、级别、部署面 | 发现、证据锚 |
| 5 | 逃逸 | `execute --chain`、`exploit` | 链前置条件、备份校验 | 逃逸路径、证明 |
| 6 | 横向 | 通道转发、`probe upload` + `probe spawn`、`agent run` | 范围覆盖 | 可达图、跳板 |
| 7 | 多探针 | `probe spawn`、`probe list` | 父 token、嵌套层数、并发子探针数 | 探针树、血缘 |
| 8 | 跨集群 | `agent relay add`、`agent coverage status` | 中继 token、逐集群授权 | 中继状态、覆盖证明 |
| 9 | 报告 / 规则 / 控制台 | `report`、`export`、`rules generate`、`ui` | 外发前 `--redact` | 报告、规则包、控制台 |

### 第 1 步 — 立足

`session open` 把项目绑定到你已有的入口。`foothold` 从 Pod shell、ServiceAccount token 或授权 RCE 起步，不需要 kubeconfig；`external` 从可达服务起步，除只读侦察外，任何动作都先要有有界证明对象，再经授权 RCE 或回调投放探针；`kubeconfig` 是可选的批量 bootstrap，用于多个 Pod。记录里保存凭据的 SHA-256 指纹，不保存凭据本身。

### 第 2 步 — Rust 探针

`probe deploy` 投放静态二进制。不带 `--allow-write` 时只打印投放计划；带上后，探针经立足点（ServiceAccount token 或授权 RCE）或可选的 `kubectl` 路径投放，并登记 `probe_id`、架构与哈希。

已有探针时跳过第 1、2 步：`probe list` 列出在册探针，控制端用 `channel listen` 监听，Pod 内的探针用 `reverse` 回连。

### 第 3 步 — 通道

默认通道由探针发起：控制端 `channel listen`，Pod 内的 `inkblade-probe reverse` 主动回连。Pod 不用开监听端口，默认的最低权限立足点只要有出站 TCP 就够。目标环境里已有本地命令通道时，可以用 stdio 通道：`channel start` 暴露回环 SOCKS5 与 `--forward LOCAL:HOST:PORT`，`channel status` 报告状态，`channel stop` 关闭。子探针由父探针用 `probe upload` + `probe spawn` 投放，回连方式相同。

### 第 4 步 — 检测

检测就是执行模板。`session run --id <session> --module <key>` 经探针跑一个模板；`run --module <key>` 经控制器跑；`agent run` 针对目标图规划并执行一组模板。每个结果都带步骤、检查项、发现、产物与运行时标记。

### 第 5 步 — 逃逸

`execute --chain <id> --dry-run` 解析链图并打印每一处写入。确认后用 `execute --chain <id>` 执行。写步骤要过备份校验：执行前生成回执，执行后引用回执。`exploit <id>` 是预置利用包的入口命令；`--real` 启用 RoE、备份与部署面校验。

### 第 6 步 — 横向

横向复用同一颗探针。通道转发（反向或 stdio）经 Pod 网络命名空间访问内部服务；`probe upload` + `probe spawn` 在另一个 Pod 上启动子探针并回连控制端；`agent run` 把每个跳板记录成一条图边，并附上证明它的证据。

### 第 7 步 — 多探针

每颗探针都有 `probe_id` 与 `parent_id`。子探针继承父探针的只读状态、命令白名单和预算，且只能更严格。限制嵌套层数与并发子探针数量，清理先子后父，避免留下仍持有 token 的孤儿。

### 第 8 步 — 跨集群

`agent relay add` 注册到另一个集群的中继；`agent coverage status` 显示目标节点里哪些已完成、哪些可达但没有证明、哪些没有路径；`agent coverage proof` 写出随报告交付的完成证明。

### 第 9 步 — 报告、规则与控制台

`report --run <id> --lang bi` 用同一套证据渲染渗透叙事与修复清单；`export --format sarif|ocsf|vex` 产出机器可读结果；`rules generate` 写准入、运行时、网络三类规则包，`rules validate` 重放并输出拦截 / 检出 / 漏过矩阵；`inkblade ui` 提供本地控制台，展示发现、探针树、图与时间线。

### 写操作的五道校验

| 情况 | 会发生什么 | 怎么办 |
|---|---|---|
| 授权记录过期 | 所有运行退出 91 | 用新窗口重签；旧证据仍然有效 |
| 目标越界 | 执行前拒绝 | 调整范围，或去掉这个目标 |
| 链前置条件不成立 | 跳过该步，能继续的继续 | 先跑前置模块 |
| 写步骤没有备份目标 | 拒绝该步，退出 91 | 提供备份目标 |
| 回滚无法恢复某步 | 退出 3，这次运行被标记 | 把无法恢复的步骤作为发现报出 |
