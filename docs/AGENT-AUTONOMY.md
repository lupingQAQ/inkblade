# InkBlade Agent 自主运行时（2026-10）

> 状态：实现已落地。本文描述 **事件溯源 + 图黑板 + 调度器 + 角色 worker** 的运行方式，
> 以及与旧「批动作 / 逐步审批」模式的差异。所有目标侧动作仍然只经探针执行；agent
> 不导入、不执行任何模块代码，也没有宿主回退路径。

## 1. 架构

```text
CLI / API / MCP / A2A
        │ 一次授权（RoE HMAC + lead 启动确认）
        ▼
┌──────────────────────────── AgentSupervisor ────────────────────────────┐
│  Planner（LLM 结构化输出 / deterministic 降级）                          │
│      │  graph delta（intent / hypothesis / hint）                       │
│      ▼                                                                  │
│  PlanGraph（Fact / Intent / Hint + 因果边 + 证据门控）                    │
│      │  frontier                                                         │
│      ▼                                                                  │
│  TaskScheduler（priority / cost / lease / retry / budget / DLQ）          │
│      │  claim + lease                                                    │
│      ▼                                                                  │
│  WorkerPool: recon │ exploit │ verify │ report                           │
│      │                                                                  │
│      ▼  session.probe_task(template, params, task_id)                    │
│  Rust probe（目标 Pod 内原生执行；无 Python/解释器/宿主回退）              │
│      │  probe result（findings / steps / artifacts / sha256）             │
│      ▼                                                                  │
│  Observer → Evidence（sha256）→ confirmed Fact / hypothesis / failure     │
│      │                                                                  │
│      ▼                                                                  │
│  EventLog（append-only JSONL + hash chain + checkpoint + replay）         │
└─────────────────────────────────────────────────────────────────────────┘
```

关键不变量：

1. **证据门控**：`Fact(status=confirmed)` 必须引用至少一条 `source=probe` 且带 64 位
   SHA-256 的证据；意图完成时探针意图也必须带证据。模型只能提出 hypothesis。
2. **探针唯一执行**：worker 只调用 `session.probe_task`；`ProbeSession` 没有宿主执行分支。
   未配置探针、未知探针 id、探针不可用都会在创建 run 之前拒绝。
3. **supervisor 不执行**：supervisor 只做规划、选 intent、租约和折叠结果；探针调用在
   角色 worker 内。
4. **一次授权，自主循环**：RoE 签名 + lead 启动确认之后，不再要求逐步审批。写动作只在
   `--allow-destructive` + RoE `全影响演示` + 备份目标/回执满足时自动执行。
5. **可恢复**：每个决策/动作/证据/预算变化都是事件；checkpoint 存图快照，`resume` 跳过
   已完成 intent，`replay`/`--to-seq` 可零执行回放任意前缀。

## 2. 运行循环

运行不是固定的阶段管线，而是「图状态驱动的持续循环」：

1. 读取持久日志，恢复图、预算和租约；中断的 claimed intent 重新排队。
2. 若 frontier 为空，Planner 读取目标、已确认事实、frontier、预算、记忆和技能索引，
   返回一个 **graph delta**（新增 intent / hypothesis / hint，或 stop）。
3. Scheduler 按 priority、cost、创建顺序和记忆先验选择 Intent；先检查 RoE/范围/写面/
   备份策略，再签发 lease。
4. 角色 worker 执行：`session.probe_task` → Rust probe；结果由 Observer 归一化为
   evidence/facts/assets/capabilities/reachability/failure。
5. Scheduler 完成或重试 intent；预算、图、事件、checkpoint 落盘。
6. 目标的所有机器可判定检查通过后结束；预算、kill switch、越界或策略拒绝会带明确
   status 结束，并保留 trace/reflection。

`--dry-run` 只执行第 1–2 步的规划，不签发 lease、不调用探针。

## 3. 决策格式

Planner 每次返回严格 JSON（OpenAI 兼容池或 `mock:<script.json>`）：

```json
{
  "decision": "propose_intents",
  "rationale": "为什么这一步是当前 frontier 的最优选择",
  "expected_evidence": ["可复核证据类型"],
  "intents": [
    {
      "role": "recon|exploit|verify|report",
      "module": "declarative-template-key",
      "params": {"target": "http://127.0.0.1:8080", "namespace": "train"},
      "priority": 9,
      "cost_tokens": 120,
      "requires": ["fact-3"],
      "writes": false,
      "cleanup": false,
      "probe": true,
      "expected_evidence": ["finding/artifact"],
      "success": "machine-checkable criterion"
    }
  ],
  "facts": [{"claim": "...", "status": "hypothesis", "fact_kind": "..."}],
  "hint": {"text": "...", "priority": 5}
}
```

或：

```json
{"decision": "stop", "rationale": "objective satisfied / budget exhausted"}
```

校验规则：`decision` 只能是 `propose_intents|stop`；必须有 `rationale`；intent 的 role
必须在四类 worker 中；params 不得包含 `command/shell/script` 等宿主执行键；模型提出的
fact 只能是 `hypothesis`；confirmed 只能由 Observer 根据探针证据晋升。LLM 失败按
`max_retries` 重试；仍失败时记录 `llm.degraded` 并降级到 deterministic planner。
`graph-swarm`/`supervisor` 模式必须有 LLM；`--mode deterministic` 是显式降级基线。

## 4. 预算与停止

| 维度 | 入口 | 硬边界 |
|---|---|---|
| token | `--budget-tokens` | 每次 LLM 调用后扣减；超限不再签发新 intent |
| step | `--budget-steps` | 每次 claim 扣减；超限不再 claim |
| action | `--budget-actions` | 每次 intent 完成扣减 |
| wall clock | `--budget-seconds` | 每次循环/claim 检查；超限停止 |

- 预算超限写入 `budget.exceeded` 事件，最终 status 为 `budget-exceeded`；不会把超限
  伪装成成功。
- `agent stop --run-id ...` 写 run 级 STOP 标记和 `run.stopped` 事件；工作区
  `abort.json` 同样被识别。supervisor 在每个循环和 claim 前检查。
- 预算/停止/越界/无探针/策略拒绝都有独立 status 和 trace，便于评测和审计。

## 5. 安全边界

| 边界 | 行为 |
|---|---|
| 授权 | RoE `consent.json` HMAC 验签 + lead 一次性启动确认（`--start-token` 或 lead `--yes`/隐式启动）；无授权不创建 run |
| 范围 | 递归检查 `target/host/url/endpoint/address` 与 `namespace/target_ns`；只接受 RoE CIDR 内的 IP/URL，越界直接 `policy.refused` |
| 只读 | 默认只读 intent 自动执行；recon/verify worker 拒绝写入 intent |
| 写动作 | 需要 `--allow-destructive` + RoE `全影响演示` + 非空且可用的 `backup_targets`；runner 仍会二次执行退出码 91 备份校验 |
| 审批 | 默认 `auto`，没有逐步审批；`--approval manual` 只是兼容模式，仅在写 intent 前产生 `approval.required` |
| 探针 | 所有动作经 `session→probe_task→Rust probe`；没有 host fallback；无探针/未知探针在创建 run 前拒绝 |
| 证据 | confirmed 必须带 probe 证据 SHA-256；observer 拒绝无 evidence 行/无 hash 的步骤 |
| 清理 | 目标要求清理时，cleanup 是独立写 intent，必须走同样备份校验并留证 |
| 记忆/技能 | semantic 写入必须有 `source_ref`；skill/human 写入需 `approved_by`；技能只有 approved 才进入检索；支持版本回滚 |

### 与旧审批模式的差异

| 维度 | 旧 explorer/supervisor | 本运行时 |
|---|---|---|
| 授权粒度 | 批动作 / 每个动作批准 | 一次 RoE + lead 启动；之后自主选择 |
| 下一步 | 固定候选列表或 FIFO | 图 frontier（priority/cost/记忆先验） |
| 状态 | 进程内 proposal/queue | 事件溯源 journal + checkpoint + replay |
| 写动作 | 逐动作审批 | `--allow-destructive` + RoE + 备份校验 |
| 观察 | result dict | evidence-gated facts/assets/capabilities/failures |
| 恢复 | 失败整链重跑 | resume 跳过 done，重试 failed/incomplete |
| 轨迹 | 部分 audit | 决策/选择/证据/预算全事件 trace |

## 6. CLI

```bash
# lead 先签发一次性启动 token（可选；也可 lead --yes 启动）
inkblade agent authorize --objective cluster-takeover --allow-destructive \
  --budget-tokens 20000 --budget-steps 12

inkblade agent run --objective cluster-takeover --probe lab-probe --llm pool \
  --budget-tokens 20000 --budget-steps 12 --allow-destructive \
  --start-token <token> --mode graph-swarm --workers 2

inkblade agent run ... --dry-run                 # 只规划，不执行探针
inkblade agent status --run-id <id>              # 图/预算/目标/日志
inkblade agent trace  --run-id <id> --limit 200  # 决策轨迹
inkblade agent replay --run-id <id> --to-seq 40  # 零执行回放
inkblade agent resume --run-id <id>              # 从 checkpoint 继续
inkblade agent stop   --run-id <id> --reason "operator stop"
inkblade agent eval   --modes deterministic,supervisor,graph-swarm
```

`--probe` 必须在 `agent/probes.json`（或 `agent-probes.json`）注册；`reference` 仅用于
mock range，且要求 `--allow-reference` 或 `INKBLADE_ALLOW_REFERENCE_PROBE=1`，结果会
标注 `runtime=reference`。生产探针使用 `rust-local`/`rust-object`，结果标注
`runtime=rust`。当前主机没有 `cargo`/`kubectl`，因此实测使用 mock range 的 reference
conformance 运行时；真实 k3s 验证需在配备 Rust 工具链与 kubeconfig 的主机执行。

## 7. 评测与验证

`inkblade/agent/eval.py` 提供 CyberGym/AgentDojo 风格任务集与三种模式对比：

- `deterministic`：固定 objective stages（降级基线）。
- `supervisor`：脚本/LLM supervisor + FIFO 单 worker 控制组。
- `graph-swarm`：图 frontier + 有界角色 worker。

指标：成功率、步数、token、人工干预、证据覆盖率、探针调用数、时延。golden 任务为
8 步集群夺权链（侦察 → 暴露面 → RBAC → 探针投放 → 提权 → 夺权证明 → 报告 → 清理），
在 mock range 上断言成功、预算停止、越界拒绝、无探针拒绝和 trace 完整性。结果写入
`reports/agent-eval/`，不冒充真实 k3s 成绩。

## 8. 文件索引

| 文件 | 职责 |
|---|---|
| `inkblade/agent/runtime.py` | 事件日志、hash chain、checkpoint、resume/replay、四维预算 |
| `inkblade/agent/graph.py` | Fact/Intent/Hint、因果边、证据门控、frontier |
| `inkblade/agent/objectives.py` | 机器可判定目标与 deterministic stage |
| `inkblade/agent/scheduler.py` | frontier/priority/cost/lease/retry/dead-letter/budget |
| `inkblade/agent/supervisor.py` | 规划→选择→worker→观察→完成的编排 |
| `inkblade/agent/workers/` | recon/exploit/verify/report；探针唯一执行 |
| `inkblade/agent/observer.py` | 探针结果→证据/事实/资产/能力/失败 |
| `inkblade/agent/planner.py` | LLM 结构化输出、重试、脚本/确定性降级 |
| `inkblade/agent/policy.py` | RoE/范围/写面/备份/启动确认/kill switch |
| `inkblade/agent/probes.py` | `probe_task` 会话、Rust/reference 探针解析 |
| `inkblade/agent/protocols.py` | MCP Tasks、SEP-2640 技能包、A2A 只读委派 |
| `inkblade/agent/memory.py` | working/episodic/semantic、Reflexion、记忆投毒防护 |
| `inkblade/agent/skills.py` | 版本/成功率/审批/晋升技能库 |
| `inkblade/agent/eval.py` | 三模式评测基座 |
| `inkblade/agent/cli.py` | `inkblade agent ...` 子命令 |
