# L3 自主执行（lead 预授权 + 硬边界 + 可回放）

> 适用：`inkblade explore autonomy --autonomy L3`、`inkblade supervisor run --autonomy L3`。
> 定位：L3 是**预授权后的受控自主循环**，不是让模型自由决定攻击动作。
> 每个动作仍是注册模块，仍逐条走 `core.runner` 的授权校验、范围校验、备份校验与三层落证。

## 1. 自主等级

| 级别 | 审批方式 | 谁来点 | 适用 | 代码状态 |
|---|---|---|---|---|
| **L0** | 逐动作人工审批 | lead | 客户生产、首次接触 | 现状 `explore propose/approve/execute` |
| **L1** | 规则/LLM 辅助排序，逐动作人工审批 | lead | 高风险目标、需要人判断顺序 | 现状 `explore propose --use-llm` |
| **L2** | 一次批准一批（≤5） | lead | 已建立信任的只读侦察批 | `explore approve` + `execute --workers` |
| **L3** | lead 一次性预授权 token；循环自动 propose→approve→execute | lead **一次** | 已签 RoE 全影响、白名单与预算明确的演练/验证 | `explore autonomy --autonomy L3` / `supervisor run --autonomy L3` |

L3 的「自动批准」由 token 前置授权 + 运行时硬边界共同构成；**没有 token 就没有 L3**。

## 2. 前置条件（缺一即拒绝，退出码 2）

1. `consent.json` 已签且 HMAC 验签通过（`roe_status == complete`）；
2. RoE 级别 = **全影响演示**（`roe.LEVELS[-1]`）；「利用验证」及以下直接拒绝；
3. 工作区存在 lead 签发的 `autonomy/grant.json`，且：
   - HMAC 覆盖全部字段（改白名单/预算/token 哈希都会验签失败）；
   - `status == active`、未过期；
   - `--preauth-token` 与 `token_sha256` 常量时间比对通过。
4. 显式 `--llm` 时必须存在真实 OpenAI 兼容端点：
   `core/llmpool` 已启用且至少一个端点（`llm_pool.json`），或显式
   `INKBLADE_LLM_BASE_URL`。**无端点拒绝执行，不静默降级**。
5. 白名单非空；`max_actions` / `max_steps` / 四项预算均为正。

## 3. 预授权流程

```bash
# 1) lead 签发（token 明文只显示一次；落盘只存 sha256 + 工作区 HMAC）
python -m inkblade autonomy grant \
  --workspace l3-lab \
  --allowlist rbac-mapping,network-policy-coverage,escape-primitives \
  --max-actions 4 --max-steps 3 \
  --budget-tokens 20000 --budget-latency-ms 120000 \
  --budget-approvals 6 --budget-interventions 2 \
  --ttl-seconds 1800 --note "2026-10 演练窗口"

# 2) L3 循环（RoE 必须是全影响演示）
python -m inkblade explore autonomy --workspace l3-lab --autonomy L3 \
  --llm --preauth-token "<grant 输出的 token>" --workers 2

# 3) 查看 / 撤销 / 回放
python -m inkblade autonomy status --workspace l3-lab
python -m inkblade autonomy revoke --workspace l3-lab --reason "演练结束"
python -m inkblade autonomy replay --workspace l3-lab
```

`grant` 只允许 lead/admin（`session.can("approve")`）；tester 直接 `PermissionError`。
写动作默认禁止，必须显式 `--allow-writes`；即便如此，写模块仍要过 runner 的备份校验
（缺 `backup_targets` → 退出码 91）。

## 4. 运行时硬边界

| 边界 | 实现 | 触发行为 |
|---|---|---|
| **白名单** | `AutonomyGuard.check_action`：模块必须在 `grant.allowlist` | `allowlist` 停；`audit.jsonl` 记 `autonomy.action.denied` |
| **写权限** | `grant.allow_writes=false` 时拒绝 `action.writes` | `write-not-granted` 停 |
| **范围** | `roe.scope_violation` 检查 `params.namespace/target_ns/host` | `scope` 停 |
| **预算硬顶** | 事前按 `tokens/latency_ms/approvals` 预扣；`used+reserved+next > limit` 即拒绝 | `budget` 停；不执行该动作 |
| **单步动作上限** | `len(actions) > grant.max_actions` | `action-cap` 停 |
| **步数上限** | `guard.steps >= grant.max_steps` | `max-steps` 停 |
| **异常即停** | 连续失败 ≥ 2（`ANOMALY_FAILURES`） | `anomaly` 停，后续步骤不再规划 |
| **确定性预算降级** | `core/cost.py` 在提议期先丢可选/写动作 | 记录 `cost.degraded`，不交给模型「自觉省」 |

预算计数单位：`approvals` 按动作数计（L3 的「审批」是预授权记账，不是人工点击）；
`tokens` 为动作文本的确定性估算（4 字符/token，与 `core/cost.py` 同口径），
不冒充真实账单；`latency_ms` 取实测步时延与估算的较大值。

## 5. 全审计与回放

- `audit.jsonl`（工作区级，参数经 `jsonio.redact` 脱敏）：
  `autonomy.grant` / `autonomy.preflight` / `autonomy.guard.init` /
  `autonomy.step` / `autonomy.stop` / `autonomy.action.denied` /
  `autonomy.llm.fallback` / `autonomy.supervisor.run` / `autonomy.revoke`。
- `autonomy/trace.jsonl`：每步 `{step, proposal, mode, plan, plan_sha256, results, budget}`。
  `plan_sha256` 覆盖 `(seq, module, writes, params)` 的规范化 JSON。
- `python -m inkblade autonomy replay` **只重放决策面，不执行模块、不写证据**；
  任一行 digest 不匹配即 `AutonomyRefused`（被篡改/版本漂移）。
- 需要重新执行时只能用**新 grant**（新 token），旧 trace 作为对照证据保留。

## 6. 确定性回退

- 启动期：显式 `--llm` 且无端点 → **拒绝**（不是静默规则模式）。
- 运行期：LLM 网络/解析/越界失败 → `core/explorer` 降级 rules 排序，
  `proposal.mode=rules` + `llm_note`；L3 额外写 `autonomy.llm.fallback`，
  返回 `llm_fallbacks` 计数。规则排序是确定性的（只读在前、有资产目标在前、链成立优先）。
- 回退不改变白名单/预算/异常边界；回退后的动作仍逐条过护栏。

## 7. 与 ARTEX 的差异

ARTEX（Autumn-27 / RuoJi6 维护分支）是 LLM 多 agent 自主渗透系统：agent 探索循环 +
`llmpool` 多模型 worker 池 + `intercept` 人工审批拦截 + `guard`/`evidence`/`report`。
本实现的 L3 与其**同题不同解**，差异是刻意的：

| 维度 | ARTEX | InkBlade L3 |
|---|---|---|
| 自主边界 | agent 可连续调用工具；人工拦截只是审批点 | 只执行**注册模块**；动作面天然受限，不能自由 shell |
| 授权模型 | 运行中人工 approve / intercept | lead **一次性 token** 前置授权 + TTL + 可撤销 + 工作区 HMAC |
| 白名单 | 依赖策略/提示 | grant 内模块白名单 + 写权限开关，代码强制 |
| 预算 | token/worker 池配额 | token/时延/审批/干预四项**事前硬顶**，越顶不执行 |
| 异常 | 人工观察/停止 | 连续失败、越界、写未授权、预算越顶均**自动停** |
| 回放 | 运行日志 | `trace.jsonl` + `plan_sha256`，`autonomy replay` 只读重放 |
| LLM 失败 | 依赖模型/编排 | 启动拒绝无端点；运行期确定性 rules 回退并留痕 |
| 审计 | 平台日志 | `audit.jsonl` 全事件 + 每步 trace；参数脱敏、token 不落明文 |

## 8. 已知限制

- L3 的「自主」止步于模块选择与排序；**不会**生成新利用代码、不会绕过备份校验。
- 预授权 token 被窃取的风险由 TTL、白名单、预算与 `revoke` 收敛，但不能消除；
  生产演练应把 token 放在 lead 的密钥管理里，不写进 shell history。
- token 计数是估算而非账单；真实成本以 `llm_pool_records.jsonl` 的端点为维度统计。
- 回放校验的是**决策面**，不校验外部集群状态；集群漂移后同一计划可能失败，
  这正是「回放不等于重放」的原因。
- 真实 LLM 端点未在 CI 中调用（无外网/密钥）；CI 验证的是预检拒绝、白名单、预算、
  异常停止、审计与回放。真实端到端演练需在客户环境按 `docs/ENTERPRISE-READINESS.md` 复测。
