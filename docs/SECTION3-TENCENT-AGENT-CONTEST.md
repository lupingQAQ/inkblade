# 第三节：腾讯 Agent 渗透大赛开源项目对比

> 范围：腾讯云黑客松 · 第一届（2025-11）与第二届（2026-04）智能渗透挑战赛的公开
> 参赛项目、官方答辩材料与赛后复盘。只做**产品/架构层**对比，不复用任何参赛代码；
> 克隆仅用于只读研究（见 `.slim/clonedeps/clonedeps.json`）。
>
> 结论先行：参赛项目的强项不在「某个漏洞利用脚本」，而在**编排层**——任务分解、
> 观察空间、错误恢复、成本预算、证据可追溯、以及让人愿意用的交互。我们的
> explorer 在提议阶段仍停留在「一次给 5 个动作、一次批准、失败靠人」，这是本节
> 要补的课。

---

## 1. 赛事坐标（官方口径）

| 赛季 | 时间 | 规模 | 赛制要点 | 官方入口 |
|---|---|---|---|---|
| 第一届 | 2025-11-10 ~ 11-29 | 238 支战队（xbow-competition 自述 7/238） | 基于 XBOW benchmark，比赛时段内题目随机轮换；仅限国内模型 | <https://zc.tencent.com/hackathon> |
| 第二届 | 2026-04-13 ~ 04-25 | 610 支战队 / 1,345 人；提交 11,031 次 | 54 个 flag，四赛区阶梯解锁；主赛场 + 「零界」Agent 社交平行赛场；不限模型 | <https://zc.tencent.com/competition/competitionHackathon?code=cha004> |

第二届主赛场四赛区（官方描述）：

1. **识器·明理**：20+ SRC 场景，自动化众测与主流漏洞发现；
2. **洞见·虚实**：典型 CVE、云安全、AI 基础设施漏洞；
3. **执刃·循迹**：多层网络，多步攻击规划与权限维持；
4. **铸剑·止戈**：基础域渗透，企业核心内网推演。

计分采用「解题名次 + 时间衰减」：第 1 名 +20%，第 31 名及以后 -80%；查看提示额外
扣 10%。这把「能不能解」变成了「解得多快、多省」，也直接解释了为什么头部项目都在
做**预算、并发、上下文压缩与终止判定**（来源：CHYing-agent 赛后复盘）。

官方资料聚合仓：[`Yeti-791/Tsec-Hackathon`](https://github.com/Yeti-791/Tsec-Hackathon)
（两届 Top20 导航、答辩 PPT、答辩视频、复盘文章索引）。本节所有「成绩」均取自
该仓导航、项目 README 或队伍公开复盘，未做二次推断。

---

## 2. 研究样本与克隆清单

按「架构代表性 + 可获取性 + 许可清晰度」选取 8 个项目做逐项对比，其中 5 个克隆到
`.slim/clonedeps/repos/`（`--depth 1`，只读）：

| # | 项目 | 队伍 / 赛季 | 许可证 | 快照 | 克隆 |
|---|---|---|---|---|---|
| P1 | [BreachWeave](https://github.com/m-sec-org/BreachWeave) | ai 小分队（绿盟）· 第二届第 1 | Apache-2.0 | `bc2d950` (2026-10-09) | ✅ |
| P2 | [Cairn](https://github.com/oritera/Cairn) | Bytex · 第二届第 3（唯一 AK） | AGPL-3.0 | `8e7e0ea` (2026-09-07) | ✅ |
| P3 | [aide-for-pentest](https://github.com/chainreactors/aide-for-pentest) | For Future · 第二届第 7 | 未声明（无 LICENSE 文件） | `958f7cf` (2026-04-30) | ✅ |
| P4 | [CyberStrikeAI](https://github.com/AIPentest/CyberStrikeAI) | 小白战队 · 第一届第 17 | Apache-2.0 | `c0d5c84` (2026-10-23) | ✅ |
| P5 | [LuaN1aoAgent](https://github.com/SanMuzZzZz/LuaN1aoAgent) | BinX · 第一届第 3 | AGPL-3.0 | `a035429` (2026-09-15) | ✅ |
| P6 | [tinyctfer](https://github.com/chainreactors/tinyctfer) | Antix · 第一届第 4 | 未声明 | README 快照 | — |
| P7 | [CHYing-agent](https://github.com/yhy0/CHYing-agent) | yhy · 第一届第 9 / 第二届主赛场第 60、零界第 1 | MIT | README 快照 | — |
| P8 | [xbow-competition](https://github.com/m-sec-org/xbow-competition) | ai 小分队 · 第一届第 7 | 未声明 | README 快照 | — |

> 许可提示：P2/P5 为 AGPL-3.0，P3/P6/P8 未声明许可证。InkBlade 只做**行为与架构**
> 层面的公开研究，不复制代码、不引入依赖；产品实现全部 clean-room。

---

## 3. 逐项目表

### P1 BreachWeave（第二届冠军）

| 维度 | 事实 |
|---|---|
| 团队/仓库 | ai 小分队（绿盟科技）/ `m-sec-org/BreachWeave` |
| 许可证 | Apache-2.0 |
| 架构 | Bun monorepo：`apps/cli` + `packages/core` + `ui-web`(Bun.serve REST) + `ui-tui`(Ink)；基于 `pi-coding-agent` / `pi-ai` SDK |
| Agent 设计 | **Manager / Solver / Observer** 三角色：Manager 管节奏与分配，Solver 并行推进攻击路线，Observer 旁路监督（偏移、状态混杂、过早结束、上下文过重） |
| 工具集 | pi SDK 工具 + MCP 适配器 + 内置 skills 18+（recon、ffuf、nuclei、JWT/OAuth、payload 研究、Redis webroot RCE、命令执行等）；`rtk rewrite` 命令改写 |
| 记忆 | `Idea`（值得推进的方向）与 `Memory`（可复用事实/证据/约束）分层；`challenge/store.ts` + board store；压缩时强制保留 scope/assets/hypotheses/findings/auth/evidence/phase/next |
| 评测方式 | TCH 第二届线上 1/613、线下决赛一等奖；官方答辩材料另述「7 模型并行竞争上岗」 |
| 成绩 | 第 1 名（一等奖） |
| 可借鉴 | ① 监督者不抢执行权；② 「方向」与「事实」分仓；③ 结束条件外置；④ 压缩协议是**结构化清单**而不是摘要散文 |

实现细节（只读快照）：`packages/core/src/solver/extension/` 下有 `scope-guard.ts`
（工具调用预算 `maxToolCalls` / `mainDirectActionLimit`）、`rtk-rewrite.ts`、
`large-tool-result.ts`、`challenge-observer/ralph-loop.ts`（有界续跑，最多 10 次、
指数退避 1s→10s）。这说明冠军方案的「自主」并不是无限放权，而是**有界重试 + 旁路
监督 + 明确终止**。

### P2 Cairn（第二届第 3，唯一 AK）

| 维度 | 事实 |
|---|---|
| 团队/仓库 | Bytex（个人）/ `oritera/Cairn` |
| 许可证 | AGPL-3.0（商业使用需单独授权） |
| 架构 | Python 3.12：`cairn server`（FastAPI + SQLite/静态前端）+ `cairn dispatch`（调度、容器、协议唯一写者）；worker 容器或 local 模式 |
| Agent 设计 | **无角色、无工作流**：黑板三原语 `Fact / Intent / Hint`；Worker 跑 OODA，任务从图状态运行时生成；通过黑板 stigmergy 协作，无直接通信 |
| 工具集 | 不内置领域工具；worker 后端为 Claude Code / Codex / Pi，复用各 CLI 已有工具；零 MCP、零 RAG（作者自述） |
| 记忆 | 显式 fact-intent 图（项目级持久化）；Hint 人类判断随时注入，下次读图即吸收 |
| 评测方式 | 第二届 54/54 flag（唯一 AK），线上/线下第 3；作者称赛前未调优、比赛当天凌晨才跑通 |
| 成绩 | 第 3 名；官方导航称「全场唯一 AK，7692 元成本」 |
| 可借鉴 | ① 把「未知」显式建模成 Intent，而不是让模型在上下文里记 TODO；② 人类输入是一等公民（Hint）；③ 成本可核算（按 token/模型账单） |

> 重要边界：Cairn 的「无角色」是**竞赛场景**下的涌现式搜索；企业授权渗透需要
> 责任链、审批与证据固化，不能直接照搬。可迁移的是「事实/意图/提示」三态与
> 图上的准入调度。

### P3 aide-for-pentest（第二届第 7）

| 维度 | 事实 |
|---|---|
| 团队/仓库 | For Future / `chainreactors/aide-for-pentest` |
| 许可证 | 未声明（仓库无 LICENSE；默认保留所有权利） |
| 架构 | 「通用 Agent 运行时 + 场景 overlay」：本仓只保留 pentest overlay（workspace 模板、任务、prompt、skill、nuclei 工具、Kali worker、脱敏配置）；`aide` core/runtime 未开源 |
| Agent 设计 | 三套 pattern：`explore_plan_execute`（探索→计划→执行，计划提交为 checkpoint，HITL/autoapprove 两种评审）、`ant_colony`（蚁群）、`ralphloop`（持续迭代）；任务角色 coordinator + ant/explorer/ralph |
| 工具集 | Kali Docker worker（常用安全工具）+ `nuclei_templates` 检索工具 + `ctf-ops` skill（回连策略、模板入口、工具速查、共享状态协议） |
| 记忆 | 共享状态协议写在 skill 中；plan/step 作为结构化输出；无独立长期记忆层 |
| 评测方式 | 第二届线上第 7，50/54 解题率 |
| 成绩 | 第 7 名 |
| 可借鉴 | ① **HITL 卡在「计划」而不是每个工具调用**——审批点设计的关键样本；② 场景适配层与 runtime 分离，换靶场不换引擎；③ 明确「不要伪造下一步」（no fabricated work） |

`resources/patterns/explore_plan_execute.yaml` 的流程节点：`start(intention) →
explore(action) → plan(action, checkpoint) → execute_step(action) → done(result)`，
`max_steps: 12`。计划节点要求 `steps / success_criteria / risks / status / next_gate`，
人类在 checkpoint 上批一次，后续步骤连续执行——这正是「不打断心流」的形态。

### P4 CyberStrikeAI（第一届第 17，产品化程度最高）

| 维度 | 事实 |
|---|---|
| 团队/仓库 | 小白战队 / `AIPentest/CyberStrikeAI`（原 `Ed1s0nZ/CyberStrikeAI`） |
| 许可证 | Apache-2.0 |
| 架构 | Go + Eino 编排 + SQLite；`internal/` 下 `agent`、`multiagent`、`workflow`、`attackchain`、`hitl`、`toolguard`、`audit`、`knowledge`、`mcp`、`c2`、`vision` 等 |
| Agent 设计 | 单 Agent 与 Deep / Plan-Execute / Supervisor 多模式；工作流节点含 Agent、工具、条件、**审批**、输出；角色化测试（按场景给提示词与工具策略） |
| 工具集 | 100+ YAML 工具配方、MCP（HTTP/stdio/SSE/联邦/动态发现）、阻塞工具 worker 化（`execution_id` 多轮等待/取消/熔断/并发限制）、Agent Skills 渐进加载、RAG 知识库、视觉模型 |
| 记忆 | SQLite 持久化对话/任务/漏洞/资产；「证据沉淀为运营记忆」；攻击链图谱与步骤回放 |
| 评测方式 | 竞赛名次 + 产品功能矩阵；未见公开冻结 benchmark |
| 成绩 | 第一届第 17；当前 8k+ stars |
| 可借鉴 | ① 审批模式 + 工具白名单 + 审计 Agent 复核是「可运营」的最小集；② 工具执行治理（同一份兜底结果入库、恢复路径二次防御）解决超大输出；③ 资产/漏洞/攻击链统一工作台，报告不是终点 |

### P5 LuaN1aoAgent v2（第一届第 3）

| 维度 | 事实 |
|---|---|
| 团队/仓库 | BinX（广州大学）/ `SanMuzZzZz/LuaN1aoAgent` |
| 许可证 | AGPL-3.0 |
| 架构 | TypeScript + Node 25 + Pi SDK；Planner / Executor / Observer；SQLite + JSONL 账本 + Artifact + 每 Task 沙箱 |
| Agent 设计 | Planner 维护**任务图**（目标/任务/里程碑/阻塞/依赖），Executor 接有界 `TaskEnvelope` 自选工具，Observer 分 Supervisor（热路径控制）与 Projector（异步图投影）；结构化终止工具（`planner_submit` / `task_result_submit` / `control_submit` / `graph_delta_submit`） |
| 工具集 | read/grep/find/ls/bash/web_fetch/web_search/vulnerability_search/browser_render/artifact_read/write/route_*；外部 Skills（pentest-skills、ctf-skills 等）按需安装 |
| 记忆 | **因果推理图**：Evidence → Hypothesis → Vulnerability → Exploit；确认节点无证据引用不可写入；大输出进内容寻址 Artifact，仅留 preview |
| 评测方式 | v1 的 benchmark 明确**不自动归属** v2，需冻结版本重跑后才发布 |
| 成绩 | 第一届第 3 |
| 可借鉴 | ① 「证据不足不能升级为结论」应写进数据模型；② 任务/动作分离（图管目标，ExecutionLog 管低层动作）；③ 单任务轮次预算 + 全局时间预算；④ 实时轨迹与因果图是 UI 一等公民 |

### P6 tinyctfer（第一届第 4）

- 定位：约百行核心代码的「意图运行时」，作者称「100 行代码，无需调优」。
- 关键概念：**Meta-Tooling**——让模型输出完整意图/脚本，而不是逐原子工具调用；
  Claude Code SubAgent + Docker 沙箱（`l3yx/sandbox`）+ 可选 VNC 观察。
- 局限：SubAgent 与 CTF 强耦合，只以找 flag 为目标；调度/提示词切换代码未整理。
- 可借鉴：工具粒度不必等于「一个模块一次 run」；对高确定性场景，**生成一段可审阅的
  意图脚本**比 20 次工具往返更省 token，也更接近专家工作方式。
- 许可：未声明，仅作研究引用。

### P7 CHYing-agent（第一届第 9，第二届零界第 1）

- 架构：Orchestrator + Executor（Kali Docker）/ Browser（Chrome DevTools MCP）/
  C2（MSF）/ Reverse（Ghidra MCP）。
- **MCP 可见性控制**：`visibility: "subagent:browser"` 让 30 个浏览器工具只对
  Browser 子 Agent 可见，Orchestrator 工具列表从 50+ 降到十几个。
- **PromptCompiler / ProgressCompiler / RetryHandoffCompiler**：做题前先「审题」；
  compact 时由独立轻量 Agent 生成接班简报；重做时编译历史为续作报告。
- 实测：GLM-5 跑 XBOW 104 题约 57%，平均 20 分钟/题（仅 PromptCompiler + 可见性
  版本）；作者明确说后两个编译器没做 A/B。
- 成本：主赛场 200 元 + 零界 500 元，总 700 元；并发 429 是主要节奏瓶颈。
- 可借鉴：① 工具**可见性**比工具数量更重要；② 压缩/接班要交给独立 Agent；
  ③ 成本与时延要按「题」核算，并接受「简单题不值得编译」的分级。

### P8 xbow-competition（第一届第 7）

- 组成：`ez-xbow-platform-mcp`（Go MCP server：挑战管理、9 类漏洞知识库、持久
  Kali 容器、尝试历史）+ `kimi-cli-for-xbow`（Python CLI：多模型、ctfer/security
  模式、daemon 无人值守、命令执行防沉迷、session 隔离）。
- 成绩：第一届 7/238，线下优秀奖。
- 可借鉴：① MCP 把「平台能力」与「模型能力」解耦；② 尝试历史跨 session 共享；
  ③ 「防沉迷」= 对循环/过度命令的硬预算。
- 许可：未声明。

---

## 4. 维度矩阵

图例：● 明确具备并产品化；◐ 部分具备/依赖外部；○ 基本没有；? 公开材料不足。
「InkBlade HEAD」= 本节改动前的 `c921595` 行为。

| 维度 | P1 BreachWeave | P2 Cairn | P3 aide | P4 CyberStrike | P5 LuaN1ao | P6 tinyctfer | P7 CHYing | P8 xbow | InkBlade HEAD |
|---|---|---|---|---|---|---|---|---|---|
| 任务分解 | ● Manager 分配 + Solver 并行 | ◐ 图上的 Intent 运行时生成 | ● explore→plan→execute（12 步） | ● Plan-Execute/Supervisor/工作流 | ● 任务图 + 依赖准入 | ○ 单题单循环 | ◐ Orchestrator 分派 | ◐ daemon 串行 | ◐ 候选排序 + max 5，无阶段 |
| 自主度分级 | ◐ 角色分工，非显式档位 | ● 无角色=最大自主，但有 hint/终止 | ● HITL / autoapprove 两档 | ● 审批模式 + 工具白名单 | ● Supervisor 决定继续/checkpoint/停止 | ○ | ◐ 人工/自动混合 | ◐ 无人值守开关 | ○ 只有「批/不批」 |
| 人机协作点 | ◐ Observer 旁路 + hint | ● Hint 随时注入 | ● 计划 checkpoint 审批 | ● 审批节点 + 审计复核 | ● checkpoint / 交回 Planner | ○ | ◐ 人给策略，Agent 执行 | ○ | ○ 仅整包批准 |
| 观察空间设计 | ● 工具结果改写/压缩 + Memory/Idea | ● Fact/Intent/Hint 图 | ◐ 结构化 plan/step | ● 工具结果治理 + 攻击链 | ● 因果图 + Artifact + 事件账本 | ○ | ● 进度/接班编译器 | ◐ 尝试历史 | ○ 结果 dict，无证据指针 |
| 工具粒度 | ● 原子工具 + skills + 命令改写 | ● 交给 worker CLI（粗粒度） | ● Kali 工具 + nuclei 检索 | ● 100+ 工具配方 + MCP | ● 细粒度工具 + 沙箱 | ● Meta-Tooling（意图脚本） | ● 子 Agent 封装 + 可见性 | ● MCP 能力抽象 | ○ 模块=一次 run |
| 错误恢复 | ● ralph 有界重试 + Observer 纠偏 | ◐ 重新调度 Intent | ● 重试/回退在 runtime | ● 熔断/取消/worker 化 | ● 有界新 session 重试 + 预算 | ○ | ● RetryHandoff | ◐ 防沉迷 | ○ 失败即记录，无策略 |
| 成本预算 | ◐ 工具调用上限；7 模型竞争 | ● 单题成本可核算 | ◐ pattern max_steps | ◐ 并发/超时治理 | ● 任务/时间预算 | ○ | ● 按题核算（700 元） | ◐ 防沉迷 | ○ 无 token/时延预算 |
| 多 Agent 协作 | ● Manager/Solver/Observer | ● 黑板 stigmergy | ● coordinator + 三类 worker | ● Supervisor/Deep/多角色 | ● P-E-O + 并发任务 | ○ | ● Orchestrator + 4 子 Agent | ○ | ◐ supervisor 并发（另一路径），explorer 串行 |
| 技能复用 | ● 18+ 内置 skills | ○ 刻意不做领域技能 | ● ctf-ops + 场景 overlay | ● Skills + RAG + 角色 | ● 外部 Skills 生态 | ◐ 单 skill | ● Skill 体系（零界 8 个） | ◐ 知识库 | ◐ 模块/链/模板，缺 playbook 层 |
| 评测方法 | ● 实战 54 flag，第 1 | ● 54/54 AK | ● 50/54 | ◐ 名次 + 功能矩阵 | ● v1 benchmark，v2 待重跑 | ◐ 单题 demo | ● XBOW 104 题 57% | ● 238 队第 7 | ◐ lab 仿真 + 单测，缺前后对照 |
| UX 交互 | ● Web + TUI + 配置台 | ● Web 图 + hint | ◐ CLI/pattern | ● 仪表盘/任务/漏洞/资产/会话 | ● 实时轨迹 + 因果图工作台 | ◐ VNC 旁观 | ◐ 日志/复盘 | ◐ CLI | ○ CLI/JSON 为主 |
| 可观测性 | ● Observer 轨迹 + 统计 | ● 图增量 + 协议日志 | ◐ plan/step 输出 | ● 审计/决策追踪/回放 | ● 事件账本 + 图 + Artifact | ○ | ◐ 日志 | ◐ 尝试历史 | ◐ audit.jsonl/evidence.db，缺实时视图 |

**矩阵读数**：

- 冠军/前列项目的共同点是 **观察空间 + 终止/预算 + 监督**，而不是「更多工具」。
  P4 工具最多，但只排第 17；P2 零工具、零 MCP，却唯一 AK。
- 「自主度」不是越高越好：P1 用 Observer 和 ralph 上限约束自治，P3 把 HITL 卡在
  计划层，P5 用 Supervisor 决定 checkpoint——都是**有边界的自主**。
- 我们的空白集中在右侧四列：自主度分级、观察空间、成本预算、UX/可观测性。

---

## 5. 反思：我们的不足（14 条，逐条给改进方案）

> 证据均可在本仓代码中定位；「已落地」指本节提交内可运行的实现，「下一轮」给出
> 接口与验收，不假装完成。

### G1. 没有自主度分级，审批只有「整包批/不批」

- **现状**：`Explorer.propose` 一次生成 ≤5 个动作，`approve(proposal_id)` 一次性
  放行；只读侦察与不可逆写共享同一档权限，靠 `roe.level` 兜底。
- **对标**：P3 的 HITL/autoapprove 两档、P5 的 Supervisor「继续/checkpoint/停止」、
  P4 的审批模式 + 工具白名单。
- **改进（已落地）**：`inkblade/core/agent_policy.py` 定义 L0 观察 / L1 建议 /
  L2 监督执行 / L3 只读自治；混合动作取最弱链路，不可逆写强制 L1 逐动作确认；
  提议只记录等级与审批次数，不改变「批准后才执行」的硬边界。
- **验收**：`tests/test_agent_policy.py`、`tests/test_explorer_policy.py`。

### G2. 审批点位置不对：一次批 5 个动作，人被迫读一堆低价值预览

- **现状**：`proposal.actions` 无阶段、无风险摘要；重复动作也照样送审。
- **对标**：P3 在 `plan` 节点设 checkpoint（批计划、不批工具调用）；P1 的 Observer
  只纠偏不抢权。
- **改进（已落地）**：`agent_policy.decompose` 输出「只读侦察 → 受控写验证」阶段；
  `observation.action_key` 先去重，`cost.apply_budget` 再裁剪可选/尾部动作，之后
  才生成审阅项。实测审阅项 24 → 20（T1、T5 各砍一批），决策点仍为 1/任务
  （不可逆写 +1，见 G4）。
- **下一轮**：Web 端「风险摘要 + diff 预览 + 一键批准整阶段」，把审批从 JSON
  变成可读的变更单。

### G3. 没有成本预算，超支只能靠人喊停

- **现状**：`max_actions=5` 是唯一上限；没有 token/时延估算，也没有超支降级。
- **对标**：P5 的单任务轮次 + 全局时间预算；P7 的按题成本核算（700 元打完两届）；
  P1 的工具调用上限。
- **改进（已落地）**：`inkblade/core/cost.py` 提供 `Budget` / `plan_cost` /
  `degrade` / `CostTracker`；提议阶段按 4 字符/token 估算，超支先丢 optional、
  再砍写动作、最后砍尾部，至少保留 1 个动作并标记 `over_budget`。
- **验收**：`tests/test_cost.py`；`budget-crunch` 任务 token 4440 → 963。

### G4. 「不可逆写」与「可回滚写」没有区分

- **现状**：`dry_run` 只提示备份闸门，审批语义不区分；没有备份目标的写动作与有
  备份的动作等价。
- **对标**：P1 的 scope guard + 备份；P4 的高风险工具白名单；P5 的沙箱强隔离。
- **改进（已落地）**：`classify_action` 以 `writes` + `backup_targets` 分档；
  无备份写动作 → L1、`requires_human=True`、`approval_count = 动作数`。
- **验收**：`irreversible-write` 任务 ON 等级 L1、2 个决策点；OFF 只有 1 个。

### G5. 观察没有结构：动作/结果/证据/下一步混在 result dict 里

- **现状**：`execute` 返回 `{module,status,result,run,step,audit}`，失败原因与
  evidence 指针不统一；下一次提议无法复用。
- **对标**：P5 的 Evidence→Hypothesis→Vulnerability→Exploit 因果图（无证据不能
  升级为结论）；P1 的 Memory/Idea 分仓；P2 的 Fact/Intent。
- **改进（已落地）**：`inkblade/core/observation.py` 固化
  `action / result / evidence[] / next[] / claim`；`ok` 无证据直接拒绝，失败降级
  `hypothesis`；下一步候选从目录生成并剔除已成功、死胡同。
- **验收**：`tests/test_observation.py`；Web 只读视图 `/api/v1/agent/observations`。

### G6. 上下文压缩是截断，不是「接班简报」

- **现状**：`MAX_SUMMARY=400` 截断 + 黑板 `context(limit=20)`；跨 session 没有
  接班文档。
- **对标**：P1 的压缩保留 8 类清单；P7 的 ProgressCompiler/RetryHandoffCompiler
  （独立 Agent 生成接班简报）；P5 的大输出进 Artifact。
- **改进（已落地）**：`observation.compress` 以 confirmed 优先、按步号倒序，输出
  条目化视图并估算省下的 token；`large output → evidence ref` 的模型已具备。
- **下一轮**：独立 `handoff` 编译器（输入 observations + findings，输出
  `handoff.md`），并在 compact 时注入；验收：重做任务不重复已探索动作。

### G7. 错误恢复没有策略：失败即记录，重试靠人

- **现状**：`Explorer.execute` 捕获异常写 `failed`；没有错误分类、退避、回退动作。
- **对标**：P1 ralph-loop（最多 10 次、1s→10s 退避）；P5 的可重试 Provider 分类
  + 新 session；P4 的熔断/取消。
- **改进（已落地）**：`agent_policy.retry_plan` 分 transient / permanent / invalid /
  budget；瞬时错误 2 次尝试 + 250ms 退避 + 声明式 fallback；闸门类错误立即上报。
  提议块携带策略，执行仍走 runner 三闸门。
- **验收**：`gateway-auth`（瞬时）OFF 失败 → ON 成功；`dead-end` OFF 失败 → ON
  切换 fallback 成功。

### G8. 死胡同没有记忆，重复失败会反复送审

- **现状**：没有「同一模块失败两次就不再自动提议」的规则。
- **对标**：P2 的 Intent 认领避免重复；P1 的 Observer 纠偏；P7 的 RetryHandoff
  记录「哪些路走不通」。
- **改进（已落地）**：`observation.is_dead_end`（同模块 2 次失败）+ `next_candidates`
  剔除；实测 `dead-end` 任务 2 次失败后切换管理面回退。
- **下一轮**：把死胡同写入黑板负向条目，跨提议生效（需与 memory 路径协调）。

### G9. 工具粒度太粗：一个模块 = 一次 run，无法预估单步成本/风险

- **现状**：`module.json` 只有 `writes/min_level/series`；没有单步 token/时延画像，
  也没有「意图脚本」形态。
- **对标**：P6 的 Meta-Tooling（输出完整意图代码而非原子调用）；P4 的 100+ 工具
  配方；P5 的细粒度工具 + 沙箱。
- **改进（已落地）**：`cost.plan_cost` 接受动作级 `tokens/latency_ms`，未提供时按
  模块/参数估算；`agent_policy` 以动作而非整包做档位判断。
- **下一轮**：模块 manifest 增加 `cost_profile` 与 `intent_template`，允许「生成
  可审阅脚本」作为 L2 动作；验收：同一任务工具往返次数 -30%。

### G10. 专家经验没有产品化：知识散在 docs/模块里

- **现状**：链（chains）、模块知识、报告模板各自为政；没有「playbook」这一层，
  专家无法把自己的判断录成可复用资产。
- **对标**：P3 的 `ctf-ops` skill + pattern；P4 的角色 + 工具策略 + 知识库；
  P7 把零界策略写成 8 个 Skill。
- **改进方案（下一轮）**：新增 `inkblade/playbooks/*.yaml`：`preconditions /
  evidence_schema / steps[] / approval_gates[] / cost_budget / success_criteria`，
  由 `agent_policy` 直接消费；先在 K8s 三条链上试点。
- **验收**：新增 playbook 不改 Python 即可被 explorer 选中；每个 playbook 有
  golden task 与回归。

### G11. 可观测性偏「审计」而非「理解」

- **现状**：`audit.jsonl` + `evidence.db` 可追溯，但人看不到「Agent 在想什么、
  下一步为什么是它」；Web 只有 runs/findings 列表。
- **对标**：P5 的实时轨迹 + 因果图工作台；P1 的 Observer 统计；P4 的攻击链回放。
- **改进（已落地）**：新增只读视图 `/api/v1/agent/policy|observations|cost`，
  展示等级、阶段、证据指针、下一步候选与预算；不新增写路由。
- **下一轮**：SSE 实时轨迹 + 证据图（节点=run/finding，边=supports/contradicts），
  复用 `graphsnap` 数据。

### G12. 评测不可复现：只有 lab 仿真与单测，没有「前后对照」

- **现状**：`lab/agent-eval` 比 deterministic vs supervisor，但没有产品改进的
  OFF/ON 对照，也没有阈值。
- **对标**：P5 明确「v1 benchmark 不自动归属 v2」；P7 公开 104 题 57%；P2 公开
  54/54 与成本。
- **改进（已落地）**：`lab/tencent-compare/` 8 任务 × 确定性故障注入，OFF 复现
  HEAD 语义，ON 走新策略；输出 JSON + `docs/SECTION3-METRICS.md`，阈值与实测
  见下节。
- **下一轮**：冻结模型版本 + 真实靶场重跑；把「策略级」升级为「端到端」。

### G13. UX 心流：审批是命令行 JSON，缺少「一眼看懂」的风险叙事

- **现状**：CLI 输出 proposal JSON；人需要自己读模块名与 dry_run。
- **对标**：P4 的仪表盘/任务/漏洞/资产四合一；P5 的轨迹工作台；P2 的图 + hint。
- **改进（已落地）**：只读 API 提供结构化观察与成本，前端可直接渲染「动作 →
  证据 → 下一步」；提议块含 `policy.label` 与 `hard_boundary`。
- **下一轮**：审批页显示「本次将改什么、备份在哪、失败如何回滚、预计花费」四行
  摘要；支持批注式拒绝（拒绝理由进入下一次提议）。

### G14. 多 Agent 协作与并发还停留在「supervisor 跑动作」

- **现状**：`explorer.execute(workers)` 可并发，但没有任务认领、黑板竞争、角色
  隔离；多个 Solver 会重复同一动作。
- **对标**：P2 的 stigmergy（无直接通信）；P1 的 Manager 分配 + Solver 并行；
  P5 的依赖感知准入波次。
- **改进方案（下一轮，避开并行在途的 supervisor/memory 路径）**：在
  `observation` 上增加 `claim(key, owner, ttl)` 与 `release`，执行前认领；提议阶段
  按 `action_key` 去重已经是第一步。
- **验收**：8 并发下重复动作 = 0；冲突时后到者自动换候选。

---

## 6. 产品设计专题：五个问题的答案

### 6.1 如何把专家经验产品化？

参赛项目给出三种路径：**Skill 文件**（P3/P7）、**工具配方**（P4）、**图上的
pattern**（P2/P5）。共同点是「把判断写成结构化资产，而不是写进 prompt」。
我们的落点是 playbook（G10）：前置条件、证据 schema、审批闸门、预算、成功判据
都可执行；专家只需要写 YAML，不写 Python。短期先把现有 `chains/*.json` 升级为
带 `evidence_schema` 与 `approval_gates` 的 playbook，保持向后兼容。

### 6.2 如何设计审批点不打断心流？

P3 的答案是「批计划，不批工具调用」；P1 的答案是「Observer 旁路纠偏，不抢执行」；
P5 的答案是「Supervisor 只在 checkpoint 介入」。我们的设计原则：

1. **一次计划一个决策点**；只读阶段批一次即可连续执行；
2. **风险升级才加确认**：不可逆写、越权、跨 namespace 单独确认（G4）；
3. **拒绝要能带着理由回流**，下一次提议直接吸收（G13）；
4. **审批前先降噪**：去重、裁剪、按阶段分组，让人只看值得看的东西（G2）。

### 6.3 如何展示 agent 推理与证据？

不要展示「思考过程」全文，展示**决策依据链**：动作 → 结果 → 证据指针 → 下一步
候选（G5）。这与 P5 的因果图、P1 的 Memory/Idea 同构。实现上，
`observation` 的 `claim` 字段强制区分 confirmed / hypothesis / planned；
Web 只读视图先给出结构化数据，下一轮再做图（G11）。

### 6.4 如何控制成本/时延？

三层：**估算**（动作级 token/时延）、**预算**（任务级 Budget）、**降级**（先丢
optional，再砍写，最后保留最小集并上报）。P7 用 700 元打完两届说明「按题核算」
可行；P2 用 7692 元换唯一 AK 说明「预算必须显式」。我们默认 20k token / 120s /
6 次审批 / 2 次干预，按任务覆盖；超支不是失败，而是**可解释的降级**（G3）。

### 6.5 如何做可复现评测？

三条硬要求：固定任务集、固定成本口径、固定对照基线。`lab/tencent-compare/`
用 8 个任务 + 确定性故障注入，OFF 精确复现 HEAD 语义，ON 走新策略；JSON 记录每个
任务的 token/时延/审批/干预/证据覆盖，阈值写进测试。它不是「模型能力评测」，
而是**产品改进回归**；下一轮再叠加冻结模型的端到端跑分（G12）。

---

## 7. 已落地改动清单

| 文件 | 作用 | 关键约束 |
|---|---|---|
| `inkblade/core/agent_policy.py` | L0-L3 分级、阶段分解、重试/回退分类 | 纯函数；混合取最弱；只用于提议 |
| `inkblade/core/observation.py` | 结构化观察 + 证据指针 + 下一步候选 + 压缩 | confirmed 必须有证据；JSONL 只追加 |
| `inkblade/core/cost.py` | token/时延/审批/干预预算 + 超支降级 | 确定性；至少保留 1 个动作 |
| `inkblade/core/explorer.py` | 提议路径接入（`policy=True/False`） | 不执行、不建 run；OFF 精确复现 HEAD |
| `inkblade/agent_planner.py` | 链计划候选附加自主度/成本（`policy=True/False`） | plan-only；不落 actions/run |
| `inkblade/webui/api_section3.py` | 只读视图 `/api/v1/agent/*` | 仅 GET；不改既有路由语义 |
| `lab/tencent-compare/` | 8 任务 OFF/ON 微评测 | 确定性；不调用外部 LLM |
| `tests/test_*.py` | 策略/观察/成本/接线/视图/评测 | 全部 stdlib unittest |

实测结果与阈值见 [`SECTION3-METRICS.md`](SECTION3-METRICS.md)：
成功率 0.50 → 1.00；审阅项 24 → 20；时延 31.5s → 19.2s；token 12,423 → 9,111；
人工干预 4 → 0；证据覆盖 0 → 1.00。审批决策点 8 → 9（不可逆写 +1，属护栏）。

---

## 8. 来源与限制

**官方/一手来源**

- 腾讯云黑客松官网：<https://tch.cloud.tencent.com/>
- 智能渗透挑战赛入口：<https://zc.tencent.com/hackathon>；
  赛事页 `code=cha004`；比赛平台 <https://challenge.zc.tencent.com/>
- 官方资料聚合仓：<https://github.com/Yeti-791/Tsec-Hackathon>
- 第二届线上十强公告（610 队、11,031 次提交、四赛区）：
  <https://cloud.tencent.com/developer/article/2657080>
- 各项目 README / 答辩 PPT / 复盘文章（见逐项目小节链接）。

**限制**

1. 名次与成本来自队伍自述或官方导航，未独立复核；第二届第 2 名等未开源项目不在
   样本内。
2. 代码快照时间不同（2026-04 ~ 2026-10），能力会随版本变化；本对比以快照为准。
3. 未运行参赛项目（依赖 Docker/模型/靶场），架构判断基于源码结构与公开材料；
   涉及「效果」的结论只引用作者公开数据。
4. 许可未明的项目（P3/P6/P8）只做阅读，不复制、不派生。
