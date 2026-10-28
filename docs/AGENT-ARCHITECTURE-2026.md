# 2026 Agent 架构研究与差距反思

> 研究窗口：2026-10-25（单日集中核验）。方法：对每个来源做 `webfetch` 逐页核验，记录
> HTTP 状态、页面日期与正文命中；不可达来源标注 `blocked` 且**不引用其数字**。
> 语料：`corpus/agent-2026/`，共 **30 条**（28 条 verified + 2 条 blocked，见附录 A）。
> 本文只写研究与反思，不改代码；所有「我们」的实现事实都带 `file:line` 证据。

## 0. 结论摘要

1. **我们不是「不会 agent」，而是把 agent 运行时和自主执行一起砍掉了。** 2026 年的主流系统
   把 durable journal、分层记忆、技能库、沙箱、评测当成默认件；我们为了「执行确定性」把这些
   一并省略，导致执行环是稳的，**认知环是空的**。
2. **落伍点 12 条**（§2），其中最贵的三条是：无 durable journal（G03）、无分层记忆（G04）、
   无沙箱隔离（G08）。它们不是「自主性」问题，而是**长任务正确性**与**执行安全**问题。
3. **可用设计点 16 条**（§3），按 P0/P1/P2 排序；P0 全部是「不改变执行确定性也能做」的工程件。
4. **升级蓝图**（§4）：supervisor/worker + 任务队列 + durable journal + 三层记忆 + 技能库 +
   reflexion + A2A/MCP + 沙箱 + 评测，六条不变量保证「agent 只提议、执行仍确定性」。
5. **与 ARTEX/XBOW 的差异**（§5）分三类：真落后 6 项、形态差异不追 3 项、已对齐/领先 5 项。
   ARTEX 的多 agent/血缘图/情报登记是事实差距；XBOW 的千级并行与战绩是公开宣称的能力面差距。

一句话：**下一步不是把模型放进执行环，而是把 2026 的 agent 运行时套在确定性执行环外面。**

---

## 一、2026 主流 agent 架构谱系

### 1.1 一条复杂度阶梯

Anthropic 把 agentic system 分成 **workflows**（预定义代码路径编排 LLM/工具）与 **agents**
（LLM 动态决定流程与工具），并明确建议「先找最简单解法，只在确有收益时加复杂度」
（`corpus/agent-2026/anthropic-building-effective-agents.md`）。2026 年的各家实现，基本是在这条
阶梯上选择位置，再加三类横向能力（持久化、记忆/技能、协议/沙箱）。

| # | 谱系 | 代表实现 | 核心机制 | 适用 | 失效边界 | 语料 |
|---|---|---|---|---|---|---|
| 1 | ReAct 单环 | OpenAI Agents SDK 的 agent loop | 思考→工具→观察，循环到完成 | 开放、步数不可预知 | 长任务上下文爆炸、无恢复 | `openai-agents-sdk.md` |
| 2 | Plan-Execute | Aardvark 四阶段管线 | 先产出计划/威胁模型，再执行阶段 | 阶段边界清晰 | 计划错了要整体重来 | `aardvark.md` |
| 3 | Reflexion | Reflexion | 语言化反思写 episodic memory，下轮改进 | 可重复尝试、有反馈 | 反馈噪声会固化偏见 | `reflexion.md` |
| 4 | 树搜索 | LATS | MCTS + 价值函数 + 自反思 + 环境反馈 | 多分支、可 reset | 分支成本高、需沙箱 | `lats.md` |
| 5 | 分层 supervisor-worker | Anthropic Research、D-CIPHER | lead 分解/委派/综合，subagent 独立上下文 | 宽并行、信息超单上下文 | 15× token、同步瓶颈 | `anthropic-multi-agent.md`、`d-cipher.md` |
| 6 | Evaluator-optimizer | 生成-评估循环 | 一个生成、一个按 rubric 评，迭代 | 评价标准清晰 | 评估器偏见/成本 | `anthropic-building-effective-agents.md` |
| 7 | 事件驱动/状态机 | CrewAI Flows | `@start/@listen/@router` + 显式状态 | 步骤有依赖、需可视 | 状态设计差会成隐式 goto | `crewai-flows.md` |
| 8 | Durable execution | LangGraph、Temporal、CrewAI checkpoint、MCP Tasks | 每 super-step/事件落 checkpoint；崩溃重放恢复 | 长任务、需人工中断 | 确定性约束、存储增长 | `langgraph-durable.md`、`temporal-durable.md`、`mcp-tasks.md` |
| 9 | 多 agent 协议 | Google A2A + MCP | A2A 管 agent 间任务，MCP 管 agent-工具 | 跨 vendor/跨组织 | 身份与消息认证、语义漂移 | `google-a2a.md`、`mcp-spec-2026-07-28.md` |
| 10 | 技能库 | Agent Skills、Voyager、Skills over MCP | 文件夹级技能包，元数据→正文→资源渐进披露 | 可复用程序性知识 | 供应链投毒、版本漂移 | `anthropic-agent-skills.md`、`voyager.md`、`mcp-skills-over-mcp.md` |
| 11 | 沙箱执行 | E2B Runtime、OpenAI hosted shell | 每会话 microVM/容器，网络默认拒绝 | 执行不可信代码 | 冷启动/成本/逃逸面 | `e2b-sandbox.md`、`openai-computer-use.md` |
| 12 | 图记忆 | GraphRAG | 实体图 + 社区摘要，服务全局问题 | 跨文档态势/全局总结 | 建图成本、更新延迟 | `graphrag.md` |

补充两条「横向能力」而不是谱系：**工具面治理**（OpenAI tool search/namespace/延迟加载）与
**安全基线**（OWASP ASI01–ASI10）。前者决定工具多了以后模型还能不能选对，后者决定
记忆/协议/沙箱为什么必须一起上。

### 1.2 2026 的五个共识

1. **长任务默认 durable。** LangGraph 在每个 super-step 存 checkpoint 与 pending writes，失败恢复
   不重跑成功节点；Temporal 用 event history 重放；MCP Tasks 要求「返回 task handle 前已持久化」；
   CrewAI checkpoint 支持 resume/fork。四家不同层，结论一致：**agent 的状态不能只活在进程内存里**。
2. **上下文是稀缺资源，必须分层。** Anthropic 把计划写入 Memory 防 200k 截断；子 agent 把产物写
   文件系统、只回传引用；Letta 用 memory blocks + MemFS + dreaming；Agent Skills 用三层渐进披露
   （约 100 tokens 元数据 → <5000 tokens 指令 → 资源按需）。共识是：**索引常驻，正文按需，产物外置**。
3. **技能是包，不是提示词。** Agent Skills 规范把 `SKILL.md` + `scripts/` + `references/` + `assets/`
   标准化，并要求 `allowed-tools` 声明最小权限；Skills over MCP 的 SEP-2640 已于 2026-09-13 成为
   Final，技能可以经 MCP 发现/分发。Voyager 更早证明「可执行代码技能库」能跨环境迁移。
4. **工具面按需发现。** OpenAI 的 `ToolSearchTool` 延迟加载 function/namespace/MCP 工具，
   建议 namespace <10 个函数；MCP 用 `server/discover` 暴露能力；A2A 用 agent 发现替代工具堆叠。
   工具不是越多越好，**可发现性**才是规模化的前提。
5. **安全边界下沉。** 提示词防不住工具滥用：OWASP 把 Tool Misuse、Identity Abuse、Supply Chain、
   Memory Poisoning、Inter-Agent Communication 单列；OpenAI 明说「approval 不是 sandbox」；E2B 用
   每沙箱 microVM + nftables egress allowlist。共识是：**沙箱（隔离）+ 审批（意图）+ 身份（权限）
   三层，缺一不可**。

### 1.3 给 InkBlade 的选择判据

| 任务特征 | 应选 | 不应选 |
|---|---|---|
| 步骤可预定义、交付物要可复核 | workflow（我们现在的链） | 自由 agent |
| 开放探索、环境能给 ground truth、错误可承受 | agent loop / supervisor-worker | 硬编码长链 |
| 跨小时/跨天、需人工中断 | durable execution + 队列 | 进程内同步调用 |
| 宽并行、子问题独立 | supervisor-worker + 沙箱 fork | 单 agent 串行 |
| 强依赖、需共享上下文 | 单 agent + 工具 + 记忆 | 多 agent（协调成本 > 收益） |

我们的渗透场景大多落在「步骤可预定义 + 交付物可复核」，所以**执行环继续用 workflow 是对的**；
但「侦察枚举、资产梳理、多目标验证」落在「宽并行 + 独立子问题」，需要 supervisor-worker；
「跨小时的重测/审批等待」落在「durable」，需要 journal + 队列。**这三块正是我们缺的。**

---

## 二、我们为什么落伍：逐条反思

### 2.0 先承认当时的设计意图

`docs/REFLECTION-XBOW-ARTEX-KUBETRAIL.md:17-22` 写得很清楚：自主性只作用于「提议」，不作用于
「执行」；执行环永远是确定性模块 + 授权（ROE）+ 备份 + 审计四校验。这个判断**今天仍然成立**，
而且被 2026 的证据强化（AutoPenBench：全自主 21% vs 半自主 64%；OWASP ASI09 人机信任利用）。

**证据口径**：本节行号基线为 `git HEAD f1547f6`（本任务开始时的工作树快照）。同日并行任务可能
正在改动 `explorer.py`/`evidence.py` 等文件；若行号漂移，按同行描述的函数/行为定位（如
`Explorer.propose`、`run_module`、`log_action`、`parse_cron`），结论不依赖具体行号。

错误不在「不让模型执行」，而在**把 agent 运行时（journal/memory/skills/eval/sandbox/queue）也当成
自主执行一起砍掉**。这些能力与「谁来决定下一步」正交：它们让**确定性执行更可靠、更安全、更可积累**，
而不是让模型夺权。下面 12 条，按「执行运行时 / 认知能力 / 边界与验证」三组展开。

### 2.1 A 组：执行运行时（长任务的地基）

| ID | 落伍点 | 现状与证据 | 当时的取舍 | 代价 | 2026 对照 |
|---|---|---|---|---|---|
| **G01** | 确定性 DAG + 审批，无动态重规划 | `inkblade/core/chains.py:419-487` 按依赖拓扑执行（进程内 ThreadPool）；`inkblade/agent_planner.py:87-166` 只读推荐；`inkblade/core/explorer.py:159-200` 只提议不执行；`tests/test_explorer.py:48-78` 锁定 pending/审批 | 可复核、可回滚、审批校验不可绕过 | 只能跑预定义链；新攻击面要发版加链；中间结果不能改变下一步；无法做「发现异常→改道验证」 | Plan-Execute / ReAct / LATS 都允许基于观察重规划 |
| **G02** | 单进程 explorer，无 supervisor-worker | `inkblade/core/explorer.py:249-280` 顺序 for 循环逐个 `run_module`；`inkblade/core/runner.py:34-105` 单进程执行；`inkblade/core/chains.py:460` 的线程池只在单进程内并行；`tests/test_explorer.py:100-113` | 单机部署简单、证据库单写者、审计线性 | 多目标/多路径只能串行；单点崩溃全停；无法按角色分工；与 XBOW「数千 agent 并行」差一个数量级架构 | Anthropic orchestrator-worker（90.2% 提升）、D-CIPHER Planner+异构 Executor |
| **G03** | 无 durable journal（有证据库，无恢复点） | `inkblade/core/evidence.py:24-43` 只有 runs/steps/actions/findings 等表，无 journal/checkpoint 表；`inkblade/core/runner.py:56-80` 失败直接抛，链只能整条重跑；核心代码 grep 无 `resume/checkpoint/thread_id`（除业务模块名） | 证据=事实，执行=一次性；避免「恢复出不一致状态」 | 进程崩溃/审批中断后无法续跑；长任务不可行；无法 time-travel 复盘；重跑会重复副作用（写类步骤尤其危险） | LangGraph super-step+pending writes；Temporal event history；MCP Tasks durable handle；CrewAI checkpoint |
| **G10** | 无事件驱动/任务队列（cron 轮询） | `inkblade/core/scheduler.py:2-8` 明写 cron/interval；`inkblade/core/scheduler.py:62-79` 只做时间解析；`explorer.execute` 在请求线程内联执行；`evidence.py` 无 task/queue 表 | 零依赖、单机可跑、无 broker 运维 | 无多租户隔离/限流/优先级/租约；无法接 MCP Tasks 的异步语义；无法把「审批等待」变成可恢复任务 | Temporal Task Queue（poll/优先级/公平）；MCP Tasks；CrewAI Flows |

**最贵的代价是 G03。** 我们的写类模块有备份校验（`inkblade/core/runner.py:62-67`，退出码 91），但没有「这一步
已经执行到哪」的记录：崩溃后重跑，可能重复写、重复备份、甚至覆盖上一次的回滚点。证据库记录的是
**发生过什么**，不是**下一步该做什么**——这两者必须分开存。

### 2.2 B 组：认知能力（经验能否积累）

| ID | 落伍点 | 现状与证据 | 当时的取舍 | 代价 | 2026 对照 |
|---|---|---|---|---|---|
| **G04** | 无分层内存（working/episodic/semantic） | `inkblade/core/explorer.py:35` 队列落 `explorer/queue.json`；`inkblade/core/explorer.py:108-116` 全量读写队列；`inkblade/agent_planner.py:94-166` 每次从 findings 重算；跨 run 检索仍是 backlog（`docs/COMPETITIVE-MATRIX.md:260` CM-02） | 无状态=可复现；避免记忆污染 | 每次从零推理；重复发现/重复提议；长任务上下文丢失；经验不累积；token 重复付费 | Letta memory blocks+MemFS+dreaming；LangGraph Store；Anthropic 计划持久化+产物外置 |
| **G05** | 无技能库（模块 ≠ 技能） | `inkblade/core/registry.py:34-46` 只认 `module.json` 契约；`inkblade/core/runner.py:27-31` 直接加载 `run.py`；仓库无 `SKILL.md`；新增手法必须发版 | 模块=唯一可执行实现，避免「提示词即能力」的不可验证 | 成功手法无法沉淀复用；无法渐进披露；无法跨项目分发；与 ARTEX 的 3 个 skills、Agent Skills 生态脱节 | Agent Skills 规范；Voyager 可执行技能库；Skills over MCP（SEP-2640 Final） |
| **G06** | 无自反思（结果不回灌决策） | `inkblade/core/explorer.py:263-278` 记录了 `results`，但 `propose()`（`inkblade/core/explorer.py:159-200`）从不读取历史 results；`inkblade/core/scheduler.py:1-8` 的 drift 只比较 findings 集合 | 拒绝「模型自我评价」的主观性；避免反思污染证据 | 失败不学习；同一提议可反复出现；无法形成「下次避免」；人审负担不下降 | Reflexion（91% HumanEval）；Anthropic「让 agent 改进自己」使任务时间降 40% |
| **G11** | 无 token/成本预算 | `inkblade/core/explorer.py:36` 只有 `MAX_ACTIONS_DEFAULT=5`（动作数上限）；`inkblade/core/explorer.py:70-94` 单次 LLM 调用不解析 usage；证据库无 cost/token 字段 | 单次调用、成本可忽略；不想引入计费复杂度 | 多 agent/长上下文会 15× token 失控；无法按租户配额；无法做「便宜模型 triage、贵模型深挖」 | Anthropic：多 agent 15× token；token 解释 80% 性能方差；CAI 以 156× 降本为卖点 |
| **G12** | 无决策轨迹（trace） | `inkblade/core/evidence.py:208-214` actions 只记 execute/refused 等结果；`agent_planner` 的 reasons 只出现在返回值，不落库；`docs/COMPETITIVE-MATRIX.md:261` CM-03 仍是 backlog | 证据=可复核事实，不想存「模型想法」 | 无法回答「为什么选这条链」；调试靠猜；不满足 XBOW「full log of every decision」；事故复盘缺关键上下文 | OpenAI tracing；Temporal event history；A2A artifacts；Anthropic 全链路 tracing |

**最贵的代价是 G04。** 渗透是**经验密集型**工作：同一产品版本的指纹、误报模式、有效载荷组合，
本应跨 run 复用。我们现在每次都从 `findings` 重算，等于把专家记忆清零；而 `version-matrix.json`
只沉淀了「知识」（指纹/版本），没有沉淀「程序性经验」（怎么试、先试什么、失败信号是什么）。

### 2.3 C 组：边界与验证（能不能安全地变强）

| ID | 落伍点 | 现状与证据 | 当时的取舍 | 代价 | 2026 对照 |
|---|---|---|---|---|---|
| **G07** | 无 A2A（只有 MCP 只读工具） | `inkblade/mcp_server.py:54-147` 共 10 个工具；`:523` 实现 `server/discover`；`tests/test_mcp.py:117-129` 断言无 execute/write/delete/approve；无 A2A 端点/agent card | 只读工具最安全；不做「agent 平台」 | 无法被客户 SOC/其他 agent 平台当作对等体调用；侦察/计划/验证不能拆成可替换服务；跨组织协作只能靠人 | A2A（Linux Foundation，TSC 含 AWS/Google/MS/SAP/ServiceNow）；MCP 工具联邦 |
| **G08** | 无沙箱隔离（宿主进程内执行模块） | `inkblade/core/runner.py:27-31` `spec_from_file_location` + `exec_module`；`inkblade/core/runner.py:73-75` 把 store/run/backup 直接注入模块；全仓库无 subprocess/容器/microVM 执行路径（除 lab 仿真） | 单机零依赖；模块是「自己人写的」，信任边界在代码评审 | 模块/技能可读写宿主文件与网络；LLM 生成代码无法安全执行；供应链技能一进来就是 RCE 面（ASI04/ASI05） | E2B 每沙箱 Firecracker microVM + nftables；OpenAI hosted shell `network_policy=disabled/allowlist`；CrewAI 明确弃用内置执行转 E2B |
| **G09** | 无 agent 评测（只有模块/链单测） | 测试是模块单测 + e2e（`tests/test_explorer.py`、`tests/test_mcp.py` 等）；无 AgentDojo/CyberGym/AutoPenBench 类 harness；`docs/COMPETITIVE-MATRIX.md:288` CM-30、`docs/GAP-FEATURES.md:94` 均登记为缺口 | 交付物是证据，不是分数；不想为刷榜优化 | 无法量化「换模型/加记忆/加技能」是否变强；升级无基线；对外无法证明能力；回归只覆盖代码不覆盖决策 | AgentDojo（97 任务/629 用例）、CyberGym（1,507 漏洞/188 项目）、AutoPenBench（33 任务）、AgentBench（8 环境） |

**最贵的代价是 G08。** 这不是「未来风险」：只要接入一个第三方 MCP 工具或一份外部技能，宿主进程
就等于把 `exec_module` 的信任边界交给了外部内容。OWASP ASI04（供应链）与 ASI05（意外代码执行）
都直接命中；而我们连「模块只能写工作区」都没有内核级强制，只有代码约定。

### 2.4 反事实：如果 2026 年初就补上，会怎样

- **G03 先做**：过去每次链失败的整链重跑可以变成「从失败步恢复」；写类步骤不会重复备份/重复写；
  审批等待可以跨进程存活——这三点直接减少无效攻击流量（对客户生产环境是硬收益）。
- **G04 先做**：同一客户第二次测试不必从零枚举；误报模式、有效载荷组合、产品版本坑位可以复用；
  planner 的候选排序会随经验变准，而不是每次重算。
- **G08 先做**：LLM 生成的探测脚本、第三方技能、外部 MCP 工具都能进沙箱试；否则每加一个能力
  都要先问「它会不会把宿主搞坏」，创新速度被安全评审卡死。

---

## 三、还没用上的设计点清单

优先级口径：**P0** = 不补会阻塞正确性/安全性的地基；**P1** = 能力跃迁且风险可控；**P2** = 优化项，
可延后。每条都标注「解决哪个落伍点」与「参考实现」，避免拍脑袋。

| ID | 设计点 | 优先级 | 解决 | 预期收益 | 参考 |
|---|---|---|---|---|---|
| **A01** | Durable journal：`run_id/thread_id + step_seq + status + input_hash + output_ref + lease`，每步前后各写一条；恢复时跳过 success、重试 failed、`started` 转人工确认 | **P0** | G03 | 崩溃/中断可恢复；写类步骤不重复副作用；支持 time-travel 复盘 | LangGraph checkpoint/pending writes；Temporal event history |
| **A02** | 任务队列 + worker 池：claim/lease/heartbeat、按租户/优先级分队列、失败重试与死信 | **P0** | G02/G10 | 多目标并行；单点崩溃不影响全局；可限流/配额；能接 MCP Tasks | Temporal Task Queue；CrewAI Flows |
| **A03** | 三层记忆：working（本轮上下文摘要）+ episodic（每 run 决策/结果/复盘）+ semantic（资产-发现-产品图 + 技能索引） | **P0** | G04 | 经验跨 run 复用；长任务不丢目标；减少重复发现与 token | Letta blocks/MemFS/dreaming；LangGraph Store；GraphRAG |
| **A04** | 技能库：`skills/<name>/SKILL.md` + `scripts/` + `references/`；元数据/正文/资源三层加载；`allowed-tools` 只收紧权限 | **P0** | G05 | 新手法不必发版；程序性知识可复用/可分发；上下文成本可控 | Agent Skills 规范；Voyager；Skills over MCP |
| **A05** | 沙箱执行器：统一 `create/exec/upload/download/pause/kill/fork` 接口；默认无网络 + egress allowlist；只读根 + 一次性工作目录 | **P0** | G08 | 可安全执行 LLM 生成代码/第三方技能；爆炸半径限制在会话内；支持并行分支 | E2B Firecracker；OpenAI hosted shell network policy |
| **A06** | 评测基座：离线套件（AgentDojo 注入子集 + AutoPenBench 风格里程碑 + CyberGym 式 PoC 复现）+ 内部 golden tasks + 在线 canary | **P0** | G09 | 升级有基线；可量化「记忆/技能/模型」增益；对外可出具能力报告 | AgentDojo；CyberGym；AutoPenBench；AgentBench |
| **A07** | 审批即信号：审批单=durable task，状态 `working/input_required/completed`；approve/reject 是 `tasks/update`，不是进程挂起 | **P1** | G03/G10 | 审批跨重启存活；MCP/A2A 客户端可互操作；人审不阻塞 worker | MCP Tasks；LangGraph interrupts |
| **A08** | Supervisor-worker：lead 分解/委派/综合，worker 角色化（recon/exploit/verify/report），fan-out 有上限、预算有上限 | **P1** | G02/G06 | 宽并行提效；角色隔离降低路径依赖；可独立替换/扩展 worker | Anthropic orchestrator-worker；D-CIPHER |
| **A09** | Reflexion 复盘器：run 结束生成 `reflection.md`（目标/尝试/失败原因/下次避免/证据锚），写入 episodic；下一轮 propose 读取并排序 | **P1** | G06 | 失败变经验；重复提议减少；人审负担下降 | Reflexion；Anthropic「agent 改进自己」 |
| **A10** | MCP 工具联邦：namespace 分组 + 延迟加载 + `server/discover` 能力协商；长操作走 Tasks；工具描述做来源/摘要校验 | **P1** | G07/G10 | 工具多了仍可选对；外部工具可插拔；描述投毒面收敛 | MCP 2026-07-28；OpenAI ToolSearch；SEP-2640 |
| **A11** | A2A 网关：暴露 recon/plan/verify 三个只读 agent 能力；agent card + task 生命周期；写能力不暴露 | **P1** | G07 | 可被客户 SOC/其他平台调用；跨组织协作不靠人肉传文件；保持执行本地化 | A2A（Linux Foundation） |
| **A12** | 预算与配额：token/步数/时长/并发四维预算；按 run/租户归集；超限降级到便宜模型或停 | **P1** | G11 | 多 agent 成本可控；可计费/可配额；避免单任务烧穿 | Anthropic 15× token 账本；CAI 降本 |
| **A13** | 决策轨迹：trace span（proposal→approval→execute→verify）+ 理由/证据锚入 JSONL；OTel 导出 | **P1** | G12 | 可解释/可复盘；满足「每步决策留档」；调试从猜变查 | OpenAI tracing；Temporal history；XBOW decision log |
| **A14** | 图记忆/血缘：goal→intent→fact→finding 边 + 资产/版本图；社区摘要生成态势上下文 | **P2** | G04 | 全局态势可见；反查覆盖度；planner 有结构化上下文 | GraphRAG；ARTEX coldgraph（CM-16） |
| **A15** | 黑板/产物存储：worker 把大产物写对象/文件存储，协调者只拿引用；跨 worker 共享只读事实 | **P2** | G02/G04 | 避免「电话游戏」丢信息；上下文不被大产物挤爆；并行协作有共享面 | Anthropic「subagent output to filesystem」 |
| **A16** | 记忆/技能投毒防御：记忆写入策略（来源/签名/有效期/回滚）、技能签名与版本锁定、semantic 写入需人工批准 | **P0** | G04/G05 | 防止 ASI06 记忆投毒/ASI04 供应链；记忆可信才敢复用 | OWASP ASI04/ASI06；Agent Skills `allowed-tools` |

> 与「自主执行」无关的边界：A01–A06、A12、A13、A16 都不改变「谁来决定下一步」，只是让执行更可靠、
> 更安全、更可衡量。**这些应当先做，且不触碰 Ruling。**

**立刻做的 Top 5**：A01（journal）、A05（沙箱）、A06（评测）、A03（三层记忆）、A04（技能库）。
理由：前三个是「不做就会出错/出事故」，后两个是「不做就永远不积累」。

---

## 四、升级蓝图

### 4.1 目标架构（文字版）

```
                         ┌─────────────────────────────────────────────┐
  客户/平台 ────────────▶│ 接入层：CLI · REST /api/v1 · MCP · A2A       │
                         │ 认证 · 租户 · ROE 四级校验 · 速率/预算        │
                         └───────────────────┬─────────────────────────┘
                                             │ 任务提交（不直接执行）
                         ┌───────────────────▼─────────────────────────┐
                         │ Supervisor（规划者，只提议）                  │
                         │ · 目标分解 / 角色分配 / fan-out 上限          │
                         │ · 读三层记忆与技能索引                         │
                         │ · 产出 proposal（含 dry-run 预览/证据锚）     │
                         └───────┬───────────────────────┬─────────────┘
                                 │                       │
                    ┌────────────▼──────────┐   ┌────────▼─────────────┐
                    │ 任务队列 Task Queue    │   │ 记忆服务 Memory       │
                    │ claim/lease/heartbeat │   │ working / episodic   │
                    │ priority / retry / DLQ│   │ semantic + graph     │
                    └────────────┬──────────┘   └────────┬─────────────┘
                                 │                       │
        ┌────────────────────────▼───────────────────────▼──────────────┐
        │ Workers：recon │ exploit │ verify │ report                     │
        │ · 每个 worker 一个沙箱会话（microVM/容器）                      │
        │ · 工具来自 MCP 联邦（namespace + 延迟加载 + Tasks）             │
        │ · 只能调用确定性模块，不能自造执行路径                          │
        └────────────────────────┬──────────────────────────────────────┘
                                 │ 每步前后写 journal
        ┌────────────────────────▼──────────────────────────────────────┐
        │ Durable Journal（事件日志 + checkpoint + 审批信号）             │
        │ · resume / time-travel / 审批跨重启 / 幂等键                    │
        └────────────────────────┬──────────────────────────────────────┘
                                 │ 经审批的步骤
        ┌────────────────────────▼──────────────────────────────────────┐
        │ 确定性执行内核（不变量不变）                                    │
        │ ROE 校验 → 备份校验(91) → 模块 run.py → 三层落证               │
        └────────────────────────┬──────────────────────────────────────┘
                                 │
        ┌────────────────────────▼──────────────────────────────────────┐
        │ 证据库 Evidence Store（context.jsonl.gz / evidence.db / steps） │
        │ + manifest.sha256 + findings/actions/backups/rollbacks         │
        └───────────────────────────────────────────────────────────────┘

   旁路（sidecar）：
   ├─ 技能库 Skill Library：签名 SKILL.md 包，评测通过才晋升，版本锁定
   ├─ 评测基座 Eval Harness：离线套件 + golden tasks + 在线 canary
   └─ 可观测 Observability：OTel trace + 决策轨迹 + 成本归集
```

### 4.2 组件职责

| 组件 | 职责 | 不做什么 |
|---|---|---|
| 接入层 | 认证、租户、ROE、预算、任务提交 | 不直接调用 runner |
| Supervisor | 分解、委派、综合、产出 proposal | 不执行模块、不写证据 |
| 任务队列 | 租约、重试、优先级、死信 | 不解释任务语义 |
| Workers | 在沙箱内调用模块/MCP 工具、回传产物引用 | 不自造执行路径、不绕过审批 |
| Durable Journal | 记录每步状态、恢复、审批信号 | 不替代证据库 |
| 记忆服务 | working/episodic/semantic 读写与检索 | 不存原始证据（只存索引/摘要/引用） |
| 技能库 | 技能包发现/校验/版本/权限声明 | 不直接执行（执行仍走模块） |
| 执行内核 | 四校验 + 模块 + 落证 | 不接受「模型直接下令」 |
| 评测基座 | 离线/在线评分、回归、对比 | 不参与生产决策 |
| 可观测 | trace/成本/审计导出 | 不采集敏感正文（默认脱敏） |

### 4.3 数据模型（最小集）

| 表 | 关键列 | 用途 |
|---|---|---|
| `runs` | run_id, tenant, roe_level, created_at, status | 一次委托 |
| `tasks` | task_id, run_id, kind, priority, lease_owner, lease_until, attempts | 队列/租约 |
| `journal` | run_id, seq, step_key, status, input_hash, output_ref, started_at, ended_at | 恢复/重放 |
| `approvals` | approval_id, run_id, proposal_id, status, approver, decided_at, reason | 审批信号 |
| `memory_episodes` | episode_id, run_id, goal, attempts, failures, reflection, evidence_ref | 情景记忆 |
| `memory_semantic` | entity_id, kind, attrs, source_ref, valid_from, superseded_by | 语义记忆/图 |
| `skills` | skill_id, version, digest, status, eval_run_id, allowed_tools | 技能库 |

> 原则：**证据库仍是唯一事实源**；journal 存「执行到哪」，memory 存「学到什么」，skills 存
> 「怎么做」。三者都可重建/可回滚，且都带来源引用。

### 4.4 六条不变量（升级不能破）

1. **Agent 只提议，不执行。** 任何执行都必须经过 `chains/runner` 的确定性路径。
2. **每个执行步都是模块。** 技能/记忆可以影响「选哪个模块、传什么参数」，不能生成新的执行原语。
3. **每步先 journal 后执行。** 没有 journal 记录的步骤不得产生副作用。
4. **写类步骤必须有备份回执。** 现有退出码 91 的语义不变，且恢复时不得重复备份。
5. **每个 finding 必须有证据锚。** 证据锚 = 步骤 + manifest sha256 前缀，不接受「模型说发现了」。
6. **记忆/技能写入必须版本化、可签名、可回滚。** semantic 与技能晋升需人工批准（防 ASI06/ASI04）。

### 4.5 分阶段路线

| 阶段 | 范围 | 交付 | 验收（可执行） | 风险/回退 |
|---|---|---|---|---|
| **M0（2–3 周）** | Journal + 恢复 + 审批信号 | `journal` 表、resume 命令、approval 持久化 | 杀进程后 resume 跳过 success；审批跨重启；写类步骤不重复备份 | 只加表不改执行语义；可 feature flag 关闭 |
| **M1（3–4 周）** | 沙箱 + 技能包 + 评测基座 | sandbox 抽象（先子进程/netns，后 microVM）、`skills/` 目录、离线评测 runner | 模块越界写被拒；无网络默认；`skills-ref validate` 通过；AgentDojo 子集可跑 | 沙箱先只覆盖「非写类/LLM 生成」路径；失败回落宿主但记高危告警 |
| **M2（4–6 周）** | Supervisor-worker + 三层记忆 + reflexion | 队列/worker、memory 服务、reflection 生成与消费 | 3 worker 并行 mock 目标；reflection 改变下一轮候选；跨 run 检索命中 | fan-out 上限 5；无审批不落写类任务 |
| **M3（6–8 周）** | A2A + MCP Tasks + 预算 + 图记忆 | A2A 只读三能力、MCP Tasks 审批、token/步数预算、GraphRAG 摘要 | A2A 客户端提交/轮询/取结果；预算超限降级；态势摘要可复现 | A2A 仅只读；写能力永不暴露 |

### 4.6 不做什么（守住差异化）

- **不把执行环交给模型**：LLM 只影响 proposal；执行仍是模块 + 四校验。
- **不做无人审批的写操作**：即使未来提高自主等级，写类动作仍需人类/策略批准。
- **不做 C2/命令控制集成**：与「可审计交付」定位冲突。
- **不做自动武器化**：挖掘候选保持 `pending-manual-review`。
- **不为了多 agent 而多 agent**：宽并行/独立子问题才用；强依赖任务保持单 agent + 工具。

---

## 五、与 ARTEX / XBow 的架构差异

### 5.1 事实基线

- **InkBlade**：本仓库代码与 `docs/ARCHITECTURE.md`、`docs/SOTA-2026-10.md`。
- **ARTEX**：`docs/FEATURE-BY-FEATURE-ARTEX.md`（源码枚举，基线 2026-10-25：278 路由 / 59 表 /
  32 agent 组件 / 3 skills）与 `docs/GAP-FEATURES.md` 的逐项判定；克隆源码
  `.slim/clonedeps/repos/RuoJi6__ARTEX`。
- **XBOW**：官网公开宣称（商业闭源，无源码）；`corpus/agent-2026/xbow.md` 记录原文口径。
- 原则：**矩阵没登记的能力不猜**；厂商宣称标注「宣称」；性能数字只在有公开出处时引用。

### 5.2 架构对照

| 维度 | InkBlade | ARTEX（源码枚举事实） | XBOW（公开宣称） |
|---|---|---|---|
| 形态 | Python 单机 CLI + 本地 WebUI + REST/MCP | Go + Next.js + PostgreSQL，docker-compose 部署 | 商业 SaaS |
| 执行模型 | 确定性链（依赖拓扑 + 进程内线程池），四校验 | 多 agent 协作：goals/planner/worker/reporter | 数千 agent 并行，链式组合漏洞 |
| 规划 | `agent_planner` 只读推荐 + lead 审批；无重规划 | planner agent 动态规划（32 个 agent 组件） | 模型自主决定下一步（无人驱动） |
| 并发 | 单进程串行 explorer（默认 5 动作） | worker 并发 + 多模型池 llmpool（我们刻意不做） | 千级并行（宣称） |
| 审批位置 | 执行器外环：proposal→approve→human execute | agent 内环 intercept/（人工审批拦截） | 平台侧护栏：scope/impact/window + command checker |
| 记忆/血缘 | 无跨 run 记忆；血缘图未建（CM-16） | goal→intent→fact→finding 血缘图；情报 registry | 完整决策/战术日志（宣称） |
| 技能 | 硬编码模块（`module.json`），无 SKILL.md | 源码枚举 3 个 skills | 未公开 |
| 沙箱 | 无：宿主 `exec_module` | 矩阵未登记 | 未公开；宣称 production-safe checks |
| 协议 | MCP 2026-07-28 只读 10 工具；无 A2A | 任务 REST + PG；C2 MCP（我们不做） | 未公开 |
| 评测 | 模块/链单测 + effects；无 agent 基准 | 未在矩阵登记 | 第三方战绩（HackerOne #1、1,500+ exploits、Chrome full chain） |
| 证据 | 三层证据 + manifest sha256 + 双语报告 | 任务/情报/血缘（平台化） | 每 finding 附 exploit/请求响应/复现步骤 |
| 自主等级 | 低：提议制，人触发执行 | 中：agent 内环 + 审批 | 高：无人驱动（宣称） |

### 5.3 三类判定

**A. 真落后（必须补，且与差异化不冲突）**

| # | 差距 | 事实依据 | 对应设计点 |
|---|---|---|---|
| 1 | 无 durable resume | 我们失败即整链重跑（G03）；ARTEX 有 PG 持久化任务实体，XBOW 持续运行 | A01/A07 |
| 2 | 无并行 worker/队列 | 我们单进程串行（G02）；ARTEX worker 并发 + llmpool；XBOW 千级并行 | A02/A08 |
| 3 | 无跨 run 记忆/血缘 | CM-16 未建；ARTEX 有 goal→intent→fact→finding 边 | A03/A14 |
| 4 | 无技能库 | 我们只有模块；ARTEX 枚举 3 skills；Agent Skills 生态已标准化 | A04 |
| 5 | 无沙箱 | 我们宿主 exec_module（G08）；这是安全债，不是形态差异 | A05 |
| 6 | 无 agent 评测 | CM-30 未做；竞品有公开战绩/基准 | A06 |

**B. 形态差异，不追（并说明理由）**

| # | 竞品做法 | 我们不追的理由 |
|---|---|---|
| 1 | 无人驱动的全自主执行（XBOW） | 交付物是可复核证据；写操作必须有人类/策略批准（AutoPenBench：半自主 64% > 全自主 21%） |
| 2 | C2/命令控制集成（ARTEX tools.go、KubeTrail） | 与「合规审计工具」定位冲突，且是供应链/滥用风险 |
| 3 | 多模型池 llmpool（ARTEX） | 当前规模不需要；A12 预算 + 路由可在需要时再引入 |

**C. 已对齐/领先（继续守住）**

| # | 能力 | 依据 |
|---|---|---|
| 1 | 三层证据 + manifest sha256 | `evidence.py`、`reports/render.py`；XBOW 的「完整案卷」我们形态不同但同等可复核 |
| 2 | 四校验（ROE/级别/备份/审计） | `inkblade/core/roe.py`、`inkblade/core/runner.py:47-67`；退出码 91 语义 |
| 3 | 审批不可绕过性 | `tests/test_mcp.py:117-129`、`tests/test_explorer.py:69-90` 锁定只读/审批 |
| 4 | 合规映射 | ASI01–ASI10、ATLAS、NIST、ISO 42001、EU AI Act、TC260（`reports/standards.json`） |
| 5 | 版本矩阵/弹药溯源 | 42 条逐条来源 + 变体物化；竞品多为闭源弹药 |

### 5.4 结论

- 与 ARTEX 的差距主要在**平台化运行时**（多 agent、血缘、情报、任务持久化），不是「谁会打」；
  与 XBOW 的差距主要在**规模与战绩**，不是「证据形态」。
- 我们真正该补的 6 项（§5.3 A）全部是「运行时/安全/评测」，没有一项要求放弃「执行确定性」。
- 因此升级路线应是：**执行内核不动，外挂 agent 运行时**；这也解释了为什么 A01–A06 全部标 P0。

---

## 附录 A：语料台账（30 条）

| # | 文件 | 核验 | 主要用途 |
|---|---|---|---|
| 1 | `corpus/agent-2026/mcp-spec-2026-07-28.md` | verified | MCP 原语/扩展/信任边界 |
| 2 | `corpus/agent-2026/mcp-tasks.md` | verified | durable handle/审批状态机 |
| 3 | `corpus/agent-2026/mcp-skills-over-mcp.md` | verified | 技能分发协议 |
| 4 | `corpus/agent-2026/openai-agents-sdk.md` | verified | agent 运行时/sandbox agents |
| 5 | `corpus/agent-2026/openai-computer-use.md` | verified | computer-use/托管 shell/工具治理 |
| 6 | `corpus/agent-2026/anthropic-agent-skills.md` | verified | SKILL.md/渐进披露 |
| 7 | `corpus/agent-2026/google-a2a.md` | verified | agent 间协议 |
| 8 | `corpus/agent-2026/langgraph-durable.md` | verified | checkpoint/pending writes |
| 9 | `corpus/agent-2026/microsoft-agent-framework.md` | verified | workflow vs agent/后继合并 |
| 10 | `corpus/agent-2026/letta-memgpt.md` | verified | 分层记忆/MemFS/dreaming |
| 11 | `corpus/agent-2026/crewai-flows.md` | verified | 事件驱动/checkpoint/技能 |
| 12 | `corpus/agent-2026/e2b-sandbox.md` | verified | Firecracker 隔离 |
| 13 | `corpus/agent-2026/temporal-durable.md` | verified | event history/任务队列 |
| 14 | `corpus/agent-2026/owasp-agentic-top10.md` | verified | ASI01–ASI10 |
| 15 | `corpus/agent-2026/cybergym.md` | verified | PoC 复现评测 |
| 16 | `corpus/agent-2026/cai.md` | verified | 自主等级/HITL/降本 |
| 17 | `corpus/agent-2026/xbow.md` | verified | 商业竞品能力面 |
| 18 | `corpus/agent-2026/aardvark.md` | verified | 分析-验证-修补管线 |
| 19 | `corpus/agent-2026/d-cipher.md` | verified | Planner+异构 Executor |
| 20 | `corpus/agent-2026/autopenbench.md` | verified | 自主 vs 半自主基准 |
| 21 | `corpus/agent-2026/agentdojo.md` | verified | 间接注入评测 |
| 22 | `corpus/agent-2026/agentbench.md` | verified | 8 环境能力基准 |
| 23 | `corpus/agent-2026/voyager.md` | verified | 可执行技能库 |
| 24 | `corpus/agent-2026/reflexion.md` | verified | 自反思/episodic memory |
| 25 | `corpus/agent-2026/graphrag.md` | verified | 图记忆/全局摘要 |
| 26 | `corpus/agent-2026/anthropic-multi-agent.md` | verified | orchestrator-worker 工程账本 |
| 27 | `corpus/agent-2026/lats.md` | verified | MCTS/树搜索 |
| 28 | `corpus/agent-2026/anthropic-building-effective-agents.md` | verified | workflow/agent 分界 |
| 29 | `corpus/agent-2026/big-sleep.md` | **blocked** | 仅记录不可达，不进论据 |
| 30 | `corpus/agent-2026/codemender.md` | **blocked** | 仅记录不可达，不进论据 |

## 附录 B：核验方法与不可达源

- 每个来源记录：URL、HTTP 状态、`last-modified`（若有）、正文命中要点、核验日期。
- 文档类来源优先取官方一手页；论文取 arXiv 摘要页；商业产品取官网原文并标注「宣称」。
- **不可达即 blocked**：`big-sleep`（ECONNREFUSED/ECONNRESET）与 `codemender`（ECONNRESET，
  含镜像）本轮未取得原文，**不引用任何数字/战果**；后续可达再升级。
- 已知偏差：MCP/Letta/CrewAI 的文档站会把深链 308 到 `llms.txt`/`llms-full.txt`，本文只用其中
  实际读到的段落；未展开的字段（如 A2A Agent Card 细节）明确不引用。

## 附录 C：与既有文档的关系

- `docs/REFLECTION-XBOW-ARTEX-KUBETRAIL.md`：产品能力面对标与「不做什么」；本文补「运行时架构面」。
- `docs/REFLECTION-ARTEX-KUBETRAIL.md`：ARTEX/KubeTrail 源码深潜；本文不重复其证据链。
- `docs/COMPETITIVE-MATRIX.md`：CM-01/02/03/16/30/31 是本文多条落伍点的 backlog 锚点。
- `docs/SOTA-2026-10.md`：能力矩阵；本文的 P0 项应反向更新其「未达成/部分」行。
- `docs/ARCHITECTURE.md`：控制端七组件架构；本文 §4 是其「外挂 agent 运行时」的演进版，不替换这七个组件。

---

## 六、2026-10 实装映射（事件溯源图运行时）

本节把 §3 的 16 个设计点映射到本仓代码与测试。口径：**已落地** = 有产品代码 + 行为测试；
**部分** = 核心接口已接线，但仍受基础设施/迁移约束；**未做** = 明确未实装并写原因。
本节的运行时与执行内核解耦：agent 只产生 graph delta，目标侧动作仍由 Rust 探针执行。

| ID | 设计点 | 代码 | 测试 | 状态 / 未做原因 |
|---|---|---|---|---|
| A01 | Durable journal：run/step 状态、input/output、恢复 | `inkblade/agent/runtime.py`（`EventLog`、`AgentRuntime`、`checkpoint`、`resume`、`replay`、`state_at`） | `tests/test_agent_runtime.py`、`tests/test_agent_supervisor.py`（resume/time-travel） | 已落地：append-only JSONL + SHA-256 链 + checkpoint；`resume` 跳过 done、重排中断的 claimed intent |
| A02 | 任务队列 + worker 池：claim/lease/heartbeat、优先级、重试、死信 | `inkblade/agent/scheduler.py`、`inkblade/agent/workers/`、`inkblade/agent/supervisor.py` | `tests/test_agent_scheduler.py`、`tests/test_agent_supervisor.py` | 已落地：frontier、lease、heartbeat、retry、dead-letter、有界 worker；队列状态由事件图重建，未引入外部 broker |
| A03 | 三层记忆：working / episodic / semantic | `inkblade/agent/memory.py` | `tests/test_agent_memory_skills.py` | 已落地：working 压缩、episodic 跨 run 检索与排序、semantic 版本/过期；episodic 已接入 scheduler 的 `priority_adjustment` |
| A04 | 技能库：`SKILL.md` 包、渐进披露、版本、成功率、审批 | `inkblade/agent/skills.py`、`inkblade/agent/protocols.py`（`SkillPackage`） | `tests/test_agent_memory_skills.py`、`tests/test_agent_protocols.py` | 已落地：SEP-2640 元数据/正文/资源三层、allowed-tools 校验、版本历史、approved 才可检索、eval 分数晋升 |
| A05 | 沙箱执行器：create/exec/upload/download/pause/kill/fork、默认禁网 | `inkblade/agent/probes.py`、`inkblade/agent/workers/probe.py`、既有 Rust probe | `tests/test_agent_supervisor.py`（探针唯一执行/无宿主回退） | **部分**：目标侧动作在目标 Pod 内由 Rust probe 原生执行，宿主无模块代码；未做 microVM/Firecracker + egress allowlist（需要基础设施，且本轮无 Rust/cargo 构建环境） |
| A06 | 评测基座：任务集、成功率/步数/token/干预/证据覆盖 | `inkblade/agent/eval.py` | `tests/test_agent_eval_2026.py` | 已落地：deterministic / supervisor / graph-swarm 三模式；golden 8 步链；未接入真实 k3s/商业靶场（本轮无 kubectl/k3s） |
| A07 | 审批即信号：durable task、`working/input-required/completed` | `inkblade/agent/policy.py`（`issue_start`/`AgentAuthorization`）、`inkblade/agent/protocols.py`（`MCPTaskStore`）、`--approval manual` | `tests/test_agent_supervisor.py`（manual/auto）、`tests/test_agent_protocols.py` | 已落地：默认一次授权 + 无逐步审批；manual 只对写 intent 产生 `approval.required`，审批状态可持久化；未做跨进程人工审批 UI |
| A08 | Supervisor-worker：角色化 recon/exploit/verify/report、fan-out 上限 | `inkblade/agent/supervisor.py`、`inkblade/agent/workers/{recon,exploit,verify,report}.py`、`WorkerPool` | `tests/test_agent_supervisor.py`、`tests/test_agent_scheduler.py` | 已落地：supervisor 不执行，worker 在 1–8 有界池中执行；角色策略由 worker + guard 双重约束 |
| A09 | Reflexion：run 结束生成反思并进入 episodic | `inkblade/agent/memory.py`（`AgentMemory.reflect`、`reflection.md`） | `tests/test_agent_memory_skills.py` | 已落地：零执行、证据锚、失败/阻塞分类、下一次排序可读；未强制用 LLM 生成反思（避免把主观评价写成事实） |
| A10 | MCP 工具联邦：namespace、延迟发现、`server/discover`、只读提示 | `inkblade/agent/protocols.py`（`MCPToolRegistry`、`MCPFederation`） | `tests/test_agent_protocols.py` | 已落地：发现/搜索/调用，`readOnlyHint=false` 直接拒绝；未接生产 MCP 传输（stdio/SSE 适配仍是既有 `core/a2a.py` 的职责） |
| A11 | A2A：agent card、任务生命周期、只读委派 | `inkblade/agent/protocols.py`（`A2AServer`、`A2AClient`、`A2AAgentCard`） | `tests/test_agent_protocols.py` | 已落地：card/get、message/send、tasks/get/cancel；写技能默认拒绝；未做跨组织网络传输与身份联邦 |
| A12 | 预算/配额：token、步数、时长、动作 | `inkblade/agent/runtime.py`（`Budget`）、`inkblade/agent/scheduler.py`、`inkblade/agent/cli.py` | `tests/test_agent_runtime.py`、`tests/test_agent_scheduler.py`、`tests/test_agent_supervisor.py` | 已落地：四维硬顶、超限 status、预算事件；未做租户级计费/多租户配额服务 |
| A13 | 决策轨迹：决策/选择/证据/预算 span | `inkblade/agent/runtime.py`（`decision.made`、`plan.proposed`、`trace`）、`inkblade/agent/cli.py`（`agent trace`） | `tests/test_agent_runtime.py`、`tests/test_agent_supervisor.py`、`tests/test_agent_cli.py` | 已落地：JSONL 事件即 trace，支持 `--to-seq` 回放；未做 OTel exporter |
| A14 | 图记忆/血缘：goal→intent→fact→evidence 边 | `inkblade/agent/graph.py`（`PlanGraph`、因果边、`replay_graph`） | `tests/test_agent_graph.py`、`tests/test_agent_supervisor.py`（replay） | 已落地：Fact/Intent/Hint、requires/derived_from/produced_by 边、证据门控；未做 GraphRAG 社区摘要 |
| A15 | 黑板/产物存储：大产物外置、引用共享 | `inkblade/agent/graph.py`（evidence ref/sha256）、`inkblade/agent/workers/report.py`、既有 evidence store | `tests/test_agent_supervisor.py`、`tests/test_agent_graph.py` | 已落地：证据指针 + SHA-256，报告/产物写 run 目录；未接入对象存储/多 worker 文件服务 |
| A16 | 记忆/技能投毒防御：来源、签名、TTL、回滚、批准 | `inkblade/agent/memory.py`（`SemanticMemory` provenance/approval/rollback/expiry）、`inkblade/agent/skills.py`（approved/promote） | `tests/test_agent_memory_skills.py` | 已落地：无 source_ref 拒绝、skill/human 需 approved_by、版本回滚、TTL；未做密码学签名链（依赖工作区 HMAC/审批记录） |

### 与 G04/G05/G06/G11/G12 的接线

| 修复项 | 接线点 | 可观察证据 |
|---|---|---|
| G04 分层记忆 | `AgentMemory.priority_adjustment` → `PlanGraph.frontier` → `TaskScheduler.claim_next` | episodic 成功/失败改变 frontier 排序（`test_priority_and_memory_ranking`） |
| G05 技能库 | `SkillLibrary.propose_from_graph → submit → approve → search → index_into(memory)` | 未批准技能不可检索；成功率/版本进入 semantic（`test_agent_memory_skills`） |
| G06 自反思 | `AgentMemory.reflect` 在 finalize 读写 episodic + `reflection.md` | `executed=False`；失败原因进入 `next_avoid`（`test_reflection_is_zero_execution`） |
| G11 成本预算 | `Budget` 四维硬顶 + `budget.spent/exceeded` 事件 | step/token 超限停止且 status 明确（`test_budget_*`） |
| G12 决策轨迹 | `decision.made`/`plan.proposed`/`policy.refused`/`intent.*` 事件 | `agent trace` + `--to-seq` 回放（`test_trace_contains_decision_and_reason`、`test_replay_time_travel`） |

### 明确未做（本轮）

1. **A05 内核级沙箱**：本轮只确认 Rust probe 是目标侧唯一执行面，宿主不执行模块代码；
   microVM/egress allowlist 需要节点权限与 Firecracker/CNI 基础设施，未在本机伪造。
2. **真实 k3s 成绩**：开发机无 `kubectl`/`k3s`/`cargo`，8 步链和三种评测模式均在
   `lab/template_range` + reference conformance runtime 上实测；不把 mock 结果写成 k3s 结果。
3. **OTel/GraphRAG/对象存储/跨组织 A2A 传输**：接口与本地实现已就绪，网络/存储适配属于
   部署层，未在本轮引入新依赖。

### 验证口径

- 新增测试：`tests/test_agent_{graph,runtime,scheduler,protocols,memory_skills,supervisor,eval_2026,cli}.py`
  共 68 个用例；覆盖证据门控、lease/retry/dead-letter、预算硬顶、越界拒绝、无探针拒绝、
  8 步自主链、resume、time-travel、MCP/A2A/技能/记忆/Reflexion/评测三模式。
- 迁移在途红测：由 Rust 探针/模板迁移的并行工作造成，若出现 `run.py`/旧模板路径失败，
  在提交说明中单列，不混入本运行时结论。
