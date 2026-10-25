# CrewAI Flows — 事件驱动编排、checkpoint 与技能/知识分层

- 分类：agent-2026 / 编排与持久化
- 来源：CrewAI 官方文档
- 核验日期：2026-10-25；核验状态：verified（webfetch 200，docs llms-full 正文命中：Flows/Checkpointing/Agent Capabilities）

## 来源
- https://docs.crewai.com/en/concepts/flows
- https://docs.crewai.com/en/concepts/checkpointing
- https://docs.crewai.com/en/concepts/agent-capabilities

## 核验（实际读到的）
- Crews（角色化多 agent）+ **Flows**（`@start`/`@listen`/`@router` 事件驱动编排、状态管理、持久化与恢复）。
- **Checkpointing**：事件驱动写快照（默认 `task_completed`）；`JsonProvider` 一文件一 checkpoint，`SqliteProvider` 单库（WAL，适合高频）；`max_checkpoints` 剪枝；支持 **resume** 与 **fork（新 lineage）**；Crew/Flow/Agent 继承 checkpoint 配置，可单独 opt-out。自动 checkpoint 是 best-effort（失败只记日志）。
- 能力五分：Tools（动作）、MCP（远程工具）、Apps（SaaS）、**Skills（SKILL.md，注入“怎么想”）**、Knowledge（RAG，“知道什么”）。明确区分 action vs context capabilities；技能支持渐进披露。
- 代码执行：`allow_code_execution`/`CodeInterpreterTool` **已弃用**，官方建议改用 E2B/Modal 等专用沙箱。

## 架构要素
- 事件驱动 + 显式状态：Flow 是状态机，Crew 是角色协作。
- checkpoint 粒度可配置（事件级），并支持分叉实验。
- 技能（程序性知识）与知识（事实检索）分离，避免把两者混进同一 RAG。

## 对我们的启示
- 我们的 `scheduler.py` 是 cron 轮询（`trident/core/scheduler.py:62-79`），不是事件驱动；`explorer.execute` 同步串行（`explorer.py:249-280`），没有 checkpoint/fork（G10/G03）。
- 「技能 vs 知识」的分离值得照搬：我们的 `version-matrix.json` 是知识（指纹/版本/变体），`module.json` 是动作，缺的是中间层「程序性技能」。
- 他们因安全弃用内置代码执行、转向 E2B，正好印证我们的 G08 判断：agent 框架不应自己造隔离。
