# OpenAI Agents SDK — 少原语 + 托管运行时 + sandbox agents

- 分类：agent-2026 / 框架
- 来源：OpenAI
- 核验日期：2026-10-25；核验状态：verified（webfetch 200，页面 last-modified 2026-10-22）

## 来源
- https://openai.github.io/openai-agents-python/
- https://github.com/openai/openai-agents-python

## 核验（实际读到的）
- 定位：Swarm 的生产级后继；刻意「极少抽象」。
- 三原语：**Agents**（指令+工具）、**Agents as tools / Handoffs**（委派）、**Guardrails**（输入/输出校验，与执行并行、失败快停）。
- 运行时能力：内置 agent loop（跑到任务完成）、**Sessions**（跨轮工作上下文持久层）、**Tracing**（可视化/调试/评测/微调）、**Human in the loop**、**MCP server tool calling**。
- 明确提供 **Sandbox agents**：在真实隔离工作区运行专家 agent，支持 manifest 定义文件、sandbox client 选择、**可恢复的 sandbox session**。
- 与 Responses API 的分工：想自己拥有 loop/tool dispatch/state 就直接用 Responses；需要运行时管理轮次、工具执行、guardrails、handoffs、sessions 就用 SDK。

## 架构要素
- 分层：模型 API（Responses）↔ agent 运行时（loop/session/trace）↔ 执行环境（sandbox）。
- 委派有两种语义：handoff（控制权转移）与 agent-as-tool（父 agent 保留控制权）。
- 可恢复性下沉到 sandbox session，而不是应用自己拼状态。

## 对我们的启示
- 我们的 `agent_planner` 只做「排序 + 理由」，没有 loop、没有 session、没有 trace（G02/G12）；`explorer` 有提议状态机但没有运行时抽象。
- 不需要照搬「模型决定执行」：可以把 SDK 的 **runtime 分层**借过来，执行端仍接我们的确定性 runner 四闸门。
- 「handoff vs agent-as-tool」是 supervisor-worker 的关键设计选择：渗透场景应默认 agent-as-tool（父级保留审批与预算），只在明确移交时 handoff。
