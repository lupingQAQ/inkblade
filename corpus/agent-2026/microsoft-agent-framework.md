# Microsoft Agent Framework — AutoGen + Semantic Kernel 的合流与 workflow 优先

- 分类：agent-2026 / 框架
- 来源：Microsoft Learn
- 核验日期：2026-10-25；核验状态：verified（webfetch 200，ms.date 2026-07-29，updated 2026-08-25）

## 来源
- https://learn.microsoft.com/en-us/agent-framework/overview/

## 核验（实际读到的）
- 四大块：**Agents**（LLM+工具+MCP）、**Harness Agent**（长任务：规划/todo、上下文压缩、文件访问与记忆、don't-ask-again 工具审批、可观测）、**Workflows**（函数式/图式显式执行路径）、**Integrations**。
- 基础件：model clients（chat/responses）、**agent session 状态管理**、context providers（记忆）、middleware（拦截 agent 动作）、MCP clients。
- 明确定位：**AutoGen 与 Semantic Kernel 的直接后继**，同一团队；合并 AutoGen 的 agent 抽象与 SK 的企业能力（session 状态、类型安全、filter、telemetry），再加**图式 workflow** 与长任务/HITL 状态管理。
- 选型规则（原文）：开放/对话任务用 agent；步骤明确、需要显式控制顺序、多个 agent/函数协同用 workflow；**「能用函数解决就别用 AI agent」**。
- Go 版 public preview，声明式 agent/RAG/CodeAct/函数式 workflow 尚不可用。

## 架构要素
- 双模：agent（自主）与 workflow（显式），不是二选一而是同一运行时的两种编排。
- 企业能力下沉：middleware 拦截、session 状态、telemetry。
- Harness 把「长任务必需件」（规划、压缩、记忆、审批、可观测）打包成默认。

## 对我们的启示
- 我们的链本质是「workflow 模式」，但缺少 session/中间件/telemetry/压缩；`agent_planner` 是 agent 模式的雏形，但没有 loop。
- 可直接借用的结构：**middleware 拦截点**（在 runner 前后加策略/预算/审计）、**session 状态**（按 run 持久化）、**「能用函数就别用 agent」** 作为每个新能力的准入判据。
- 我们的优势是 workflow 的确定性更强（模块+四闸门）；差距是 workflow 引擎没有 durable 状态与可视化 trace（G03/G12）。
