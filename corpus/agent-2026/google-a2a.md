# Google A2A（Linux Foundation）— agent 间协议，与 MCP 互补

- 分类：agent-2026 / 多 agent 协议
- 来源：A2A Protocol（Google 发起，捐赠 Linux Foundation）
- 核验日期：2026-10-25；核验状态：verified（webfetch 200，页面 last-modified 2026-10-15）

## 来源
- https://a2a-protocol.org/latest/

## 核验（实际读到的）
- 定位：**不透明 agentic 应用之间**的开放通信标准；agent 可跨框架（LangGraph/CrewAI/Semantic Kernel/自研）互相发现、委派子任务、交换结果。
- 设计要点：**Secure & Opaque**——交互不需要共享内部记忆、工具或私有逻辑；可扩展（extensions + custom bindings，分级晋升治理）。
- 治理：原 Google 项目，**捐赠 Linux Foundation**；TSC 含 AWS、Cisco、Google、IBM Research、Microsoft、Salesforce、SAP、ServiceNow；Apache-2.0。
- 与 MCP 的分工（原文）：**MCP = agent-to-tool**，**A2A = agent-to-agent**；两者互补。A2A 明确**不是** agent 开发框架、不是子 agent/工具调用协议、不替代 MCP。
- 生态：Python/JS/Java/C#/Go/Rust SDK；A2A CLI（2026-10-01 发布）；DeepLearning.AI 课程。
- 页面未展开 Agent Card 字段细节，本文不引用具体字段名以免臆造。

## 架构要素
- 协议边界：跨组织/跨 vendor 的 agent 互操作层，不侵入 agent 内部实现。
- 不透明性=安全属性：只交换任务与产物，不交换记忆/工具。
- 扩展治理：核心稳定，能力靠 extension/binding 演进。

## 对我们的启示
- 我们只有 MCP 只读工具（`trident/mcp_server.py:54`，10 个工具），没有 A2A：无法把「Trident 侦察 agent」作为可被客户 SOC/其他平台调用的对等体（G07）。
- 最合理的 A2A 暴露面：`recon`（只读资产/发现）、`plan`（只读计划）、`verify`（证据校验）三个 agent 能力；执行与审批留在本地，不通过 A2A 暴露写能力。
- 与 MCP 组合：A2A 传任务，MCP 供工具；这正好对应我们「提议在外、执行在内」的分层。
