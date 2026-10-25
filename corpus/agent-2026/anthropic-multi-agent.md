# Anthropic 多 agent 研究系统 — orchestrator-worker 的工程账本

- 分类：agent-2026 / 分层多 agent
- 来源：Anthropic 官方工程/研究博客
- 核验日期：2026-10-25；核验状态：verified（webfetch 200，正文命中）

## 来源
- https://www.anthropic.com/research/multi-agent-research-system
- （原 /engineering/ 路径 308 重定向到 /research/）

## 核验（实际读到的）
- 架构：**orchestrator-worker**；lead agent 分析查询、制定策略、并行 spawn 子 agent；lead 把计划**写入 Memory**（防止 200k 上下文截断丢失）；子 agent 独立搜索、交错思考、回传发现；CitationAgent 处理引用。
- 效果：Opus 4 lead + Sonnet 4 subagents 在内部 research eval 上比单 Opus 4 高 **90.2%**。
- 成本：agent 约 **4×** chat token，多 agent 约 **15×**；token 使用解释 BrowseComp **80%** 方差（加工具调用数、模型选择共 95%）。
- 适用边界：宽并行、信息超单上下文、多复杂工具的任务适合；**强依赖/需共享上下文的任务不适合**（多数编码任务并行度低）。
- 工程：错误会级联 → 需要 **durable execution + 定期 checkpoint**；全链路 tracing；rainbow deployment 避免升级打断运行中 agent；当前子 agent **同步执行**是瓶颈，异步是下一步。
- 评估：约 **20 条**真实查询即可看到 prompt 改动效果；LLM-as-judge 按事实性/引用/完整性/来源质量/工具效率打分；人工评测抓 SEO 内容农场偏差。
- 反「电话游戏」：子 agent 把产物写**外部文件系统**，只把轻量引用回传协调者。

## 架构要素
- 分层：lead（规划/综合）→ subagents（宽并行、独立上下文）→ citation/verifier（专门后处理）。
- 记忆：计划显式持久化；产物外置，避免上下文复制。
- 观测与部署：trace + checkpoint + 灰度，是 agent 系统的一等工程件。

## 对我们的启示
- 这是我们**最该抄的架构**：supervisor-worker + 共享黑板（artifact store）+ durable checkpoint，正好补 G02/G03/G04/G10。
- 但不要盲上多 agent：15× token 成本，且我们的任务是「深链验证」不是「宽检索」；应限定在**并行侦察/多目标枚举/独立验证**三类。
- 「子 agent 写文件、回传引用」与我们证据库天然契合：产物落 `steps/*.tar`，协调者只拿 sha256/路径。
