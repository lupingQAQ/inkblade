# LangGraph durable execution / checkpointing — super-step、pending writes、恢复

- 分类：agent-2026 / durable execution
- 来源：LangChain / LangGraph 官方文档
- 核验日期：2026-10-25；核验状态：verified（webfetch 200，persistence.md 与 checkpointers.md 正文命中）

## 来源
- https://docs.langchain.com/oss/python/langgraph/persistence.md
- https://docs.langchain.com/oss/python/langgraph/checkpointers.md

## 核验（实际读到的）
- 两套持久化：**Checkpointer**（线程内图状态快照，短期记忆）与 **Store**（跨线程应用数据，长期记忆）。
- Checkpoint 在**每个 super-step 边界**保存；super-step = 一次调度 tick，节点可并行；`thread_id` 是主键，恢复/中断/时间旅行都依赖它。
- **Pending writes**：同一 super-step 内某节点失败时，其他已完成节点的写入已持久化；恢复时**不重跑成功节点**。节点级 writes 存 `checkpoint_writes` 表。
- 能力：人类中断后检查/修改状态再恢复、time travel（从任意 checkpoint 重放/分叉）、故障恢复（从最后成功步重启）。
- 三种 durability：`exit`（仅退出时写，崩溃不可恢复）、`async`（异步写，崩溃可能丢）、`sync`（下步前同步写，最稳）。
- 实现：SQLite/Postgres/Mongo/Cosmos checkpointer；`EncryptedSerializer` 可加密；官方提供 conformance test suite。
- 明确警告：`MemorySaver` 重启即丢；checkpoint 会无限增长，需要保留策略。

## 架构要素
- 恢复粒度 = super-step（不是整条链，也不是单个 API 调用）。
- 「已完成的副作用不重放」是核心不变量，靠 pending writes 保证。
- 状态与证据分离：checkpoint 存执行状态，业务证据仍应独立落库。

## 对我们的启示
- 我们的 `evidence.db` 有 `actions/findings/steps`（`inkblade/core/evidence.py:24-43`），但没有「下一步是什么」的恢复点；`runner.run_module` 失败直接抛（`runner.py:76-80`），链只能整条重跑（G03）。
- 最小改造：在 `chains.execute` 的每个步骤前后写 `journal(thread_id, step_id, status, input_hash, output_ref)`，恢复时跳过 `success`、重试 `failed`、把 `started` 标成 `unknown` 并要求人工确认。
- 不要用 `MemorySaver` 式内存态做审批：我们的审批队列必须 durable（对齐 MCP Tasks 的「返回前已持久化」）。
