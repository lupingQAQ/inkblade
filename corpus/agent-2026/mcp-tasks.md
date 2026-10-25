# MCP Tasks 扩展 — durable handle 与 `input_required`

- 分类：agent-2026 / durable execution
- 来源：Model Context Protocol（ext-tasks 工作组）
- 核验日期：2026-10-25；核验状态：verified（webfetch 200，正文命中）

## 来源
- https://modelcontextprotocol.io/extensions/tasks/overview.md
- https://github.com/modelcontextprotocol/ext-tasks

## 核验（实际读到的）
- Tasks 解决「工具调用不立即返回」：服务端返回 **durable handle** 而不是阻塞连接；客户端 `tasks/get` 轮询。
- 六步流程：能力协商（`io.modelcontextprotocol/tasks`）→ 创建任务（`CreateTaskResult`，含 `taskId`/初始状态/TTL/`pollIntervalMs`，**返回前必须已持久化**）→ 轮询 → 飞行中输入（`input_required` + `inputRequests`，用 `tasks/update` 回应）→ 完成（`result`）→ 取消（`tasks/cancel`，协作式）。
- 状态机：`working | input_required | completed | failed | cancelled`；后三者终态。
- 明确要求客户端**持久化 task ID**，崩溃/重启后可继续轮询；通知可选（`notifications/tasks`），轮询是默认。
- 适用场景点名：CI/批处理/训练、**human-in-the-loop 审批**、外部 job 系统、弱网、批处理进度。

## 架构要素
- 长任务的第一等抽象：任务 ID + TTL + 状态 + 输入请求 + 结果，全部可持久化。
- 审批不再是「进程挂起等回调」，而是任务状态机的一次迁移。
- 与 MCP 核心的无状态请求模型兼容：状态在扩展层，不在连接层。

## 对我们的启示
- 这是 G03（无 durable journal）与 G10（无任务队列）的**协议级答案**：审批单可以直接建模为 `input_required` 任务，`approve/reject` 就是 `tasks/update`。
- 我们当前的审批队列是单工作区 JSON（`explorer.py:35`、`:108-116`），进程重启后没有租约/恢复语义；对齐 Tasks 后，MCP/A2A 客户端都能安全地「提交—等待—批准—取结果」。
- 证据链不受影响：任务结果仍需落 `evidence.db` 三层证据，Tasks 只承载调度状态。
