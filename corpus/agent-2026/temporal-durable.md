# Temporal — event history 重放式的 durable execution

- 分类：agent-2026 / durable execution
- 来源：Temporal 官方文档
- 核验日期：2026-10-25；核验状态：verified（webfetch 200，页面 last-modified 2026-10-24）

## 来源
- https://docs.temporal.io/evaluate/understanding-temporal

## 核验（实际读到的）
- Durable Execution：workflow 一旦启动就跑到底（秒到年）；进程崩溃后服务把工作交给另一个 worker，**重建状态并从断点继续，局部变量与进度不丢**。
- Workflow 必须**确定性**（因为要重放重建状态）；一切外部副作用放 **Activity**；Activity 有 retry policy、timeout、heartbeat，worker 死亡会重调度。
- **Event History** 是有序 durable log：workflow 调 SDK（执行 Activity/启 Timer）→ SDK 记 Command → worker 完成任务时上报 → 服务执行并 append Event；崩溃后新 worker 拉 history **replay** 代码恢复。
- 能力：durable timer（分钟到月）、Signals/Updates/Queries、Child Workflow、Schedule、Workflow Pause（不终止不丢状态）。
- **Task Queue**：worker 主动 poll，服务匹配；按服务/机队/硬件分队列；支持优先级与公平性，防单租户独占。
- Worker Versioning：运行中的 execution 钉在启动时的部署版本，新 execution 走新版本（长任务灰度）。

## 架构要素
- 状态=事件日志，不是内存；代码可重放是硬约束。
- 控制面（Frontend/History/Matching）与计算面（Worker）分离；worker 无状态、可水平扩。
- 长任务的一等公民：timer/signal/child workflow/pause。

## 对我们的启示
- 我们的「链执行」是一次性函数调用（`chains.execute` + `runner.run_module`），失败即抛、无 history、无重放（G03）；`scheduler` 是最朴素的定时器（G10）。
- 不需要引入 Temporal 依赖：可以用 SQLite 表实现「事件日志 + 确定性步骤函数 + 重放」，关键不变量是**步骤幂等/可重放**与**副作用只发生一次**。
- Workflow Versioning 对应我们的模块版本：一次 run 必须钉住模块/技能版本，升级不能改变进行中 run 的语义（证据链要求）。
