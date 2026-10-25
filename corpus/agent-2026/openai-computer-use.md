# OpenAI computer-use / hosted shell — 工具执行面与安全闸

- 分类：agent-2026 / 工具执行与沙箱
- 来源：OpenAI Agents SDK 文档（Tools）
- 核验日期：2026-10-25；核验状态：verified（webfetch 200，页面 last-modified 2026-10-22）

## 来源
- https://openai.github.io/openai-agents-python/tools/
- 相关：https://openai.github.io/openai-agents-python/sandbox_agents/

## 核验（实际读到的）
- 工具分五类：托管 OpenAI 工具、本地/运行时工具、FunctionTool、agents-as-tools、实验性 Codex 工具。
- 托管工具含 WebSearch/FileSearch/**CodeInterpreter（沙箱执行）**/HostedMCP/ImageGeneration/**ToolSearch**/**ProgrammaticToolCalling**。
- **ComputerTool 是本地 harness**：应用实现 `Computer/AsyncComputer` 接口（screenshot/click/type/scroll/drag/keypress/wait），SDK 映射到 Responses 的 computer 面；GA 模型发 `{"type":"computer"}`，可批量 `actions[]`；旧 preview 模型仍走 `computer_use_preview`。
- **安全闸**：`computer_call` 可带 `pending_safety_checks`，`ComputerTool.on_safety_check` 逐条决定是否放行；未配置则默认执行且不确认。
- **Hosted container shell + skills**：`container_auto` 提供容器，`network_policy` 支持 `disabled`/`allowlist`，可挂 `skill_reference`/inline skill bundle；`container_reference` 复用容器。
- **工具面治理**：`ToolSearchTool` 延迟加载 function/namespace/MCP 工具；namespace 建议 <10 个函数；`ProgrammaticToolCalling` 在**全新 V8、无文件/网络/持久进程**中跑生成的 JS，只能调用显式允许的工具。
- 本地 shell/apply_patch 默认 `needs_approval=False`，SDK 明确声明「approval 不是 sandbox」；需要审批时 run 暂停，`result.interruptions` + `RunState` 恢复。

## 架构要素
- 执行环境三档：本地 harness（自己负责隔离）／托管容器（网络策略+技能）／托管 V8（最小权限编程）。
- 工具发现与工具执行分离：先搜索/命名空间，后按需加载。
- 审批是**可暂停/可恢复**的 run 状态，不是阻塞调用。

## 对我们的启示
- 我们的模块在宿主进程 `exec_module`（`trident/core/runner.py:27-31`），没有容器、没有网络策略、没有审批-恢复语义（G08/G03）。
- 可借鉴的最小组合：`network_policy=allowlist` + 只读根 + 每模块一次性工作目录；LLM 生成的代码只在 V8/子进程里跑，且工具白名单由服务端固定。
- 「approval ≠ sandbox」这句话要写进我们的设计原则：审批防「有意作恶」，沙箱防「意外/供应链作恶」，两者不能互相替代。
