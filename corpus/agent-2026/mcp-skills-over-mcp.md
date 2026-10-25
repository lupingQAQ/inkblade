# Skills over MCP — 技能成为可发现、可分发的协议原语

- 分类：agent-2026 / 技能库与工具联邦
- 来源：Model Context Protocol Skills Over MCP Working Group
- 核验日期：2026-10-25；核验状态：verified（webfetch 200，正文命中）

## 来源
- https://modelcontextprotocol.io/community/working-groups/skills-over-mcp.md

## 核验（实际读到的）
- 工作组章程：定义 agent skills（富结构化的 agent 工作流指令）如何经 MCP **发现、分发、消费**。
- 起点是 SEP-2076「Agent Skills as a First-Class MCP Primitive」；**SEP-2640 Skills Extension 已 Final，2026-09-13 合并**；官方扩展标识 `io.modelcontextprotocol/skills`，实现仓库 `modelcontextprotocol/ext-skills`。
- 扩展基于 **Resources**；与 Registry WG（技能发现/分发、registry schema）、Agents IG（激活、服务端元数据）、**Progressive Disclosure WG** 协作；并对外部 **Agent Skills 规范（agentskills.io）** 做内容格式与 well-known URI 发现的对齐。
- 一致性测试场景 2026-09-11 合并；客户端支持矩阵单独维护。

## 架构要素
- 技能不是提示词片段，而是「可发现 + 可版本化 + 可分发」的协议对象。
- 发现与激活分离：元数据先加载，正文按需加载（渐进披露）。
- 生态分工：Agent Skills 定内容格式，MCP 定传输/发现，Registry 定分发。

## 对我们的启示
- 我们的能力单元是**硬编码 Python 模块**（`trident/core/registry.py:34` 读 `module.json`），新增手法必须发版；这与「技能库」不是一回事（见 G05）。
- 可行的最小路径：把高价值手法写成 `SKILL.md`（步骤/前置/证据要求/回滚点），用 MCP Resources 暴露给外部 agent，同时保留模块作为**唯一可执行实现**——技能负责「怎么想/怎么验」，模块负责「怎么执行」。
- 安全：技能是可执行的供应链对象（ASI04）。必须签名 + 来源 + 版本锁定；`allowed-tools` 字段只能收紧不能扩权。
