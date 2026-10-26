# Letta / MemGPT — 分层记忆、MemFS 与 sleep-time reflection

- 分类：agent-2026 / 记忆分层
- 来源：Letta（MemGPT 团队）官方文档
- 核验日期：2026-10-25；核验状态：verified（webfetch 200，docs index；memory 详情页 308 重定向到 index，细节引用以 index 与链接页标题为限）

## 来源
- https://docs.letta.com/
- https://docs.letta.com/configuration/memory/index.md
- https://docs.letta.com/concepts/memfs/index.md

## 核验（实际读到的）
- 定位：stateful agents / continual learning；核心是 **Context Constitution**——规定什么进入上下文窗口、顺序、粒度、保留多久。
- 记忆形态：**memory blocks**（token 空间里的持久身份/记忆）、**MemFS**（git 版本化的记忆文件系统，agent 可读/写/重组自己的记忆文件）、多会话共享记忆、**dreaming / sleep-time subagents**（后台反思与记忆整理）。
- 能力：技能（可自己写、从 GitHub 导入）、子 agent（任务分解+并行）、计划任务、权限（allowlist + 交互式审批）、secrets、mods（自改 harness）。
- 明确的学习观：不改模型权重，靠「主动管理上下文」形成持久的身份与连续性。

## 架构要素
- 三层：上下文内 memory blocks（热）→ 文件化 MemFS（温，可 diff/回滚）→ 后台 dreaming 整理（冷）。
- 记忆是**可版本化的一等公民**，不是聊天记录副产品。
- 反思是**离线/后台任务**，不占用主循环上下文。

## 对我们的启示
- 我们只有「当前 run 的 findings」和 explorer 队列，没有跨 run 记忆（G04）；`agent_planner` 每次从证据库重算（`inkblade/agent_planner.py:94-166`），经验不累积。
- 可落地的三层：working（本轮上下文/工具结果摘要）→ episodic（每轮 run 的决策+结果+复盘，SQLite/JSONL）→ semantic（资产/发现/产品指纹图 + 技能索引）。
- MemFS 的「git 版本化」很适合我们：记忆变更可 diff、可审计、可回滚，符合证据链文化；dreaming 可做成离线的「复盘作业」，产出需人工批准后才写入 semantic。
