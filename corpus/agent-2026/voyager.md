# Voyager — 可增长技能库 + 自动课程 + 迭代自验证

- 分类：agent-2026 / 技能库与终身学习
- 来源：NVIDIA/Caltech 等（arXiv 2305.16291，v2 2023-10-19）
- 核验日期：2026-10-25；核验状态：verified（webfetch 200，摘要页命中）

## 来源
- https://arxiv.org/abs/2305.16291
- https://voyager.minedojo.org/

## 核验（实际读到的）
- 三个组件：**automatic curriculum**（最大化探索）、**ever-growing skill library of executable code**（存储/检索复杂行为）、**iterative prompting**（环境反馈 + 执行错误 + 自验证来改程序）。
- 技能是**时序扩展、可解释、可组合**的，能力复利增长并缓解灾难性遗忘。
- 结果：比此前 SOTA 多 3.3× 独特物品、2.3× 移动距离、科技树里程碑快 15.3×；学到的技能库能在**新世界**从零解新任务。
- 黑盒调用 GPT-4，不微调权重。

## 架构要素
- 技能=可执行代码 + 描述 + 检索键；不是自然语言备忘。
- 课程负责「学什么」，自验证负责「学对没」。
- 技能库可迁移到新环境，是能力的持久载体。

## 对我们的启示
- 我们的「技能」目前等于模块（`registry.load_modules`，`inkblade/core/registry.py:34`），新增要发版、不可组合、不记录成功条件（G05）。
- 可落地：每次成功链产出「技能草稿」（步骤/前置/证据/回滚/失败案例），经评测与人工批准后进入技能库；下次由 planner 检索复用。
- 关键差异：渗透技能必须带**授权与副作用元数据**（min_level/writes/backup_targets），不能像游戏技能一样无条件复用。
