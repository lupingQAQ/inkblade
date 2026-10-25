# Anthropic《Building effective agents》— workflow 与 agent 的分界

- 分类：agent-2026 / 架构谱系
- 来源：Anthropic 官方研究博客（2024-12 发布，页面 2026 仍在线并加注）
- 核验日期：2026-10-25；核验状态：verified（webfetch 200，正文命中）

## 来源
- https://www.anthropic.com/research/building-effective-agents
- （原 /engineering/ 路径 308 重定向）

## 核验（实际读到的）
- 区分 **workflows**（LLM 与工具由预定义代码路径编排）与 **agents**（LLM 动态决定流程与工具使用）。
- 建议：**先找最简单解法**，只在确有收益时增加复杂度；很多场景优化单次 LLM 调用 + 检索 + 上下文示例就够了。
- 基础块：**augmented LLM**（检索/工具/记忆）；MCP 是工具集成的一种实现。
- 五种 workflow：**prompt chaining**（含程序化 gate）、**routing**（按类别分流，可路由到小模型降本）、**parallelization**（sectioning / voting）、**orchestrator-workers**（子任务不预定义，由编排者动态拆分）、**evaluator-optimizer**（生成-评估循环）。
- Agent 的适用条件：开放性问题、无法预先硬编码步骤、可接受多轮自主、环境能提供 ground truth、有检查点与停止条件。
- 三条原则：**简单**、**透明**（显式展示计划步骤）、**精心设计 ACI**（工具文档/测试/边界/示例，poka-yoke）。
- 成本/风险：自主性=更高成本 + 复合错误；建议在**沙箱**中大量测试并加护栏。

## 架构要素
- 谱系是「复杂度阶梯」：单调用 → 链 → 路由 → 并行 → 编排者-工人 → 评估-优化 → 自主 agent。
- 选择判据不是「先不先进」，而是「任务是否可预定义 + 环境是否给 ground truth + 错误是否可承受」。
- 透明性是可运维性：计划步骤要显式可见。

## 对我们的启示
- 我们的确定性链 = prompt chaining/parallelization 的代码化版本，方向没错；**错在只实现了阶梯的下半截**，没有 orchestrator-workers / evaluator-optimizer / agent loop。
- 「透明」我们做得比多数框架好（证据+审批+审计），但缺**机器可读的决策轨迹**（G12）。
- 「先简单」应成为升级门槛：每个新设计点必须证明相对现有链的增益，否则不进主线。
