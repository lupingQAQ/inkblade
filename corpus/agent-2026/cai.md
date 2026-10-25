# CAI（Cybersecurity AI）— 自主等级分类 + HITL 的工程化

- 分类：agent-2026 / 自主渗透框架
- 来源：Alias Robotics 等（arXiv 2504.06017）
- 核验日期：2026-10-25；核验状态：verified（webfetch 200，摘要页命中）

## 来源
- https://arxiv.org/abs/2504.06017
- https://github.com/aliasrobotics/cai

## 核验（实际读到的）
- 提出**网络安全自主等级分类**（autonomy levels），并给出开源框架 CAI：模块化 agent + 工具集成 + **human oversight（HITL）**。
- CTF 战绩：特定任务比人类快 **3,600×**，平均 **11×**；"AI vs Human" 直播赛 AI 队第一、全球前 20，奖金 $750。
- 真实平台：一周内 Hack The Box 西班牙前 30、全球前 500；平均降本 **156×**。
- 非专业者在 bug bounty 中发现 CVSS **4.3–7.5** 的问题，比例接近专家。
- 论点：反对「LLM 安全能力有限」的厂商说法；自主+工具+HITL 已可实用。

## 架构要素
- 自主不是二值：分级授权 + 人在环，按任务风险调整。
- Agent/工具/人类监督三层分离；强调可复现的真实平台战绩。
- 成本是核心卖点（156×），不是纯能力。

## 对我们的启示
- 我们的「审批制」其实是低自主等级；缺的是**分级模型**（哪些动作可自动、哪些必须批）与**按等级选择 agent 数量/预算**。
- HITL 的价值被量化（AutoPenBench 也显示 assisted 64% vs autonomous 21%），可作为我们「审批不是拖累」的外部证据。
- 我们的差异化应写成「可审计的自主等级」：同一任务可按客户策略在 L0–L3 间切换，证据链不随等级变化。
