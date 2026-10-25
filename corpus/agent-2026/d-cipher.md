# D-CIPHER — Planner + 异构 Executor 的 CTF 多 agent

- 分类：agent-2026 / 多 agent 自主渗透
- 来源：NYU / 多校（arXiv 2502.10931，v2 2025-05-11）
- 核验日期：2026-10-25；核验状态：verified（webfetch 200，摘要页命中）

## 来源
- https://arxiv.org/abs/2502.10931

## 核验（实际读到的）
- 问题：单 agent 的 reasoning-action 单环不足以解复杂 CTF；真实 CTF 是团队协作。
- 设计：**Planner**（全局解题）+ 多个**异构 Executor**（各自负责任务）+ **Auto-prompter**（自动生成高相关初始提示）；角色间动态反馈回路。
- 结果：NYU CTF Bench **22.0%**、Cybench **22.5%**、HackTheBox **44.0%**，比此前工作高 2.5–8.5 个百分点；解出的 MITRE ATT&CK 技术数多 **65%**。
- 额外：把 NYU CTF Bench 的题目手工映射到 ATT&CK，便于按战术评估。

## 架构要素
- 规划与执行分离，执行者异构（不同工具/专长），反馈回路动态。
- 角色分工带来覆盖度（ATT&CK 技术数）而不只是分数。
- 自动提示工程降低对人工 prompt 的依赖。

## 对我们的启示
- 我们的 `agent_planner` 只有「排序」，没有 Planner/Executor 分离、没有反馈回路（G02/G06）。
- 可借用其「异构 executor」：recon/exploit/verify 三类 worker 工具集不同，不应让一个通用 agent 全干。
- ATT&CK 覆盖率是比「成功/失败」更好的中间指标；我们的链已有 MITRE 标注，可做覆盖率评分。
