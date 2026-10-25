# LATS — 把 MCTS 接进语言 agent 的推理/行动/规划

- 分类：agent-2026 / 搜索式规划
- 来源：UIUC/Princeton 等（arXiv 2310.04406，v3 2024-06-06）
- 核验日期：2026-10-25；核验状态：verified（webfetch 200，摘要页命中）

## 来源
- https://arxiv.org/abs/2310.04406
- https://github.com/lapisrocks/LanguageAgentTreeSearch

## 核验（实际读到的）
- LATS 把 **Monte Carlo Tree Search** 引入语言 agent，统一 reasoning/acting/planning；用 LM 做价值函数 + **self-reflection** 指导探索。
- 关键：引入**外部环境反馈**，形成更审慎、可适应的问题求解，突破单链 acting 的限制。
- 结果：HumanEval 用 GPT-4 达 **92.7% pass@1**（SOTA）；WebShop 用 GPT-3.5 平均 **75.9**，与梯度微调相当（gradient-free）。
- 覆盖编程、交互式 QA、网页导航、数学。

## 架构要素
- 树搜索：多分支尝试 + 价值评估 + 回溯，不是一条路走到黑。
- 反思用于「哪条分支值得扩展」，而不是只改下一次 prompt。
- 环境反馈是搜索信号，必须有低成本 reset/隔离才能跑多分支。

## 对我们的启示
- 我们的链是**单路径 DAG**，没有分支评估/回溯（G01）；渗透场景天然适合树搜索（多利用路径、多凭证组合）。
- 但树搜索的前提是**可重置的沙箱/靶场**（G08）与**分支成本核算**（G11）；否则一次分叉就可能污染真实目标。
- 可先做「只读侦察阶段」的树搜索（资产/版本/暴露面），写类步骤仍单路径 + 审批，降低风险。
