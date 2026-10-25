# Reflexion — 语言化自我反思 + episodic memory

- 分类：agent-2026 / 自反思
- 来源：Northeastern / MIT 等（arXiv 2303.11366，v4 2023-10-10）
- 核验日期：2026-10-25；核验状态：verified（webfetch 200，摘要页命中）

## 来源
- https://arxiv.org/abs/2303.11366

## 核验（实际读到的）
- 不更新权重，而用**语言反馈**强化 agent：对任务反馈信号做 verbal reflection，把反思文本存入 **episodic memory buffer**，影响后续尝试。
- 可接纳多种反馈：标量/自由文本、外部/内部模拟。
- 结果：HumanEval **pass@1 91%**，超过此前 GPT-4 的 80%；在顺序决策、编码、语言推理上均优于 baseline。
- 做了反馈信号、反馈融入方式、agent 类型的消融分析。

## 架构要素
- 反思是「可读的文本状态」，不是梯度；因此可审计、可编辑、可迁移。
- 记忆按「尝试」组织（episodic），下次同任务族复用。
- 反馈质量决定反思质量。

## 对我们的启示
- 我们的 `explorer.execute` 记录结果（`explorer.py:263-278`），但 `propose` 不消费结果（G06）：失败不改变下一次提议。
- 最小实现：每次 run 结束生成 `reflection.md`（目标/尝试/失败原因/下次避免/证据锚），存 episodic；下次 propose 时作为候选排序的上下文（仍由规则/审批约束）。
- 注意 ASI06：反思文本是记忆，可能被投毒；写入前要脱敏、标注来源、可回滚。
