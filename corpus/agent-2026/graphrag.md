# GraphRAG — 实体知识图谱 + 社区摘要，服务全局性问题

- 分类：agent-2026 / 语义记忆
- 来源：Microsoft Research（arXiv 2404.16130，v2 2025-02-19）
- 核验日期：2026-10-25；核验状态：verified（webfetch 200，摘要页命中）

## 来源
- https://arxiv.org/abs/2404.16130

## 核验（实际读到的）
- 问题：传统 RAG 在**全局性问题**（"这个语料的主要主题是什么"）上失效，因为它是 query-focused summarization 而非显式检索。
- 方法：LLM 两阶段建图——先从源文档抽**实体知识图谱**，再为紧密关联实体群**预生成社区摘要**；回答时每个社区摘要生成部分答案，再汇总为最终答案。
- 结果：在 100 万 token 级语料上，对全局性问题的**全面性与多样性**显著优于传统 RAG baseline。

## 架构要素
- 索引=图（实体/关系）+ 层级社区摘要，不是扁平向量块。
- 查询=map-reduce：局部摘要→全局归并。
- 适合「跨文档/跨 run 的全局态势」，不适合低延迟单点检索。

## 对我们的启示
- 我们的证据是**天然图**：资产→服务→产品→版本→finding→链→MITRE；已有 `graph_nodes/graph_edges` 表（`inkblade/core/evidence.py:40-41`）与 `compliance.py` 的映射。
- 但图只用于展示/映射，没有作为**检索与推理记忆**（G04）；可把 GraphRAG 的「社区摘要」用于生成「攻击面态势摘要」，供 planner 作为上下文。
- 与 CM-16（探索血缘图）同源：先把 goal→intent→fact→finding 的边补齐，再谈社区摘要，否则图是空的。
