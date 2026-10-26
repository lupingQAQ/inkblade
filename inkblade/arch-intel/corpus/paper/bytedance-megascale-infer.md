# ByteDance MegaScale-Infer — MoE 推理规模化（MegaScale 后续）

- 分类：paper（论文/第三方分析源）
- 组织 / 系统：ByteDance Seed & 北大 / MegaScale-Infer（SIGCOMM 2025）
- 核验日期：2026-10-25；核验状态：verified（arXiv 摘要页直读；SIGCOMM'25 论文 PDF 检索命中）

## 来源
- https://arxiv.org/abs/2504.02263
- https://chaojin0310.github.io/files/papers/SIGCOMM25-MegaScale-Infer.pdf

## 万卡证据（原文摘录）
- ➖（本源为规范/漏洞/机制证据，非万卡规模实证；wanka_evidence=false）

## 网络要素
- ➖（无独立网络要素主张；以规模/吞吐与通信域语义为主）

## 架构要素
- MegaScale 系列后续：面向大规模 MoE 推理（attention/FFN 解耦部署，各自独立并行与异构部署）
- ping-pong pipeline parallelism：请求批切微批在 attention/FFN 模块间往返，隐藏通信开销
- M2N 高性能 token 分发库：消除 GPU↔CPU 拷贝、组初始化开销与 GPU 同步
- 每 GPU 吞吐较 SOTA +1.90×；在 Mixtral 8×22B / DBRX / 317B 自研 MoE 上验证
- 与训练侧 MegaScale（NSDI'24）共用生产网络与可观测体系（流量画像/故障恢复）

## 安全问题点（放大前提 × 模块机器键）
- attention/FFN 解耦 = 新通信域（token 分发面）：入组/分发无身份即推理操纵面 → `nccl-collective-join`
- M2N 组初始化优化同样降低攻击者建链成本 → `nccl-port-exhaustion`
- 推理/训练共用 fabric：推理 token 洪与训练 all-reduce 竞争同一 PFC/ECN 域 → `roce-pfc-storm`

## 横向思路
- 推理侧 token 分发风暴 + 训练侧集合通信 → 共享 fabric 双向耗尽（`fabric-exhaustion-chain`）
