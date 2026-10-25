# Oracle OCI — 首个 Zettascale 云计算集群（16,384 H100 / 131,072 B200 口径）

- 分类：official-en（外文官方源）
- 组织 / 系统：Oracle Cloud Infrastructure / OCI Supercluster（zettascale）
- 源类型：newsroom（oracle.com 官方新闻 2024-09-11 CloudWorld）
- 核验日期：2026-10-25；核验状态：verified-partial（oracle.com webfetch 403（WAF 拒连），以 websearch 快照引用官网原句佐证）

## 来源
- https://www.oracle.com/news/announcement/ocw24-oracle-offers-first-zettascale-cloud-computing-cluster-2024-09-11/
- https://www.oracle.com/ai-infrastructure/（产品页，同样 403）

## 万卡证据（原文摘录）
- ✅（官网快照原句）"OCI Superclusters with H100 GPUs can scale up to 16,384 GPUs with up to 65 ExaFLOPS of performance and 13Pb/s of aggregated network throughput."
- ✅（产品页快照）"With OCI Supercluster, you can scale up to more than 100,000 GB200 Superchips, 131,072 B200 GPUs, 65,536 H200 GPUs, 32,768 A100 GPUs, 16,384 H100 GPUs"

## 网络要素
- 聚合网络吞吐 13 Pb/s 口径；RDMA（OCI Cluster Networking，RoCE 族——快照口径）

## 架构要素
- 组网：多档位 supercluster（H100→B200→GB200）；单集群上限 131,072 B200
- 云集成点：OCI 租户形态（多租云上交付万卡）

## 安全问题点（放大前提 × 模块机器键）
- 云上多租交付的万卡 fabric：跨租隔离=云网络策略语义 → `network-policy-coverage`、`cni-stack-capability`
- 13Pb/s 聚合面=性能型攻击高杠杆 → `collective-communication-surface`

## 横向思路
- OCI 租户内 RDMA 面探测（既有 OCI/eRDMA 类比）→ 集合通信入组
