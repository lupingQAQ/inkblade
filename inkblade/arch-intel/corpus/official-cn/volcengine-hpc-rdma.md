# 火山引擎高性能计算集群 — RDMA 互通与集群间隔离语义

- 分类：official-cn（中文官方源）
- 组织 / 系统：Volcengine（字节跳动）/ GPU 云服务器 HPC 集群 + RDMA
- 源类型：vendor-docs（火山引擎文档中心；页面需 JS 渲染，以检索快照佐证）
- 核验日期：2026-10-25；核验状态：verified（webfetch 需 JS 不可提取（重定向 docs.volcengine.com），以 websearch 官方文档快照佐证）

## 来源
- https://docs.volcengine.com/docs/gpu/HPC-cluster-overview
- https://www.volcengine.com/docs/gpu/Buying-High-Performance-Computing-Optimized-instances

## 万卡证据（原文摘录）
- ❌ 文档无 ≥10k 口径（火山引擎 2023-04 官方发布会“支持万卡级大模型训练”经由媒体通稿佐证，非文档原文；MegaScale 12,288 卡证据见 corpus/paper/bytedance-megascale.md）

## 网络要素
- isolation（官方文档快照原句）：“火山引擎提供的高性能计算集群，用于实现高性能计算GPU实例（计算节点）的逻辑隔离。同一集群内实例间RDMA网络互联互通，不同集群内实例间RDMA网络相互隔离”
- RDMA 设备默认 IP 段固定（198.x.x.x/33，快照口径）

## 架构要素
- 组网：VPC 基础上叠加 RDMA 网卡（高性能计算集群逻辑隔离）
- 隔离边界：集群 ID = RDMA 互通域边界
- 通信：RDMA 直访 vePFS 文件存储（产品页口径）
- 云集成点：火山引擎 GPU 云

## 安全问题点（放大前提 × 模块机器键）
- “集群间 RDMA 相互隔离”依赖平台侧隔离实现：同集群内无租户级网络身份 → `collective-communication-surface`
- RDMA 默认固定 IP 段=可预测面 → `cni-aware-reachability-graph`（pod↔IB 维）
- vePFS RDMA 直访：存储面旁路 → `shared-volume-weight-copy`

## 横向思路
- 同集群取到任一 RDMA 网卡 → 互通全域 → NCCL 入组 / RDMA 读邻居；跨集群边界列为突破目标
