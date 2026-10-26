# NCCL — GPU 集合通信库（传输与入组面）

- 分类：网络架构专源（集合通信层）
- 组织 / 系统：NVIDIA / NCCL
- 核验日期：2026-10-25；核验状态：verified（README 全文 + 官方用户指南链接）

## 来源
- https://raw.githubusercontent.com/NVIDIA/nccl/master/README.md
- https://docs.nvidia.com/deeplearning/nccl/user-guide/docs/（环境变量/拓扑调优权威）

## 架构要素
- 组网：任意拓扑上构建 ring/tree 集合通信图；传输栈覆盖 PCIe/NVLink/NVSwitch、IB Verbs（RoCE 同族）、TCP
- 隔离边界：无内建认证/加密（库层）；隔离依赖 fabric（IB Partition/安全组）
- 身份：bootstrap（TCPStore/rendezvous）纯协调无鉴权
- 存储：无
- 通信：梯度/参数面（训练最高价值流量）
- 管理面：环境变量驱动（NCCL_SOCKET_IFNAME/IB_HCA 等，见用户指南）
- 多租户：comm 组即边界（入组即全通）
- 云集成点：各云 GPU 集群默认集合库

## 安全问题点（放大前提 × 模块机器键）
- **集合通信无认证（bootstrap 可加入）**：核心横向前提 → `nccl-collective-join`
- 环境变量可注入通信行为（代理/接口劫持）→ `collective-communication-surface`
- TCP fallback：IB 不通时自动回落 TCP——策略面常忽略该路径 → `cni-aware-reachability-graph`

## 横向思路
- 探测 TCPStore/rendezvous 端口 → 按协议入组 → 注入张量（梯度投毒）或旁听 all-reduce（参数泄露）

---
## 万卡证据（2026-10-25 重收批注）
- ❌ 未达 ≥10k 口径：无 ≥10k 披露：NCCL 文档
## 网络要素
- （本源为控制面/组件语义类，不直接承载 8 项 fabric 要素）
- 分类迁移：corpus 扁平目录 → corpus/official-en（外文官方源）
