# NVIDIA GB200 NVL72 — 机架级 NVLink 交换域

- 分类：自建与超大规模训练组网（硬件形态）+ DRA/IMEX 目标平台
- 组织 / 系统：NVIDIA / GB200 NVL72
- 核验日期：2026-10-25；核验状态：verified（nvidia.com 产品页 HTTP 200 抓取）

## 来源
- https://www.nvidia.com/en-us/data-center/gb200-nvl72/

## 架构要素
- 组网：单机架 72 GPU 通过 NVSwitch 全互联（NVL72 = NVLink 域）；跨机架 MNNVL/IMEX 扩展多节点 NVLink
- 隔离边界：机架=一个 NVLink 信任域；跨域靠 IMEX ComputeDomain（见网络专源条目）
- 身份：域成员资格由驱动/编排决定，无网络认证概念（内存语义互联）
- 存储：独立存储网（另见 SuperPOD/网络专源）
- 通信：NVLink 域内 RDMA 式内存访问；集合通信走 NVLS/组播
- 管理面：SMB/基板管理 + K8s DRA 驱动（compute-domain kubelet plugin）
- 多租户：域内 Pod 全互通（ComputeDomain 声称对域外隔离）
- 云集成点：各云 GB200 实例（P6e-GB200 等）

## 安全问题点（放大前提 × 模块机器键）
- 内存语义互联无认证：域内可达≈可读写对端 GPU 内存（越权取决于 ComputeDomain 划界正确性）→ `fabric-topology-isolation`
- ComputeDomain 控制器/Kubelet 插件提权面：错配把非成员划入域=跨节点内存越权 → `gpu-network-operator-posture`
- 域=故障域：单成员异常可扰动全域集合通信 → `collective-communication-surface`

## 横向思路
- 侦察 DRA 对象 → 若 ComputeDomain 划界宽松 → 以 ResourceClaim 加入目标域 → 直接读写训练权重/梯度所在 GPU 内存（无需 NCCL 入组）

---
## 万卡证据（2026-10-25 重收批注）
- ❌ 未达 ≥10k 口径：无 ≥10k 披露：NVL72 为 72 GPU 机架级域
## 网络要素
- （本源为控制面/组件语义类，不直接承载 8 项 fabric 要素）
- 分类迁移：corpus 扁平目录 → corpus/official-en（外文官方源）
