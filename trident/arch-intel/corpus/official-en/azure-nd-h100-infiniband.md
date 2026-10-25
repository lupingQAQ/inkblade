# Azure ND H100 v5 — 每 GPU 独占 IB 的训练实例

- 分类：云商 K8s GPU/加速器集群（硬件/网络形态）
- 云商 / 系统：Microsoft Azure / NDv5 系列
- 核验日期：2026-10-25；核验状态：verified（Microsoft Learn 规格页）

## 来源
- https://learn.microsoft.com/en-us/azure/virtual-machines/sizes/gpu-accelerated/ndh100v5-series

## 架构要素
- 组网：8×H100/NVLink4；每 GPU 一条独占 400Gbps CX7 IB（拓扑无关声明）；同 VMSS 自动互联；数千 GPU 横向扩展（每 VM 3.2Tbps）
- 隔离边界：IB 面在租户内自动组网；跨租户隔离靠 Azure fabric（无 IB Partition 自管入口）
- 身份：VM 标识/IMDS
- 存储：远程盘 + 本地 NVMe
- 通信：IB + NCCL/MPI（GPUDirect RDMA）
- 管理面：VMSS/AKS 节点池
- 多租户：云级多租户（同 VMSS=同租户域）
- 云集成点：IMDS、ExpressRoute（另条目）

## 安全问题点（放大前提 × 模块机器键）
- IB 无认证：同 fabric 可达即可尝试入组/嗅探（隔离完全依赖云 fabric 划界）→ `fabric-topology-isolation`、`nccl-collective-join`
- VMSS 内自动组网=横向免配置：拿到一个 ND 节点即天然可达同 VMSS 全部节点 IB 面 → `cni-aware-reachability-graph`
- 不支持实时迁移：宿主异常处置少一层，逃逸影响更"物理" → `privileged-gpu-pod-escape`

## 横向思路
- AKS Pod（hostNetwork/IB 设备）→ 扫 IB 子网 → 入组污染/窃听 → checkpoint 桶（托管标识）
