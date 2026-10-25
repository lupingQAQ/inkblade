# ib-kubernetes — InfiniBand 分区管理（Pod 级 PKey）

- 分类：网络架构专源（IB 隔离）
- 组织 / 系统：NVIDIA（Mellanox）/ ib-kubernetes
- 核验日期：2026-10-25；核验状态：verified（README 全文）

## 来源
- https://raw.githubusercontent.com/Mellanox/ib-kubernetes/master/README.md

## 架构要素
- 组网：IB fabric + SM（子网管理器）；PKey=分区键（IB 的“VLAN”）；GUID 表控制成员
- 隔离边界：**Partition/SM 是 IB 唯一隔离手段**（无认证无加密）；Pod 经注解获得 PKey 成员资格
- 身份：无（拓扑/PKey 即边界）
- 存储：IB 存储（Lustre/GPFS 类）同 fabric
- 通信：RDMA 读直写
- 管理面：ib-kubernetes daemon + SM 插件（对接 UFM/内置）
- 多租户：分区=租户边界（配置正确时）
- 云集成点：ND/EKS 等托管 IB 隐藏该层（云侧代管）

## 安全问题点（放大前提 × 模块机器键）
- **IB 无认证**：可达 fabric 且 PKey 划分错误即全通 → `fabric-topology-isolation`
- SM 单点：SM 被攻陷=全网重划（隔离失效）→ `gpu-network-operator-posture`
- RoCE 变体无 PKey 等价物：隔离回退到 VLAN/安全组（常漏配）→ `cni-stack-capability`

## 横向思路
- 枚举 PKey/GUID → 若 default 分区全通 → 直接 RDMA 读写邻居（含存储流量）→ 免 NCCL 的底层窃听
