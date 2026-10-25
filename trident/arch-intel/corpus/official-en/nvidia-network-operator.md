# NVIDIA Network Operator — GPU 集群网络栈编排

- 分类：网络架构专源
- 组织 / 系统：NVIDIA（Mellanox）/ network-operator
- 核验日期：2026-10-25；核验状态：verified（README 全文）

## 来源
- https://raw.githubusercontent.com/Mellanox/network-operator/master/README.md

## 架构要素
- 组网：单 CR（nic-cluster-policy）声明式下发 OFED 驱动、RDMA/SR-IOV 设备插件、ib-kubernetes、nv-ipam、Multus/IPoIB 二级网
- 隔离边界：节点级驱动域；HostDeviceNetwork 把宿主设备池化为 NAD
- 身份：operator SA（集群级）+ 驱动容器 privileged
- 存储：无
- 通信：RoCE/IB 全栈（ConnectX-5+）
- 管理面：operator + 每子状态 ready/ignore 聚合
- 多租户：设备资源池共享
- 云集成点：各云 GPU 节点常用（或以其托管变体）

## 安全问题点（放大前提 × 模块机器键）
- **OFED 驱动容器特权 + 内核模块加载**：容器逃逸/镜像投毒=宿主 root → `gpu-network-operator-posture`、`privileged-gpu-pod-escape`
- operator 掌 CR 即掌全网卡配置（隔离重写面）→ `rbac-mapping`
- ib-kubernetes 子状态关联 IB 分区管理（与 partition 旁路相关）→ `fabric-topology-isolation`

## 横向思路
- 拿 CR 写权/operator SA → 重配 PKey/网络划分 → 把攻击者 Pod 划入目标分区 → IB 直达
