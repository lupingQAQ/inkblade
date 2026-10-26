# 阿里云 ACK — eRDMA 容器网络加速

- 分类：云商 K8s GPU/加速器集群（RDMA 通道）
- 云商 / 系统：Alibaba Cloud / ACK + eRDMA Controller
- 核验日期：2026-10-25；核验状态：verified（阿里云帮助中心全文）

## 来源
- https://help.aliyun.com/zh/ack/ack-managed-and-ack-dedicated/user-guide/use-erdma-in-ack-clusters

## 架构要素
- 组网：VPC 内弹性 RDMA（eRDMA），GPU 节点 preferDriver=ofed/compat；容器以扩展资源 `aliyun/erdma: 1` 申请，拿到 /dev/infiniband/uverbs0 等设备
- 隔离边界：设备以设备插件分配；NUMA 亲和分配；未提供网络级认证/加密说明（VPC 内明文 RDMA 语义）
- 身份：ECS RAM 角色/RRSA
- 存储：CPFS/NAS 高性能存储联动
- 通信：NCCL over eRDMA（nccl-test 官方示例验证 erdma_0/1）
- 管理面：ACK eRDMA Controller 组件 + Terway 白名单协同
- 多租户：设备级抢占式共享
- 云集成点：与 Terway ENI 体系紧耦合

## 安全问题点（放大前提 × 模块机器键）
- 设备申请即旁路 CNI：拿到 uverbs0 的 Pod 直接说 RDMA，NetworkPolicy 不覆盖该路径 → `multus-sriov-rdma-bypass`、`cni-aware-reachability-graph`
- 集合通信无认证：eRDMA 可达=可尝试 NCCL 入组 → `nccl-collective-join`
- “全部 eRDMA 设备分配”选项：单 Pod 可独占节点 RDMA 面（邻居租户扰动）→ `gpu-network-operator-posture`

## 横向思路
- 申请 erdma 资源（RBAC 允许即可）→ 探 VPC RDMA 段 → 入组/窃听 → 元数据（RAM 角色）→ OSS 权重桶

---
## 万卡证据（2026-10-25 重收批注）
- ❌ 未达 ≥10k 口径：无 ≥10k 披露：eRDMA 设备文档
## 网络要素
- isolation
- 分类迁移：corpus 扁平目录 → corpus/official-cn（中文官方源）
