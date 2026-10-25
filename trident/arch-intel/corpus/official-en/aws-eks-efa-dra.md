# AWS EKS — EFA 设备管理（DRA 与设备插件双轨）

- 分类：云商 K8s GPU/加速器集群
- 云商 / 系统：AWS / EKS + Elastic Fabric Adapter
- 核验日期：2026-10-25；核验状态：verified（EKS 用户手册 GitHub 源文件直读）

## 来源
- https://raw.githubusercontent.com/awsdocs/amazon-eks-user-guide/mainline/latest/ug/ml/device-management-efa.adoc（EKS 用户指南开源仓）
- https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/efa.html（EC2 EFA，指南内引用）

## 架构要素
- 组网：EFA（OS bypass RDMA 网卡）挂 EC2 GPU 实例；placement group 约束；NodeClass advancedNetworking.networkInterfaces（Auto Mode）/Karpenter/托管节点组
- 隔离边界：安全组（SG）为 EFA 流量边界；VPC 内网
- 身份：节点实例角色 + IRSA（Pod 级云身份）
- 存储：EFS/FSx（指南另有 fsx-csi-tuning-efa 页）
- 通信：EFA + NCCL/MPI；GPUDirect RDMA
- 管理面：EKS 控制面 + Karpenter/Auto Mode
- 多租户：namespace/节点池分层
- 云集成点：IMDSv2、EC2 API

## 安全问题点（放大前提 × 模块机器键）
- EFA 走 SR-IOV/OS bypass：Pod 拿到 EFA 后 NetworkPolicy/SG 双控制面语义需逐一核对 → `cni-stack-capability`、`multus-sriov-rdma-bypass`
- DRA ResourceClaim 可共享 EFA：错误 RBAC（create resourceclaims）=跨命名空间抓网卡 → `rbac-mapping`
- 节点角色/IRSA 过权 → S3 权重桶 → `cloud-role-overprivilege`、`multi-cloud-imds-credentials`

## 横向思路
- 云指纹识别 EKS+EFA → can-i create ResourceClaim → 抓 EFA 入集合通信网 → NCCL 入组；或元数据出网 → 云凭据 → 桶横向
