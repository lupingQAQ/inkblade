# AWS EKS Auto Mode — 托管加速负载

- 分类：云商 K8s GPU/加速器集群
- 云商 / 系统：AWS / EKS Auto Mode
- 核验日期：2026-10-25；核验状态：verified（EKS 用户指南开源仓）

## 来源
- https://raw.githubusercontent.com/awsdocs/amazon-eks-user-guide/mainline/latest/ug/automode/auto-accelerated.adoc

## 架构要素
- 组网：AWS 托管节点（用户不可 SSH）；NodePool（Karpenter v1 语义）+ NodeClass
- 隔离边界：托管面收走节点 root；安全组/VPC 边界
- 身份：Auto Mode 托管 IAM + EKS 访问条目
- 存储：托管存储集成
- 通信：EFA 管理见 device-management-efa（Auto Mode 仅 device plugin 通道）
- 管理面：AWS 全托管（驱动/设备插件/CNI/存储/LB/IAM 打包）
- 多租户：namespace
- 云集成点：深 IAM 绑定（开箱即用的组件都带 AWS 托管权限）

## 安全问题点（放大前提 × 模块机器键）
- “驱动不可见”弱化主机面侦察，但云权限面扩大（托管组件的权限边界不透明）→ `cloud-integration-fingerprint`、`cloud-role-overprivilege`
- 缩容到零+自动拉起：节点漂移使 IP/端口白名单容易过宽 → `exposure-mapping`
- managed nodegroup 类似：node 角色权限常被多池共用 → `overprivileged-sa-escalation`

## 横向思路
- 元数据/出网面 → 节点角色或托管组件角色 → 云资源（S3/EC2 映射）横向 → 回旋集群（伪造 admission/操作 CR）

---
## 万卡证据（2026-10-25 重收批注）
- ❌ 未达 ≥10k 口径：无 ≥10k 披露：EKS Auto Mode 文档
## 网络要素
- （本源为控制面/组件语义类，不直接承载 8 项 fabric 要素）
- 分类迁移：corpus 扁平目录 → corpus/official-en（外文官方源）
