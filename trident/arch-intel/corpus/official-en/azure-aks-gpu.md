# Azure AKS — GPU 节点池与设备插件

- 分类：云商 K8s GPU/加速器集群
- 云商 / 系统：Microsoft Azure / AKS
- 核验日期：2026-10-25；核验状态：verified（Microsoft Learn 官方页）

## 来源
- https://learn.microsoft.com/en-us/azure/aks/use-nvidia-gpu

## 架构要素
- 组网：Azure CNI（VPC-native）/ Azure CNI overlay；节点池按 VM SKU 隔离
- 隔离边界：NSG + Azure 网络策略（NPM/Cilium 变体）
- 身份：节点托管标识（Managed Identity）+ workload identity（OIDC 联邦）
- 存储：Azure Blob/Files（CSI）
- 通信：ND 系列 InfiniBand（另条目）
- 管理面：AKS 控制面（托管）；gpu-driver 三态（managed/self/none）
- 多租户：nodepool taint（sku=gpu:NoSchedule）+ namespace
- 云集成点：IMDS（169.254.169.254）+ Azure AD

## 安全问题点（放大前提 × 模块机器键）
- 设备插件 DaemonSet 挂 hostPath /var/lib/kubelet/device-plugins：可写 kubelet 插件目录的工作负载=节点面风险 → `escape-primitives`
- 节点托管标识过权 → Blob/Files 权重面 → `cloud-role-overprivilege`、`multi-cloud-imds-credentials`
- 自管模式安装 GPU Operator=特权 DaemonSet 全节点 → `gpu-network-operator-posture`

## 横向思路
- Pod → IMDS 取托管标识 token → Blob 权重桶读写；或污点容忍节点上的特权 operator 面提权
