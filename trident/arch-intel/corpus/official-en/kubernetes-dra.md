# Kubernetes DRA — 动态资源分配（结构化参数）

- 分类：网络架构专源（设备管理）
- 组织 / 系统：Kubernetes SIG-Node / KEP-4381（基线）+ KEP-3063（撤回）
- 核验日期：2026-10-25；核验状态：verified（两 KEP 全文）

## 来源
- https://raw.githubusercontent.com/kubernetes/enhancements/master/keps/sig-node/4381-dra-structured-parameters/README.md
- https://raw.githubusercontent.com/kubernetes/enhancements/master/keps/sig-node/3063-dynamic-resource-allocation/README.md

## 架构要素
- 组网：网络附加设备（CXL/加速器池）为一等资源；调度器内完成分配（无需驱动往返）
- 隔离边界：DeviceClass 管理员参数（含 root 初始化命令 DANGER 示例）；ResourceSlice 按 nodeName 隔离写权
- 身份：驱动名+节点名绑定（VAP 可限写）
- 存储：无
- 通信：kubelet↔插件 gRPC（本节点）
- 管理面：kube-controller-manager 建 ephemeral claim；kube-scheduler 分配
- 多租户：claim 配额/RBAC（注意 ephemeral claim 可绕过创建 RBAC 的告警）
- 云集成点：EKS EFA DRA（DRANET）已产品化（见 aws 条目）

## 安全问题点（放大前提 × 模块机器键）
- **KEP 自认：被攻陷的 kubelet 插件≈节点 root**（DRA 驱动常需特权）→ `gpu-network-operator-posture`、`escape-primitives`
- DeviceClass initCommand：管理员参数注入面（伪装用户参数）→ `combo-signature-static`
- 被攻陷节点伪造 ResourceSlice 诱调度（KEP 风险节）→ `cni-aware-reachability-graph`（调度面）

## 横向思路
- create resourceclaim RBAC 检查 → 申领敏感 DeviceClass/共享设备 → 借 CDI 注入获得 GPU/NIC/IMEX 通道

---
## 万卡证据（2026-10-25 重收批注）
- ❌ 未达 ≥10k 口径：无 ≥10k 披露：KEP 文档
## 网络要素
- isolation
- 分类迁移：corpus 扁平目录 → corpus/official-en（外文官方源）
