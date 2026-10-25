# NVIDIA ComputeDomain / IMEX — 多节点 NVLink 的 DRA 编排

- 分类：网络架构专源（2026 新架构面）
- 组织 / 系统：NVIDIA / k8s-dra-driver-gpu（GPU + ComputeDomain 两插件）
- 核验日期：2026-10-25；核验状态：verified（README 全文）

## 来源
- https://raw.githubusercontent.com/NVIDIA/k8s-dra-driver-gpu/main/README.md

## 架构要素
- 组网：ComputeDomain 保证域内 Pod 间 MNNVL 可达、与域外 Pod “安全隔离”；IMEX=daemon/domain/channel 三原语（GB200 系统编排重点）
- 隔离边界：域成员资格=信任边界；placement 随工作负载；生命周期=ephemeral（随负载）
- 身份：ResourceClaim 声明式入域
- 存储：无
- 通信：跨节点 NVLink 内存语义（非网络协议栈）
- 管理面：两个 kubelet 插件（可分装分启）
- 多租户：域间隔离声明（正确性依赖驱动实现）
- 云集成点：GB200 实例/P6e 类产品

## 安全问题点（放大前提 × 模块机器键）
- 域界错配=跨节点 GPU 内存越权（比 NCCL 注入更底层：内存语义无认证）→ `fabric-topology-isolation`
- compute-domain kubelet 插件特权面 → `gpu-network-operator-posture`
- “域外隔离”为厂商声明：需实证（实验室 fixture 推演+人工核验）→ `cni-aware-reachability-graph`

## 横向思路
- 观测 ComputeDomain CR → 构造 claim 尝试与目标同域 → 域内直接读改对端 GPU 内存（权重/梯度）
