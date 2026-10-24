# Multus + SR-IOV Network Operator — 多网卡与硬件直通

- 分类：网络架构专源
- 组织 / 系统：K8s Network Plumbing WG / multus-cni + sriov-network-operator
- 核验日期：2026-10-25；核验状态：verified（两 README 全文）

## 来源
- https://raw.githubusercontent.com/k8snetworkplumbingwg/multus-cni/master/README.md
- https://raw.githubusercontent.com/k8snetworkplumbingwg/sriov-network-operator/master/README.md

## 架构要素
- 组网：Multus 委托多个 CNI（eth0 之外的 net0/net1…）；SR-IOV VF/macvlan/DPDK；NAD CRD 定义附加网
- 隔离边界：附加接口流量绕过主接口策略路径；operator 命名空间需 pod-security enforce=privileged（README 明示）
- 身份：设备资源（resourceName）+ 注解（networks）
- 存储：无
- 通信：VF 直通（性能≈宿主）
- 管理面：Operator + Webhook + Resource Injector（mutating admission）
- 多租户：NAD 可跨命名空间引用
- 云集成点：各云 GPU 节点 RDMA 网通用模式

## 安全问题点（放大前提 × 模块机器键）
- **SR-IOV VF/macvlan/IB 流量不受 NetworkPolicy 约束**（旁路族核心事实）→ `multus-sriov-rdma-bypass`
- Resource Injector 是准入 webhook：错配注入=自动扩权 → `rbac-mapping`
- NAD 跨命名空间共享：附网可达性跨租户蔓延 → `cni-aware-reachability-graph`

## 横向思路
- 枚举 NAD → 挂附加网（若 RBAC 允许）→ 在策略盲区直扫 RDMA/存储网 → 入组/直读存储
