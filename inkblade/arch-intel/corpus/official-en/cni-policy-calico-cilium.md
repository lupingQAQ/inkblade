# Calico / Cilium — CNI 策略语义与节点防火墙

- 分类：网络架构专源
- 组织 / 系统：Project Calico（Tigera）/ Cilium（Isovalent）
- 核验日期：2026-10-25；核验状态：verified（Cilium 文档直读；Calico README 当日网络超时——两引擎语义按各自官方文档体系记录）

## 来源
- https://docs.cilium.io/en/latest/security/host-firewall/（已抓取）
- https://raw.githubusercontent.com/projectcalico/calico/master/README.md（当日超时，待复验）

## 架构要素
- 组网：Calico（BGP/overlay）与 Cilium（eBPF）数据面
- 隔离边界：Cilium 以安全身份（label）而非仅 IP 做策略；Host Firewall 把节点自身纳入策略管辖；节点间加密可开
- 身份：Cilium 身份=标签集合（身份广播机制）
- 存储：无
- 通信：L3-L7 策略（L7 需代理）
- 管理面：operator+agent（每节点）
- 多租户：策略命名空间化/全局化
- 云集成点：云厂商托管策略引擎多为二者变体

## 安全问题点（放大前提 × 模块机器键）
- 策略语义因 CNI 而异：同一份 NetworkPolicy 在不同引擎覆盖不同（如 egress 到 hostNetwork）→ `cni-stack-capability`
- Host Firewall 非默认开：节点面常为策略空白 → `cni-aware-reachability-graph`（pod↔宿主维）
- eBPF 程序可写=数据面接管（特权容器前提）→ `escape-primitives`

## 横向思路
- 指纹引擎与版本 → 按引擎挑旁路（hostNetwork/SR-IOV/未启用面）→ 逐维验证可达矩阵

---
## 万卡证据（2026-10-25 重收批注）
- ❌ 未达 ≥10k 口径：无 ≥10k 披露：策略语义文档
## 网络要素
- isolation
- 分类迁移：corpus 扁平目录 → corpus/official-en（外文官方源）
