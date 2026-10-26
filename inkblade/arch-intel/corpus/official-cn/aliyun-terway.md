# 阿里云 ACK — Terway 容器网络插件

- 分类：云商 K8s GPU/加速器集群（CNI 形态）
- 云商 / 系统：Alibaba Cloud / ACK（托管/专有）+ Terway
- 核验日期：2026-10-25；核验状态：verified（阿里云帮助中心全文抓取）

## 来源
- https://help.aliyun.com/zh/ack/ack-managed-and-ack-dedicated/user-guide/work-with-terway

## 架构要素
- 组网：Pod 直取 VPC IP（ENI 多 IP / 独占 ENI / Trunk ENI）；DataPath V2 用 eBPF 绕过节点协议栈、K8s≥1.34 不再跑 kube-proxy
- 隔离边界：NetworkPolicy 由 eBPF 实现（v1.9.2+）；Trunk ENI 给 Pod 独立安全组+固定 IP（托管集群 1.31+ 默认开）
- 身份：ECS 元数据（RAM 角色）/RRSA（OIDC）
- 存储：NAS/CPFS/OSS（云侧权重面）
- 通信：VPC 内直达；独占 ENI 模式绕过节点协议栈
- 管理面：terway-eniip/terway-controlplane 组件 + CRD（podnetworkings.network.alibabacloud.com 等，系统资源禁改）
- 多租户：节点池级模式混部（v1.11.0+ 共享/独占 ENI 可共存）
- 云集成点：ENI/OpenAPI、安全组、CEN（另条目）

## 安全问题点（放大前提 × 模块机器键）
- **独占 ENI 节点池不支持 NetworkPolicy**：性能模式=策略盲区（官方明示）→ `cni-stack-capability`、`network-policy-coverage`
- Egress NetworkPolicy 无法约束到 hostNetwork Pod/节点 IP（官方限制）：hostNetwork 旁路实锤 → `multus-sriov-rdma-bypass`（同类旁路族）
- 安全组与 NetworkPolicy 双控制面：Trunk ENI 的 Pod 安全组配置漂移即跨域 → `cni-aware-reachability-graph`
- eBPF conntrack LRU 淘汰：长连接记录被逐出可被利用做状态绕过 → `network-policy-coverage`

## 横向思路
- 识别 Terway 模式（terway-eni vs terway-eniip DaemonSet 名）→ 独占 ENI 池做策略盲区横移 → Pod 安全组错配直达管理网段 → ECS 元数据取 RAM 角色 → OSS/CPFS 权重面

---
## 万卡证据（2026-10-25 重收批注）
- ❌ 未达 ≥10k 口径：无 ≥10k 披露：CNI 插件语义文档
## 网络要素
- isolation、multi-tenancy
- 分类迁移：corpus 扁平目录 → corpus/official-cn（中文官方源）
