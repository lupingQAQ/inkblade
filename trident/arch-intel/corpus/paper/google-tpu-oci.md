# Google TPU v4 — 光交换可重构超算

- 分类：自建与超大规模训练组网
- 组织 / 系统：Google / TPU v4（ISCA 2023，arXiv 2304.01433）
- 核验日期：2026-10-25；核验状态：verified（arXiv API 检索命中）

## 来源
- https://arxiv.org/abs/2304.01433

## 架构要素
- 组网：4096 芯片 Pod；OCS（光路交换）动态重构 ICI 拓扑，可选扭曲 3D torus；DCN 走数据中心网
- 隔离边界：slice 划分 + OCS 重构实现物理级重配；论文将 security 列为 OCS 动态重构收益（重构即改变可达集合）
- 身份：编排系统（Borg/Jupiter 体系）持有切片权
- 存储：GCS/Colossus 体系（云侧条目另述）
- 通信：ICI（芯片间）+ DCN（数据中心）；比 IB 便宜/省电（<5% 成本、<3% 功耗）
- 管理面：集中编排，拓扑随负载重构
- 多租户：切片级共享（pod 内多 slice）
- 云集成点：GCP TPU 服务（见 gcp 条目）

## 安全问题点（放大前提 × 模块机器键）
- 拓扑即隔离：安全边界依赖编排正确性——编排凭据泄露=拓扑重配横向 → `rbac-mapping`、`cloud-role-overprivilege`
- slice 间共享 fabric：可达性需按 slice 推演 → `cni-aware-reachability-graph`（跨集群/slice 维度）
- OCS 控制面：重构通道被扰动=链路 DoS/拓扑欺骗 → `fabric-topology-isolation`

## 横向思路
- 云凭据（WIF/元数据）→ TPU 控制面 → 创建相邻 slice/查询拓扑 → 定位目标作业 slice → 数据面相邻性利用
