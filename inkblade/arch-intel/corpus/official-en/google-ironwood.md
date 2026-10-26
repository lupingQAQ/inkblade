# Google — Ironwood TPU（第 7 代，9,216 芯片 Superpod）

- 分类：official-en（外文官方源）
- 组织 / 系统：Google / Ironwood TPU v7（inference 世代）
- 源类型：engineering-blog（blog.google，2025-11-25）
- 核验日期：2026-10-25；核验状态：verified（webfetch blog.google 官方博文直读，原句摘录；注：cloud.google.com 在本实验网络拒连（既有矩阵已记录），故取 blog.google 域）

## 来源
- https://blog.google/innovation-and-ai/infrastructure-and-cloud/google-cloud/ironwood-google-tpu-things-to-know/

## 万卡证据（原文摘录）
- ❌ 未达 ≥10k（9,216<10,000，如实标注）："With Ironwood, we can scale up to 9,216 chips in a superpod."
- ✅ 关键带宽数据："These chips are linked via a breakthrough Inter-Chip Interconnect (ICI) network operating at 9.6 Tb/s."

## 网络要素
- ICI 芯片间互联 9.6 Tb/s；9,216 芯片单域直连（1.77 PB 共享 HBM）

## 架构要素
- 组网：superpod 单域；ICI 高带宽低时延
- 定位：推理/thinking 模型世代；4x per-chip 性能提升

## 安全问题点（放大前提 × 模块机器键）
- 单域 9,216 芯片共享 HBM 语义：ICI 可达即大域内存邻接 → `fabric-topology-isolation`（类比 ComputeDomain）
- superpod 编排凭据=拓扑分配权 → `cloud-role-overprivilege`

## 横向思路
- ICI 域边界探测（类比 IMEX/NVLink domain）→ 跨 pod 段注入；OCS 相关见 corpus/paper/google-tpu-oci.md
