# Google TPU v7 Ironwood — 9216 片 superpod 与 OCS 光交换拓扑

- 分类：paper（论文/第三方分析源）
- 组织 / 系统：Google / TPU v7 Ironwood（3D torus + OCS）
- 核验日期：2026-10-25；核验状态：verified（websearch+webfetch：introl 架构指南与检索快照；
  cloud.google.com / docs.cloud.google.com 在本实验网络超时（与矩阵 GCP 条目既有缺口一致），官方页直读待复验）

## 来源
- https://introl.com/blog/google-tpu-architecture-complete-guide-7-generations（2025-12-01，7 代全表）
- https://newsletter.semianalysis.com/p/tpuv7-google-takes-a-swing-at-the（2025-11-28）
- 官方（本网络不可达，记录缺口）：https://cloud.google.com/blog/products/compute/inside-the-ironwood-tpu-codesigned-ai-stack

## 万卡证据（原文摘录）
- ✅ "9,216-chip superpods delivering 42.5 exaflops of compute power"
- ✅ "deploy over one million Ironwood chips beginning in 2026"

## 网络要素
- optical-switching

## 架构要素
- Ironwood（TPU v7，2025）：原生 FP8 4.6 PFLOPS/片（192GB HBM3e、7.4TB/s、600W）
- ICI：4 链路 9.6 Tbps 聚合双向（1.2 TB/s/片）；3D torus；pod 256 片 → **superpod 9216 片（42.5 FP8 EFLOPS）**
- OCS：MEMS 镜阵重配光路（亚 10ns 重配），物理/逻辑拓扑解耦；故障片光旁路维持 torus
- v5p 先例：48 OCS / 13824 光口 wiring 8960 片（4 Pbps 光交换矩阵）；Jupiter 可理论聚合约 43 个 superpod（≈40 万片）
- Anthropic 承诺 2026 起部署 100 万+ Ironwood 片训练 Claude

## 安全问题点（放大前提 × 模块机器键）
- OCS/fabric manager 是拓扑单点：重配 API 可达即拓扑武器化（切片内 locality/旁路可被改写）→ `rail-mismatch-forcing`
- 9216 片同步域：单慢片拖累全 pod（无 straggler 隔离时）→ `nccl-straggler-injection`
- 超大 KV/激活（192GB HBM）承接长上下文：预留面无上限即 OOM 炸弹 → `kv-oom-bomb`

## 横向思路
- 拓扑管理面（OCS/ICI 表）无鉴权 → 拓扑错配 + 慢 rank 叠加 → pod 级 goodput 崩塌
