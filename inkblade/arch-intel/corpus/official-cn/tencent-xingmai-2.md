# 腾讯星脉网络 2.0 — 单集群 10 万卡自研高性能计算网络

- 分类：official-cn（中文官方源）
- 组织 / 系统：Tencent / 星脉网络 2.0（含 TiTa2.0、TCCL2.0）
- 源类型：engineering-blog（腾讯云开发者社区官方发布文）
- 核验日期：2026-10-25；核验状态：verified（webfetch cloud.tencent.com 官方发布文，原句摘录）

## 来源
- https://cloud.tencent.com/developer/article/2433459
- https://cloud.tencent.com/developer/news/1116208（2023-06 首次披露）

## 万卡证据（原文摘录）
- ✅ “星脉网络2.0可支撑的整体组网规模实现翻倍，支持单集群10万卡GPU以上的规模。”
- ✅ “万卡级训练故障卡顿、慢节点的定位时间从天级降低至分钟级。”

## 网络要素
- congestion-control：TiTa2.0 主动拥塞控制（部署位置从交换机移到网卡）
- ops-fault-surface：故障定位分钟级、拥堵智能调度快速自愈
- multi-plane：星脉多轨道架构（另见同站解读文 2585074）

## 架构要素
- 组网：自研交换机 25.6T→51.2T、自研硅光模块 200G→400G、自研算力网卡、整机通信带宽 3.2T
- 隔离边界：集群边界即通信域边界
- 通信：TCCL2.0 NVLINK+NET 异构并行通信库；通信效率 +60%、训练效率 +20%
- 管理面：TiTa 拥塞治理 + 智能运维（自愈）
- 云集成点：腾讯云 GPU 云服务器搭载

## 安全问题点（放大前提 × 模块机器键）
- 拥塞控制在网卡（端侧）：端侧 CC 状态可被恶意发送速率扰动 → `collective-communication-surface`（性能攻击面）
- TCCL 通信库无网络层认证：入组面同 NCCL → `nccl-collective-join`
- 分钟级故障定位=深度可观测面暴露 → `observability-exposure`

## 横向思路
- 打入 backend 网段 → 伪造慢节点/抖动源触发“自愈”误摘除 → 调度面投毒（`scheduler-network-semantics`）→ fabric 面预留
