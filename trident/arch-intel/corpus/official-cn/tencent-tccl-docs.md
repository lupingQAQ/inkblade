# 腾讯云 TCCL — 星脉架构定制集合通信库（官方文档）

- 分类：official-cn（中文官方源）
- 组织 / 系统：Tencent Cloud / TCCL（TACO Kit TACO Train 组件）
- 源类型：vendor-docs（腾讯云官方文档中心）
- 核验日期：2026-10-25；核验状态：verified（webfetch 官方文档（product/560/61564 → 301 至 product/1573/74385），原句摘录）

## 来源
- https://cloud.tencent.com/document/product/1573/74385
- https://cloud.tencent.com/document/product/560/61564（入口跳转）

## 万卡证据（原文摘录）
- ❌ 无 ≥10k 直接口径：TCCL 文档为组件语义（万卡级由星脉网络条目承载）

## 网络要素
- ops-fault-surface：“具备网络故障快速感知与自愈的智能运维能力”（原句）

## 架构要素
- 通信：TCCL（Tencent Collective Communication Library）针对星脉网络硬件架构定制；与 AngelPTM/HARP/LightCC/TTF 组成 TACO Train 训推加速链
- 管理面：故障快速感知与自愈属库内能力（端网协同）

## 安全问题点（放大前提 × 模块机器键）
- 集合通信库替换/伪造：TCCL 与 NCCL 同构暴露面 → `nccl-collective-join`、`collective-communication-surface`
- 故障自愈依赖端侧探测：伪造故障信号可触发摘除 → `scheduler-network-semantics`

## 横向思路
- 探测 TACO/TCCL 端口与版本 → 与星脉 fabric 条目联动做入组/扰动链
