# The Llama 3 Herd of Models — Meta 万卡双集群训练（论文）

- 分类：paper（论文/技术报告）
- 组织 / 系统：Meta AI / Llama 3（405B）
- 源类型：paper（arXiv 2407.21783）
- 核验日期：2026-10-25；核验状态：verified（webfetch arXiv 摘要页直读；集群规模与网络细节以 Meta 官方博文同系统口径交叉佐证）

## 来源
- https://arxiv.org/abs/2407.21783
- https://engineering.fb.com/2024/03/12/data-center-engineering/building-metas-genai-infrastructure/（同系统官方口径）

## 万卡证据（原文摘录）
- ✅ 官方同系统口径（Llama 3 训练集群）："two versions of our 24,576-GPU data center scale cluster at Meta...We use this cluster design for Llama 3 training."（Meta Engineering 原句）
- ✅ 论文口径（Meta 官方博文引用）：训练中断率“drive the interruption rate down by ~50x (based on normalized interruption/reliability metrics)”（引自 arXiv 2407.21783）

## 网络要素
- RoCE 与 InfiniBand 双 fabric 24k 集群（400G endpoints，见官方博文条目）
- ops-fault-surface：硬件中断/训练稳定性 50x 改进；checkpoint 数千 rank 毫秒级

## 架构要素
- 通信：大规模并行（PP/TP/EP/DP）+ 400G 集合通信
- 存储：Tectonic + Hammerspace 双轨 checkpoint

## 安全问题点（放大前提 × 模块机器键）
- 双 fabric 训练=攻击者双通道选择 → `fabric-topology-isolation`
- 中断率数据=故障注入效果基线（攻击者以极低速率即可超越正常故障率）→ `scheduler-network-semantics`

## 横向思路
- 以 50x 中断率基线量化“低速率扰动”攻击价值；双 fabric 环境做对照实验（IB vs RoCE 旁路差异）
