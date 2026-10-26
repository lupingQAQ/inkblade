# xAI Colossus 二代 — 550K GB200/GB300 与 2 GW 扩张

- 分类：paper（论文/第三方分析源）
- 组织 / 系统：xAI（SpaceXAI）/ Colossus 1 → Colossus 2（Memphis, TN）
- 核验日期：2026-10-25；核验状态：verified（websearch+webfetch：introl 2026-01 扩张实录 + Spectrum-X 官方页交叉；
  x.ai 主站在本实验网络拒连（与既有 xai-colossus 条目同缺口），官方页直读待复验）

## 来源
- https://introl.com/blog/xai-colossus-2-gigawatt-expansion-555k-gpus-january-2026
- https://newsletter.semianalysis.com/p/xais-colossus-2-first-gigawatt-datacenter
- 官方（本网络不可达，记录缺口）：https://x.ai/colossus

## 万卡证据（原文摘录）
- ✅ "~2 GW total capacity with 555,000+ NVIDIA GPUs"
- ✅ "Colossus 2: Operational at ~1 GW with 550,000 GB200s/GB300s"

## 网络要素
- multi-plane

## 架构要素
- Colossus 1：19 天建成；100K→200K H100（92 天翻倍）；~500MW、230K GPU（含 30K GB200）
- Colossus 2：2025-07 首批 550K GB200/GB300 上线（~1GW）；2025-12-30 购第三栋 → 全站 ~2GW、
  已购 555K+ NVIDIA GPU（约 $18B）；目标 100 万+ GPU
- NVIDIA 官方口径：Spectrum-X 以太网加速「xAI 建造的世界最大 AI 超算」（UEC 前最大规模 RoCE 自适应路由部署）
- 机架以 GB200 NVL72 为单位（~7700+ 计算机架满配）

## 安全问题点（放大前提 × 模块机器键）
- 单以太 fabric 承载 55 万 GPU：Spectrum-X 控制面（自适应路由/多平面）单点 → `rail-mismatch-forcing`
- 超大规模 NCCL 通信域初始化与弹性扩缩：rendezvous 端口面按作业无上限即耗尽 → `nccl-port-exhaustion`
- 工程速度优先（19 天/92 天）：变更与配置面暴露概率放大 → `roce-pfc-storm`

## 横向思路
- 「世界最大单 fabric」= 世界最大单点控制面：端口/IO/配额三耗尽即可打停 frontier 训练
