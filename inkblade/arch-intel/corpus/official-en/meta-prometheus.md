# Meta Prometheus — 吉瓦级超集群（2026-10-19 工程实录）

- 分类：official-en（外文官方源）
- 组织 / 系统：Meta / Prometheus（New Albany, Ohio；训练 Muse 前沿模型）
- 核验日期：2026-10-25；核验状态：verified（Meta engineering 官方博客直读，2026-10-19）

## 来源
- https://engineering.fb.com/2026/10/19/data-center-engineering/inside-prometheus-meta-gigawatt-scale-supercluster/
- https://engineering.fb.com/2026/02/09/data-center-engineering/building-prometheus-how-backend-aggregation-enables-gigawatt-scale-ai-clusters/

## 万卡证据（原文摘录）
- ✅ "hundreds of thousands of GPUs across multiple interconnected buildings"
- ✅ "At full scale, Prometheus will comprise roughly 1 million distributed GPUs"

## 网络要素
- multi-plane / congestion-control / ops-fault-surface

## 架构要素
- 规模：数十万 GPU、多楼栋锁步运行；满配约 100 万 GPU；首期已训 Muse Wonder（85%+ 预训 goodput、90%+ RL goodput、MTBI 47k→54k+ GPU 时）
- 硬件谱系：Catalina（GB200 NVL72 Ariel，2×CX-7 400G=800G/GPU）→ Clemente（GB300 NVL72 单 rack，CX-8 原生 800G）→ San Miguel（Vera Rubin NVL72，216TB/s NVLink）
- 楼栋 fabric：每楼至多 **20736 GPU**；DSF（Disaggregated Scheduled Fabric，子包级多路径+VOQ+信用流控）→ NSF（Non-Scheduled Fabric，51.2T 浅缓冲交换机 Minipack3/Minipack3N + DLB/自适应路由 + FBOSS）
- 跨楼：BAG（Backend Aggregation）hub-spoke 多层，Arista 7800 + Jericho3 深缓冲，2km–100km+，800G-ZR 相干光
- 可靠性：NVL72=9× 故障域（72 GPU rack 为分配单元，64 活跃+8 备件，523 rack 供 32768 活跃 GPU）；
  PAFT（并行感知容错）+ 分布式 delta checkpoint（多层存储、内存暂存）；
  中断率一年内降 99%（目标 2 次/8K GPU/天）；Dynamo Dimmer 全集群功率平滑

## 安全问题点（放大前提 × 模块机器键）
- 楼栋 fabric 控制器（DSF/NSF/FBOSS）单点：路由/调度配置可写即楼栋级停摆 → `roce-pfc-storm`、`rail-mismatch-forcing`
- checkpoint 依赖多层共享存储：I/O 面无限速即风暴 → `checkpoint-io-storm`
- NVL72 大故障域：健康/Xid 写面 = 整 rack 训练中断 → `driver-reset-trigger`
- 百 k GPU 控制面（固件 100k GPU 数小时下发）：apiserver/下发通道配额缺失即集群级 DoS → `api-server-flood-surface`

## 横向思路
- 单楼 fabric 控制面 → BAG 放大到全集群：I/O 洪与请求洪叠加耗尽共享控制面（`fabric-exhaustion-chain`）
