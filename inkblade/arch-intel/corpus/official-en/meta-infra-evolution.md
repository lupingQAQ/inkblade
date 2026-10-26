# Meta Engineering — Infrastructure Evolution and the Advent of AI（129k 集群/Prometheus/Hyperion）

- 分类：official-en（外文官方源）
- 组织 / 系统：Meta Engineering / 129k H100 集群、Prometheus（1GW）、Hyperion（5GW）
- 源类型：engineering-blog（engineering.fb.com，2025-09-29）
- 核验日期：2026-10-25；核验状态：verified（webfetch 官方博文全文直读，原句摘录）

## 来源
- https://engineering.fb.com/2025/09/29/data-infrastructure/metas-infrastructure-evolution-and-the-advent-of-ai/

## 万卡证据（原文摘录）
- ✅ "This led to us to build two clusters of 24k H100s each in late 2023, one using Infiniband and the other using RoCE."
- ✅ "By emptying out five production data centers we were able to build a single AI cluster with 129k H100 GPUs – all in a matter of months!"
- ✅ "Our next AI cluster, Prometheus, will be a 1-gigawatt cluster spanning across multiple data center buildings." / "Hyperion...5 gigawatts"（2028 起）

## 网络要素
- 光互联：silicon photonics "the only viable path to increasing shoreline beyond 3.2T"（原句）
- 长距离训练：Twine + MAST 支撑跨地理 DC 训练；AI 任务中断率降 ~50x（引 Llama 3 论文口径）
- open standards：scale-up/scale-out 网络标准化诉求（多厂商混布）

## 架构要素
- 组网：129k 单集群（清空五栋生产 DC）；GB200 Catalina 机架（72 GPU/NVLink 1.8TB）+ AALC 液冷
- 演进叙事：4k 集群（2020）→ 24k×2（2023）→ 129k（2024）→ 1GW/5GW（2026-2028）
- 多代硬件共存（AMD/MI300、NVIDIA、自研 MTIA）

## 安全问题点（放大前提 × 模块机器键）
- 跨栋/跨 DC 训练网络（长距 fabric）=平网边界外扩 → `hybrid-cloud-egress-pivot`（DC 间回旋）
- 异构硬件混布抽象层=供应链+凭据聚合面 → `trust-remote-code-supply-chain`
- 129k 单域故障域超大：自愈/调度自动化被劫持影响面巨大 → `scheduler-network-semantics`

## 横向思路
- 多 DC 骨干可达性探测 → 跨栋任务 rank 关联 → 远端 fabric 段入组（新攻击面：跨 DC NCCL）
