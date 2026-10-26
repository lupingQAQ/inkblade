# Microsoft — Infinite Scale: The Architecture Behind the Azure AI Superfactory

- 分类：official-en（外文官方源）
- 组织 / 系统：Microsoft Azure / Fairwater AI 超工厂（Atlanta/Wisconsin）
- 源类型：engineering-blog（blogs.microsoft.com，2025-11-12，Scott Guthrie）
- 核验日期：2026-10-25；核验状态：verified（webfetch 官方博文全文直读，原句摘录）

## 来源
- https://blogs.microsoft.com/blog/2025/11/12/infinite-scale-the-architecture-behind-the-azure-ai-superfactory/

## 万卡证据（原文摘录）
- ✅ "Fairwater...uses a single flat network that can integrate hundreds of thousands of the latest NVIDIA GB200 and GB300 GPUs into a massive supercomputer."
- ✅ "an advanced network architecture that can scale reliably beyond traditional Clos network limits with current-gen switches (hundreds of thousands of GPUs on a single flat network)."

## 网络要素
- flat network / 超越传统 Clos 限制；two-tier ethernet-based backend network，800 Gbps GPU-to-GPU
- congestion-control："Improvements across packet trimming, packet spray and high-frequency telemetry...deliver advanced congestion control, rapid detection and retransmission and agile load balancing"（原句）
- SONiC："Relying on a broad ethernet ecosystem and SONiC (Software for Open Networking in the Cloud – which is our own operating system for our network switches)"
- 光 WAN："we have built a dedicated AI WAN optical network...delivered over 120,000 new fiber miles across the US"

## 架构要素
- 组网：单平网两级以太 backend + AI WAN 光骨干跨站直达；三层结构（NVLink 机架 → pod → 跨站 WAN）
- 多代超算互联成"superfactory"；fungibility（训推混合调度）
- 隔离边界：流量按需分段（scale-up/scale-out/跨站）

## 安全问题点（放大前提 × 模块机器键）
- “单平网”=无层级隔离红利：任意 GPU 间可达性按设计全通 → `fabric-topology-isolation`、`cni-aware-reachability-graph`
- AI WAN 跨站直达=跨站横向通道（容器逃逸后跨 DC 平移）→ `hybrid-cloud-egress-pivot`
- SONiC 交换机 OS 开放生态=交换机控制面供应链面 → `gpu-network-operator-posture`

## 横向思路
- 站内平网入组（NCCL/集合通信）→ 跨站 WAN 段探测 → 对端站点算力/存储面；与 gen-26 fabric 面模块（平网可达性图）直接对接
