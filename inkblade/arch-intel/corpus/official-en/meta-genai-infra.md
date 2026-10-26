# Meta Engineering — Building Meta's GenAI Infrastructure（24k×2 集群）

- 分类：official-en（外文官方源）
- 组织 / 系统：Meta Engineering / GenAI Infrastructure（Llama 3 训练集群）
- 源类型：engineering-blog（engineering.fb.com）
- 核验日期：2026-10-25；核验状态：verified（webfetch 官方博文全文直读，原句摘录）

## 来源
- https://engineering.fb.com/2024/03/12/data-center-engineering/building-metas-genai-infrastructure/

## 万卡证据（原文摘录）
- ✅ "Today, we're sharing details on two versions of our 24,576-GPU data center scale cluster at Meta."
- ✅ "By the end of 2024, we're aiming to continue to grow our infrastructure build-out that will include 350,000 NVIDIA H100 GPUs as part of a portfolio that will feature compute power equivalent to nearly 600,000 H100s."

## 网络要素
- RoCE（Arista 7800 + Wedge400/Minipack2）与 Quantum2 InfiniBand 双集群对照："one cluster with a remote direct memory access (RDMA) over converged Ethernet (RoCE) network fabric...The other cluster features an NVIDIA Quantum2 InfiniBand fabric. Both of these solutions interconnect 400 Gbps endpoints."（原句）
- ops-fault-surface：desync debug / distributed collective flight recorder；拓扑感知调度 + NCCL 路由协同
- 存储双轨：Tectonic(FUSE) + Hammerspace(NFS)，checkpointing 数千 rank

## 架构要素
- 组网：RoCE 与 IB 两套 24,576 GPU 集群并行评估；Grand Teton + OpenRack
- 隔离边界：训练 backend 与通用 DC 网分离（见 RoCE 博文条目）
- 通信：AllGather 优化后 90%+ 利用率；FP8；PyTorch 进程组初始化 hours→minutes
- 管理面：拓扑感知内部调度器

## 安全问题点（放大前提 × 模块机器键）
- 双 fabric（RoCE+IB）并存=两套旁路面都要测 → `fabric-topology-isolation`、`cni-aware-reachability-graph`
- 集合通信 flight recorder=高价值观测面 → `observability-exposure`
- Tectonic/Hammerspace 双存储通道=权重面双路径 → `shared-volume-weight-copy`

## 横向思路
- 混合 fabric 环境识别（IB 子网 vs RoCE VTEP 指纹）→ 对应面入组；checkpoint 通道旁听
