# Alibaba HPN — 阿里 LLM 训练双平面数据中心网络

- 分类：自建与超大规模训练组网
- 组织 / 系统：Alibaba / HPN（SIGCOMM 2024）
- 核验日期：2026-10-25；核验状态：verified（websearch 命中论文 PDF 与 ACM DOI）

## 来源
- https://dl.acm.org/doi/10.1145/3651890.3672265
- https://ennanzhai.github.io/pub/sigcomm24-hpn.pdf

## 架构要素
- 组网：2 层双平面 Clos 取代传统 3 层；单 Pod 互联 15K GPU；每 GPU 2×200Gbps 双 ToR；rail-optimized，同 rail 对可达性最强
- 隔离边界：物理平面/Tier1 Segment（1K GPU）划分；论文目标为可靠性与收敛，未定义租户级网络隔离
- 身份：无网络层身份（训练集群内部显式互信）
- 存储：不在本文范围（另有磐久/CPFS 体系）
- 通信：以太网 + NCCL 类集合通信，双平面按流分担（halving 单平面哈希碰撞）
- 管理面：数据中心网络统一管控（论文未展开权限模型）
- 多租户：多训练任务共享 Pod，隔离依赖调度器而非网络
- 云集成点：同构技术下沉至阿里云 HPN 云产品（磐久/智算集群）

## 安全问题点（放大前提 × 模块机器键）
- 平网/集合通信无认证：15K GPU 全互通，任何接入 backend 网的主机可尝试入组 → `fabric-topology-isolation`、`nccl-collective-join`
- 隔离边界=物理拓扑而非身份：跨 rail/跨 Segment 攻击面取决于 ToR 表项而非策略 → `cni-aware-reachability-graph`
- rail 对齐可被侦察推演：拓扑信息（rail/slot）即攻击地图 → `collective-communication-surface`

## 横向思路
- 拿到任一训练节点 → 探测双平面两个 200G 接口 → 定位同 rail 邻居 → NCCL 入组注入梯度，或对 ToR 上联做低速率扰动（PFC/ECN 层面）放大训练抖动
