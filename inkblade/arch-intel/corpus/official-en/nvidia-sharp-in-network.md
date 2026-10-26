# NVIDIA SHARP 在网计算（v1–v4）— all-reduce 卸载到交换机

- 分类：official-en（外文官方源）
- 组织 / 系统：NVIDIA / SHARP（Scalable Hierarchical Aggregation and Reduction Protocol）
- 核验日期：2026-10-25；核验状态：verified（NVIDIA 开发者博客直读）

## 来源
- https://developer.nvidia.com/blog/advancing-performance-with-nvidia-sharp-in-network-computing/

## 万卡证据（原文摘录）
- ➖（本源为规范/漏洞/机制证据，非万卡规模实证；wanka_evidence=false）

## 网络要素
- in-network-computing / multi-tenancy

## 架构要素
- SHARP 把 all-reduce/reduce/broadcast 卸载到 IB 交换机 ASIC 内完成：传输量减半、消除服务器抖动
- v1（EDR 100G，MPI 小消息，AllReduce 5×/Barrier 9×）；v2（HDR Quantum，AI 大消息，
  单工作负载，AllReduce 带宽 2×、BERT 训练 +17%）
- **v3（Quantum-2 NDR）：多租户在网计算——多个 AI 工作负载并行共享 SHARP**；
  Azure 报告 AllReduce 时延近一个数量级收益
- v4（Quantum-X800 XDR）：新算法覆盖更广 AI 集合通信
- 与 NCCL 深度集成（user buffer registration）；某大型服务商以 SHARP 提升 10–20% AI 工作负载

## 安全问题点（放大前提 × 模块机器键）
- 多租户在网聚合 = 集合通信信任域被交换机会话层接管：会话入组/贡献面无鉴权即梯度篡改 → `sharp-in-network-poison`
- 梯度在网聚合是单点：篡改一次 reduce 即污染全局梯度且无告警 → `training-silent-corruption`
- 会话建立与 NCCL bootstrap 绑定：端口/rendezvous 面即会话面 → `nccl-port-exhaustion`

## 横向思路
- 入组 → 篡改 reduce → loss 静默发散：训练无效但监控全绿（`fabric-silent-corruption-chain`）
