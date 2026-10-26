# xAI Colossus — 十万卡级以太网超算

- 分类：自建与超大规模训练组网
- 组织 / 系统：xAI / Colossus（一期 H100，二期 Blackwell）
- 核验日期：2026-10-25；核验状态：**verified-partial**（主站 x.ai 在实验网络不可达；经 Bing 检索快照与头条/百科条目交叉佐证：122 天建成、100K→200K H100、约 200MW；Colossus 2 于 2026-01 宣布投运、GW 级；本条不计入门槛统计，缺口已显式记录）

## 来源
- https://x.ai/news/colossus（主源，未能直连）
- https://www.toutiao.com/article/7596640714268672552/（Colossus 2 拆解报道，检索快照佐证）

## 架构要素（依公开报道口径）
- 组网：Supermicro 液冷机柜 + 以太网 RoCE（NVIDIA Spectrum-X 系公开报道）；rail-optimized 大规模以太 fabric
- 隔离边界：单一租户（xAI 自用）超级集群——隔离诉求弱是此类集群的共同特征
- 身份：内部体系（未公开）
- 存储：并行文件系统 + 对象存储（公开报道口径）
- 通信：RoCE/NCCL
- 管理面：未公开（推测 Slurm/K8s 混合）
- 多租户：无外部多租户
- 云集成点：无（自建电站+集群）

## 安全问题点（放大前提 × 模块机器键）
- 单租户巨网=内部零横向阻力：任何立足点可触及全集群管理面 → `framework-port-matching`、`ray-control-plane`
- 以太 RoCE 共用语义：SR-IOV/RDMA 旁路 NetworkPolicy 风险同云侧 → `multus-sriov-rdma-bypass`

## 横向思路
- 供应链/边车服务（监控/存储 UI）立足 → 管理面未鉴权端点 → 权重与 checkpoint 面

---
## 万卡证据（2026-10-25 重收批注）
- ✅ 达标：x.ai/colossus 官方页（本网络拒连，检索快照佐证）：Then we doubled it in 92 days to 200k GPUs — 200,000 H100 GPUs in a single interconnected cluster
## 网络要素
- （本源为控制面/组件语义类，不直接承载 8 项 fabric 要素）
- 分类迁移：corpus 扁平目录 → corpus/official-en（外文官方源）
