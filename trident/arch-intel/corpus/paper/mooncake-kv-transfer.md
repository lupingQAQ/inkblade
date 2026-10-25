# Mooncake — KVCache 为中心的分离式 LLM 服务

- 分类：自建与超大规模训练组网（推理服务架构）
- 组织 / 系统：Moonshot AI（月之暗面）/ Mooncake（arXiv 2407.00079，FAST'25 方向）
- 核验日期：2026-10-25；核验状态：verified（arXiv 摘要页）

## 来源
- https://arxiv.org/abs/2407.00079

## 架构要素
- 组网：预填充集群 + 解码集群 + 分离式 KVCache 池（复用集群 CPU/DRAM/SSD）；传输引擎走 RDMA
- 隔离边界：KV 池为全局共享资源，按请求调度分配
- 身份：调度器/元数据服务管理，未见 KV 块级租户标记的公开描述
- 存储：KVCache 多级存储（DRAM/SSD）即服务存储面
- 通信：KV 传输引擎（RDMA）+ 预测式早拒绝（过载控制）
- 管理面：KVCache 中心调度器 + 集群管理器
- 多租户：多请求共享 KV 池（前缀复用提升吞吐）
- 云集成点：无（自建，Kimi 平台）

## 安全问题点（放大前提 × 模块机器键）
- 共享 KV/前缀缓存跨请求残留：提示词/前缀可被跨用户推断或污染 → `training-data-leak`、`inference-gateway-pd`
- KV 传输通道无认证公开描述：可达即可读/写 KV → `collective-communication-surface`
- 全局调度器=单点控制面：调度操纵可定向影响租户 SLO → `scheduler-network-semantics`

## 横向思路
- 推理面立足 → 命中 KV 池端点 → 读取他人 KV（会话泄露）或注入污染 KV（操纵后续生成）→ 顺带元数据服务横向

---
## 万卡证据（2026-10-25 重收批注）
- ❌ 未达 ≥10k 口径：无 ≥10k 披露：面向 KV 传输架构，未公开集群规模
## 网络要素
- （本源为控制面/组件语义类，不直接承载 8 项 fabric 要素）
- 分类迁移：corpus 扁平目录 → corpus/paper（论文/技术报告）
