# llm-d + NIXL — 分离式推理栈与 KV 传输库

- 分类：网络架构专源（分离式推理/KV 传输）
- 组织 / 系统：llm-d（CNCF sandbox；Red Hat/Google/IBM/CoreWeave/NVIDIA 联创）+ NVIDIA NIXL
- 核验日期：2026-10-25；核验状态：verified（两 README 全文）

## 来源
- https://raw.githubusercontent.com/llm-d/llm-d/main/README.md
- https://raw.githubusercontent.com/ai-dynamo/nixl/main/README.md

## 架构要素
- 组网：预填充/解码分离 + 宽专家并行；多后端传输（NIXL 插件：UCX、GDS、对象存储、Mooncake、UCCL）
- 隔离边界：路由/调度层（多租户流控）；传输层无内建租户隔离描述
- 身份：组件间（etcd 协调 NIXL_ETCD_*）无强认证语义公开
- 存储：KV 分层卸载（CPU/盘/对象）
- 通信：P2P 传输（GPUDirect/verbs）；UCX 1.23.x + GDRCopy
- 管理面：llm-d operator/inference-scheduler
- 多租户：SLO 感知自动伸缩 + 多租户流控（README 明示）
- 云集成点：B200/MI300X/H200/TPU/Intel XPU 多硬件

## 安全问题点（放大前提 × 模块机器键）
- **KV 通道（NIXL over RDMA）无认证描述**：可达即可注入/篡改 KV → `inference-gateway-pd`、`collective-communication-surface`
- etcd 协调元数据：未认证 etcd=拓扑与端点全泄露 → `dns-service-discovery`
- 分层 KV 卸载：KV 落盘/对象存储的残留读取 → `training-data-leak`

## 横向思路
- 发现 NIXL/etcd 端点 → 注册伪节点接管 KV 流 → 篡改预填充→解码 KV（操纵输出/泄露上下文）

---
## 万卡证据（2026-10-25 重收批注）
- ❌ 未达 ≥10k 口径：无 ≥10k 披露：llm-d/NIXL 仓
## 网络要素
- multi-tenancy
- 分类迁移：corpus 扁平目录 → corpus/official-en（外文官方源）
