# 长上下文与大规模训练专项（LONG-CONTEXT）

本文件是 InkBlade 在**长上下文推理（128K–1M）**与**大规模训练（千卡–万卡）**两个面上的威胁模型、
模块↔链映射与检测口径说明。配套代码：

- 仿真靶场：`lab/longctx_sim.py`（OpenAI 兼容，仅 127.0.0.1，真实 HTTP）
- 模块：`inkblade/modules/` 下 8 个专项模块（`long-context-*` / `prefix-cache-*` / `kv-cache-*` /
  `prefill-decode-*` / `checkpoint-shard-*` / `context-limit-*`）
- 攻击链：`inkblade/chains/long-context-cache-leak.json`、`inkblade/chains/pd-kv-poison.json`
- 规则：`suricata-longctx-kv-endpoints`（长上下文/KV/分片/指标端点异常访问）
- 实效验证：`inkblade/verify-effects.py` 中 `longctx-*` 四项（见 `docs/EFFECT-VERIFICATION.md`）

**边界声明**：本文与仿真器描述的是**控制面/数据面语义同构的实验室仿真实效**，
不是真实 GPU 推理或真实万卡集群实测；真实拓扑结论必须来自客户集群的只读快照与网络事实采集。

---

## 1. 大规模训练威胁模型

### 1.1 并行维度与攻击面

| 维度 | 切分对象 | 通信形态 | 主要攻击面 | 关联模块 |
|---|---|---|---|---|
| **DP**（Data Parallel） | batch | 梯度 all-reduce | 梯度注入、rank 冒充 | `nccl-collective-join`、`areal-awex-nccl-injection` |
| **TP**（Tensor Parallel） | 单层权重/激活 | 每层 all-reduce/all-gather（高频、低延迟） | 节点内 NVLink 域被同宿租户共享；TP rank 入组 | `collective-communication-surface`、`long-context-training-collective-surface` |
| **PP**（Pipeline Parallel） | 层段 | 阶段间 activation send/recv | 流水线气泡侧的 activation 窃听/篡改；PP 端点枚举 | `long-context-training-collective-surface` |
| **EP**（Expert Parallel） | MoE 专家 | all-to-all（DeepEP/NVSHMEM） | all-to-all 端口面、专家路由投毒、跨节点 GPU 内存写 | `long-context-training-collective-surface`、`imex-computedomain-gpu-memory-crossing` |
| **CP**（Context Parallel） | 序列维 | ring attention / all-gather KV | 长序列分片边界的 KV 泄露、ring 环入组 | `long-context-training-collective-surface`、`long-context-window-exhaustion` |
| **SP**（Sequence Parallel） | LayerNorm/Dropout 序列段 | 与 TP 复合的 reduce-scatter/all-gather | 与 TP 共享通信域，边界难分辨 | `long-context-training-collective-surface` |

**关键判断**：并行维度本身不是漏洞；漏洞来自「通信域 = 信任域」的默认假设。
当 rendezvous/TCPStore/KV 通道在 Pod 网络可达且无 mTLS 时，任意同网主体可尝试 join / 读 / 写，
而并行度（TP/PP/EP/CP/SP）与端口恰好是入组所需的第一手情报。

### 1.2 ring attention 与层级 all-reduce

- **ring attention（CP）**：序列按 CP 度切分，KV 块沿 ring 逐跳传递。攻击者只需加入 ring
  （或伪造 ring 邻接）即可读取相邻 rank 的 KV 分片；CP 度越大，单跳数据量与可枚举的环结构越多。
- **层级 all-reduce**：节点内 NVLink/NVSwitch 全连接 + 节点间 rail-optimized RDMA。
  层级边界（node/rail/pod）决定集合通信的可见范围；`world_size`、`collective_ports`、
  `nccl_bootstrap_port` 一旦暴露，攻击者可推断层级结构并选择「最小代价入组路径」。
- **可观测性反噬**：训练平台为排障开放的 `/metrics`（NCCL 计数器、并行度、端口）在未鉴权时
  就是拓扑测绘面。本专项的 `long-context-training-collective-surface` 即针对该面。

### 1.3 万卡拓扑假设 A1–A8

以下假设用于把「实验室可验证的控制面语义」映射到万卡集群的真实约束；每条都标注了对应检测模块。

| 编号 | 假设 | 安全含义 | 对应模块/链 |
|---|---|---|---|
| **A1** | 单集群 8k–32k GPU，NVL72/rail-optimized fat-tree 三层组网，单 NVL 域 ≤72 GPU | 节点内信任域天然大于单 Pod；跨域流量经 rail 交换机 | `fabric-topology-isolation`、`long-context-training-collective-surface` |
| **A2** | 训练与推理共用物理 fabric，逻辑隔离依赖 IB Partition / VPC 子网 / NetworkPolicy | 逻辑隔离配置错误即平网；NetworkPolicy 不覆盖 RDMA | `multus-sriov-rdma-bypass`、`fabric-topology-isolation` |
| **A3** | 每作业独占 TP/PP/EP/CP/SP 组合，作业内 rank 互信，作业间无强身份隔离 | 跨作业 join 集合通信即获得梯度/KV 读写能力 | `nccl-collective-join`、`long-context-training-collective-surface` |
| **A4** | rendezvous/TCPStore/NCCL bootstrap/KV 通道在 Pod 网络可达，默认无 mTLS | 通道可达即身份可信是系统性缺陷 | `prefill-decode-kv-channel-unauth`、`kv-cache-integrity-poison`、链 `pd-kv-poison` |
| **A5** | checkpoint 写入共享对象存储/并行文件系统，桶级/目录级权限即权重面 | 分片写权限 = 训练恢复污染能力 | `checkpoint-shard-poison`、`storage-protocol-csi`、`shared-volume-weight-copy` |
| **A6** | 长上下文训练启用 ring attention / context parallel，通信量与 CP 度线性相关 | 超窗请求放大 CP 通信与 KV 驻留 | `long-context-window-exhaustion`、`long-context-memory-amplification` |
| **A7** | 层级 all-reduce：节点内 NVLink/NVSwitch + 节点间 RDMA/rail；层级边界可枚举 | 拓扑/端口泄露直接降低入组成本 | `long-context-training-collective-surface`、`collective-communication-surface` |
| **A8** | PD 分离推理 + 共享 prefix cache/KV 池，租户隔离依赖 cache_salt/元数据而非网络隔离 | cache_salt 缺失即跨租户前缀复用；KV 池共享即跨租户写面 | `prefix-cache-cross-tenant-leak`、链 `long-context-cache-leak`、链 `pd-kv-poison` |

---

## 2. 长上下文推理威胁模型（128K–1M）

### 2.1 窗口强制与上下文上限绕过

- 真实服务通常按 `context_window`（128k/1M）与 `max_tokens` 做准入；若只校验**声明值**
  而不校验**实际 prompt token**，攻击者可声明 128k、实发 900k，绕过上限并挤占 prefill 队列。
- 若完全不校验（fail-open），超窗请求被接受且进入 prefill 队列，`queue_depth` 持续增长，
  形成低成本请求级 DoS；1M 窗口下单请求的 KV 预留可达 GB 级。
- 模块：`long-context-window-exhaustion`（超窗接受 + 队列增长）、`context-limit-bypass`
  （声明/实际不一致）。证据均来自真实 HTTP：`usage.prefill_tokens > context_window` 与
  `/metrics.queue_depth` 差分。

### 2.2 KV cache 生命周期

1. **prefill**：按 prompt 长度分配 KV block；窗口声明越大，预留越多。
2. **decode**：逐 token 追加 KV；`max_tokens` 决定 decode 侧增长。
3. **复用**：prefix cache 以 prefix 哈希为键，命中则跳过 prefill。
4. **回收/迁移**：PD 分离场景下 KV block 经 NIXL/Mooncake 等通道从 prefill 节点迁移到 decode 节点。
5. **持久化**：部分实现将 KV 落盘/落共享存储，跨请求复用。

攻击面贯穿全生命周期：分配（内存放大/耗尽）、复用（跨租户泄露）、迁移（通道注入）、
回收（释放后重用/越界读）、持久化（跨租户残留）。

### 2.3 prefix cache 隔离

- 正确实现：cache key = `hash(prefix) + tenant + cache_salt`；跨租户必须显式 salt 且服务端强制。
- 失败模式：cache key 仅 `hash(prefix)`；或 salt 可选且缺省共享。此时租户 B 发送与 A 相同的
  prefix 即可获得 `usage.cached_tokens > 0`，既泄露「该 prefix 已被处理」的侧信道，
  也为 KV 内容推断/前缀注入提供跳板。
- 模块：`prefix-cache-cross-tenant-leak`（真实 HTTP 的 `cached_tokens` 差分）。
- 链：`long-context-cache-leak`（窗口压力 → 跨租户 prefix 复用）。

### 2.4 PD 分离 KV 通道

- Prefill/Decode 分离后，KV 块通过 NIXL/Mooncake/RDMA 在池内传输；EPP/路由器决定复用路径。
- 失败模式：通道无 mTLS/身份校验、KV 块 ID 可枚举、跨租户写入不校验。
  攻击者可读（内容泄露）、写（推理操纵）、伪造（缓存命中劫持）。
- 模块：`prefill-decode-kv-channel-unauth`（读握手差分 + 池计数器）、
  `kv-cache-integrity-poison`（benign marker 写入 + 独立读回 sha256）。
- 链：`pd-kv-poison`（通道探测 → KV 块投毒，写类步骤走备份校验）。

### 2.5 内存放大

- 若服务按**声明窗口**预留 KV（而非实际 prompt+decode），一个 1K token 的请求声明 1M 窗口
  即可触发约 1000× 的 KV 字节增长；叠加并发与队列即形成 KV 内存耗尽。
- 模块：`long-context-memory-amplification`，以 `/metrics.kv_cache_bytes` 增量 /
  `prompt_tokens × 每 token KV 字节` 的放大比判定（阈值 64×）。

### 2.6 checkpoint 分片

- 长上下文训练 checkpoint 体积大、分片多、写入频繁；分片写面常由训练 sidecar/对象存储网关暴露。
- 无鉴权写面允许替换单个分片（benign marker 验证），训练恢复时即加载被污染分片。
- 模块：`checkpoint-shard-poison`（写后读回 sha256 + 备份回滚精确复原）。

---

## 3. 模块 ↔ 链映射

| 模块 | 系列/级别 | 写类 | 证据口径（真实 HTTP） | 关联链 |
|---|---|---|---|---|
| `long-context-window-exhaustion` | 网络架构 / 主动探测 | 否 | 超窗 200 + `prefill_tokens > context_window` + `queue_depth` 增长 | `long-context-cache-leak` |
| `prefix-cache-cross-tenant-leak` | 窃取与数据泄露 / 主动探测 | 否 | 租户 B 无 salt 复用 → `usage.cached_tokens > 0` | `long-context-cache-leak` |
| `context-limit-bypass` | 网络架构 / 主动探测 | 否 | baseline 200 vs 声明/实际不一致仍 200 | — |
| `long-context-memory-amplification` | 网络架构 / 主动探测 | 否 | `/metrics.kv_cache_bytes` 增量/放大比 > 64 | — |
| `long-context-training-collective-surface` | 网络架构 / 主动探测 | 否 | `/metrics.training` 暴露 world_size/并行度/端口 | — |
| `prefill-decode-kv-channel-unauth` | 网络架构 / 主动探测 | 否 | KV 读握手 200 + 池计数器可读 | `pd-kv-poison` |
| `kv-cache-integrity-poison` | 横向利用 / 利用验证 | **是** | KV 写入 200 + 独立读回 value/sha256 一致 | `pd-kv-poison` |
| `checkpoint-shard-poison` | 横向利用 / 利用验证 | **是** | 分片写入 200 + 读回 sha256 一致 + 回滚复原 | — |

链定义（`inkblade/chains/`）：

- `long-context-cache-leak`：`window-pressure`（超窗）→ `cache-reuse`（跨租户 prefix 复用）。
- `pd-kv-poison`：`kv-channel-probe`（未鉴权读握手）→ `kv-block-poison`（写类，备份校验 + http 快照）。

两条链均接入规则引擎：`suricata-longctx-kv-endpoints` 以
`/v1/chat/completions|/kv/transfer|/checkpoint/shards|/metrics` URI 签名覆盖，
紫队矩阵（`inkblade rules validate`）保持零漏过。

---

## 4. 仿真靶场（`lab/longctx_sim.py`）

| 路由 | vulnerable | fixed | 说明 |
|---|---|---|---|
| `POST /v1/chat/completions` | 200（超窗也 200） | 200（窗口内）/400（超窗、max_tokens 超限） | `X-Tenant` 必需；fixed 未知租户 401、跨租户无 `cache_salt` 403 |
| `GET /metrics` | 200 | 401（管理密钥 200） | `kv_cache_usage` / `queue_depth` / `prefill_pool` / `decode_pool` / `training` |
| `POST /kv/transfer` | 200 | 401（管理密钥 200；跨租户 403） | `op=read|write`，KV 块 value/sha256 |
| `GET /kv/transfer?block_id=` | 200 | 401（管理密钥 200） | KV 读回 |
| `POST /checkpoint/shards` | 200 | 401（管理密钥 200） | 真实写 `<root>/checkpoints/<shard>.safetensors` |
| `GET /checkpoint/shards/{shard}` | 200 | 200 | 分片读回 |
| `GET /__routes__` | 200 | 200 | 路由清单 |

设计约束：

- **不返回仿真器答案**：响应中不出现 `vulnerable/fixed` 标记；模块只能从状态码、
  `usage` 计数器、`/metrics` 计数器与读回内容判定。
- `prompt_tokens` 为确定性计数提示（缺省按内容长度估算），使 128k/1M 用例无需传输数百 KB。
- 一切写盘仅限 `Server.root`；`shutdown()` 清理自建临时目录。
- 两态表驱动测试：`tests/test_longctx_sim.py`；模块两态测试：`tests/test_modules_longctx.py`。

---

## 5. 检测与规则

- `suricata-longctx-kv-endpoints`：URI 级签名覆盖长上下文补全、PD KV 传输、checkpoint 分片写面与指标面；
  `blocks_modules` 覆盖全部 8 个模块，`blocks_chains` 自动求交得到两条新链。
- 调参建议：按推理分区登记合法调用方（网关/EPP/eval 作业）；`/metrics` 仅允许监控命名空间抓取；
  KV/checkpoint 写面加 mTLS 后只对异常源告警。
- 紫队：`probes.json` 为两条新链登记重放计划（HTTP 补全探针 + KV 通道日志 fixture），
  矩阵断言 `拦截/检测` 且零漏过。

---

## 6. 实效验证（4 项，全 PASS）

`python -m inkblade.verify-effects --out reports/samples/effects/` 中：

| 检查项 | 证据 |
|---|---|
| `longctx-window-overflow` | 超窗 200；`prefill_tokens(200000) > context_window(131072)`；`queue_depth` +1 |
| `longctx-prefix-reuse` | 租户 A 预热 → 租户 B 无 `cache_salt` 复用，`cached_tokens=4096` |
| `longctx-kv-channel-write` | KV 块写入 benign marker，独立 GET 读回，sha256 与写入一致 |
| `longctx-checkpoint-rollback` | 分片 sha256 前后不同 → `rollback` 后与原始完全一致（字节级） |

---

## 7. 局限与后续

- 未在真实 GPU/真实万卡集群实测；A1–A8 需以客户集群只读快照逐条核验（见 `arch-intel/` 语料）。
- PD KV 通道仿真为 HTTP 语义同构，不覆盖 RDMA/NIXL 二进制协议与 GPU 显存语义。
- 后续：接入 NVSHMEM/DeepEP 端口测绘、ring attention 通信量估算模型、
  以及 checkpoint 分片 Merkle 校验的检测规则。
