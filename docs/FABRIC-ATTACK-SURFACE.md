# 万卡集群破坏性漏洞面（FABRIC ATTACK SURFACE）

本文件是 Trident 在**万卡（10K–1M GPU）训练/推理 fabric 控制面与数据面**上的威胁模型、
模块↔链映射与检测口径说明。配套代码：

- 仿真靶场：`lab/fabric_dos_sim.py`（仅 127.0.0.1，真实 HTTP，vulnerable/fixed 两态）
- 模块：`trident/modules/` 下 12 个专项模块（SHARP/IB/PFC/NCCL/IO/API/KV/梯度/gang/Xid/rail）
- 攻击链：`trident/chains/fabric-silent-corruption-chain.json`、`trident/chains/fabric-exhaustion-chain.json`
- 规则：`sigma-fabric-sharp-unauth-join`、`sigma-fabric-exhaustion-quota-miss`、
  `falco-fabric-collective-poison`、`falco-fabric-control-plane-mutation`、
  `suricata-fabric-control-uri`（紫队重放计划 `probes.json` sim=fabric）
- 实效验证：`trident/verify-effects.py` 中 `fabric-*` 三项（见 `docs/EFFECT-VERIFICATION.md`）

**边界声明**：本仿真与模块描述的是**控制面/数据面语义同构的实验室仿真实效**，
破坏效果全部以计数器/状态变化度量（不真破坏交换机、IB SM、NCCL 进程或 GPU 驱动）；
真实 fabric 结论必须来自客户集群的只读快照与网络事实采集。

---

## 1. 威胁模型：fabric 即武器

万卡集群把三件事折叠进了同一批控制面：

1. **集合通信的语义下沉**：all-reduce 从 NIC/主机内存下沉到交换机在网计算
   （SHARP v3/v4、UEC INC、NVLink 交换 SHARP FP8）——reduce 结果的正确性依赖
   「会话成员 = 作业成员」这一默认假设；
2. **拓扑即性能**：rail-optimized/多平面/自适应路由/OCS 拓扑把「绑定关系」变成
   可写配置——写错一条绑定即集群级性能武器；
3. **规模即故障域**：NVL72 使单 rack 故障域 ×9（Meta 口径）、9216 片 TPU superpod
   同步域、550K GPU 单 fabric（xAI Colossus 2）——单点控制面的任何配额缺失
   都被放大为 frontier 训练停摆。

**关键判断**：fabric 的信任域 ≠ K8s 的信任域。RDMA/IB/SR-IOV 面不受 NetworkPolicy
覆盖（见 `network/rdma-sriov-uncovered.md` 与 `ib-partition-advice.yaml`），
因此 IB SM Partition、SHARP 会话、PFC 档位、rail 绑定这些**fabric 原生控制面**
既是唯一的隔离手段，也是唯一的攻击点。

---

## 2. 攻击面分解（11 面 × 模块）

### 2.1 SHARP 在网聚合会话面 → `sharp-in-network-poison`

- 语义：`POST /sharp/sessions` 入组（vulnerable 无鉴权 200）+ `POST /sharp/reduce`
  提交带 `tamper_factor` 的贡献 → 结果 = 正确值 + 篡改增量，`silent=true` 无告警。
- 证据口径：基线 reduce 与篡改 reduce **前后值差分** + `/metrics.sharp.tampered_reduces` 增长。
- 语料问题点：SHARP v3 多租户在网计算（`nvidia-sharp-in-network`）、UEC INC 2× 加速
  （`ultra-ethernet-spec-2026`）、Quantum-X800 SHARPv4（`nvidia-quantum-x800`）、
  NVLink 交换内 SHARP FP8（`nvidia-nvlink-fusion`）——在网聚合越强，会话面单点越值钱。

### 2.2 IB SM / Partition 面 → `ib-subnet-manager-hijack`

- 语义：`GET /ib/sm/partition` 枚举成员（拓扑测绘）；`POST` 增删成员即重定义 RDMA 信任域。
- 证据：benign marker 成员写入后读回一致 + `/metrics.ib.membership_changes` 增长。
- 语料问题点：IB 唯一隔离手段 = SM/Partition（`ib-partition-rdma`）；UFM/SM 管理面
  随 Quantum-X800 规模化（`nvidia-quantum-x800`）；白盒 NOS 管理面失陷即 SM 失陷
  （`sonic-whitebox-security` CVE-2025-38741 未认证远程）。

### 2.3 RoCE PFC/ECN 面 → `roce-pfc-storm`

- 语义：`POST /roce/pfc {mode:"storm"}` → `pfc_pause_frames` 计数暴增（每轮 +25000，
  阈值 ≥50000）+ ECN 同步增长 + `storm_active` 置位——无损以太的暂停风暴等价于
  fabric 级队列停摆（仅计数器，不真破坏）。
- 语料问题点：Meta 大规模 RoCE 实践与拥塞治理（`meta-roce-fabric`）、MegaScale PFC
  链路抖动治理（`bytedance-megascale`）、UEC CSIG/PCM 把拥塞控制变成可编程面
  （`ultra-ethernet-spec-2026`）、Spectrum-X 自适应路由控制面（`nvidia-spectrum-x-adaptive`）。

### 2.4 NCCL bootstrap/rendezvous 与 rank 状态面 → `nccl-port-exhaustion` / `nccl-straggler-injection`

- 语义一（端口耗尽）：`POST /nccl/bootstrap` 有界分配（≤30 次）占满端口池
  （capacity 24）→ 诚实作业 `honest:true` 收到 503 `bootstrap_ports_exhausted`
  ——新训练作业无法建链（集群级 DoS）。
- 语义二（慢 rank）：`POST /nccl/rank {straggler_ms:5000}` → `/train/step` 计时从
  120ms 基线劣化到 ≥2×——同步 all-reduce 被单 rank 拖垮，goodput 静默下降。
- 语料问题点：NCCL bootstrap 无认证语义（`nccl-transports`）、集合通信初始化优化
  降低建链成本（`bytedance-megascale`）、MegaScale-Infer M2N 组初始化
  （`bytedance-megascale-infer`）、Meta goodput/MTBI 工程口径（`meta-prometheus`）。

### 2.5 checkpoint I/O 面 → `checkpoint-io-storm`

- 语义：`POST /checkpoint/io {bytes_mb:4096, burst:4}` ×5 → `io_bytes_mb` Δ≥40960、
  `io_queue` 增长、`rate_limited=false`——与训练 checkpoint 竞争共享存储与 fabric 缓冲。
- 语料问题点：Prometheus 多层分布式 delta checkpoint 依赖共享存储（`meta-prometheus`）、
  CSI/NFS AUTH_SYS 可伪造（`storage-protocol-csi`）。

### 2.6 apiserver/IMDS 控制面 → `api-server-flood-surface`

- 语义：`POST /apiserver/request {count:250}` ×4 + `/imds/request` ×2 →
  requests 计数 Δ≥500 且 `quota_enforced=false`；fixed 姿态 429。
- 语料问题点：百 k GPU 规模的固件/控制面下发通道（`meta-prometheus`）、
  UltraCluster 共享无阻塞网的单租户外溢（`aws-trainium-ultraserver`）。

### 2.7 KV/激活内存面 → `kv-oom-bomb`

- 语义：`POST /train/context {context_tokens:4000000, declared:8192}` → 200 接受、
  `kv_bytes > capacity`、`oom_events=1`、`silent=true`——声明/实际不一致 +
  无 max 生效 = 单请求显存炸弹。
- 语料问题点：Ironwood 192GB HBM 承接超长上下文 KV（`google-tpu-ironwood-ocs`）、
  PD 分离 KV 部署（`deepseek-prefill-decode`，另见 `docs/LONG-CONTEXT.md` §2.5）。

### 2.8 梯度/损失数值面 → `training-silent-corruption`

- 语义：`POST /train/gradient {mode:"byzantine", scale:3.0}` → loss 轨迹静默发散
  （≥2×）且 `silent=true`、`corruption_events` 增长——训练无效但监控不报警的最坏组合。
- 语料问题点：SHARP 把梯度聚合搬进交换机（`nvidia-sharp-in-network`）、
  NCCL 注入面既有模块族（`nccl-gradient-injection` 链）。

### 2.9 gang/EPP 调度面 → `gang-scheduler-abuse`

- 语义：`POST /sched/gang {gang_size:8, placeholders:8, hold:true}` ×5 →
  `pending_gpus(40) > capacity(16)`、`clogged=true`——占位 job 阻塞全部后续作业。
- 语料问题点：NVL72 64/72 切片与备件调度模型（`meta-prometheus`）、
  EPP/推理扩展调度（`gateway-api-inference-extension`）。

### 2.10 GPU 健康/Xid 面 → `driver-reset-trigger`

- 语义：`POST /gpu/health {xid_code:79}` → `driver_resets+1`、`healthy=false`
  （复位族 48/63/79/94/119）——NVL72 大故障域下单次复位即整 rack 训练中断。
- 语料问题点：Meta「72-GPU 故障域 ×9」与中断归因体系（`meta-prometheus`）、
  GB200 NVL72（`nvidia-gb200-nvl72`）、Trn3 UltraServer 144 片域
  （`aws-trainium-ultraserver`）。

### 2.11 rail/拓扑绑定面 → `rail-mismatch-forcing`

- 语义：`POST /nccl/rail {rank:7, force_rail:"rail-0"}` → rail 图改写、
  `cross_rail_flows` 增长、`/train/step` 步时劣化——rail-optimized 局部性被破坏。
- 语料问题点：多平面拓扑并行替代层级（`nvidia-spectrum-x-multiplane-paper`）、
  HPN 双平面 rail-optimized（`alibaba-hpn`）、OCS/ICI 拓扑管理面
  （`google-tpu-ironwood-ocs`）、Spectrum-X 自适应路由（`nvidia-spectrum-x-adaptive`）。

---

## 3. 两条攻击链

| 链 | 步骤 | 效果度量 | 规则 |
|---|---|---|---|
| `fabric-silent-corruption-chain` | IB Partition 改写 → SHARP 入组+reduce 篡改 → Byzantine 梯度 | reduce 前后差分 + loss 轨迹差分 + tampered_reduces/corruption_events 计数 | Sigma（SHARP 无鉴权入组）+ Falco（collective poison / config mutation）+ Suricata（fabric URI） |
| `fabric-exhaustion-chain` | bootstrap 端口占满 → gang 占位打满队列 → checkpoint I/O 洪峰 | ports_remaining=0 + 诚实作业 503 + pending>capacity + io_bytes Δ | Sigma（配额缺失）+ Falco（config mutation）+ Suricata（fabric URI） |

前置判定：分别以 `sharp-in-network-poison` 与 `nccl-port-exhaustion` 的 high finding 为闸；
写类步骤（sharp/ib/gradient/rank/xid/rail/pfc）全部走 runner backup_targets 备份闸门。

---

## 4. 仿真靶场（`lab/fabric_dos_sim.py`）路由总览

| 面 | 路由 | vulnerable | fixed |
|---|---|---|---|
| SHARP 会话 | `POST /sharp/sessions`、`GET /sharp/sessions/{id}` | 200 无鉴权 | 401（作业令牌/管理密钥 200） |
| SHARP reduce | `POST /sharp/reduce` | 200（篡改静默生效） | 401（管理密钥 200，篡改 400） |
| IB SM | `GET|POST /ib/sm/partition` | 200 无鉴权 | 401（管理密钥 200） |
| PFC/ECN | `GET|POST /roce/pfc` | 200（storm 档生效） | 401（storm 档 400） |
| NCCL bootstrap | `POST /nccl/bootstrap` | 200 至耗尽（诚实 503） | 401（令牌 200，按作业上限 429） |
| NCCL rank/rail | `POST /nccl/rank`、`GET|POST /nccl/rail` | 200 无鉴权 | 401（>500ms / 错配 400） |
| 训练度量 | `POST /train/step`、`GET /train/loss` | 200 | 200 |
| 上下文/梯度 | `POST /train/context`、`POST /train/gradient` | 200（OOM/发散静默） | 400 / 401 |
| checkpoint I/O | `POST /checkpoint/io` | 200 无限速 | 401/429（限速 512MiB） |
| apiserver/IMDS | `POST /apiserver/request`、`POST /imds/request` | 200 无配额 | 429（配额 60） |
| gang 调度 | `POST /sched/gang` | 200（队列打满） | 401/429（容量 16） |
| GPU 健康 | `GET /gpu/health`、`POST /gpu/health` | 200（Xid→复位） | GET 200 / POST 401 |
| 指标 | `GET /metrics` | 200 无鉴权 | 401（管理密钥 200） |

设计约束：响应中不出现 `vulnerable/fixed` 标记；模块只能从状态码、计数器差分、
读回内容与计时差分判定；一切状态内存态（不落盘），`shutdown()` 只关服务。

---

## 5. 实效验证（3 项，全 PASS）

`python -m trident.verify-effects --out reports/samples/effects/` 中：

| 检查项 | 证据 |
|---|---|
| `fabric-sharp-reduce-tamper` | 入组 200；基线 reduce 36.0 vs 篡改 108.0（差分）；`tampered_reduces≥1` |
| `fabric-pfc-storm-counter` | 3 轮 storm 写入 → `pfc_pause_frames` Δ≥50000、`storm_active=true` |
| `fabric-straggler-step-slowdown` | 注入 5000ms 慢 rank → 步时 120ms→5120ms（≥2× 计时差分） |

---

## 6. 局限与后续

- RDMA/IB 二进制协议、真实 SHARP 聚合树、真实 NCCL 握手未覆盖（HTTP 语义同构）；
- OCS/Jupiter 拓扑管理面仅以 rail 绑定面等价表达；
- 后续：接入真实集群只读快照核验（SM Partition 清单 / PFC 计数 / bootstrap 端口池配置）、
  交换机 telemetry（CSIG/INT）导出的检测规则、以及 fabric 控制器审计事件源对接。
