# 混沌/扰动编排对照：Chaos Mesh · LitmusChaos · Chaos Toolkit

> 实现：`trident/chaos/`（catalog / orchestrator / runtime / errors）
> CLI：`trident chaos list|run|abort`
> 实测：`tests/test_chaos.py` 19 项全绿；延迟 / 断连 / PFC 风暴三实验实跑记录见
> `reports/samples/chaos/three-live.json`（可由 `trident chaos run ... --json-out` 复现）。

## 1. 边界（先说不做什么）

所有注入只发生在**本地仿真靶场**：

- `fabric-dos` / `fabric-sim` / `longctx` / `mock` 都是 `lab/` 下的进程内 mock，
  只监听 `127.0.0.1`，端口随机；
- 网络故障由 `FaultProxy` 在应用层完成（延迟 / 丢包 / 按 `X-Chaos-Group` 分区），
  **不写** `tc`/`netem`、**不碰**宿主机网络栈、**不碰**真实交换机；
- GPU Xid/ECC、PFC、NVSwitch、BMC 等是 mock 计数器/离散事件仿真，**不是真实
  NVML/Redfish/SONiC 写入**；
- DNS 故障是客户端解析层 shim（`*.chaos.test`），不劫持真实 DNS。

因此本文的「对照」是**实验模型与能力边界对照**，不是「已在生产 K8s/GPU 集群
验证」；真实集群落地需要把 runtime 的注入后端替换成 Chaos Mesh/Litmus 的 CRD
或厂商 API（见第 5 节）。任何写操作在真实环境仍须 ROE + 备份 + 审批三闸门。

## 2. 实验模型

每个实验都是一个可判定闭环，字段与 Chaos Toolkit 的 Method 对齐：

| 阶段 | Trident | 对应 Chaos Toolkit | 对应 Chaos Mesh / Litmus |
|---|---|---|---|
| 稳态假设 | `steady` probes 全部成立才允许注入 | `steady-state-hypothesis` | Litmus `probe`（steady-state） |
| 注入 | `inject` Action（http/proxy/dns/admin-reset） | `method` 的 action | `NetworkChaos`/`PodChaos`/... CRD |
| SLO 度量 | `measure` probes，记录 baseline/during | `method` 后续 probe | 无内建；靠 Prometheus/自定义 probe |
| 中止 | `abort_when` + 外部 `trident chaos abort` | `controls`/自定义 | 无统一语义；靠 experiment 超时 |
| 自动回滚 | `rollback` 无论成败都执行 | `rollback` | Litmus `cleanup`/Chaos Mesh 删除 CR |
| 恢复断言 | `recovery`（默认复用 steady） | 再次 `steady-state-hypothesis` | 无内建；需重跑 probe |
| 报告 | `chaos-runs/latest.json` + 每实验 phases | journal | CR status/事件 |

实现要点：

- 稳态不成立 → `steady_state_failed`，**拒绝注入**（fail-safe，不动靶场）；
- 任一 `abort_when` 命中 → `aborted_by_condition`，仍执行回滚；
- 网络类实验结束在 `finally` 清空 fault profile，防止故障泄漏到下一个实验；
- 回滚后恢复断言失败 → `rollback_failed`，报告保留 phases 供人工介入；
- 编排模式：`sequential` / `parallel`（线程池，结果按输入顺序回填）/
  `--cycles N --every S` 定时循环；`abort` 通过 `.chaos/abort.json` 跨进程生效。

## 3. 实验目录（18 个）

| # | id | 类别 | 注入 | 稳态 / SLO 度量（摘要） | 中止条件 | 回滚 | ML 独有 | 对照注记 |
|---|---|---|---|---|---|---|---|---|
| 1 | `net-latency-step-degradation` | network | FaultProxy `delay_ms=400` | 基线步时 <250ms；注入后 ≥350ms 且 ≥2× 基线 | >10s 安全阀 | `delay_ms=0` | 是 | Chaos Mesh NetworkChaos delay；度量面是 `/train/step` 训练步时 |
| 2 | `net-disconnect-workers` | network | `drop_rate=1.0` | 成功率 100% → 0% | error_rate >50% | `drop_rate=0` | 否 | NetworkChaos loss 100% / partition |
| 3 | `net-partition-rail-groups` | network | `block_groups=[group-b]` | group-a 100%、group-b 0% | 两组同时为 0 | 清空 block_groups | 否 | NetworkChaos partition + selector |
| 4 | `net-packet-loss` | network | `drop_rate=0.35`（固定种子） | 成功率 100% → <95% 且 >20% | error_rate >80% | `drop_rate=0` | 否 | NetworkChaos loss percent |
| 5 | `dns-resolution-failure` | dns | DnsShim fail `trainer.chaos.test` | 解析+200 → 0% 成功 | 持续 error_rate >50% | 取消 fail | 否 | Chaos Mesh DNSChaos；客户端解析层仿真 |
| 6 | `fabric-pfc-storm` | fabric | fabric-sim `/roce/pfc mode=storm` | `storm=false` → `storm=true` 且 PFC 暂停帧 Δ≥25,000 | >10,000,000 帧 | `mode=clear` | 是 | 三大工具均无 RDMA/PFC；fabric-sim 离散事件计数器 |
| 7 | `fabric-bootstrap-port-exhaustion` | fabric | 占满 24 个 NCCL bootstrap 端口 | 剩余端口 >0 → 0，诚实作业 503 | 拒绝 >1000 | `admin/reset nccl` | 是 | 无直接对应；NCCL rendezvous 为 ML 面独有 |
| 8 | `gpu-xid-driver-reset` | gpu | mock NVML Xid 79 | 无 Xid/healthy → reset≥1/unhealthy | reset>32 | `admin/reset gpu` | 是 | 无 GPU 实验；真实落地用 DCGM/NVML mock 或 GPU Operator |
| 9 | `node-drain-gang-hold` | node | 8 GPU gang 占位 ×3 | pending_gpus ≤16 → >16 且 clogged=1 | >512 | `admin/reset gang` | 否 | PodChaos pod-delete / Litmus pod-delete 的调度队列等效 |
| 10 | `io-throttle-checkpoint` | io | checkpoint 4×4096MB burst | io_queue <4 → bytes≥16,000MB 且 queue≥4 | queue>1024 | `admin/reset checkpoint_io` | 否 | IOChaos latency/limit；度量 checkpoint 写面 |
| 11 | `memory-pressure-kv-oom` | memory | 1.5M token 上下文预留 | 无 OOM → oom≥1 且 KV>64GiB | oom>64 | `admin/reset memory` | 否 | StressChaos memory；KV 预留面为 ML 独有 |
| 12 | `kv-eviction-storm` | memory | 800k token 预留 | KV 水位 <80% → ≥80% | oom>16 | `admin/reset memory` | 是 | 三大工具无 KV cache 实验 |
| 13 | `checkpoint-write-conflict` | storage | 双写者 2×2048MB burst ×2 | 单写者 queue<8 → queue≥4 且 bytes≥8192MB | queue>256 | `admin/reset checkpoint_io` | 是 | 无 checkpoint 语义；写冲突为 ML 独有 |
| 14 | `apiserver-request-flood` | control-plane | 800 请求 | 请求数低水位 → ≥800 | >1,000,000 | `admin/reset api` | 否 | HTTPChaos qps 近似；Litmus 无原生 apiserver 洪泛 |
| 15 | `trainer-master-loss` | control-plane | 分区 master 组 | master/worker 均 100% → master 0%、worker 100% | worker 也 0 | 清空 block_groups | 是 | partition + selector 可近似；master/worker 语义为 ML 独有 |
| 16 | `nccl-slow-rank-straggler` | training | rank-3 straggler 4000ms | 步时比 <1.5× → ≥2.0×；worst_straggler≥4000ms | 步时比>50× | straggler=0 | 是 | 三大工具无集合通信/慢 rank 实验 |
| 17 | `gradient-noise-threshold` | training | Byzantine scale=4 | loss 发散比 <1.5 → ≥1.5；回滚后 loss<0.5 | loss>1000 | `admin/reset training` | 是 | 无训练数值面实验 |
| 18 | `kv-hit-rate-degradation` | training | 200 个 1M-token 冷前缀 | warm cached_tokens≥256 → cold=0 且 KV 使用>0.3；回滚后命中恢复 | queue>10,000 | 重预热工作集 | 是 | 无 KV/prefix cache 实验；longctx-sim 无淘汰策略 |

`ml_specific=true` 共 10 个（1、6、7、8、12、13、15、16、17、18），覆盖任务要求的
「训练步时退化 / KV 命中率 / 梯度噪声阈值」三类 ML 独有面，另含 PFC、NCCL
bootstrap、GPU Xid、KV 驱逐、checkpoint 写冲突、master 失联。

## 4. 与三大工具的能力矩阵

图例：● 原生支持；◐ 可近似/需自定义；○ 无内建。

| 能力 | Chaos Mesh | LitmusChaos | Chaos Toolkit | Trident（本项目） |
|---|---|---|---|---|
| 实验描述 | K8s CRD（YAML） | ChaosEngine/CRD | JSON/YAML Method | Python dataclass 目录 + CLI |
| 稳态假设 | 无内建（Prometheus 外部） | `probe`（steady-state） | ● `steady-state-hypothesis` | ● `steady` probes（HTTP/延迟/成功率/ML 指标） |
| SLO 度量 | 无内建 | 有限 probe | ◐ probe + 自定义 | ● baseline/during + 每 probe 判定 |
| 自动回滚 | 删除 CR（声明式） | cleanup pod | ● rollback | ● 无论成败执行 + 恢复断言 |
| 中止条件 | duration/deadline | 无统一 abort | controls/自定义 | ● `abort_when` + 跨进程 `chaos abort` |
| 顺序/并行/定时 | 多 CR + 工作流（◐） | 多 engine（◐） | ● 多 method/脚本 | ● sequential/parallel/cycles+every |
| CLI | `chaosctl`（部分） | `litmusctl` | `chaos` | ● `trident chaos list/run/abort` |
| 网络延迟/丢包/分区 | ● NetworkChaos | ● 网络实验 | ◐ 需插件/toxiproxy | ● FaultProxy（应用层） |
| DNS 故障 | ● DNSChaos | ◐ 自定义 | ○ | ● DnsShim（客户端层） |
| IO/内存/CPU 压力 | ● IOChaos/StressChaos | ● | ◐ 插件 | ● checkpoint 队列 / KV 内存 mock |
| Pod/节点驱逐 | ● PodChaos | ● pod-delete | ◐ K8s 插件 | ● gang 占位压队等效 |
| GPU Xid/ECC | ○ | ○ | ○ | ● mock NVML 计数器 |
| RDMA/PFC/IB | ○ | ○ | ○ | ● fabric-sim 计数器（ML fabric 面） |
| NCCL 集合通信/慢 rank | ○ | ○ | ○ | ● 步时比 + worst straggler |
| KV/prefix cache | ○ | ○ | ○ | ● warm/cold 命中 + KV 水位 |
| checkpoint 写冲突 | ◐ IOChaos 可压 IO | ◐ | ○ | ● 双写者队列堆积 |
| 训练数值面（loss/梯度） | ○ | ○ | ○ | ● loss 发散比 / Byzantine 注入 |
| 管理者失联（master/worker 脑裂） | ◐ partition+selector | ◐ | ◐ | ● 分组分区 + 双面观测 |
| 真实内核/网络栈注入 | ● tc/netem/iptables | ● | ◐ 插件 | ○ 仅应用层仿真 |
| 真实 GPU/交换机写入 | ●（GPU 需扩展） | ◐ | ○ | ○ mock/仿真，不写硬件 |
| 生产多租户/审计 | ● K8s RBAC | ● | ◐ | ◐ 本地单用户；服务模式有 RBAC |

### 结论

- **实验模型**：Trident 比三大工具更接近「可判定闭环」——稳态、SLO、中止、
  回滚、恢复五段齐全；Chaos Mesh/Litmus 强在真实注入后端与 K8s 编排，弱在
  统一的中止/恢复语义与 ML 指标。
- **故障面**：通用网络/DNS/IO/压力/节点类与三大工具重叠；GPU/RDMA-PFC/
  NCCL/KV cache/checkpoint/训练数值是三大工具没有的 ML 面，本项目用本地仿真
  给出可复现实验，但明确不声称真实硬件效果。
- **不是替代品**：生产落地应把 `runtime.apply_action` 的 `proxy/dns/http/
  admin-reset` 后端替换为 Chaos Mesh CRD、Litmus ChaosEngine、厂商 NVML/
  Redfish/SONiC API；实验目录、稳态/SLO/中止/回滚编排可直接复用。

## 5. 真实集群落地映射（建议）

| 本地实验 | 生产注入后端 | 需要替换的度量 |
|---|---|---|
| `net-latency-*` / `net-packet-loss` / `net-partition-*` | Chaos Mesh `NetworkChaos`（delay/loss/partition） | `/train/step` 客户端时延 → 训练框架 step time / NCCL timer |
| `dns-resolution-failure` | Chaos Mesh `DNSChaos` | 解析失败率 → CoreDNS 指标 |
| `io-throttle-checkpoint` / `checkpoint-write-conflict` | Chaos Mesh `IOChaos` + 对象存储限速 | checkpoint 队列 → 存储侧 P99 / 写入吞吐 |
| `memory-pressure-kv-oom` / `kv-eviction-storm` | StressChaos + 推理引擎 KV 指标 | mock KV 水位 → vLLM/SGLang `kv_cache_usage` |
| `gpu-xid-driver-reset` | DCGM/NVML fault injection（或 GPU Operator 实验） | mock 计数器 → DCGM Xid/ECC/remap 指标 |
| `fabric-pfc-storm` | 交换机遥测/网卡 PFC 计数器（真实写入需厂商支持） | fabric-sim → `ethtool -S` / SONiC `COUNTERS` |
| `nccl-slow-rank-straggler` | 训练框架故障注入（sleep/hook） | mock step ratio → 实际 step time + NCCL trace |
| `gradient-noise-threshold` | 训练代码 hook（梯度缩放/Byzantine） | mock loss → 真实 loss 曲线 |
| `kv-hit-rate-degradation` | 推理引擎 prefix cache 压测 | longctx-sim → 引擎 cached_tokens/命中率 |
| `apiserver-request-flood` | kube-apiserver 压测工具（如 kube-burner） | mock 计数 → apiserver request latency/429 |
| `trainer-master-loss` | NetworkChaos 按 master label 分区 | mock 双面 → 训练 job 状态/心跳 |

## 6. 复现与验收

```powershell
# 目录（18 个）
python -m trident chaos list --json

# 任务要求的三条实跑：延迟 / 断连 / PFC
python -m trident chaos run net-latency-step-degradation net-disconnect-workers fabric-pfc-storm `
  --json-out reports/samples/chaos/three-live.json

# 中止（另一终端）：写标记文件，编排器在当前阶段后回滚退出
python -m trident chaos abort --reason "operator stop"

# 全目录回归（含并行/定时/外部中止）
python -m unittest tests.test_chaos -v
```

验收口径：

- 三实验均出现 `degraded=true` 与 `recovered=true`；
- 断连实验 `outcome=aborted_by_condition` 且仍回滚恢复；
- PFC 实验 `pfc_pause_frames` Δ≥25,000，回滚后 `storm=false`；
- 全目录无 `rollback_failed` / `steady_state_failed`；
- 报告写 `chaos-runs/latest.json`，含 `boundary` 字段声明本地仿真边界。
