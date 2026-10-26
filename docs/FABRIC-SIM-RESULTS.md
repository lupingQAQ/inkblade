# 万卡 Fabric 仿真结果（2026-10-25）

> **这是模拟，不是真实硬件。** 没有 1,024/10,000 GPU 集群、没有真实交换机/网卡、
> 没有 PFC watchdog/ASIC 共享缓冲数据。本文的所有时延、PFC 帧、ECN 标记均由
> `lab/fabric-sim/` 的纯 Python 离散事件模型产生；**不能**替代
> `docs/SOTA-2026-10.md` 中「万卡/超大规模网络」的实机验收部分。

## 1. 模型

| 组件 | 实现 | 边界 |
|---|---|---|
| 拓扑 | `topology.py`：rail-optimized 多平面 fat-tree；每 host × 8 rail 逻辑 NIC；leaf→spine→leaf；跨 rail 经 inter-plane core | 逻辑聚合，不物化全部 host-to-host 链路；不是真实交换机配置 |
| 流 | `sim.py`：ring all-reduce 风格的 rank→rank 流，按 chunk 串行推进 | 不是 NCCL 协议栈逐包仿真 |
| 队列 | 每条 link FIFO，`free_time` 服务模型；积压触发 PFC/ECN/drop | 无 ASIC 共享缓冲、无 PFC watchdog、无 HOL 细节 |
| 注入 | PFC storm、ECN 低阈值、rail 错配、straggler（host link 5–8% 容量）、spine 故障重路由 | 攻击面为参数注入，不是真实配置面写入 |
| 判定 | `detectors.py` 与 `inkblade/modules/roce-pfc-storm`（≥50,000 帧）、`nccl-straggler-injection`（≥2×）、fabric-topology-isolation（rail/HCA、IB Partition）同阈值 | 真实模块另跑 HTTP/快照裁决（§3） |
| 可视化 | `viz.py`：确定性 SVG（链路 top-N、rank 完成时间、rail×leaf 热力）+ 无 JS HTML | 无时间戳/绝对路径 |

拓扑规模（实际输出）：

| nodes | leaves | spines | hosts/leaf | rails | planes | 逻辑 links（按流生成） |
|---|---|---|---|---|---|---|
| 1,024 | 64 | 32 | 16 | 8 | 2 | 192 |
| 10,000 | 79 | 32 | 127 | 8 | 2 | 897 |

## 2. 场景结果

命令：

```bash
python lab/fabric-sim/run_sim.py --nodes 1024 --scenario baseline --out reports/samples/fabric-sim
python lab/fabric-sim/run_sim.py --nodes 1024 --scenario mixed --out reports/samples/fabric-sim
python lab/fabric-sim/run_sim.py --nodes 10000 --scenario mixed --ranks 256 --chunks 8 --out reports/samples/fabric-sim
```

| 场景 | nodes | ranks | PFC 暂停帧 | ECN | 跨 rail 流 | worst / median (ms) | goodput (Gbps) | 判定 |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| baseline | 1,024 | 64 | 96 | 32 | 0 | 2.776 / 2.745 | 3,093.9 | `fabric.baseline-clean`（无异常） |
| mixed | 1,024 | 128 | **76,801,033** | 74 | **37** | **9.040 / 2.060** | 1,425.3 | PFC storm + rail mismatch + straggler + link failure |
| mixed | 10,000 | 256 | **102,401,629** | 133 | **64** | **8.953 / 1.377** | 2,878.5 | PFC storm + ECN + rail mismatch + straggler + link failure |

其他单场景（1,024 节点，`tests/test_fabric_sim.py` 覆盖）：

| 场景 | 关键指标 | 判定 |
|---|---|---|
| pfc-storm | PFC 51,200,096 帧 | `fabric.pfc-pause-storm` high |
| ecn | ECN 128 标记（512 chunks 的 25%） | `fabric.ecn-congestion` medium |
| rail-mismatch | cross-rail 41 条流；worst 6.347 / median 2.759 | `fabric.rail-mismatch` + straggler |
| straggler | worst 9.128 / median 2.747（3.3×） | `fabric.nccl-straggler` medium |
| link-failure | 2 条 spine link 故障，4 条流重路由 | `fabric.link-failure` info |

> 绝对时延（2–9 ms）是模型参数（400 Gbps、1 µs/跳、1–2 MB chunk）的结果，**不是**
> 真实集群的 step time；只有相对趋势（PFC/ECN/rail 错配/straggler）有参考意义。

## 3. 真实产品模块裁决

`lab/fabric-sim/run_modules.py` 把同一份仿真 telemetry 暴露为 lab HTTP 端点，然后
调用**仓库内真实模块**（不是改写判定）：

```bash
python lab/fabric-sim/run_modules.py --nodes 1024
# counts: fabric-topology-isolation=7, roce-pfc-storm=1, nccl-straggler-injection=1
# sev: fabric-topology-isolation=[high,info,medium], roce=[high], nccl=[high]
```

| 模块 | 输入 | 结果 |
|---|---|---|
| `fabric-topology-isolation` | 1,024 节点快照（每 17 个节点缺 HCA 清单、IB Partition 为空、双平面、ComputeDomain） | **high** IB 无 Partition；**medium** rail 与 HCA 错配；medium 双平面；medium ComputeDomain；info 基线 |
| `roce-pfc-storm` | lab `/roce/pfc` GET 基线 + 3×POST storm | **high** PFC 暂停帧 delta ≥50,000 |
| `nccl-straggler-injection` | lab `/train/step` 基线 + `/nccl/rank` 注入 5000ms + 再测 | **high** 步时劣化 2,428×（模型 step 基线仅 ~2ms，比值被放大；关注判定而非倍率） |

产物：`reports/samples/fabric-sim/module-findings.json`。

## 4. 可视化

- `reports/samples/fabric-sim/fabric-mixed-1024.svg` / `.html`
- `reports/samples/fabric-sim/fabric-mixed-10000.svg` / `.html`
- `reports/samples/fabric-sim/fabric-baseline-1024.json` 等

SVG 内容：链路 top-N 字节量（PFC/ECN 着色）、rank 完成时间柱状、rail×leaf 热力、
findings 列表。文件字节确定性（同 seed 同输出，无时间戳）。

## 5. 与真实硬件的差距（必须保留的边界）

1. **PFC 帧数**是模型计数，不是交换机 `pfc_pause_frames` 计数器；真实 PFC watchdog
   会在数秒级暂停后触发，模型没有 watchdog。
2. **ECN/drop** 只按队列阈值计数，没有真实 RED/WRED、共享缓冲、burst 吸收。
3. **rail 错配**用跨 plane core 路径近似，真实 fabric 可能因 ECMP hash/rail 交换机
   端口映射出现极化，模型未覆盖 ASIC 级 hash。
4. **straggler** 用 host link 容量比例近似，真实 straggler 可能来自 GPU 降频、
   PCIe 争用、NCCL 算法/拓扑选择，步时绝对值不可比。
5. **规模**：10,000 节点的对象仍是逻辑聚合（79 leaf × 32 spine），没有 10,000 台
   真实交换机/网卡的上线、控制面、光模块、功耗与故障率数据。
6. **攻击面**：PFC storm/rail mismatch 是参数注入，不是对真实交换机配置面的写操作；
   真实利用需现场授权与厂商补丁状态确认。

## 6. 复现与测试

```bash
python -m unittest tests.test_fabric_sim -v   # 15 tests
python lab/fabric-sim/run_sim.py --nodes 1024 --scenario baseline --out reports/samples/fabric-sim
python lab/fabric-sim/run_modules.py --nodes 1024 --out reports/samples/fabric-sim/module-findings.json
```

测试覆盖：1,024/10,000 精确节点数、确定性、baseline 零 high、PFC/ECN/rail/straggler/
link-failure 各自判定、mixed 全检测器、真实模块裁决、SVG/HTML 无时间戳、artifacts
无绝对路径、10,000 节点 <30s。

## 7. 状态

| 子项 | 状态 |
|---|---|
| 1,024–10,000 节点 rail/多平面 fat-tree 仿真 | **模拟验证** |
| PFC/ECN/rail 错配/straggler/链路故障注入与判定 | **模拟验证** |
| 真实 fabric 模块（topology-isolation / PFC / straggler）裁决 | **模拟验证**（模块真实，输入为仿真） |
| 真实 10K GPU 集群 + 真实交换机计数器 | **仍未达成** |
