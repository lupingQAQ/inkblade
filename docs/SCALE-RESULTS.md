# Trident 规模压测结果（合成快照 + 真 k3s 200 对象点）

> 生成日期：2026-10-25　执行机：Windows 11 / Python 3.12.15 / 单进程 CPU 计时
> 复现：`python lab/bench/scale-bench.py run --scales 100,1000,5000,10000 --out-md lab/bench/out/scale-bench.md`
> 原始数据：`lab/bench/out/scale-bench.json`、`lab/bench/out/baseline-compare.json`、
> `reports/samples/scale/k3s-scale.json`
> **边界**：合成快照是自建数据，不是客户集群；真 k3s 点是 QEMU TCG 单节点实验室的**采集/分析**规模点
> （Pod 只要求对象存在，不等待 Ready），不是运行时吞吐点。

## 1. 口径

| 项 | 口径 |
|---|---|
| 规模 | `namespaces + pods + services + networkpolicies + roles/clusterroles/bindings + pvcs/pvs/storageclasses + secrets/serviceaccounts` 对象数，逐 scale 精确等于目标值（`snapshot_object_count` 断言） |
| 被测面 | 侦察 11 模块（`_recon-common` 消费者）+ CNI 可达性图（每命名空间指纹 → `core.reachability.infer` → 合并）+ 规则生成（`rules.generate_all`，输入=该 scale 全部 findings） |
| 计时 | 只计模块 `run({}, {"snapshot": ...})` 的墙钟；**不含** tracemalloc（实测 tracer 会把耗时放大 ~10×，故计时/内存分两遍采集） |
| 内存 | ① `tracemalloc` Python 堆峰值（第二遍采集）② 进程 RSS（`ctypes GetProcessMemoryInfo`，20ms 采样，覆盖整轮） |
| 隔离 | 每个 scale 独立子进程（`--isolate` 默认开），避免堆残留污染 RSS 曲线 |
| 阈值 | 单模块 >60s，或折算 >60s/万对象 → 视为瓶颈，必须修复 |

规模分布（权重固定，`pods` 吸收余量）：pods ≈ 35%、services ≈ 15%、netpol ≈ 13%、
RBAC ≈ 11%、存储/Secret/SA ≈ 23%、namespaces ≈ 2%。

## 2. 总览曲线（优化后）

| 对象数 | 侦察 11 模块 | 侦察/万对象 | 可达性图 | 规则生成 | 总耗时 | 峰值 RSS | findings | Python 堆峰值 |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 100 | 1.0ms | 0.10s | 0.07ms | 46.3ms | 290ms | 34MB | 117 | 0.8MB |
| 1,000 | 5.0ms | 0.05s | 0.5ms | 52.3ms | 432ms | 36MB | 1,088 | 0.8MB |
| 5,000 | 19.0ms | 0.04s | 1.1ms | 59.4ms | 909ms | 42MB | 5,459 | 3.6MB |
| 10,000 | 40.4ms | 0.04s | 2.2ms | 93.9ms | 1,645ms | 54MB | 10,891 | 7.1MB |

- **无超时项**：10,000 对象全量跑批 1.6s（其中侦察 40ms），最慢单模块 12ms；
  折算 0.04s/万对象，远低于 60s/万对象阈值。
- **增长近似线性**：侦察耗时 5,000→10,000（对象×2）为 2.1×（线性=2.0×）。
- **内存**：RSS 34→54MB（+20MB）；Python 堆峰值 0.8→7.1MB，峰值出现在 `build_snapshot`
  （快照本体），侦察阶段单模块峰值 ≤3.5MB（metadata-egress）。findings 数量随 Pod 数线性增长
  （每 Pod 一条出网/SA 发现），是检测语义而非内存泄漏；findings 明细不进快照缓存，跑完即释放。

### 各模块耗时（ms）

| 模块 | 100 | 1,000 | 5,000 | 10,000 |
|---|---:|---:|---:|---:|
| cloud-integration-fingerprint | 0.1 | 0.1 | 0.3 | 0.5 |
| escape-primitives | 0.1 | 0.7 | 2.8 | 5.7 |
| exposure-mapping | 0.1 | 0.6 | 1.3 | 2.9 |
| framework-port-matching | 0.1 | 0.6 | 2.7 | 5.0 |
| metadata-egress | 0.2 | 1.1 | 5.5 | 12.0 |
| network-policy-coverage | 0.1 | 0.2 | 1.8 | 4.1 |
| observability-exposure | 0.1 | 0.3 | 0.9 | 2.2 |
| privileged-workloads | 0.1 | 0.8 | 2.0 | 4.5 |
| ray-control-plane | 0.1 | 0.2 | 0.5 | 0.8 |
| rbac-mapping | 0.1 | 0.2 | 0.5 | 1.0 |
| storage-sharing | 0.1 | 0.2 | 0.8 | 1.6 |
| reachability-graph（每 NS 推演+合并） | 0.1 | 0.5 | 1.1 | 2.2 |
| rules-generate | 46.3 | 52.3 | 59.4 | 93.9 |

## 3. 发现的瓶颈与修复

首轮（`git show HEAD` 版本，关闭 tracemalloc 对照，`lab/bench/_baseline_compare.py`）
暴露三处 **O(n²)** 扫描。三个模块的 findings 在修复前后**逐条一致**（`findings_equal=true`，
另用 `lab/bench/_equiv_check.py` 对 `lab/fixtures/recon/*.json` 做整段 JSON 比对）。

| 模块 | 旧实现 | 复杂度 | 修复 | 同输入加速（10k 对象） |
|---|---|---|---|---|
| metadata-egress | 每 Pod 调 `_egress_covered()` 全扫策略表；每 Pod 线性 `next()` 找 SA | pods×(policies+SAs) | 一次性建 `egress_covered_ns` 集合 + `(ns,name)→automount` 字典 | **×18.1**（283.4ms→15.6ms） |
| network-policy-coverage | 每命名空间 `[p for p in policies if ns]` | namespaces×policies | `namespace → 策略列表` 分组索引 | **×4.1**（17.1ms→4.2ms） |
| ray-control-plane | 每 RayCluster `next()` 扫全部 Service | rayclusters×services | `name → 首个同名 Service` 字典（保持 next() 首匹配语义） | **×7.5**（7.4ms→1.0ms） |

### 修复前后总量（同一份合成快照，同一进程，先预热）

| 对象数 | 旧实现总耗时 | 新实现总耗时 | 加速 | findings 一致 |
|---:|---:|---:|---:|---|
| 100 | 0.4ms | 0.3ms | ×1.33 | ✓ |
| 1,000 | 6.1ms | 3.3ms | ×1.85 | ✓ |
| 5,000 | 82.9ms | 18.4ms | ×4.51 | ✓ |
| 10,000 | 330.8ms | 46.5ms | ×7.11 | ✓ |

**增长倍率**（对象×2 时）：
- 旧实现 5,000→10,000：330.8/82.9 = **4.0×**（超线性，符合 pods×policies 的二次项）；
- 新实现 5,000→10,000：46.5/18.4 = 2.5×（含分配器/GC 抖动，关 GC 后单模块为 1.75×）。

> 诚实说明：在 10,000 对象（pods≈3,500、netpol≈1,300）时二次项只有 ~0.3s，**没有触发
> >60s/万对象阈值**。判为缺陷的依据是增长倍率（4× for 2×）与生产形态外推：
> 10k Pods × 2k NetPol ≈ 20M 次字典比较 ≈ 0.9s/模块；50k Pods × 8k NetPol ≈ 400M ≈ 18s/模块。
> 任务要求「发现 O(n²) 即修」，因此仍按索引化重写。

### 外推（旧实现，按实测 ≈45ns/次策略比较）

| Pods | NetPol | 比较次数 | metadata-egress 估算 |
|---:|---:|---:|---:|
| 3,500 | 1,300 | 4.6M | 0.28s（实测 283ms，吻合） |
| 10,000 | 2,000 | 20M | ≈0.9s |
| 50,000 | 8,000 | 400M | ≈18s |
| 100,000 | 20,000 | 2,000M | ≈90s（**破 60s/万对象**） |

新实现该项恒为 O(pods+policies)，上表不再适用。

## 4. 真 k3s 规模点（200 对象）

单节点 k3s v1.36.5+k3s1（QEMU TCG，`lab/qemu-k3s`，`-accel tcg -smp 4`）。

| 阶段 | 结果 |
|---|---|
| 创建对象 | **204 个**：12 Namespace / 60 Pod / 60 Service / 36 NetworkPolicy / 12 SA / 12 Role / 12 RoleBinding |
| apply 耗时 | 156.9s（TCG 下 API+调度，**非**产品开销） |
| `kubectl get -o json` 采集（全集群） | 6.4s；快照含 65 Pod / 63 Service / 37 NetPol / 19 Role / 20 RoleBinding / 74 ClusterRole / 57 ClusterRoleBinding / 68 SA / 1 Node |
| 侦察 11 模块跑批 | **199.7ms**，145 findings（0.07–1.33ms/模块） |
| 证据 | `reports/samples/scale/k3s-scale.json` |

结论：真实 API 快照的**归一化 + 分析**在 200 对象量级是亚秒级；瓶颈在 TCG 下的对象创建（157s），
属于实验室虚拟化成本，不计入产品性能。`framework-port-matching` / `storage-sharing` 在该点 0 findings
是数据形态所致（Service 名不含框架 hint、无 PV/PVC），非漏检。

## 5. 回归护栏

`tests/test_scale_bench.py`（12 项）：

1. **对象数精确**：100/1,000/5,000/10,000 逐 scale `total == scale`；生成器可复现（同参两次字节一致）。
2. **复杂度护栏（不靠计时）**：`CountingDict` 统计模块对 policy/SA/service 字典的读取次数——
   索引化实现下读取次数 ≤ 12×对象数；旧实现是 pods×对象数（400×）。计时会受机器负载影响，计数不会。
3. **语义不回归**：无策略命名空间=high、有选择策略但无 deny-all=medium；出网缺口按 Pod 计数。
4. **端到端**：`run_scale(100)` 产出 build/recon/reachability/rules 全阶段指标，且
   `recon_over_60s=False`；规则生成对 1,000 对象快照的全部 findings 仍满足「每链 ≥1 规则」。

## 6. 未达成 / 下一步

- **没有 10k+ 对象真集群**：真机点止于 204 对象（TCG 单节点）。合成曲线不代表真实 API 采集与
  CNI/etcd 抖动；生产验收需 ≥10k 对象真集群复测采集+分析总时长。
- **合成分布是假设**：35% pods / 13% netpol 的配比来自典型 ML 集群直觉，未做多客户采样；
  外推表用「比较次数」而非时间，避免把假设配比说成实测。
- **规则生成随 findings 线性**：10,891 findings → 94ms；若要 10 万 findings 需再压 mapping.json
  的 finding_links（当前 R×F 双循环，R≈31 固定，实测未构成瓶颈，未提前优化）。
- **可达性图核心规则集固定规模**（≤6 节点/指纹集），本压测测的是「每命名空间推演+合并」的
  多租户路径，不把固定规模规则宣传成线性扫描能力。
