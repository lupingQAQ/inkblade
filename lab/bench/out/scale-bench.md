# Trident 规模压测结果（合成快照）

> 生成时间：2026-10-25T00:43:36Z　平台：Windows-11-10.0.26300-SP0　Python：3.12.15
> 数据来源：`lab/bench/scale-bench.py`（每 scale 独立子进程）；原始 JSON：`lab/bench/out/scale-bench.json`。
> 边界：合成快照，非真实集群；规模=namespaces+pods+services+netpol+rbac+storage 对象数，逐 scale 精确等于目标值。

## 总览曲线

| 对象数 | 侦察 11 模块 | 侦察/万对象 | 可达性图 | 规则生成 | 总耗时 | 峰值 RSS | findings |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 100 | 1.0ms | 0.10s | 0.1ms | 46.3ms | 290.1ms | 34MB | 117 |
| 1,000 | 5.0ms | 0.05s | 0.5ms | 52.3ms | 431.7ms | 37MB | 1,088 |
| 5,000 | 19.0ms | 0.04s | 1.1ms | 59.4ms | 909.4ms | 42MB | 5,459 |
| 10,000 | 40.4ms | 0.04s | 2.2ms | 93.9ms | 1.64s | 54MB | 10,891 |

## 各模块耗时（ms）

| 模块 | 100 | 1,000 | 5,000 | 10,000 |
|---|---|---|---|---|
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
| reachability-graph | 0.1 | 0.5 | 1.1 | 2.2 |
| rules-generate | 46.3 | 52.3 | 59.4 | 93.9 |

## Python 堆峰值（MB / 阶段）

| 模块 | 100 | 1,000 | 5,000 | 10,000 |
|---|---|---|---|---|
| cloud-integration-fingerprint | 0.0 | 0.0 | 0.0 | 0.0 |
| escape-primitives | 0.0 | 0.0 | 0.2 | 0.4 |
| exposure-mapping | 0.0 | 0.1 | 0.3 | 0.7 |
| framework-port-matching | 0.0 | 0.1 | 0.4 | 0.8 |
| metadata-egress | 0.0 | 0.3 | 1.7 | 3.5 |
| network-policy-coverage | 0.0 | 0.0 | 0.1 | 0.2 |
| observability-exposure | 0.0 | 0.1 | 0.3 | 0.5 |
| privileged-workloads | 0.0 | 0.0 | 0.2 | 0.4 |
| ray-control-plane | 0.0 | 0.0 | 0.1 | 0.2 |
| rbac-mapping | 0.0 | 0.0 | 0.0 | 0.1 |
| storage-sharing | 0.0 | 0.0 | 0.1 | 0.1 |

## 增长倍率（侦察耗时 vs 对象数）

| 区间 | 对象× | 耗时× | 判定 |
|---|---:|---:|---|
| 100→1,000 | 10.0 | 4.94 | 近似线性 |
| 1,000→5,000 | 5.0 | 3.77 | 近似线性 |
| 5,000→10,000 | 2.0 | 2.13 | 近似线性 |

## 判定口径

- 阈值：单模块 >60s 或折算 >60s/万对象 即视为瓶颈并修复（见各 scale 的 `recon_over_60s*`）。
- 修复判据：改为索引/流式后，耗时增长倍率 ≤ 对象增长倍率 ×1.6，且同输入 findings 逐条一致。
- 合成快照的 findings 数量本身随 Pod 数线性增长（每 Pod 一条出网/SA 发现），这是检测语义而非缺陷；
  评测算力时看「耗时/对象」与增长倍率，不看 findings 绝对数。
