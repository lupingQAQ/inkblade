# Swarm 角色化 worker 评测（1 vs 4）

> 目标：验证「角色化 worker + 本机多进程队列」在 15 个任务上不降低成功率，并量化时延与审批墙钟收益。**simulate 执行器，非真实模块/客户 SLA。**
> 机器可读：`reports/samples/swarm-eval/results.json`（本文数字由 `python lab/swarm_eval.py` 生成）。

## 1. 任务集

| 项 | 值 |
|---|---|
| 任务数 | 15（recon×5 / exploit×4 / verify×4 / report×2） |
| 模拟时延 | recon 60ms、exploit 90ms、verify 70ms、report 40ms |
| 审批门 | 40ms/任务（预授权批量批准；模拟 lead 校验） |
| 注入失败 | 永久 `exploit-03`；瞬时 `verify-02`（fail_times=1） |
| 重派上限 | 2 |
| 测量 | warm batch 启动进程后，3 个 batch 取中位数 |

## 2. 结果

| 配置 | worker | 角色分布 | 成功率 | 时延中位数 | 审批次数 | 审批墙钟 | 峰值并发 | 重试 | 进程 |
|---|---:|---|---:|---:|---:|---:|---:|---:|---:|
| 1 worker | 1 | any×1 | 14/15 (93.33%) | 1887 ms | 15 | 603 ms | 1 | 2 | 1 |
| 4 worker | 4 | recon×1、exploit×1、verify×1、report×1 | 14/15 (93.33%) | 657 ms | 15 | 399 ms | 4 | 2 | 4 |

- **时延加速 2.87×**：1887 → 657 ms。
- **审批墙钟加速 1.51×**：603 → 399 ms；审批**次数不变**（15 次预授权），并发只压缩等待墙钟。
- **成功率一致**：93.33% vs 93.33%（14/15；永久失败如实保留，瞬时失败重试成功）。
- 重试：2 vs 2；峰值并发 1 vs 4；进程数 1 vs 4（真实多进程）。

## 3. 逐角色

| 角色 | 1w 成功/总数 | 1w 重试 | 4w 成功/总数 | 4w 重试 |
|---|---:|---:|---:|---:|
| recon | 5/5 | 0 | 5/5 | 0 |
| exploit | 3/4 | 1 | 3/4 | 1 |
| verify | 4/4 | 1 | 4/4 | 1 |
| report | 2/2 | 0 | 2/2 | 0 |

## 4. 护栏（与 L3/supervisor 同源）

- 每任务必须 `approval.status=approved` 且有 `approved_by`，否则 `ApprovalRequired`，入队前整体校验、零残留；
- 角色上限每角色默认 2、最小 2、最大 8；总 worker 1–16；4 worker = 每角色 1 个；
- 失败由父进程按 `max_attempts` 重派到**同角色**队列，超过上限才终态失败；
- 生产执行器 `runner` 在子进程内构造 EvidenceStore + `core.runner.run_module`，授权/备份/三层落证闸门照旧（本评测未启用真实模块）。

## 5. 诚实边界

- simulate 执行器按角色 sleep，不是真实模块；数字只证明本机多进程队列的吞吐/审批并发
- 先跑 warm batch 启动进程，测量 3 个 batch 取中位数（排除 Windows spawn 启动成本）
- 1 个永久失败 + 1 个瞬时失败重试：成功率两边一致（14/15），并发不改变正确性
- 审批墙钟是各任务审批区间的并集；审批次数不变（15 次预授权），并发只压缩墙钟
- 真实模块的时延/资源占用取决于目标集群与模块实现；本页不能外推为生产 SLA。
- Windows spawn 启动成本（每进程数百 ms）已用 warm batch 排除；冷启动场景需另测。
- 审批墙钟是 40ms 模拟门；真实 lead 审批时延远高且不可并发压缩，预授权才是 L3 的关键收益。

## 6. 复现

```bash
python lab/swarm_eval.py
python -m unittest tests.test_swarm -v
python -m trident swarm roles
python -m trident swarm run --tasks tasks.json --workers 4 --executor simulate
```
