# Agent 架构评测（deterministic vs supervisor-worker）

任务集：`tasks.json`（15 任务，6 类：recon / exploit / chain / long-context / gateway / gpu-tenant）。
全部本地：127.0.0.1 仿真靶场（`lab/ai_gateway_sim.py`、`lab/longctx_sim.py`、
`lab/gpu_cloud_sim.py`）+ 本地快照 fixture；写类模块不参与（`mode=probe-only`）。

## 运行

```bash
python lab/agent-eval/run_eval.py
```

产出：

- `reports/samples/agent-eval/agent-eval.json`（机器可读：逐任务/汇总/差值）
- `docs/AGENT-EVAL-RESULTS.md`（表格报告）

## 两种模式

| 模式 | 审批 | 并发 | 重派 | 事件日志 |
|---|---|---|---|---|
| deterministic | 整批 1 次 | 1（顺序） | 无（单次尝试） | 无 |
| supervisor-worker | 逐动作 | 4（1–8 有界） | max_attempts=2 | `_journal/journal.jsonl` |

## 故障注入（显式）

`gateway-auth` 任务的首个动作首次尝试注入 `TimeoutError`（模拟瞬时网络故障），
用于测量「失败重派」的真实恢复能力；结果 JSON 的 `config.fault_injection` 明确记录，
不与真实能力混淆。

## 指标口径

- 成功率：任务级（finding 数 + 标题命中 + 链 verdict/步骤数）；
- 耗时：任务墙钟时间（supervisor 用动作 started/finished 聚合）；
- token：确定性估算（CJK 按字 + 其余 4 字符/token），仅用于相对比较；
- 审批次数：deterministic=1（整批），supervisor=动作数（逐动作审批）。
