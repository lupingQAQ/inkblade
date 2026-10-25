# lab/tencent-compare — 腾讯 Agent 渗透大赛对标微评测

策略级、确定性的 OFF/ON 对照，回答一个问题：**第三节的编排改进（自主度分级 /
结构化观察 / 成本预算）是否让同一批任务更快、更省、更少人工干预？**

- `tasks.json`：8 个任务，覆盖 TCH 第二届四赛区 + 证据审计 + 预算 + 不可逆写护栏；
- `run_eval.py`：OFF 复现 HEAD(`c921595`) 语义；ON 走
  `trident.core.agent_policy` / `observation` / `cost`；
- 输出：`reports/samples/tencent-compare/tencent-compare.json` +
  `docs/SECTION3-METRICS.md`；
- 测试：`tests/test_tencent_compare.py`（阈值、护栏、接线、确定性）。

```bash
python lab/tencent-compare/run_eval.py --write   # 生成 JSON + Markdown
python -m unittest tests.test_tencent_compare -v
```

## 口径

- **成功**：findings 数 ≥ 任务阈值；带 `min_evidence_ratio` 的任务还要求结论可追溯。
- **token / 时延**：按模块输出规模标定的确定性成本，不是线上账单；ON 的结构化
  观察按原始工具输出的 35% 计入上下文。
- **审批**：`approvals` 是人工决策点（计划批准 + 不可逆写确认）；
  `approval_items` 是人类需要过目的动作预览数。
- **人工干预**：手工重试、手工跳过死胡同、手工裁剪超支、永久错误上报。
- 故障注入覆盖：瞬时错误、死胡同、预算超支、不可逆写；每类只出现一次，用于
  验证策略而非估计总体成功率。

## 阈值（写进测试）

| 指标 | 阈值 |
|---|---|
| success_rate | ON ≥ OFF + 0.25 |
| approval_items | ON ≤ OFF × 0.85 |
| latency_ms | ON ≤ OFF × 0.80 |
| tokens | ON ≤ OFF × 0.85 |
| human_interventions | ON = 0 |
| approvals（护栏） | ON ≤ OFF + 1 |
| evidence_ratio（护栏） | ON ≥ 0.90 |

当前结果见 `docs/SECTION3-METRICS.md`。修改任务集后必须重新生成文档与 JSON。
