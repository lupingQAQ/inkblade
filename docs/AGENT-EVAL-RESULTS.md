# Agent 架构评测结果（deterministic vs supervisor-worker）

- 生成时间：2026-10-25T14:30:12Z
- 任务集：`lab/agent-eval/tasks.json`（15 任务；类别：recon 4、exploit 3、chain 2、long-context 2、gateway 2、gpu-tenant 2）
- 网络边界：仅 127.0.0.1 仿真靶场 + 本地 fixture；写类模块不参与（probe-only）
- 审批口径：deterministic = 整批 1 次；supervisor-worker = 逐动作审批
- 故障注入：`gateway-auth` 首个动作首次尝试注入 `TimeoutError`（显式标注，用于测量重派恢复）

## 总览

| 模式 | 成功率 | 成功/总数 | 耗时 (ms) | token | 审批次数 | 重派 | 发现数 |
|---|---|---|---|---|---|---|---|
| deterministic | 93.3% | 14/15 | 4844 | 4288 | 1 | 0 | 225 |
| supervisor-worker | 100.0% | 15/15 | 2899 | 4387 | 32 | 1 | 230 |

## 差值

- 成功率差值：+6.7%
- 耗时差值：-40.2%
- token 差值：+2.3%
- 审批次数差值：+31

## 逐任务

| 任务 | 类别 | deterministic | supervisor-worker | 发现(d/s) |
|---|---|---|---|---|
| recon-exposure | recon | PASS | PASS | 18/18 |
| recon-kubelet | recon | PASS | PASS | 47/47 |
| recon-cis | recon | PASS | PASS | 50/50 |
| recon-secrets | recon | PASS | PASS | 48/48 |
| exploit-socket | exploit | PASS | PASS | 2/2 |
| exploit-cve | exploit | PASS | PASS | 13/13 |
| exploit-rbac | exploit | PASS | PASS | 20/20 |
| chain-weight-poison | chain | PASS | PASS | 15/15 |
| chain-gpu-tenant | chain | PASS | PASS | 1/1 |
| longctx-window | long-context | PASS | PASS | 2/2 |
| longctx-cache | long-context | PASS | PASS | 2/2 |
| gateway-auth | gateway | FAIL（TimeoutError: injected transient failure） | PASS | 0/5 |
| gateway-cache | gateway | PASS | PASS | 3/3 |
| gpu-metrics | gpu-tenant | PASS | PASS | 2/2 |
| gpu-mps | gpu-tenant | PASS | PASS | 2/2 |

## 结论

- 两种模式均可完整执行同一任务集；结果结构（成功率/耗时/token/审批/逐任务）完整。
- deterministic 单批审批、顺序执行：审批少，但无重派，遇到瞬时故障即任务失败（本次注入故障使其在 `gateway-auth` 失败）。
- supervisor-worker 逐动作审批（32 次）、有界并发、失败重派（本次重派 1 次）：在同一故障下恢复并完成任务。
- token 为确定性估算（CJK 按字 + 其余 4 字符/token），用于相对比较而非计费口径。
- 评测只覆盖本地仿真/快照；真实集群表现见 `docs/REAL-CLUSTER-VERIFICATION.md`。

