# 覆盖闭包证明

- schema: `inkblade-coverage-proof/1`
- run: `coverage-demo-two-clusters`
- objective: `read-only-recon`
- stop_reason: `closed`
- closed: `True`
- success: `True`

## 1. 四条闭包判据

| 状态 | 判据 | 说明 | 缺口 |
|---|---|---|---|
| PASS | coverage:assets | 4/4 个可达资产已有 probe/只读检查 | 0 |
| PASS | coverage:permissions | 3/3 条可利用权限边已尝试 | 0 |
| PASS | coverage:probes | 2/2 个探针已注册并完成基线 collect | 0 |
| PASS | coverage:frontier | 0 个未处理 frontier/未收敛意图 | 0 |

## 2. 覆盖计数

| 对象 | 总数 | 已覆盖 | 比例 |
|---|---|---|---|
| 可达资产 | 4 | 4 | 1.0 |
| 可利用权限边 | 3 | 3 | 1.0 |
| 探针 | 2 | 2 | 1.0 |

- 已检测模板: 2（api-version, exposure）

## 3. 缺口清单

无。所有可达资产、可利用权限边、探针基线与 frontier 均已处理。

## 4. 覆盖图节点

| id | 类型 | 集群 | 名称 | 已检查 | 基线 |
|---|---|---|---|---|---|
| cluster:prod-a | asset | prod-a | prod-a | yes | - |
| cluster:prod-b | asset | prod-b | prod-b | yes | - |
| svc:prod-a/registry | service | prod-a | model-registry | yes | - |
| svc:prod-b/trainer | service | prod-b | trainer-api | yes | - |
| sa:prod-a/ml-agent | identity | prod-a | ml-agent | no | - |
| sa:prod-b/trainer | identity | prod-b | trainer | no | - |
| probe:prod-a/relay-a | probe | prod-a |  | no | yes |
| probe:prod-b/relay-b | probe | prod-b |  | no | yes |

## 5. 覆盖图边

| id | 源 | 关系 | 目标 | 可利用 | 尝试 |
|---|---|---|---|---|---|
| edge-1 | cluster:prod-a | exposes | svc:prod-a/registry | no | - |
| edge-2 | cluster:prod-b | exposes | svc:prod-b/trainer | no | - |
| edge-3 | sa:prod-a/ml-agent | can | svc:prod-a/registry | yes | blocked |
| edge-4 | sa:prod-a/ml-agent | can | svc:prod-a/registry | yes | failed |
| edge-5 | sa:prod-b/trainer | can | svc:prod-b/trainer | yes | success |

## 证据 / 限制

- 本文件由 `coverage-proof.json` 确定性渲染；JSON 是机器判据，Markdown 只供人工复核。
- `closed` 只表示四条判据成立；是否成功还必须由 objective 证据门控共同判定（`success`）。
- 覆盖检查与权限尝试必须带证据引用；失败/阻断必须带原因，缺一不计数。
- 未提供 planner 图时判据四无法证明，会输出 `frontier-unavailable`。
- 覆盖闭包证明的是“已声明的可达面被处理”，不是“不存在未发现资产”；资产发现本身的遗漏不在本证明范围内。
