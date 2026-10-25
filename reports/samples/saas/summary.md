# SaaS 本地压测摘要

**本地模拟，非商业 SLA。**

- 配置：{'tenants': 8, 'concurrency_per_tenant': 8, 'requests_per_client': 20, 'workers': 4, 'work_ms': 30, 'max_concurrent_per_tenant': 4, 'max_runs_per_tenant': 1000, 'evidence_bytes_per_run': 2048}
- 运行：382 submitted / 382 done / 898 quota rejects
- 吞吐：17.579 runs/s，总耗时 21.731s
- submit p50/p95/p99：72.033/727.612/2436.029 ms
- complete p50/p95/p99：921.596/3176.999/3708.761 ms
- 隔离违规：0（跨租户 403：192）
- 审批：创建 8 / 成功 8 / 重复拒绝 8 / 越权拒绝 1

## 每租户

| tenant | runs_total | done | active | evidence_bytes |
|---|---:|---:|---:|---:|
| tenant-00 | 40 | 40 | 0 | 80384 |
| tenant-01 | 32 | 32 | 0 | 64000 |
| tenant-02 | 54 | 54 | 0 | 109056 |
| tenant-03 | 40 | 40 | 0 | 80384 |
| tenant-04 | 69 | 69 | 0 | 139776 |
| tenant-05 | 51 | 51 | 0 | 102912 |
| tenant-06 | 51 | 51 | 0 | 102912 |
| tenant-07 | 53 | 53 | 0 | 107008 |

## Checks
- tenant_isolation: PASS
- quota_enforced: PASS
- approval_single_use: PASS
- approval_role_gate: PASS
- all_submitted_eventually_done_or_rejected: PASS
