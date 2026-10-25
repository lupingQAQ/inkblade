# SaaS 多租户本地压测结果（2026-10-25）

> **本地模拟，不是商业 SLA。** 单机、单 SQLite、模拟模块工作（sleep + 小 artifact），
> 不是跨 region/跨副本的分布式集群，也没有真实网络/存储/GPU 负载。所有数字只证明
> 本仓库租户隔离、配额、审批队列的并发语义，不构成生产容量承诺。

## 1. 架构

`lab/saas/service.py`：

```
ThreadingHTTP (request_queue_size=256)
  ├─ 静态 Bearer token → tenants 表（role/workspace/quota）
  ├─ POST /v1/runs：BEGIN IMMEDIATE → 原子检查 max_concurrent / max_runs /
  │                  max_evidence_bytes → INSERT queued → multiprocessing.Queue
  ├─ POST /v1/approvals/{id}/approve：BEGIN IMMEDIATE + UPDATE ... WHERE status='pending'
  │                  （单次生效；并发重复批准只有一个 rowcount=1）
  └─ GET /v1/runs|usage：按 token 过滤；跨租户 403

multiprocessing worker × N（Windows spawn）
  ├─ UPDATE runs SET status='running' WHERE status='queued'（抢占式）
  ├─ EvidenceStore(root, workspace=ws-<tenant>) → 真实 run 目录/步骤/manifest
  └─ UPDATE runs SET status='done'；异常 → failed + error
```

租户隔离用 `workspace`（`ws-<tenant>`）+ `EvidenceStore` 真实落盘；配额/审批用 SQLite
WAL + `busy_timeout=30s` + `BEGIN IMMEDIATE` 保证原子。没有跨副本一致性/租户 KMS/
Postgres/消息队列——这些是「分布式调度 / 多租户 SaaS」仍未达成的部分。

## 2. 压测配置与结果

命令：

```bash
python lab/saas/load.py --tenants 8 --concurrency 8 --requests 20 \
  --workers 4 --work-ms 30 --out reports/samples/saas/load.json
```

| 项 | 值 |
|---|---:|
| 租户数 | 8（+1 tester 租户用于越权测试） |
| 每租户并发客户端 | 8 |
| 每客户端请求数 | 20 |
| worker 进程 | 4 |
| 模拟工作 | 30 ms/run |
| 每租户 max_concurrent | 4 |
| 总尝试 | 1,280 |
| 提交成功（202） | 422 |
| 完成（done） | 422 |
| 配额拒绝（429） | 858 |
| 隔离违规 | **0** |
| 跨租户 403 | 192 |
| HTTP 错误 | 0 |
| 吞吐 | **17.26 runs/s** |
| 总耗时 | 24.45 s |
| submit p50 / p95 / p99 | 74.0 / 1,146.4 / 2,454.4 ms |
| complete p50 / p95 / p99 | 968.3 / 4,846.6 / 5,821.2 ms |
| 审批创建 / 成功 / 重复拒绝 / 越权拒绝 | 8 / 8 / 8 / 1 |

> 延迟被 SQLite 写锁 + 64 个客户端轮询放大；p95 不是产品 SLA。`quota_rejects` 高是
> 因为每租户 8 并发 > max_concurrent 4，负载故意压过配额以验证 429 语义。

产物：`reports/samples/saas/load.json`、`reports/samples/saas/summary.md`。

## 3. 测试矩阵（`tests/test_saas.py`，14 项）

| 用例 | 断言 |
|---|---|
| auth required | 无 token 401 |
| login | 正确 tenant/token 200；错误 401 |
| tenant isolation | A 的 run 被 B GET → 403；B 列表不含 A |
| concurrency quota | max_concurrent=1 时第二次提交 429 `max_concurrent` |
| run quota | max_runs=1 时第二次 429 `max_runs` |
| evidence quota | 超过 max_evidence_bytes 429 |
| approval role gate | tester 批准 403；其他租户 404 |
| approval single-use | 第一次 200；第二次 409；reject 已批准 409 |
| concurrent duplicate approval | 两线程并发批准，恰好一个 200 / 一个 409 |
| worker completion + evidence | 多进程 worker 完成；`EvidenceStore.verify_manifest` 通过；artifact 内容正确 |
| artifact determinism | 同 tenant/module/evidence 两次 artifact 字节一致 |
| workspace traversal | 非法 tenant 登录 401；body 伪造 workspace 403 |
| usage | runs/done/evidence/limits 正确 |
| load smoke 8 tenants | 8 租户并发，隔离违规 0，配额拒绝 >0，审批检查全通过 |

## 4. 配额与审批语义

- `max_concurrent`：按 `status IN ('queued','running')` 计数；提交时在 `BEGIN IMMEDIATE`
  内检查并插入，避免 N 个并发请求同时越过上限。
- `max_runs`：按租户累计 run 数（含历史）；达到后 429，管理员需归档/调额。
- `max_evidence_bytes`：单 run 上限 + 租户累计预算（`limit*8`）双重检查；
  本压测 2 KB/run，远离 1 MiB 上限。
- 审批：`approve` 必须 `role=lead`；`UPDATE ... WHERE status='pending'` 单次生效；
  重复/并发重复返回 409。审批是**单次**的，不做多级会签（单级 lead）。
- 隔离：workspace 由 token 绑定，请求体不能改；`EvidenceStore` 只读写自己的
  `evidence/<workspace>`；跨租户查询在 SQL 层按 tenant 过滤 + 403。

## 5. 边界与未达成

- **不是分布式**：单机 SQLite + 单 HTTP 进程；没有跨副本任务队列、租约/故障转移、
  Postgres/Redis/Kafka、跨 AZ 一致性。
- **不是商业 SLA**：没有真实 SLA/计费/限流网关/多 region；延迟受本机 SQLite 写锁
  与轮询影响很大。
- **没有按租户加密**：证据目录是普通文件系统权限；生产需 per-tenant KMS/envelope
  encryption + 密钥轮换。
- **没有真实工作负载**：worker 只写 2 KB artifact + sleep；没有 K8s API/GPU/网络。
- **审批只有单级 lead**：没有多级审批、四眼原则、审批超时/升级、跨副本幂等日志。
- **故障注入有限**：未测 worker 崩溃后的 lease 超时重派（当前 failed 由 worker 自己
  标记；进程被 kill 的 run 会停在 running，需要运维清理）。

## 6. 复现

```bash
python -m unittest tests.test_saas -v   # 14 tests
python lab/saas/load.py --tenants 8 --concurrency 8 --requests 20 \
  --workers 4 --work-ms 30 --out reports/samples/saas/load.json
```

## 7. 状态

| 子项 | 状态 |
|---|---|
| 多进程 worker + 8 租户并发 + workspace 隔离 | **模拟验证** |
| 原子配额（并发/总量/证据字节）与 429 | **模拟验证** |
| 审批单次生效 + 角色闸门 + 并发重复拒绝 | **模拟验证** |
| 真实分布式队列/跨副本配额/租户 KMS/HA | **仍未达成** |
