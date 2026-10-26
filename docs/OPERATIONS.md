# InkBlade（墨刃零）运营手册（HA / 升级 / 备份 / 多租户 / 交付边界）

> 适用版本：v0.2.0（2026-10-26）。本手册区分「本地已验证」与「生产必须具备但本仓库
> 未实现」；不得把 runbook 的存在写成「已演练/已上线」。
>
> 结论先行：当前交付形态是**单机试点/实验室**；HA、跨副本队列、客户 KMS、分布式
> 调度是 Production 的**外部依赖**，需按本文清单在客户环境补齐并演练。

## 1. 部署形态与能力边界

| 形态 | 组成 | 适用 | 明确不具备 |
|---|---|---|---|
| 单机 POC/Pilot | 1 个 API/CLI 进程 + 本地 `evidence/` + SQLite + 本机 worker | 只读清点、单客户小规模试点 | HA、多副本、跨 AZ、租户 KMS |
| 单机多租户 Lab | `lab/saas`：ThreadingHTTP + 多进程 worker + SQLite 原子配额 | 验证隔离/配额/审批语义 | 生产 SLA、分布式租约、真实 GPU 负载 |
| Production（客户） | 外部 LB + 多副本 API + Postgres/Redis（或等价队列）+ 共享证据存储 + KMS/HSM + 集中日志 | 企业生产 | 本仓库**未提供**这些组件的托管实现 |

**禁止宣称**：单机 SQLite 压测数字不是生产容量；`lab/saas` 不是商业 SaaS；
仓库内没有 HA 控制器/跨副本选主/租户 KMS。

## 2. HA runbook（Production 前置）

### 2.1 目标（需客户确认）

| 指标 | 建议目标 | 当前状态 |
|---|---|---|
| API 可用性 | 99.9%（客户 SLA 为准） | 单进程，无 HA |
| RTO | ≤30 min | 未演练 |
| RPO | ≤15 min（证据/审批元数据） | 依赖外部备份，未演练 |
| 证据完整性 | manifest 校验 100% | 本地 `verify_manifest` 已验证 |
| 租户隔离 | 跨租户 0 违规 | 单机压测 0 违规；非分布式 |

### 2.2 拓扑要求

1. **API**：≥2 副本，无状态；会话 token 需外部化（Redis/DB），不能依赖进程内
   `UserStore._sessions`。
2. **队列/租约**：Postgres `SKIP LOCKED` 或 Redis Streams/Kafka；worker 崩溃后
   lease 超时重派（当前单机实现会停在 `running`，需运维清理）。
3. **证据存储**：共享对象存储/NFS，开启版本与对象锁；manifest 与 DB 分离备份。
4. **数据库**：Postgres 主备/托管实例；审批/配额用事务与唯一约束，不能只靠 SQLite。
5. **KMS/HSM**：per-tenant 信封加密；密钥轮换与吊销流程。
6. **入口**：LB + mTLS/OIDC；管理面与执行面分网；SIEM 出站白名单。

### 2.3 故障切换演练（客户环境）

1. 触发条件：健康检查连续 3 次失败 / 节点驱逐 / DB 主备切换。
2. 步骤：摘除故障副本 → 确认队列租约未丢 → 新副本接管 → 校验进行中 run 的
   `actions`/`backups` 一致性 → 对 `running` 超时 run 标记 `failed` 并通知。
3. 验收：RTO ≤ 目标；无重复执行（幂等键：workspace+run+step）；证据 manifest 100% 通过。
4. 回退：若新副本无法接管，停止入口流量，保留证据，升级到平台 owner。

## 3. 升级 runbook

### 3.1 升级前

- [ ] 读取 `CHANGELOG`/commit 与 `pyproject.toml` 版本；确认 Python 3.10+。
- [ ] 备份 `evidence/`、`users.json`、`workspace.json`、`consent.json`、
      `approvals.json`、连接器/通知配置（见 §4）。
- [ ] 在预生产跑 `python -m unittest discover -s tests`；记录测试数与失败项。
- [ ] 冻结写验证窗口；通知 SOC/平台/数据 owner；确认回滚包可用。
- [ ] 检查 DB schema：当前 SQLite `evidence.db` 由代码 `CREATE TABLE IF NOT EXISTS`
      建表；跨大版本升级需先导出/迁移，不能假设自动兼容。

### 3.2 升级步骤

1. 停新任务入口（保留只读查询）；等待运行中 run 完成或超时。
2. 部署新版本到 canary 副本；跑只读 smoke：
   `inkblade roe`、`inkblade pilot --snapshot ...`、`inkblade export`。
3. 校验证据读写：新 run 的 `manifest.sha256` 与 `verify_manifest`；旧 run 可读。
4. 逐步放量；观察错误率、队列积压、证据写入延迟、SIEM 投递失败。
5. 完成后解除冻结，记录升级窗口与版本。

### 3.3 回滚

- 代码回滚到上一 tag；DB 若已迁移，按迁移脚本逆向或恢复备份（优先恢复）。
- 回滚后跑只读 smoke + 一条 dry-run 链；确认不重复执行历史动作。
- 失败升级必须保留现场证据（日志、DB 快照、manifest），24h 内出复盘。

## 4. 备份与恢复 runbook

### 4.1 备份对象

| 对象 | 路径/表 | 频率 | 保留 |
|---|---|---|---|
| 证据归档 | `evidence/<workspace>/<run>/steps/*` + `manifest.sha256` | 每 run 完成 | 合同期限（默认 365d） |
| 证据 DB | `evidence/<workspace>/<run>/evidence.db` | 每 run/每日 | 同上 |
| 授权 | `evidence/<workspace>/workspace.json`、`consent.json` | 变更即备 | 合同期限 |
| 用户 | `users.json` | 变更即备 | 合同期限；离职即回收 |
| 审批 | `approvals.json`（哈希链） | 变更即备 | 合同期限 |
| 集成配置 | 连接器/通知/SIEM/ITSM（不含明文 token） | 变更即备 | 合同期限 |
| 审计 | `actions` 表 + SIEM 副本 | 每日 | ≥180d（客户合规为准） |

### 4.2 备份命令（单机示例）

```powershell
# 停写后做一致性快照（示例；生产用存储快照/对象存储版本）
$stamp = Get-Date -Format yyyyMMdd-HHmmss
Compress-Archive -Path evidence,users.json -DestinationPath "backup-$stamp.zip"
# 校验：解压后逐 run 跑 verify_manifest
python -c "from inkblade.core.evidence import EvidenceStore; ..."
```

> 生产必须用客户批准的加密备份（KMS/HSM），备份介质与密钥分离；禁止把
> consent 私钥、SIEM token 明文放进普通 zip。

### 4.3 恢复演练

1. 在隔离环境解压；`EvidenceStore.verify_manifest` 对每个 run 校验。
2. 恢复 `workspace.json` 后验证 consent 签名（`roe_status == complete`）。
3. 恢复 `approvals.json` 后 `ApprovalChain.verify` 校验哈希链。
4. 抽查 3 个 run 的报告渲染与证据锚；记录 RTO/RPO 实测。
5. 失败项：manifest 不一致、签名失败、审批链断裂 → 停止，升级安全负责人。

## 5. 单机多租户并发压测（复用 lab/saas）

### 5.1 命令

```bash
python lab/saas/load.py --tenants 8 --concurrency 8 --requests 20 \
  --workers 4 --work-ms 30 --out reports/samples/saas/load.json
```

### 5.2 已记录结果（2026-10-26 复跑）

| 指标 | 值 |
|---|---:|
| 租户 / 每租户并发 / 请求 | 8 / 8 / 20 |
| 总尝试 / 提交成功 / 完成 | 1,280 / 382 / 382 |
| 配额拒绝（429） | 898（负载故意压过配额） |
| 隔离违规 / 跨租户 403 | **0 / 192** |
| 吞吐 | **17.58 runs/s** |
| submit p50 / p95 / p99 | 72.0 / 727.6 / 2,436.0 ms |
| complete p50 / p95 / p99 | 921.6 / 3,177.0 / 3,708.8 ms |
| 审批创建 / 成功 / 重复拒绝 / 越权拒绝 | 8 / 8 / 8 / 1 |

产物：`reports/samples/saas/load.json`、`reports/samples/saas/summary.md`；旧一轮
（17.26 runs/s）保留在 `docs/SAAS-LOAD-RESULTS.md`，差异来自本机调度/锁竞争。

**边界**：单机、单 SQLite、模拟模块（sleep + 2KB artifact）；延迟受 SQLite 写锁与
64 客户端轮询放大；**不是 SLA/容量承诺**。生产需 Postgres/Redis、多副本、真实
K8s/GPU 负载与网络。

### 5.3 压测判据

- 隔离违规必须为 0（跨租户 GET 403，body workspace 伪造 403）。
- 配额（并发/总量/证据字节）必须原子；重复审批只能一次成功（409）。
- worker 崩溃后的 `running` 泄漏必须由外部 lease/巡检处理（当前未实现）。
- 任何 p95 数字必须附「单机模拟」标签，不得写进客户 SLA。

## 6. 监控与告警（建议）

| 指标 | 阈值（试点） | 处置 |
|---|---|---|
| API 5xx 比例 | >1% 5min | 回滚/摘副本 |
| 队列积压 | >100 或 >10min | 扩容 worker/限流 |
| run `running` 超时 | >30min | 标记 failed、通知、查租约 |
| 证据写入失败 | >0 | 停写、查存储、保留现场 |
| manifest 校验失败 | >0 | 安全事件，隔离证据 |
| SIEM 投递失败 | >1% 或连续 3 次 | 告警、死信、人工补投 |
| 审批链校验失败 | >0 | 停止写验证，安全负责人介入 |
| 误报率（Pilot） | >20% | 暂停，调基线/例外清单 |

## 7. 许可证与交付边界

- **许可证**：Apache License 2.0；见 `LICENSE` 与 `NOTICE`。第三方/移植代码的
  归属与许可证见 NOTICE；不得移除版权/许可声明。
- **授权使用**：仅可对获得书面授权的资产测试；未签署 ROE/consent 时 CLI/API 拒绝执行。
- **无担保**：按 Apache-2.0「AS IS」提供；不承诺适销性/特定用途/不侵权。
- **交付物**：源码、测试、文档、样张；不含客户凭据、真实 IdP/SIEM/ITSM 账号、
  商业 SLA、保险、合规认证。
- **数据处理**：客户数据由客户负责分类/授权；InkBlade 只处理授权范围内的证据；
  跨境/驻留/保留期限按客户合同。
- **禁止用途**：未授权渗透、破坏性拒绝服务、绕过客户安全控制、隐瞒发现。
- **出口/制裁**：客户自行确认使用地法律与出口管制；本仓库不提供法律意见。
- **责任矩阵（建议）**：客户安全负责人（授权/验收）、平台 owner（集群/窗口）、
  数据 owner（数据/模型）、InkBlade 交付方（工具/支持）、法务（合同/合规）。
- **双签角色映射**：审批链要求 `lead` → `security-owner`；客户 IdP 的
  `inkblade-security-owners` 组映射平台 `admin`，签署时以审批角色 `security-owner`
  记录（不能把平台 `admin` 直接当第二签，避免角色混淆）。

## 8. 运营检查清单（每次 Pilot/Production 窗口）

- [ ] ROE/consent 完整且在窗口内；范围（namespace/CIDR）与客户确认。
- [ ] lead→安全负责人双签；备份/回滚预案签字。
- [ ] 只读通过率 ≥95%；采集命令仅 `get/list/watch`。
- [ ] 写动作逐个有 backup 回执；回滚演练 100%。
- [ ] 报告签核 6/6；证据 manifest 校验通过；保留策略登记。
- [ ] SIEM/ITSM 投递干跑通过；失败有死信/人工补投。
- [ ] 事后 24h 内复盘；P1 事故 0；未达标项进入下一阶段门槛。
