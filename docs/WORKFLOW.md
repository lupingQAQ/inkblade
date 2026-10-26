# Workflow / 流程

[English](#english) · [中文](#中文)

The order is the product. Each stage leaves behind something the next stage can check, and
any stage can refuse. This page is the long version of the eleven-step list on the site.

---

## English

### The eleven stages

| # | Stage | Command | Gate | Artifact |
|---:|---|---|---|---|
| 1 | Authorization | `quickstart`, `roe` | Signed consent record, hash pinned | `consent/` |
| 2 | Assets | `discover`, `import-scan`, `collect` | Read-only sources only | `assets.json`, collection snapshot |
| 3 | Reconnaissance | `run --module`, `surfaces` | Level 1–2 only | findings, surface matrix |
| 4 | Combination | `module list`, `assess explain` | No execution | ranked combinations |
| 5 | Chain planning | `execute --chain <id> --dry-run` | Preconditions evaluated | plan, write surface |
| 6 | Approval | `explore approve`, `autonomy`, `calendar` | Human decision or bounded pre-auth | approval record |
| 7 | Execution | `execute`, `exploit --real` | Consent + level + backup | action log, backups |
| 8 | Evidence | automatic | Manifest verified per step | `context.jsonl.gz`, `evidence.db`, `steps/` |
| 9 | Report | `report`, `export` | `--redact` before disclosure | bilingual reports, SARIF/OCSF/VEX |
| 10 | Rules | `rules generate`, `rules validate` | Replay must run | rule packs, coverage matrix |
| 11 | Retest | `schedule run-due`, `ci-gate` | Baseline exists | drift report, exit code |

### Stage 1 — authorization

Two commands, one purpose. `user add` creates the people; `quickstart` writes the record that
binds scope, level, window and emergency contact. The record is hashed, and the hash travels
with every run. If someone later asks “under what authority was this executed”, the answer is
one file, not a meeting.

Common mistake: signing a record that lists a namespace that does not exist yet. The gate does
not care. It will happily let you test a name, and you will get empty findings. Check the
target list first.

### Stage 2 — assets

Seeds in, asset table out. `discover` expands namespaces and services; `import-scan` folds
Trivy, Syft or grype results into the same findings model; `collect` takes a read-only snapshot
of the cluster, HTTP endpoints, files and hardware inventory.

Asset quality decides everything downstream. A missing namespace produces a clean report with
a hole in it, which is worse than a noisy report with a caveat.

### Stage 3 — reconnaissance

Level 1 and 2 modules only. 191 of the 286 modules sit at these levels: read-only enumeration
and active probing, no state change. Run `surfaces` with the collection directory and you get
the honest answer about what is testable here, including the modules that are not.

### Stage 4 — combination

Single findings are rarely the interesting part. Manifests carry combination signatures; two
low-severity findings that compose into cluster takeover are surfaced together, with their
preconditions written out. Nothing executes at this stage.

### Stage 5 — planning

`--dry-run` prints the resolved graph. Read the write surface. If a chain would touch
something you did not expect — a shared PVC, an admission webhook, a controller namespace —
stop and fix the scope rather than trusting the approval from last week.

Preconditions are evaluated by a small expression language, not `eval`. A step whose
precondition is unknown is skipped, not attempted.

### Stage 6 — approval

Three ways to say yes: a one-off approval with a name attached, a bounded pre-authorisation
with an explicit level and expiry, or a calendar window that opens during a maintenance slot.
All three leave a record. There is no “approve everything” switch, and `autonomy` cannot
exceed the level in the consent record.

### Stage 7 — execution

The backup gate is blunt: a write module without a backup target exits 91. With a target, the
runner snapshots first, executes second, and records both. If a step fails mid-chain, the
remaining steps do not run unless their dependencies are satisfied.

`rollback --run <id> --step <n>` restores one step and prints a receipt. A failed restore
exits 3 and marks the run; that mark shows up in the report, which is where you want it.

### Stage 8 — evidence

Three layers, every step. The context journal tells you what the tester saw. The SQLite
database answers queries: which findings, which actions, which backups, which rollbacks. The
tar archive plus manifest lets a third party verify one step without the rest of the run.

Hashes are computed over the archive, and the report anchors point at them. A finding that
cannot be replayed is downgraded during review — by us, before a client sees it.

### Stage 9 — reporting

Two reports, one evidence base. The pentest report follows the PTES structure and carries the
ML-specific chapters; the remediation report is a checklist for the platform team. `--lang bi`
produces both languages in one file. `--redact` strips zero-day detail before a report leaves
the engagement.

`export` is for machines: SARIF 2.1.0 for code scanning dashboards, OCSF for SIEM ingestion,
OpenVEX for “not affected” statements.

### Stage 10 — rules

Each chain maps to at least one rule. `rules generate --cni cilium` writes admission, network,
detection and convergence packs. `rules validate` replays them against mocks and produces a
matrix per chain: blocked, detected, missed.

The missed column is the useful one. A policy that everyone assumes works, and that the replay
says does not, is exactly the finding a purple team is paid to produce.

### Stage 11 — retest

`schedule add` takes a cron expression or an interval and a chain subset. `schedule run-due`
runs whatever is due and diffs the result against the baseline: new findings, resolved
findings, drift in configuration.

For pipelines, `ci-gate --fail-on high --new-only` exits non-zero on new high findings and
ignores the accepted backlog. That distinction is the difference between a gate people keep
and a gate people disable on a Friday.

### Failure modes worth knowing

| Situation | What happens | What to do |
|---|---|---|
| Consent record expired mid-engagement | Every run exits 91 | Re-sign with a new window; old evidence stays valid |
| Chain precondition false | Step skipped, chain continues where possible | Run the prerequisite module first |
| Backup target fills up | Write step refuses | Free space or point at a new target; do not skip |
| Surface unknown | Module skipped unless `--probe` | Confirm with the platform owner, then probe |
| Rollback fails | Exit 3, run marked | Treat the unrestored step as a finding and report it |

---

## 中文

### 十一个阶段

| # | 阶段 | 命令 | 闸门 | 产物 |
|---:|---|---|---|---|
| 1 | 授权 | `quickstart`、`roe` | 签署记录，哈希钉存 | `consent/` |
| 2 | 资产 | `discover`、`import-scan`、`collect` | 只接受只读来源 | `assets.json`、采集快照 |
| 3 | 侦察 | `run --module`、`surfaces` | 仅 1–2 级 | 发现、部署面矩阵 |
| 4 | 组合 | `module list`、`assess explain` | 不执行 | 组合排序 |
| 5 | 链编排 | `execute --chain <id> --dry-run` | 前置条件求值 | 计划、写面 |
| 6 | 审批 | `explore approve`、`autonomy`、`calendar` | 人工决定或有界预授权 | 审批记录 |
| 7 | 执行 | `execute`、`exploit --real` | 授权 + 级别 + 备份 | 动作日志、备份 |
| 8 | 证据 | 自动 | 每步校验 manifest | `context.jsonl.gz`、`evidence.db`、`steps/` |
| 9 | 报告 | `report`、`export` | 外发前 `--redact` | 双语报告、SARIF/OCSF/VEX |
| 10 | 规则 | `rules generate`、`rules validate` | 必须完成重放 | 规则包、覆盖矩阵 |
| 11 | 复测 | `schedule run-due`、`ci-gate` | 存在基线 | 漂移报告、退出码 |

### 第 1 步 — 授权

两条命令，一个目的。`user add` 建人，`quickstart` 写记录：范围、级别、时间窗、应急联系人。记录会算哈希，
哈希跟着每一次 run 走。日后有人问“凭什么是你们做的”，答案是一个文件，不是一场会。

常见错误：记录里写了一个还不存在的命名空间。闸门不管这个。它会老老实实让你测一个名字，然后给你一堆空发现。
先核对目标清单。

### 第 2 步 — 资产

种子进去，资产表出来。`discover` 展开命名空间与服务；`import-scan` 把 Trivy、Syft、grype 的结果折进同一套
发现模型；`collect` 对集群、HTTP 端点、文件与硬件清单做只读快照。

资产质量决定后面一切。漏掉一个命名空间，会得到一份干净但带洞的报告——比一份有噪音但写明前提的报告更糟。

### 第 3 步 — 侦察

只跑 1、2 级模块。286 个模块里有 191 个处在这两级：只读枚举和主动探测，不改状态。把采集目录交给 `surfaces`，
你会得到“这里到底能测什么”的诚实答案，包括那些不能测的。

### 第 4 步 — 组合

单条发现很少是有意思的部分。manifest 里带组合签名；两条单独看都不严重、叠起来能接管集群的发现，会被摆在一起，
前置条件写清楚。这个阶段不执行任何东西。

### 第 5 步 — 编排

`--dry-run` 打印解析后的链图。读写面。如果某条链会碰你没预料到的东西——共享 PVC、准入 webhook、控制器命名空间——
停下来修范围，而不是相信上周的审批。

前置条件用一个小的表达式求值器判断，不用 `eval`。前置未知的步骤会被跳过，不会被尝试。

### 第 6 步 — 审批

三种“同意”：署名的一次性批准；带级别与有效期的有界预授权；维护窗口内自动开启的日历窗口。三种都留记录。
没有“全部批准”开关，`autonomy` 也不能超过授权记录里的级别。

### 第 7 步 — 执行

备份闸门很直白：写类模块没有备份目标就退出 91。有目标时，先快照、再执行、两者都记录。链中途失败时，
依赖不满足的后续步骤不会运行。

`rollback --run <id> --step <n>` 恢复单步并打印回执。恢复失败退出 3 并把这次 run 标记出来；这个标记会进报告，
这正是它该在的地方。

### 第 8 步 — 证据

每一步三层。上下文日志告诉你测试者当时看到了什么；SQLite 库回答查询：哪些发现、哪些动作、哪些备份、哪些回滚；
tar 归档加 manifest 让第三方只验一步，不必拿到整次 run。

哈希算在归档上，报告锚点指向它。审阅时无法重放的发现会被降级——在我们手里降，不是在客户面前。

### 第 9 步 — 报告

两份报告，一套证据。渗透报告按 PTES 结构写，带 ML 专章；修复报告是给平台组的清单。`--lang bi` 一次出双语。
`--redact` 在报告离开项目前剥掉零日级细节。

`export` 给机器看：SARIF 2.1.0 进代码扫描面板，OCSF 进 SIEM，OpenVEX 用来声明“不受影响”。

### 第 10 步 — 规则

每条链至少对应一条规则。`rules generate --cni cilium` 生成准入、网络、检测、收敛四类规则包。
`rules validate` 对着 mock 重放，逐链产出矩阵：拦截、检出、漏过。

“漏过”那一列最有用。一条所有人都以为有效、重放却说无效的策略，正是紫队该交出来的发现。

### 第 11 步 — 复测

`schedule add` 接受 cron 表达式或固定间隔，加一个链子集。`schedule run-due` 跑到期的任务，与基线做差异：
新增发现、已修复发现、配置漂移。

流水线用 `ci-gate --fail-on high --new-only`：新增高危才非零退出，已接受的存量不管。这个区别决定了门禁是被保留，
还是周五被人关掉。

### 值得记住的失败模式

| 情况 | 会发生什么 | 怎么办 |
|---|---|---|
| 授权中途过期 | 所有 run 退出 91 | 用新窗口重签；旧证据仍然有效 |
| 链前置条件为假 | 跳过该步，能继续的继续 | 先跑前置模块 |
| 备份目标写满 | 写步骤拒绝 | 腾空间或换目标；不要跳过 |
| 部署面未知 | 模块跳过，除非 `--probe` | 先与平台负责人确认，再探测 |
| 回滚失败 | 退出 3，run 被标记 | 把恢复不了的那一步当发现报出去 |
