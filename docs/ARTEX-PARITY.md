# ARTEX Clean-room 功能对齐（ARTEX-PARITY）

> **方法（clean-room）**：仅依据公开功能描述（`docs/FEATURE-BY-FEATURE-ARTEX.md`、
> `docs/COMPETITIVE-MATRIX.md`、公开协议/标准）与 InkBlade 自身架构约束独立实现。
> **未读取、未复制、未改编、未逐行翻译** ARTEX（Autumn-27/ARTEX、RuoJi6/ARTEX）
> 的 AGPL-3.0 源码；接口、数据模型、闸门与测试均为本项目独立设计。
> 生成日期：2026-10-25。

## 0. 结论

| 指标 | 结果 |
|---|---|
| 本轮功能族 | **8 / 8 完成**（LLM 池、通知、模板、日历、侧问、图快照、黑板、bounded 并发） |
| Backlog S/M | **30 / 30 清零**（S 13 + M 17；全部 done + 证据） |
| ARTEX `missing` 行 | **180 → done 70 / technical-infeasible 6 / not-applicable 104 / missing 0** |
| 新测试 | 8 个功能族 + 30 个 backlog 项，每组至少 1 组；含闸门/权限/只读/无网络断言 |
| 默认安全 | 新功能默认关闭或只读；所有执行路径复用 RoE/角色/备份三闸门 |

机器可读逐行处置见 [`artex-parity-rows.json`](artex-parity-rows.json)（可由
`scripts/build-artex-parity.py` 重建）。`tests/test_artex_parity.py` 锁定：
行数 = 180、`missing_unclassified = 0`、所有 done 行证据文件存在、本文件与 README/NOTICE 的 clean-room 声明存在。

## 1. 八个功能族

| # | 功能 | 实现（clean-room） | API / CLI | 测试 | 默认状态 |
|---|---|---|---|---|---|
| 1 | LLM 多模型池：端点/模型/权重/健康检查/失败切换/配额/调用留档 | [`inkblade/core/llmpool.py`](../inkblade/core/llmpool.py) | `GET /api/v1/llm/pool|records|models`、`GET /api/v1/tokens/*`；`inkblade llm-pool` | [`tests/test_llmpool.py`](../tests/test_llmpool.py) | **关闭**；`complete` 抛 `PoolDisabled` |
| 2 | 通知渠道 + 事件规则 + 投递重试 | [`inkblade/core/notify.py`](../inkblade/core/notify.py) | `/api/v1/notify/*`；`inkblade notify` | [`tests/test_notify.py`](../tests/test_notify.py) | **关闭**；投递 `suppressed`（可审计未发送） |
| 3 | 任务模板：链子集 + 参数预设 + dry-run 计划 + 从 run 反推 | [`inkblade/core/templates.py`](../inkblade/core/templates.py) | `/api/v1/templates*`；`inkblade template` | [`tests/test_templates.py`](../tests/test_templates.py) | 只读计划；不执行 |
| 4 | 计划任务日历：一次性窗口 + 暂停/恢复 + 日历视图 | [`inkblade/core/calendar.py`](../inkblade/core/calendar.py) | `/api/v1/calendar*`；`inkblade calendar` | [`tests/test_calendar.py`](../tests/test_calendar.py) | 不后台自动执行；`run-due` 须 ROE + execute |
| 5 | run 内侧问：tester 提问 → lead 回复，全程审计 | [`inkblade/core/threads.py`](../inkblade/core/threads.py) | `/api/v1/threads*`、`/api/v1/side-questions/{id}/*`；`inkblade threads` | [`tests/test_threads.py`](../tests/test_threads.py) | 只问答；**不触发执行** |
| 6 | 资产/攻击图快照 + 跨 run 差异（cold graph） | [`inkblade/core/graphsnap.py`](../inkblade/core/graphsnap.py) | `/api/v1/graph/*`；`inkblade graph` | [`tests/test_graphsnap.py`](../tests/test_graphsnap.py) | 只读重算；写盘仅快照目录 |
| 7 | 跨 run 上下文继承（只读黑板） | [`inkblade/core/blackboard.py`](../inkblade/core/blackboard.py) | `/api/v1/blackboard*`；`inkblade blackboard` | [`tests/test_blackboard.py`](../tests/test_blackboard.py) | 只读注入 `proposal.context.blackboard` |
| 8 | 已批准提议 bounded 并发执行（1–8，默认 1） | [`inkblade/core/explorer.py`](../inkblade/core/explorer.py) `execute(workers=)` | `POST /api/v1/explorer/execute {workers}`；`inkblade explore execute --workers` | [`tests/test_concurrency.py`](../tests/test_concurrency.py) | 默认 1；每动作独立 run/evidence.db |

### 1.1 安全闸门（与既有执行路径同源）

- **RoE**：`calendar.run_due`、`retest.run_retest(live=True)`、`explorer.execute(workers)`
  在 consent 未签署时抛 `ExecutionLocked`（API 423）；LLM 池/通知/模板/图/黑板默认不执行模块。
- **角色**：渠道/规则/模板/日历/黑板/LLM 端点写操作要求 lead/admin（approve）；
  tester 可提问与执行已批准提议；auditor 全只读；工作区隔离沿用 `Session.open_store`。
- **备份闸门**：新功能不新增写模块；`kubelet-surface` 为只读侦察；`connectors`/`notify`
  默认 dry-run/关闭；`pcap` 仅写本地证据文件。写类执行仍由 `runner` 强制备份回执（退出码 91）。
- **审计**：run 级动作写 `evidence.db.actions`；工作区级动作写 `audit.jsonl`；
  通知/侧问/重试/图快照/决策/复测均留摘要与证据锚。

## 2. ARTEX `missing` 行处置

`FEATURE-BY-FEATURE-ARTEX.md` 当前有 **180** 条 `missing` 行；本轮按以下口径逐行处置，
**没有一行保持 `missing`**：

| 处置 | 数量 | 覆盖 |
|---|---:|---|
| `done`（clean-room 等价） | **70** | notify 12、LLM/token 24、finding-case 归并 16、ScopesSentry 同步 7、侧问 5、情报 4、触发器 2 |
| `technical-infeasible` | **6** | `/api/update/{settings,check,apply,rollback,stream}`：无签名发布通道/供应链信任根，自动更新与回滚会破坏证据链完整性；升级由部署方在受控环境执行 |
| `not-applicable` | **104** | 见下方分类；均为 ARTEX 的 UI/PG/对话式 agent 产品形态，非本轮 8 功能或 S/M backlog |
| `missing` | **0** | — |

`not-applicable` 的 104 行分类（每行在 JSON 中带具体理由）：

| 类别 | 数量 | 理由（摘要） |
|---|---:|---|
| 对话式主 agent / agents / conversations / chat / visibility | 43 | InkBlade 无自主对话循环；自主性止步于 lead 审批的提议队列，侧问由 `threads.py` 承担 |
| PG 任务实体 / 分类 / 归档 / Web 工作区 / goal-scope-constraint | 30 | run + 三层证据库为一等对象；不引入可变任务实体与 Web 文件编辑器 |
| Next.js 页面 | 7 | CLI/REST/MCP/静态 SPA 形态；页面不是功能闸门 |
| companies 多租户 | 6 | 工作区 + 四角色隔离；多租户 SaaS 属 L 项 CM-31 |
| PostgreSQL 配置键 | 6 | SQLite/JSON 存储 |
| intercept AI judge | 3 | 人工审批为确定性闸门；AI 自动放行不可审计 |
| agent loop compaction/noa/wrapup | 3 | 无自主 agent 循环 |
| HTTP Basic Auth | 3 | Bearer 会话 + 反向代理（含一条续行） |
| web-search / python-detect / playwright skill | 3 | 外部检索/解释器/浏览器 skill 不在产品边界 |

> 说明：`partial` 行（201 条）不在“missing 归零”口径内；其中与本轮 8 功能直接相关的
> 模板、流量快照、图、日志/检索、任务情报、finding-case、触发器、side-question 已由下列
> 实现升级为等价能力；其余 partial 行维持原登记。

### 2.1 与 8 功能直接相关的 partial → done 等价

| ARTEX partial 面 | 本轮等价实现 |
|---|---|
| 任务模板（链模板已有） | `core/templates.py`（实体 CRUD + 参数预设 + 计划 + 从 run 反推） |
| traffic_evidence_snapshots | `core/pcap.py`（traffic ↔ pcap）+ `core/retest.py`（断言复测） |
| graph_nodes/graph_edges（运行内图） | `core/graphsnap.py`（cold graph 快照/差异/UI）+ `core/pathcalc.py` |
| JSONL artifacts 日志 | `core/search.py`（跨 run 全文检索 + 证据锚）+ `GET /api/v1/logs` |
| task_intelligence | `core/intel.py`（metadata/redact/raw 三态 + 证据绑定） |
| finding_cases | `core/dedupe.py`（跨 run 归并 + 根因确认 + 统一报告） |
| triggers | `core/scheduler.py` + `core/calendar.py`（cron/interval/一次性窗口/暂停） |
| side questions | `core/threads.py`（提问/回复/取消/事件，不执行） |

## 3. Backlog S/M 清零（COMPETITIVE-MATRIX §5）

S 13 + M 17 = **30 项全部 done**；L 3 项不在本轮 S/M 范围。

| ID | 一句话 | 实现 | 测试 | 状态 |
|---|---|---|---|---|
| CM-01 | run 级凭据/线索/敏感数据 registry（证据绑定） | `core/intel.py` | `test_backlog_s.TestIntel` | done |
| CM-02 | 跨 run 过程全文检索 + 证据锚 | `core/search.py` | `test_backlog_s.TestSearch` | done |
| CM-03 | 决策/意图留档（规划器理由/选择） | `core/decisions.py`；`inkblade plan --record` | `test_backlog_s.TestDecisions` | done |
| CM-04 | 定时调度 + 测试窗口（ROE 内） | `core/scheduler.py` + `core/calendar.py` | `test_scheduler`、`test_calendar` | done |
| CM-05 | legacy SA token 逐 token SSRR/SSAR 审计 | `core/tokenaudit.py` | `test_backlog_s.TestTokenAudit` | done |
| CM-06 | 敏感证据 raw/redact/metadata 三态引用 | `core/intel.py` | `test_backlog_s.TestIntel` | done |
| CM-07 | VID 式漏洞 KB 条目（中英双语） | `core/kb.py` | `test_backlog_s.TestKB` | done |
| CM-08 | kubelet 10250 面扫描模块 | `inkblade/modules/kubelet-surface/` | `test_backlog_s.TestKubeletModule` | done |
| CM-09 | Falco 宏/列表复用规则模型 | `core/rulemacro.py` | `test_backlog_s.TestRuleMacro` | done |
| CM-10 | 规则/告警多路分发（stdout/file/syslog/program/http） | `core/dispatch.py` + `core/notify.py` | `test_backlog_s.TestDispatch`、`test_notify` | done |
| CM-11 | CI/CD exit code 契约 + 机器摘要 | `core/cigate.py`；`inkblade ci-gate` | `test_backlog_s.TestCiGate` | done |
| CM-12 | 声明式评估配置（YAML/JSON 矩阵 + 基线） | `core/evalconfig.py` | `test_backlog_s.TestEvalConfig` | done |
| CM-13 | Trivy/Syft/grype → findings；ScopesSentry 资产同步 | `core/importers.py`；`inkblade import-scan` | `test_backlog_s.TestImporters` | done |
| CM-14 | finding 级确定性复测 + 结论留档 | `core/retest.py` | `test_backlog_m.TestRetest` | done |
| CM-15 | 工单/SIEM 直投连接器 | `core/connectors.py` | `test_backlog_m.TestConnectors` | done |
| CM-16 | 探索血缘图 goal→intent→fact→finding | `core/lineage.py` | `test_backlog_m.TestLineage` | done |
| CM-17 | 同根因归并 + 统一报告 | `core/dedupe.py` | `test_backlog_m.TestDedupe` | done |
| CM-18 | pcap 级录制/回放（离线；live MITM 见边界） | `core/pcap.py` | `test_backlog_m.TestPcap` | done（限定） |
| CM-19 | Sankey 攻击路径 + 修复优先级 | `core/sankey.py` | `test_backlog_m.TestSankeyPathCalc` | done |
| CM-20 | CTEM 五阶段报告叙事 | `core/narrative.py`；`inkblade report-ctem` | `test_backlog_m.TestNarrative` | done |
| CM-21 | 泄露凭据有效性验证（fixture 驱动） | `core/credcheck.py`；`inkblade credcheck` | `test_backlog_m.TestCredCheck` | done |
| CM-22 | in-pod 只读采集器（safe 模式等价） | `core/inpod.py` | `test_backlog_m.TestInPod` | done |
| CM-23 | 攻击路径最短/关键节点/割点 + 图查询 | `core/pathcalc.py` | `test_backlog_m.TestSankeyPathCalc` | done |
| CM-24 | admission dry-run/fuzz 探测 | `core/admission.py` | `test_backlog_m.TestAdmission` | done |
| CM-25 | Tetragon TracingPolicy 目标 | `core/policygen.tetragon_policy` | `test_backlog_m.TestPolicyGen` | done |
| CM-26 | KubeArmorPolicy LSM 阻断目标 | `core/policygen.kubearmor_policy` | `test_backlog_m.TestPolicyGen` | done |
| CM-27 | Kyverno CEL + verifyImages 目标 | `core/policygen.kyverno_policy` | `test_backlog_m.TestPolicyGen` | done |
| CM-28 | 存量资源 background 合规覆盖矩阵 | `core/policygen.background_coverage` | `test_backlog_m.TestPolicyGen` | done |
| CM-29 | Crescendo/TAP 多轮策略 + 评分器 | `core/llmredteam.py` | `test_backlog_m.TestLLMRedTeam` | done |
| CM-30 | agent 工具面注入基准 | `core/agentbench.py` | `test_backlog_m.TestAgentBench` | done |
| CM-31/32/33 | 多租户 SaaS / garak 级探针族 / CIS 模块族 | — | — | L，超出 S/M 范围 |

## 4. 复现

```bash
python -m unittest tests.test_llmpool tests.test_notify tests.test_templates \
  tests.test_calendar tests.test_threads tests.test_graphsnap tests.test_blackboard \
  tests.test_concurrency tests.test_backlog_s tests.test_backlog_m tests.test_webui_ext -v
python scripts/build-artex-parity.py
python -m unittest tests.test_artex_parity -v
```

## 5. 已知边界（诚实声明）

1. **LLM 池**：测试使用注入的 OpenAI 兼容 transport（无真实厂商端点）；启用后仍建议先用
   `health` 与配额验证。默认关闭。
2. **通知**：webhook/Slack 真实 HTTP 仅在显式启用 + 规则 + 投递时发生；邮件是 **stub**
   （渲染 EML、落库、不发 SMTP）。
3. **pcap**：支持 traffic ↔ 标准 libpcap 双向转换与离线回放；**不做在线 MITM 抓包**，
   因为需要特权网络位置/流量镜像（运维在授权位置采集后导入即可获得同等证据链）。
4. **live 面**：kubelet 扫描、in-pod 采集、admission dry-run、凭据有效性、retest live 均
   需要授权环境；测试以 fixture/注入 transport 验证算法与闸门，不在测试中触达真实目标。
5. **ARTEX 产品形态差异**：对话式主 agent/PG 任务实体/Next.js 页面/自动更新等 110 行
   （104 N/A + 6 technical-infeasible）不是能力缺失，而是架构不适用或技术不可行，理由逐行
   记录在 JSON。
6. **外部依赖**：核心实现仅标准库；`core/search.py` 的 `.zst` 归档检索在未安装 zstandard 时
   跳过（gzip 始终可用），不阻断其它命中。
