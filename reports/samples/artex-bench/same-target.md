# ARTEX vs Trident — 同靶场同面扫描对比（same-target）

> 采集时间 2026-10-25T20:59:36；靶场 http://10.0.2.2:18080（lab/mock_targets.py，vulnerable）。ARTEX v0.3.23（QEMU TCG k3s VM 内，官方镜像、零改动），LLM 为脚本化计划器 mock（按其真实协议返回确定的 tool_calls 序列）；Trident 同链 flat-network-admin-plane-weight-poison 直接在本机执行。

## 1. 验收要点

- ARTEX 任务终态：**done**（任务 #1，提交→终态 13,510 ms）
- ARTEX worker 对靶场的真实 HTTP 请求：**3 次**（路径：/__routes__, /pause, /pull_weights）
- ARTEX 侧 finding：**1 条**（按级别 {"critical": 0, "high": 1, "medium": 0, "low": 0}）
- Trident 链执行：成功（sglang-admin-failopen=success, slime-weight-pull-poison=success）

## 2. 每步时延

### ARTEX（LLM 轮 + 工具执行）

| 步骤 | 时延 ms |
|---|---|
| goal-decompose (set_goals) | 214 |
| probe-1 GET /__routes__ | 168 |
| probe-2 POST /pause | 159 |
| probe-3 POST /pull_weights | 2,159 |
| set_goals | 1 |
| add_intent | 2 |
| report_finding | 1 |
| prove_goal | 1 |
| **合计（任务提交→终态）** | **13,510** |

### Trident（链步骤，证据库 started_at/finished_at）

| 步骤 | 时延 ms |
|---|---|
| sglang-admin-failopen | 1.9 |
| slime-weight-pull-poison | 1.6 |
| dry-run 计划 | 23.1 |
| **execute 合计** | **105.6** |

## 3. 总对比表

| 指标 | ARTEX | Trident | 说明 |
|---|---|---|---|
| total_ms | 13510 | 105.6 | ARTEX=任务提交→终态（含 3s 轮询粒度）；Trident=链 execute 墙钟 |
| requests | 3 | 5 | 靶场 /__stats__ 计数（同靶场同面） |
| tokens | in~84160/out~986 | 0 | mock 按请求体 chars/4 估算；Trident 全链确定性、零 LLM token |
| llm_calls | 12 | 0 | 按 agent {"goals": 2, "planner": 4, "worker": 5, "other": 1} |
| findings | 1 | 2 | ARTEX=report_finding 落库；Trident=链步骤成功数（各有证据语义） |
| rss_mib | 84.4 | 50.4 | ARTEX=任务窗口 docker stats 峰值（artex+pg 两容器）；Trident=执行进程工作集峰值 |
| cold_start_ms | 35710 | None | ARTEX 栈冷启动（PG+容器+迁移）；Trident 进程内启动亚秒 |

## 4. 口径与限制

- ARTEX 时延含 QEMU TCG 放大（纯软件仿真），绝对值不代表裸机；同宿主同窗口对比才有意义。
- ARTEX 的 LLM 为脚本化计划器 mock：协议真实（真实 tool_calls/工具执行/落库），决策是确定脚本，不代表模型质量。
- token 估算 = ARTEX 请求体字符数/4（mock 非真实分词器）。
- Trident 为 Windows 本机进程，直接访问 127.0.0.1:18080（与 ARTEX 经 10.0.2.2:18080 同一靶场实例）。
- 原始证据：{
 "mock_llm_log": "lab\\qemu-k3s\\out\\mock-llm.jsonl",
 "artex_raw": "lab\\qemu-k3s\\out\\artex-same-target-raw.txt",
 "target_stats": "lab\\qemu-k3s\\out\\mock-target-stats-artex.json",
 "trident_out": "lab\\qemu-k3s\\out\\trident-chain.json",
 "artex_tasks_json": "{\"active\":\"1\",\"tasks\":[{\"distinct_findings\":{\"total\":1,\"reports\":1,\"critical\":0,\"high\":1,\"medium\":0,\"low\":0,\"unassessed\":0},\"id\":\"1\",\"exploration_id\":1,\"name\":\"\",\"remark\":\"\",\"pinned\":false,\"description\":\"ARTEX same-target bench scan of the Trident mock lab at http://10.0.2.2:18080 (authorized lab).\",\"goal\":\"Probe the authorized lab target http://10.0.2.2:18080 without credentials: fetch its route manifest, exercise unauthenticated admin action and weight pull, and record confirmed endpoints as findings.\",\"status\":\"done\",\"created_at\":\"2026-10-25T12:52:12Z\",\"created_unix\":1792932732,\"completed_at\":\"2026-10-25T12:52:20Z\",\"completed_unix\":1792932740,\"last_activity_unix\":1792932741,\"paused\":false,\"queued\":false,\"tokens\":{\"input_tokens\":0,\"output_tokens\":0,\"cache_read_tokens\":0,\"cache_write_tokens\":0},\"goals_total\":1,\"goals_met\":1,\"in_flight\":0,\"findings\":{\"critical\":0,\"high\":1,\"medium\":0,\"low\":0},\"llm_profile_ids\":[],\"llm_failover_state\":\"default\",\"source_task_ids\":[],\"company_ids\":null,\"coverage_enabled\":true}]}",
 "collected_at": "2026-10-25T20:59:36"
}