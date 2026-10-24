# Trident 架构 / Architecture

Trident 采用七层架构，运行时仅依赖 Python 3.10+ 标准库；所有执行路径统一经过授权闸门与备份闸门。

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ ⑦ 规则转化层  trident/rules/                                                  │
│    generate_all: 规则↔链覆盖率硬校验；validate: mock 重放 + 简化匹配器矩阵    │
├──────────────────────────────────────────────────────────────────────────────┤
│ ⑥ 可视化层    trident/webui/                                                  │
│    六视图 SPA（DAG/攻击链/时间线/证据/报告/规则）+ export_static 离线兜底     │
├──────────────────────────────────────────────────────────────────────────────┤
│ ⑤ 报告层      trident/reports/                                                │
│    PTES 七段 + 五个 ML 专节 + NIST/等保/GB-T 20984 + CVSS 3.1 + 双语渲染      │
├──────────────────────────────────────────────────────────────────────────────┤
│ ④ 证据层      trident/core/evidence.py                                        │
│    三层：context.jsonl.gz（摘要）/ evidence.db（SQLite）/ steps/*.tar + SHA256 │
├──────────────────────────────────────────────────────────────────────────────┤
│ ③ 模块层      trident/modules/<key>/{module.json, run.py}                     │
│    侦察 / 横向 / 权限链 / 窃取 / 核心代码 / 网络 / 混合云 / 绕过 / 零日级      │
├──────────────────────────────────────────────────────────────────────────────┤
│ ② 编排层      trident/core/chains.py + runner.py + backup.py                  │
│    dry-run → execute；依赖拓扑/并行；写类模块先备份；失败回滚；逐动作审计      │
├──────────────────────────────────────────────────────────────────────────────┤
│ ① 授权治理层  trident/core/roe.py + users.py + zeroday.py                     │
│    consent/ROE 签名 + 级别闸门 + 四角色 RBAC + 可选零日加密扩展（默认关闭）    │
└──────────────────────────────────────────────────────────────────────────────┘
```

## 各层职责 / Layer responsibilities

| 层 | 关键实现 | 职责 |
|---|---|---|
| ① 授权治理 | `core/roe.py`, `core/users.py`, `core/zeroday.py` | consent/ROE 哈希签存；只读侦察 → 主动探测 → 利用验证 → 全影响演示四级闸门；admin/lead/tester/auditor 角色；可选 `private` 模块加密扩展（默认关闭，当前 6 个零日级模块均为公开模块，不走该闸门） |
| ② 编排 | `core/chains.py`, `core/runner.py`, `core/backup.py` | 链前置三态判定（自实现表达式求值，禁 `eval`）；dry-run 预览写面；依赖拓扑与并行执行；备份闸门（退出码 91）；失败回滚 |
| ③ 模块 | `modules/*/module.json`, `modules/*/run.py` | 统一契约：`key/name/series/description/min_level/writes/requires`；`run(ctx, params) -> {summary, artifacts, findings}`；`private` 仅用于可选加密扩展 |
| ④ 证据 | `core/evidence.py` | 每步三层落证；`manifest.sha256` 逐文件校验；`findings`/`actions`/`backups`/`rollbacks` 审计表 |
| ⑤ 报告 | `reports/render.py`, `reports/cvss.py` | 双语渗透与修复报告；证据锚 = 步骤 + manifest sha256 前 16 位；零日级细节默认展示，`redact_zeroday=True` 可选脱敏 |
| ⑥ 可视化 | `webui/server.py`, `webui/export_static.py` | 本地控制台与六视图；静态导出 `window.TRIDENT_DATA`，`file://` 免服务打开 |
| ⑦ 规则转化 | `rules/generate.py`, `rules/validate.py` | 规则包（准入/网络/检测/收敛）；每链 ≥1 规则；紫队重放覆盖率矩阵（拦截/检测/漏过） |

## 运行边界 / Runtime boundaries

- 默认 mock 靶场 `lab/mock_targets.py` 仅监听 `127.0.0.1`，所有写盘限于注入的 `root`。
- 真实集群测试需要显式授权、kubeconfig 与网络可达性；平台不内置任何真实凭据。
- KIND 与 ARTEX 黑盒对标属实验室可选项，需启用虚拟化后按 `lab/kind/run-proof.sh`、`lab/bench/artex-bench.sh` 执行。
