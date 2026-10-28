# InkBlade（墨刃零）架构 / Architecture

InkBlade 的控制端由七个组件组成，运行时只依赖 Python 3.10+ 标准库；所有执行路径都要经过授权校验与备份校验。
检测模型另有十层（前九层覆盖业务面，第十层是防护绕过），见 [`DETECTION-LAYERS.md`](DETECTION-LAYERS.md) 与 [`PRODUCT.md`](PRODUCT.md)。

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ ⑦ 规则转化层  inkblade/rules/                                                  │
│    generate_all: 规则与链的覆盖率校验；validate: 规则重放 + 匹配器矩阵        │
├──────────────────────────────────────────────────────────────────────────────┤
│ ⑥ 可视化层    inkblade/webui/                                                  │
│    六视图 SPA（DAG/攻击链/时间线/证据/报告/规则）+ 静态导出                    │
├──────────────────────────────────────────────────────────────────────────────┤
│ ⑤ 报告层      inkblade/reports/                                                │
│    PTES 七段 + 五个 ML 专节 + NIST/等保/GB-T 20984 + CVSS 3.1 + 双语渲染      │
├──────────────────────────────────────────────────────────────────────────────┤
│ ④ 证据层      inkblade/core/evidence.py                                        │
│    三层：context.jsonl.gz（摘要）/ evidence.db（SQLite）/ steps/*.tar + SHA256 │
├──────────────────────────────────────────────────────────────────────────────┤
│ ③ 模块层      inkblade/modules/<key>/{module.json, template.json}              │
│    侦察 / 横向 / 权限链 / 窃取 / 核心代码 / 网络 / 混合云 / 绕过 / 零日      │
├──────────────────────────────────────────────────────────────────────────────┤
│ ② 编排层      inkblade/core/chains.py + runner.py + backup.py                  │
│    dry-run → execute；依赖拓扑/并行；写类模块先备份；失败回滚；逐动作审计      │
├──────────────────────────────────────────────────────────────────────────────┤
│ ① 授权治理层  inkblade/core/roe.py + users.py + zeroday.py                     │
│    consent/ROE 签名 + 级别校验 + 四角色 RBAC + 可选零日加密扩展（默认关闭）    │
└──────────────────────────────────────────────────────────────────────────────┘
```

## 各层职责 / Layer responsibilities

| 层 | 关键实现 | 职责 |
|---|---|---|
| ① 授权治理 | `core/roe.py`, `core/users.py`, `core/zeroday.py` | consent/ROE 记录带哈希；只读侦察 → 主动探测 → 利用验证 → 全影响演示四级校验；admin/lead/tester/auditor 角色；可选 `private` 模块加密扩展（默认关闭） |
| ② 编排 | `core/chains.py`, `core/runner.py`, `core/backup.py` | 链前置条件三态判定（自行实现表达式求值，不使用 `eval`）；dry-run 列出写入；依赖拓扑与并行执行；备份校验（退出码 91）；失败回滚 |
| ③ 模块 | `modules/*/module.json`, `modules/*/template.json` | 统一元数据：`key/name/series/description/min_level/writes/requires`；模板声明 steps/checks/findings/artifacts；`private` 只用于可选的加密扩展 |
| ④ 证据 | `core/evidence.py` | 每个步骤写三层证据；`manifest.sha256` 逐文件校验；`findings`/`actions`/`backups`/`rollbacks` 审计表 |
| ⑤ 报告 | `reports/render.py`, `reports/cvss.py` | 双语渗透与修复报告；证据锚 = 步骤 + manifest sha256 前 16 位；零日细节默认展示，`redact_zeroday=True` 可脱敏 |
| ⑥ 可视化 | `webui/server.py`, `webui/export_static.py` | 本地控制台与六个视图；静态导出写入 `window.INKBLADE_DATA`，直接用 `file://` 打开 |
| ⑦ 规则转化 | `rules/generate.py`, `rules/validate.py` | 规则包（准入/网络/检测/收敛）；每条链至少一条规则；紫队重放覆盖率矩阵（拦截/检测/漏过） |

## 运行边界 / Runtime boundaries

- 真实集群测试需要显式授权与 kubeconfig，网络也要可达；仓库里不内置任何真实凭据。
- KIND 实验室验证是可选项，启用虚拟化后按 `lab/kind/run-proof.sh` 执行。
