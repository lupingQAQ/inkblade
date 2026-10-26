# UX 产品化评估：错误人话 · 空态/引导 · 双语 · 10k 渲染 · kubeconfig→pilot

> 日期：2026-10-26
> 方法：**专家走查（expert heuristic walkthrough，非真实用户数据）** + 可复现基准
> 环境：Windows 11 · Python 3.12.15（reproenv-d）· Chrome/Edge headless ·
> 本地 mock/离线 snapshot；不连接真实集群、不发外网
> 复现：`python scripts/usability-walkthrough.py`、
> `python scripts/ui-perf-run.py --runs 3`；原始 JSON 在
> `reports/samples/usability/walkthrough.json`、`reports/samples/ui-perf/10k-render.json`

## 0. 口径与诚实声明

- 本文的「用户」是 **5 个 persona 角色**，由实现者按脚本执行；**不是真实用户**、
  不是受试者、不是可用性实验，不构成 SUS 分数/统计显著性/认证。
- 「前后对比」的“前”指本任务开始前的仓库在途状态（可复现：HEAD 的
  `humanize.catalog()` 只解析出 17 个错误码、`onboard-cluster` 引用缺失模块、
  UI 无 i18n、报告全量渲染 10k 行）；“后”指本任务 commit。
- 性能数字是**相对比较**，不是 SLA；合成数据，不代表真实客户字段分布。
- 真实集群只做了离线 snapshot 的只读 pilot 预演；未验证真实 kubectl 网络/
  RBAC/规模。

## 1. 前后对比总表

| 维度 | 前（在途状态，实测/代码审查） | 后（本任务） | 证据 |
|---|---|---|---|
| 错误人话覆盖 | `catalog()` 仅 **17** 个唯一错误码；35 条 fixture 多数被错误折叠（`_materialize` 收到 tuple，未还原异常类型） | **34** 个唯一错误码（E101–E111 / E201–E208 / E301–E303 / E401–E403 / E501–E503 / E601–E603 / E701 / E801 / E900），每条都有「发生了什么/为什么/怎么修」+ 可执行命令 | `humanize.catalog_codes()`；`tests/test_ux_productization.py::TestHumanizeCatalog` |
| UI 空态 | 多数视图只有一行「暂无…」或直接空白；无下一步命令 | **10/10 视图**统一引导空态：标题 + 原因 + 可复制命令（`demo` / `onboard-cluster --dry-run`）+ 真实集群提示 | `app.js::EMPTY_STATES/emptyState`；`TestUIProductization` |
| 双语 | 仅中文硬编码 | **中/英切换**（header `EN/中文`，localStorage 记忆，`data-i18n` 静态文案 + `t()` 动态视图；90+ 词条） | `index.html`、`app.js::I18N/applyI18n/setLang` |
| 10k findings 渲染 | 一次性建 **10,000 行 / 90,040 个报告 DOM**；同步 **114.2 ms** | 默认 200 行/页；**6.7 ms**、1,840 个报告 DOM；显示更多 +200；`?perf=legacy` 保留旧路径 | `docs/UI-PERF.md` |
| kubeconfig→pilot | CLI 有 `onboard-cluster` 但 `trident/cluster_wizard.py` **缺失**，执行即 ImportError | 自动发现（显式 > `KUBECONFIG` > `~/.kube/config` > `~/.kube/*.yaml`）→ 解析/合并/列 context → dry-run 打印下一步 → 只读 pilot；失败走 E101/E701 人话 | `trident/cluster_wizard.py`；`TestClusterWizard` |
| 5 角色走查 | 旧 onboarding 评估：7 条命令、3 次失败、2 次前台阻塞、首次有效结果未达成 | **10 步 / 0 失败 / 5 角色全绿**；总 9.740s；首条结果 3.758s；p50 338.0ms、p95 3758.4ms | `reports/samples/usability/walkthrough.json` |
| 错误路径可见性 | API/资产/差异失败常只有静默空或裸 `e.message` | 空态/加载失败可操作提示；差异失败带 `drift.json`/静态导出指引 | `app.js` |

## 2. 错误人话：10 → 34 类

### 2.1 之前为什么只有 17 类

`catalog()` 把 `(code, spec)` 元组整体传给 `_materialize`，后者只识别 `dict`，
于是 `FileNotFoundError` 等真实异常没有被还原，`explain_exception` 只能按字符串
子串命中少数分支；最终 35 条 fixture 折叠成 17 个码。这是“看起来有 30 类、实际
计数不成立”的典型回归。

### 2.2 修复

- `_materialize(spec)` 接收单条 spec，按 `kind` 还原真实内置异常
  （`FileNotFoundError` / `ModuleNotFoundError(name=...)` / `OSError(errno)` /
  `ConnectionRefusedError` / `TimeoutError` / ...），保留 `isinstance/errno/name`；
-  `PilotError` 的 E701 判定提前到通用 YAML/JSON 解析兜底（E111）之前，避免
  kubeconfig 解析失败被错误归类；
- `catalog()` 去重后按码排序，测试断言 **≥30 类**且每条三行式 + fix 长度 >10。

### 2.3 覆盖族

| 族 | 码 | 例子 |
|---|---|---|
| E1xx 环境/安装 | E101–E111 | kubeconfig 缺失、可选依赖、端口占用、bash、磁盘满、超时、SSL、配置解析、Python 版本 |
| E2xx 授权/权限 | E201–E208 | consent 未签、级别不足、越界、时间窗、角色权限、字段缺失、向导取消、未知角色 |
| E3xx 备份/回滚 | E301–E303 | 备份回执缺失、对象不存在、回滚校验失败 |
| E4xx 存储/对象 | E401–E403 | run/工作区不存在、demo 拒绝、证据库损坏 |
| E5xx 混沌 | E501–E503 | 中止、稳态拒绝注入、回滚未恢复 |
| E6xx API | E601–E603 | 401/403/423 授权锁 |
| E7xx 试点 | E701 | kubeconfig/试点输入不可用 |
| E8xx 计划 | E801 | cron/interval 非法 |
| E9xx 未知 | E900 | 兜底 + `TRIDENT_DEBUG=1` 才出堆栈 |

## 3. UI 空态与引导（10/10 视图）

统一组件 `emptyState(view)`：

- 图标/编号（①–⑩）+ 标题（说清“为什么空”）+ 说明（数据来源）；
- 两条**可复制**命令：`python -m trident demo`（本地结果）与
  `python -m trident onboard-cluster --dry-run`（真实集群只读预演）；
- 每个视图有专属下一步：DAG/时间线/证据 → demo；报告 → quickstart 授权；
  资产 → discover；差异 → schedule run-due；审批 → explorer propose；计划 →
  schedule add。
- 复制失败（`file://`/剪贴板权限）降级为可手动选择的命令文本，不弹错误。

首屏 demo 引导卡增加三步流（doctor → demo → 真实集群 dry-run）与 kubeconfig
自动发现说明；关闭状态仍用 localStorage 记忆。

## 4. 双语切换

- Header 右上 `EN / 中文`；默认中文，选择写入 `localStorage["trident-lang"]`；
- `index.html` 的静态文案用 `data-i18n`，`app.js` 动态视图用 `t(key, vars)`；
- 覆盖：导航十视图、状态五色、报告统计/表头/分页/脱敏、空态十套、资产/差异/
  审批/计划、登录/模式提示、页脚；
- 未做：翻译公司审校、RTL、日期/数字本地化（已知差距，见第 8 节）。

## 5. 10k findings 渲染

完整方法/局限见 `docs/UI-PERF.md`；核心数字：

| 指标（中位数，3 次） | 优化前 | 优化后 |
|---|---:|---:|
| 同步渲染 | 114.2 ms | **6.7 ms** |
| tbody 行数 | 10,000 | 200 |
| 报告 DOM | 90,040 | 1,840 |
| body DOM | 90,195 | 1,994 |
| JS 堆 | 7.6 MiB | 5.6 MiB |
| load | 268.7 ms | 319.7 ms（无稳定差异） |

产品取舍：默认 200 行/页 + “显示更多”，保证打开报告不冻结；`?perf=legacy`
只用于回归/对照。静态导出 2.5 MB 内嵌数据仍是 load 的主要成本。

## 6. kubeconfig → pilot 引导流

```powershell
# 零参数：自动发现 KUBECONFIG / ~/.kube/config / ~/.kube/*.yaml
python -m trident onboard-cluster --dry-run

# 指定文件 + 只看某个 context
python -m trident onboard-cluster --kubeconfig ~/.kube/config --context prod --dry-run

# 离线/客户先导：用 kubectl get 导出的 snapshot，不连集群
python -m trident onboard-cluster --snapshot east-prod.json --out reports/pilot
```

流程：

1. **发现**：显式 `--kubeconfig` 优先；否则 `KUBECONFIG`（可多路径）→
   `~/.kube/config` → `~/.kube/*.yaml|*.yml`；去重。
2. **校验/合并**：stdlib YAML 子集解析，列 clusters/contexts/users、来源与冲突；
   解析失败 → E701 人话（先 dry-run、换 snapshot、看 conflicts）。
3. **选择 context**：`--context` 可重复；未给则默认全部（非交互不阻塞 stdin）；
   不存在的 context → 明确列出可用值。
4. **dry-run**：打印将执行的 `trident pilot ...` 命令 + JSON 摘要，不调用
   kubectl、不写文件。
5. **执行**：只读 pilot（`allow_write=False`）→ 报告/审批清单/manifest；
   写计划不在此向导暴露，仍需三闸门。
6. **失败**：找不到 kubeconfig → E101（含 `doctor`/`demo` 备选路径）；
   snapshot 缺失 → 三行式错误；退出码 2，不抛堆栈。

实测：`east-prod.json` dry-run 0.21s，列出 context `east-prod` 与下一步命令；
非 dry-run 只读清点 1 context / 8 nodes / 4 GPU nodes / 32 findings。

## 7. 5 角色专家走查（非真实用户）

### 7.1 角色与步骤

| 角色 | 目标 | 步骤（实测） | 结果 | 耗时 |
|---|---|---|---|---|
| 平台管理员 platform-admin | 环境可用 + 首条发现 | `doctor --mode mock` → `demo --json` | 2/2 | 0.495s + 3.758s |
| 安全负责人 security-lead | 授权状态 + 真实集群只读预演 | `roe --workspace demo-lab` → `onboard-cluster --snapshot ... --dry-run` | 2/2 | 0.251s + 0.257s |
| 渗透测试员 pentester | 模块清单 + 链 dry-run | `module list` → `execute --chain ... --dry-run` | 2/2 | 0.302s + 0.381s |
| 审计员 auditor | 双语报告 + CTEM 叙事 | `report --run ... --kind pentest --lang bi` → `report-ctem` | 2/2 | 0.494s + 0.315s |
| ML 平台工程师 ml-engineer | 混沌目录 + 延迟/断连/PFC 实跑 | `chaos list --json` → `chaos run <3 实验>` | 2/2 | 0.338s + 3.148s |

### 7.2 汇总指标（来自 `walkthrough.json`）

| 指标 | 值 |
|---|---:|
| 角色数 | 5 |
| 步骤数 | 10 |
| 失败步骤 | 0 |
| 成功率 | 100% |
| 总耗时 | 9.740s |
| 平均步骤 | 974.0 ms |
| p50 / p95 步骤 | 338.0 ms / 3758.4 ms |
| 首条有效结果（demo） | 3.758s |
| 全绿角色 | 5/5 |
| 错误码 | 无 |

说明：

- 首条结果 3.758s 与 `docs/ONBOARDING-EVALUATION.md` 的 5.33s 同量级（机器负载/
  是否导出 UI 会波动），**不作为 SLA**；关键是 0 失败、0 阻塞。
- p95 由 chaos 三实验步骤（3.0s）拉高，属于真实注入+回滚+恢复断言的预期成本，
  不是 UI 卡顿。
- 旧 onboarding 基线是 7 条命令、3 次失败、2 次前台阻塞、首次有效结果未达成；
  本任务把“平台管理员到首条结果”压到 2 条命令，且其余角色复用同一 run。

### 7.3 SUS 模板（未施测）

- 状态：**template-only**，`responses=[]`；不得把模板/专家走查当作 SUS 分数。
- 10 条标准 SUS 陈述（中英），1=非常不同意 … 5=非常同意；
- 计分：奇数题 `响应-1`，偶数题 `5-响应`，总分 `10 题和 × 2.5`（0–100）；
- 建议：至少 10 名真实受试者、独立任务、同一环境；n<10 不报告中位数/均值。

完整模板在 `reports/samples/usability/walkthrough.json` 的 `sus_template`。

## 8. 仍存风险（诚实清单）

1. **非真实用户**：5 个 persona 由实现者执行；没有招募、没有知情同意、没有
   行为数据；不能推断真实客户的学习曲线或满意度。
2. **未做 SUS**：模板/公式就绪，但无受试者响应；任何“SUS 分数”都是伪造。
3. **真实集群未端到端**：kubeconfig 发现/解析/context 选择已测，真实 kubectl
   网络、RBAC、规模、超时未测；离线 snapshot 不等于客户生产。
4. **双语未审校**：英文为工程翻译，未经过母语技术写作/术语一致性审校；长句
   在窄屏可能换行不美观。
5. **服务模式未分页**：10k 优化只覆盖静态导出；服务模式 `/api/report` 仍可能
   一次返回全量 findings，后端游标/分页是下一步。
6. **静态导出体积**：2.5 MB 内嵌 JSON，load ~281ms；低端设备/移动网络会更慢。
7. **可访问性未审计**：颜色对比、键盘焦点、屏幕阅读器、ARIA 只做了基础
   `aria-label`；未跑 WCAG/axe。
8. **空态命令仍偏技术**：虽然可复制，但“onboard-cluster --dry-run”对非工程
   角色仍有认知门槛；下一步应提供向导式表单/按钮，而不是只给命令。
9. **错误码覆盖是目录口径**：34 类来自 representative fixtures；真实异常仍可能
   落到 E900，需要持续从现场日志补 fixture。
10. **性能数字非 SLA**：本机 Chromium headless、合成数据；真实客户数据/终端/
    浏览器版本会不同。

## 9. 复现

```powershell
# 错误码目录（应 34 类）
python -c "from trident.core.humanize import catalog_codes; c=catalog_codes(); print(len(c), c)"

# 5 角色专家走查 → JSON + SUS 模板
python scripts/usability-walkthrough.py

# 10k 渲染 fixture + Chromium headless 实测
python scripts/ui-perf-bench.py --findings 10000
python scripts/ui-perf-run.py --runs 3

# 定向测试
python -m unittest tests.test_ux_productization tests.test_spa tests.test_onboarding -v
```
