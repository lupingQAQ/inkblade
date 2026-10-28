# 陌生用户走查评估：基线 vs 零摩擦改造 / Onboarding Evaluation

> 评估日期：2026-10-26（基线 2026-10-25 夜至 2026-10-26 跨日复测）
> 环境：Windows 11 · Python 3.12.15（任务提供的隔离解释器）· 无 kubeconfig · 无外网依赖
> 方法：在临时目录下新建临时克隆；**只按 README.md 操作**，不读源码、不问人；逐条记录命令、原文报错、耗时与卡点。

## 0. 先决条件与口径

| 项目 | 基线（改造前） | 改造后 |
|---|---|---|
| 获取代码 | `git clone --local` 临时目录（HEAD `bec5b1a`） | 临时克隆（HEAD + 本任务文件，等价于最终 commit） |
| Python | 3.10+；本机 `python` 是 Microsoft Store 别名，实际使用任务提供的 `reproenv-d` 3.12.15 | 同上（README 已写明先决条件） |
| kubeconfig | 不需要（mock） | 不需要（demo/mock）；quickstart 才需要 |
| 网络 | 不需要 | 不需要 |
| 计时 | 每条命令的实际墙钟；汇总为「到首次有效结果」 | 同左 |
| 「有效结果」定义 | 命令生成**渗透测试报告或发现**；`module list` 的清单、单元测试 PASS 不算 | 同左（`demo` 打印发现并落盘双语报告） |
| 失败 | 非零退出、崩溃、或命令永久阻塞（需手动 Ctrl+C/杀进程） | 同左 |

> 说明：本机 `python` 命令本身不可用（Windows Store 别名）。为保证可复现，走查统一用任务提供的 Python 3.12.15 完整路径；这等价于一个已正确安装 Python 的陌生用户。该先决条件已补进新 README 顶部。

## 1. 基线走查（改造前，实测）

按旧 README「快速开始」顺序执行。命令数 **7**（安装、全量测试、前台 mock、模块清单、UI、e2e、effects）。

| # | 命令（原文） | 结果 | 耗时 | 原文报错/卡点 |
|---|---|---|---|---|
| 1 | `python -m pip install -e .` | 成功 | 7.4s | 无（PowerShell 把 pip 的 stderr 显示成 NativeCommandError，退出码 0） |
| 2 | `python -m unittest discover -s tests -v` | **失败**：`Ran 1148 tests ... FAILED (failures=1, skipped=5)` | 190.9s | `FAIL: test_originals_unchanged (test_dev_log.TestDevLog)` → `AssertionError: False is not true`（`.superpowers/sdd/.../progress.md` 被 gitignore，克隆里不存在） |
| 3 | `python lab/mock_targets.py --mode vulnerable` | **崩溃 + 前台阻塞** | 6.1s 后杀进程 | 见下方 traceback：`UnicodeEncodeError: 'charmap' codec can't encode characters in position 0-3` |
| 4 | `python -m inkblade module list --modules-dir inkblade/modules` | 成功（打印模块表） | 0.2s | 无；但只是清单，不是发现/报告 |
| 5 | `python -m inkblade ui --port 8765` | **永久阻塞** | 5.1s 后杀进程 | 前台服务不返回；重定向时无任何提示，陌生用户不知道下一步 |
| 6 | `python inkblade/e2e-check.py` | **失败**：`e2e: 8/15 PASS` | 3.9s | 7 项 FAIL，核心原因：`ExecutionLocked: 授权时间窗外：时间窗已过期（截至 2026-10-25 23:59:59）`；报告检查连带失败 `AssertionError: 渗透报告缺要素 sha256:` |
| 7 | `python -m inkblade.verify-effects --out reports/samples/effects/` | 成功：`20/20 PASS` | 3.5s | 是效果级验证，不是渗透测试报告/发现；且只有跑完前 6 条才到达 |

### 基线原文报错（节选）

第 3 条 mock 靶场：

```text
mock lab: http://127.0.0.1:51921/ mode=vulnerable root=...
Traceback (most recent call last):
  File "...\lab\mock_targets.py", line 750, in <module>
    raise SystemExit(main())
  File "...\lab\mock_targets.py", line 738, in main
    print(f"路由清单: {server.url('/__routes__')}（共 {len(ROUTE_TABLE)} 条）")
  File "...\encodings\cp1252.py", line 19, in encode
    return codecs.charmap_encode(input,self.errors,encoding_table)[0]
UnicodeEncodeError: 'charmap' codec can't encode characters in position 0-3: character maps to <undefined>
```

第 6 条 e2e（跨日后复测，7 项 FAIL 的根因都是同一时间窗）：

```text
[FAIL] backup-gate-exit-code-91 — ...（ExecutionLocked: 授权时间窗外：时间窗已过期（截至 2026-10-25 23:59:59））
[FAIL] module-family-subset — ...（ExecutionLocked: 授权时间窗外：时间窗已过期（截至 2026-10-25 23:59:59））
[FAIL] chain-execute-weight-poison — ...（AssertionError: 链执行失败: {... ExecutionLocked ...}）
[FAIL] evidence-three-layers-manifest — ...（AssertionError: 缺层 ...\context.jsonl.gz）
[FAIL] zeroday-public-no-gate — ...（ExecutionLocked: 授权时间窗外：时间窗已过期（截至 2026-10-25 23:59:59））
[FAIL] report-bilingual-public-details — ...（AssertionError: 渗透报告缺要素 sha256:）
[FAIL] roles-and-workspace-isolation — ...（ExecutionLocked: 授权时间窗外：时间窗已过期（截至 2026-10-25 23:59:59））
e2e: 8/15 PASS → ...\reports\samples\e2e\e2e-check.json
```

### 基线结论

- **命令数 7**；**失败 3 次**（测试 1 项失败、mock 崩溃、e2e 8/15），另 **2 次永久阻塞**（mock、UI 前台服务）。
- **首次有效结果：未达成**。按 README 无法创建 demo 工作区、无法签授权、无法执行任何模块或链，因此无法生成渗透测试报告/发现。
- 若把「effect 验证 20/20 PASS」勉强算作首个有效结果，耗时约 **217 秒**（7.4 + 190.9 + 6.1 + 0.2 + 5.1 + 3.9 + 3.5），且这是第 **7** 条命令。
- 真正的卡点不是某条命令语法，而是 **README 缺少「从零到第一条发现」的路径**：没有 workspace/consent 创建，没有可执行模块/链，只有开发者验收脚本；且验收脚本自身会在跨日后失效。

## 2. 改造后走查（只按新 README，实测）

新 README 顶部「5 分钟上手」只列 3 条命令；前两条即出结果。

| # | 命令（原文） | 结果 | 耗时 | 产物/说明 |
|---|---|---|---|---|
| 1 | `python -m inkblade doctor` | **成功**，`EXIT=0`，无阻塞 | **0.29s** | 12 项 PASS/WARN/FAIL；结论「环境可用（本地 mock）」；给出下一步 `python -m inkblade demo` |
| 2 | `python -m inkblade demo` | **成功**，`EXIT=0` | **3.56–5.00s**（最终复测 5.00s；墙钟 3.83–5.33s） | 10 条发现（high 8 / medium 2）；链 2/2 成功（0.76–0.81s）；双语报告 + 35 条规则/25 链 + 静态 UI；落盘 `demo/` |
| 3 | `python -m inkblade quickstart` | 交互向导；本次用 `--yes` 非交互验证 | 0.6s | 建 `local-lab` 授权、lead/tester、`workspace.json` target 记录；失败可重入 |

### 改造后实测输出（原文节选）

```text
InkBlade demo 完成
================================================================
耗时：5.00 秒（目标 ≤60 秒）
工作区：...\demo\workspace（demo-lab）
授权：全影响演示 / 127.0.0.0/8 / 2026-10-25 23:17 – 2026-11-02 00:17
模块：framework-port-matching(4), multi-cloud-imds-credentials(4)
链：flat-network-admin-plane-weight-poison → 成功（0.81 秒；admin-failopen-probe:success, weight-pull-poison:success）
发现：10 条（high 8, medium 2）
产物：
  报告（中英双语）：...\demo\reports\pentest-bi.md
  修复报告：      ...\demo\reports\remediation-bi.md
  规则包：        ...\demo\rules-pack（35 条规则 / 25 链）
  Web UI（file://）：demo\webui\index.html
```

### 改造后结论

- **命令数 2**（doctor + demo；quickstart 是可选第 3 条）。
- **失败 0**。
- **首次有效结果 5.33 秒**（最终复测墙钟，含进程启动与全部输出；早先一次为 3.83 秒），远低于 5 分钟目标；demo 内部自计时 5.00 秒（早先 3.56 秒），远低于 60 秒目标。
- 产物齐全：三层证据（`evidence.db` / `context.jsonl.gz` / `manifest.sha256` + 归档）、双语渗透/修复报告、规则包、静态 UI、`summary.json`。
- 同一临时克隆内 `python -m unittest tests.test_onboarding -v`：**17 tests OK（6.3s）**；`python inkblade/e2e-check.py`：**15/15 PASS**（跨日不再误报）。

## 3. 基线 vs 改造后对照表

| 维度 | 基线 | 改造后 | 变化 |
|---|---|---|---|
| 首次有效结果 | **未达成**（只有 effect PASS，无报告/发现） | **5.33s** 看到 10 条发现 + 双语报告 | 从 0 到 1 |
| 命令数（到首个结果） | 7（实际到第 7 条才勉强有 PASS） | **2**（doctor → demo） | 7 → 2 |
| 失败次数 | 3 + 2 次阻塞 | **0** | 归零 |
| 安装前耗时 | 190.9s 全量测试 | 0（测试移到 CONTRIBUTING/开发者路径） | 移除 |
| 前台阻塞 | mock、UI 各一次 | 无（demo 自起自停 mock；UI 为静态导出） | 消除 |
| 跨日可复现 | e2e 次日 8/15（时间窗过期） | e2e 15/15（窗口按运行时刻生成） | 修复 |
| 错误可读性 | 部分原文堆栈/裸异常 | 10 类高频错误三行式 + 错误码 | 新增 |
| UI 首屏 | 只有登录/视图，无引导 | demo 引导卡（2 条命令 + quickstart） | 新增 |
| Windows 中文控制台 | mock `UnicodeEncodeError` 崩溃 | UTF-8 重配置，`--help`/启动正常 | 修复 |

## 4. 失败根因（按影响排序）

1. **README 的入口是「开发者验收」而不是「用户拿到结果」**：第 2 步全量测试 191 秒，第 3/5 步前台服务永久阻塞；没有 workspace/consent/2 模块/1 链的最小闭环。
2. **没有 demo 工作区与授权路径**：旧 README 只有 RUNBOOK 里的 Python 片段；陌生用户不会写 `init_roe`，因此任何 `inkblade run` 都命中 `ExecutionLocked`。
3. **mock 靶场入口未处理 Windows 控制台编码**：`lab/mock_targets.py` 直接 `print` 中文，cp1252/IBM437 下 `UnicodeEncodeError`；这是 README 第 3 步的硬崩溃。
4. **e2e 验收脚本的授权时间窗是「当天 00:00–23:59」**：跨日后必然过期，7 项检查连带失败；让陌生用户在第一天之后看到「平台坏了」的假象。
5. **全新克隆的测试因内部台账缺失而红**：`test_dev_log` 依赖被 `.gitignore` 的 `.superpowers/sdd/...`，公开克隆不含该文件。
6. **CLI 默认模块目录只找 `home/modules`**：陌生用户的 home 没有 `modules/`，`run`/`execute`/`module list` 会找不到模块；`--home` 只能放在子命令之前，文档示例却常写在后面。
7. **捕获后的错误仍是裸异常字符串**：没有「发生了什么/为什么/怎么修」，端口、bash、kubeconfig、备份校验等高频错误无法自救。
8. **UI 首屏没有 demo 入口**：即使平台能跑，陌生用户打开控制台也不知道先做什么。

## 5. 修复清单

| 修复 | 文件 | 验收 |
|---|---|---|
| 新增 `inkblade doctor`（Python/写权限/磁盘/端口/可选依赖/mock/真集群/kubeconfig/bash/kubectl/授权/时钟） | `inkblade/onboarding.py`、`inkblade/cli.py` | `tests/test_onboarding.py::TestDoctor` 3 项 |
| 新增 `inkblade demo`（demo 工作区、lead/tester、真实 `init_roe` 签名、mock 靶场、2 模块 + 1 链、双语报告、规则包、静态 UI、摘要/下一步；`--no-ui`/`--keep`/`--temp`） | `inkblade/onboarding.py`、`inkblade/cli.py` | `TestDemo` 5 项；实测 5.00s；17 项产物断言 |
| 新增 `inkblade quickstart`（目标/范围/级别/用户/签授权 5 问；CIDR/kubeconfig 校验；重入；`--yes`） | `inkblade/onboarding.py`、`inkblade/cli.py` | `TestQuickstart` 4 项（含坏 CIDR 重问、二次运行保留 consent） |
| 10 类高频错误三行式 + 错误码（E101/E102/E103/E104/E201/E202/E203/E205/E301/E401） | `inkblade/core/humanize.py` | `TestHumanizedErrors` 2 项（逐条断言 code + 三行） |
| CLI 未捕获异常统一人话；`INKBLADE_DEBUG=1` 才出堆栈 | `inkblade/cli.py` | doctor/demo/quickstart/run 冒烟 |
| mock 靶场 UTF-8 控制台 | `lab/mock_targets.py` | `test_mock_targets_help_works_under_cp1252` |
| e2e 授权时间窗按运行时刻生成（7 天） | `inkblade/e2e-check.py` | 跨日复测 15/15 PASS |
| 全新克隆测试跳过缺失的内部 SDD 台账 | `tests/test_dev_log.py` | 新克隆 discover 不再因 `.superpowers` 红 |
| `run`/`execute`/`module list` 默认模块目录回落到包内 `inkblade/modules` | `inkblade/cli.py` | quickstart 下一步 dry-run 实测可跑 |
| UI 首屏 demo 引导卡（可关闭，localStorage 记忆） | `inkblade/webui/static/{index.html,style.css,app.js}` | `test_ui_first_screen_demo_card` |
| README 顶部「5 分钟上手」3 条命令；RUNBOOK 第 0 节 + 错误码表 | `README.md`、`docs/RUNBOOK.md` | `test_readme_quickstart_three_commands` |
| 默认输出 `./demo/`、`./inkblade-workspace/` 加入 gitignore | `.gitignore` | demo 运行后 `git status` 干净 |
| 新增走查评估（本文件） | `docs/ONBOARDING-EVALUATION.md` | 文档存在 + 对照表 |

## 6. 仍存的上手风险（诚实清单）

1. **`python` 不在 PATH**：本机 `python` 是 Microsoft Store 别名，必须先安装 Python 3.10+ 或使用 `py -3.12`/完整路径。`doctor` 无法在解释器本身不可用时自救；新 README 已写明先决条件，但这仍是最大环境门槛。
2. **真实集群路径未端到端实测**：`quickstart` 只校验 kubeconfig 文件存在且含 `server:`，不建立连接；真实 `kubectl` 采集、权限、网络可达性仍需现场验证。当前可信证据仍是 mock/fixture/效果级。
3. **`--keep` 会按设计阻塞**：保留 mock 靶场供手工探索，需 Ctrl+C 结束；自动化只用默认模式，未对 `--keep` 做计时断言。
4. **demo 链含一个写步骤**：`slime-weight-pull-poison` 以 HTTP 备份回执在 mock 上演示；真实集群必须重新评估备份目标，不能把 demo 参数直接用于生产。
5. **Windows 编码仍有覆盖面**：CLI、onboarding、mock、e2e 已重配置 UTF-8；其他 lab 脚本（KIND/bench 等）仍可能依赖控制台编码，未逐一改造。
6. **demo 耗时受杀软/磁盘影响**：本机实测 3.6–11.4 秒波动（一次冷启动 20.5 秒），仍远低于 60 秒；CI 断言用 120 秒宽松阈值。
7. **全量测试仍约 3 分钟**：已从「5 分钟上手」路径移除，但首次贡献者跑全量仍要等；属于开发者体验而非用户上手。
8. **`doctor` 的 bash 检查只查 PATH 存在性**：WindowsApps 的 `bash.exe` 可能是 WSL 存根，实际不可用；不阻塞 demo。

## 7. 复现方式

```powershell
# 基线（HEAD 旧 README）
git clone --local <repo> <tmp>\baseline
cd <tmp>\baseline
python -m pip install -e .
python -m unittest discover -s tests -v
python lab/mock_targets.py --mode vulnerable
python -m inkblade module list --modules-dir inkblade/modules
python -m inkblade ui --port 8765
python inkblade/e2e-check.py
python -m inkblade.verify-effects --out reports/samples/effects/

# 改造后（新 README，仅 2 条到结果）
git clone --local <repo> <tmp>\after
cd <tmp>\after
python -m inkblade doctor
python -m inkblade demo
```

> 基线 e2e 的「8/15」是在 2026-10-26 00:02 复测得到；同一天 00:00 前首次运行曾为 15/15。这正说明硬编码当天窗口的脆弱性；修复后 00:17 复测恢复 15/15。
