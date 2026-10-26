# Usage / 使用手册

[English](#english) · [中文](#中文)

---

## English

A workspace is a directory: user file, consent record, asset inventory, one evidence tree per run.
`--home` (or `--workspace`) points at it and nothing else is read.

`python -m inkblade ...` and `inkblade ...` are the same program. Every flag belongs to a
subcommand, so `inkblade run --help` is the reference for `run`.

### Quick reference

| Group | Command | What it does |
|---|---|---|
| Setup | `inkblade doctor` | Python, write access, port, optional deps, cluster reachability. |
| Setup | `inkblade pilot --dry-run` | Offline rehearsal: empty profile, plan, approval list. |
| Setup | `inkblade ui` | Local console on `127.0.0.1:8765`. |
| Setup | `inkblade quickstart` | Five-question wizard ending in a signed authorization. |
| People | `inkblade user add <name> <password> admin\|lead\|tester\|auditor` | Account in the workspace user file. |
| People | `inkblade roe` | Current consent / rules-of-engagement state. |
| Look | `inkblade module list` | Series, level, read/write, required surfaces. |
| Look | `inkblade surfaces --profile <p>` | Production-testability matrix for one profile. |
| Look | `inkblade pilot --kubeconfig <path>` | Read-only inventory and approval checklist. |
| Collect | `inkblade collect --profile <p> --out <dir>` | k8s objects, HTTP, files, hardware. |
| Collect | `inkblade discover --seeds <file>` | Expands seeds into the asset table. |
| Collect | `inkblade import-scan <file>` | Trivy / Syft / grype output into findings. |
| Run | `inkblade run --module <key>` | One module behind consent, scope, backup gates. |
| Run | `inkblade execute --chain <id> --dry-run` | Plan only: topology, preconditions, write surface. |
| Run | `inkblade execute --chain <id>` | The real thing, still behind the gates. |
| Run | `inkblade exploit --list` | Weapon packs with readiness state. |
| Run | `inkblade exploit <id> --real --backup-target <dir>` | One pack, gates on `--real`. |
| Undo | `inkblade rollback --run <id> --step <n>` | Restores one step, prints a receipt. |
| Undo | `inkblade abort` / `--clear` | Workspace hold, and releasing it. |
| Report | `inkblade report --run <id> --kind pentest --lang bi` | Bilingual report from the evidence tree. |
| Report | `inkblade export --run <id> --format sarif` | SARIF, OCSF or VEX. |
| Defend | `inkblade rules generate --out <dir> --cni native` | Admission, network, detection, convergence. |
| Repeat | `inkblade schedule add --cron "<expr>" --chains <ids>` | Recurring retest. |
| Repeat | `inkblade schedule run-due` | Runs what is due, diffs against baseline. |
| Gate | `inkblade ci-gate --run <id> --fail-on high --new-only` | Exit-code contract. |
| Embed | `inkblade mcp` | Read-only MCP server over stdio. |
| Embed | `inkblade sdk list` | Plugin SDK: new, lint, validate, trust, run, list. |

### 1. Workspace and people

```bash
python -m inkblade user add alice '<password>' lead
python -m inkblade user add bob '<password>' tester
python -m inkblade user add carol '<password>' auditor
python -m inkblade roe
```

`lead` approves. `tester` executes inside an approved scope. `auditor` reads evidence and runs
nothing. `admin` manages the workspace. Skip this and nobody can approve a high-impact step later.

### 2. Sign first

```bash
python -m inkblade quickstart
```

Five questions, then a consent record with a hash that is stamped into every run. Levels are
cumulative: read-only recon, active probing, exploit verification, full-impact demo. A level-3
module under a level-2 record does not run — no `--force`, no env var.

### 3. Inventory, then look

```bash
python -m inkblade pilot --kubeconfig ~/.kube/config --out pilot/
python -m inkblade collect --profile bare-k8s-gpu --out collection/
python -m inkblade surfaces --profile bare-k8s-gpu --collect collection/
```

`pilot` is read-only: profile, heat map, approval checklist. `collect` adds details. `surfaces`
tells you whether the surface each module needs exists here at all.

### 4. One module

```bash
python -m inkblade run --module k8s-rbac-surface --role tester
```

| Exit | Meaning |
|---:|---|
| 0 | ran |
| 91 | a gate refused |
| 3 | rollback left something behind |

Write modules need a backup target:

```bash
python -m inkblade run --module <write-module> \
  --params '{"namespace":"ml-team"}' \
  --backup-target ./backups/
```

### 5. Chains

```bash
python -m inkblade execute --chain <id> --dry-run
python -m inkblade execute --chain <id> --workers 2
```

The dry run prints order, dependencies, writes and preconditions. A false precondition stops the
chain; a typo in the chain id fails immediately.

### 6. Evidence

| Layer | File | Use it for |
|---|---|---|
| Context | `context.jsonl.gz` | What the tester saw, step by step. |
| Audit | `evidence.db` | Findings, actions, backups, rollbacks. |
| Proof | `steps/*.tar.gz` + `manifest.sha256` | Handing one step to someone else. |

### 7. Report, export, defend

```bash
python -m inkblade report --run <id> --kind pentest --lang bi
python -m inkblade export --run <id> --format sarif --out findings.sarif
python -m inkblade rules generate --out rules/ --cni cilium
```

Two renderings of one evidence tree, so they cannot disagree. `--redact` strips deep detail before
a report leaves the team. `rules validate` replays each pack and reports blocked / detected /
missed per chain.

### 8. Retest and CI

```bash
python -m inkblade schedule add --cron "0 3 * * 1" --chains <ids>
python -m inkblade schedule run-due
python -m inkblade ci-gate --run <id> --fail-on high --new-only
```

### 9. Embedding

`inkblade mcp` exposes read-only tools over stdio. `inkblade plan` proposes; a `lead` still
approves. The plugin SDK is for modules in your repository, pinned by SHA-256 fingerprint — no
auto-trust path.

### Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| exit 91 on `run` | No consent, level too low, missing backup target | `inkblade roe`, then `quickstart`; add `--backup-target` |
| exit 3 on `rollback` | A step could not be restored | Read the receipt |
| `inkblade` not found | Installed in another interpreter | Use `python -m inkblade ...` |
| Port 8765 busy | Another console instance | `inkblade ui --port 8770` |
| `pilot` refuses to run | No `--kubeconfig` or `--snapshot` | Add `--dry-run` |
| Garbled console output | Legacy code page | `set PYTHONIOENCODING=utf-8` |


---

## 中文

工作区就是一个目录：用户文件、授权记录、资产清单，以及每次 run 的一棵证据树。用 `--home`（多数子命令也用
`--workspace`）指过去，工具不会去别处找。`quickstart` 会建一个并引导你填写范围；真实试点通常从 `pilot --kubeconfig` 开始。

看命令表之前先记住两件事。第一，`python -m inkblade ...` 和 `inkblade ...` 是同一个程序，短命令要先
`pip install -e .`。第二，参数属于子命令，`inkblade run --help` 才是 `run` 的准确说明。下面的表覆盖九成日常。

### 快速参考

| 分组 | 命令 | 作用 |
|---|---|---|
| 准备 | `inkblade doctor` | 检查 Python、写权限、端口、可选依赖、集群可达性。 |
| 准备 | `inkblade pilot --dry-run` | 离线演练：空画像、计划与审批清单。 |
| 准备 | `inkblade ui` | 本地控制台，`127.0.0.1:8765`。 |
| 准备 | `inkblade trial` | 离线演示 + 试用报告 + 下一步清单。 |
| 准备 | `inkblade quickstart` | 五问向导，最后落到签署授权。 |
| 人员 | `inkblade user add <名字> <口令> admin\|lead\|tester\|auditor` | 在工作区用户文件里建账号。 |
| 人员 | `inkblade roe` | 打印当前 consent / 交战规则状态。 |
| 查看 | `inkblade module list` | 模块的族、级别、读写属性、所需部署面。 |
| 查看 | `inkblade surfaces --profile <p>` | 单个画像的生产可测矩阵。 |
| 查看 | `inkblade pilot --kubeconfig <路径>` | 只读集群清点与审批清单。 |
| 采集 | `inkblade collect --profile <p> --out <目录>` | 只读采集：k8s 对象、HTTP、文件、硬件。 |
| 采集 | `inkblade discover --seeds <文件>` | 种子扩成资产表。 |
| 采集 | `inkblade import-scan <文件>` | 把 Trivy / Syft / grype 结果归一化成发现。 |
| 执行 | `inkblade run --module <key>` | 单模块，过授权、范围、备份闸门。 |
| 执行 | `inkblade execute --chain <id> --dry-run` | 只出计划：拓扑、前置条件、写面。 |
| 执行 | `inkblade execute --chain <id>` | 真正执行，闸门照旧。 |
| 执行 | `inkblade exploit --list` | 全部武器包与就绪状态。 |
| 执行 | `inkblade exploit <id> --real --backup-target <目录>` | 单个武器包，默认干跑，`--real` 才过闸门。 |
| 回退 | `inkblade rollback --run <id> --step <n>` | 恢复单步并打印回执。 |
| 回退 | `inkblade abort` / `--clear` | 工作区级急停，以及解除。 |
| 报告 | `inkblade report --run <id> --kind pentest --lang bi` | 从证据树生成双语报告。 |
| 报告 | `inkblade export --run <id> --format sarif` | 导出 SARIF、OCSF 或 VEX。 |
| 防守 | `inkblade rules generate --out <目录> --cni native` | 准入、网络、检测、收敛规则包。 |
| 复测 | `inkblade schedule add --cron "<表达式>" --chains <ids>` | 加一条周期复测。 |
| 复测 | `inkblade schedule run-due` | 跑到期的任务，与基线做差异。 |
| 门禁 | `inkblade ci-gate --run <id> --fail-on high --new-only` | 给流水线的退出码契约。 |
| 嵌入 | `inkblade mcp` | 只读 MCP 服务，stdio JSON-RPC。 |
| 嵌入 | `inkblade sdk list` | 插件 SDK：new、lint、validate、trust、run、list。 |

### 1. 先建工作区和人

```bash
python -m inkblade user add alice '<口令>' lead
python -m inkblade user add bob '<口令>' tester
python -m inkblade user add carol '<口令>' auditor
python -m inkblade roe
```

角色不是装饰。`lead` 审批，`tester` 在批准范围内执行，`auditor` 只能读证据、不能执行，`admin` 管工作区。
跳过这步 CLI 照样能用，但之后没人能批准高影响步骤。

### 2. 先签授权，再谈其他

```bash
python -m inkblade quickstart
```

五个问题：目标、范围、技术级别、用户、签署。答完得到一份带哈希的授权记录，哈希会写进后续每一次 run。
记录丢了这个洞就永远在。

别把它当勾选项。级别是累进的，且由工具强制执行：只读侦察、主动探测、利用验证、全影响演示。需要 3 级的模块
在 2 级授权下不会跑。没有例外，没有 `--force`。

### 3. 先清点，再看

```bash
python -m inkblade pilot --kubeconfig ~/.kube/config --out pilot/
python -m inkblade collect --profile bare-k8s-gpu --out collection/
python -m inkblade surfaces --profile bare-k8s-gpu --collect collection/
```

`pilot` 天生只读，产出部署画像、模块族适用热图，以及可以直接交给平台负责人的审批清单。`collect` 补细节。
`surfaces` 再逐个模块告诉你：要的面到底在不在——生产可测、有条件、还是根本没有。

最后一列很省时间。对着托管控制面硬跑四十个根本不适用的模块，不叫全面，叫噪音。

### 4. 跑一个模块

```bash
python -m inkblade run --module k8s-rbac-surface --role tester
```

看退出码，不要只看文字。`0` 是跑完了，`91` 是闸门拒绝，`3` 是回滚有遗留。拒绝会点名是哪道闸门、怎么修。
那不是崩溃，是产品在工作。

写类模块要带备份目标：

```bash
python -m inkblade run --module <写类模块> \
  --params '{"namespace":"ml-team"}' \
  --backup-target ./backups/
```

没有 `--backup-target` 就在闸门前停下。这是故意的。我们没见过后悔做备份的团队，倒是见过不少后悔没做的。

### 5. 链

```bash
python -m inkblade execute --chain <id> --dry-run
python -m inkblade execute --chain <id> --workers 2
```

dry-run 会打印解析后的链图：哪个模块先跑、每步依赖什么、哪些步骤会写、哪些前置条件必须已成立。读它。
前置条件不成立时链会停在那里，而不是即兴发挥。

链 id 在 `inkblade/chains/*.json` 里。`--chain` 写错时立即失败、什么都不列——这是你对拼写错误的合理期待。

### 6. 证据

每次 run 在 `<工作区>/evidence/<run>/` 下留三层：

| 层 | 文件 | 用途 |
|---|---|---|
| 上下文 | `context.jsonl.gz` | 逐步还原测试者当时看到了什么。 |
| 审计 | `evidence.db` | 查询：发现、动作、备份、回滚。 |
| 证明 | `steps/*.tar.gz` + `manifest.sha256` | 把某一步交给别人，且可校验。 |

报告锚点是步骤哈希，不是段落。发现被质疑时，重放那一步，而不是争论。

### 7. 报告、导出、防守

```bash
python -m inkblade report --run <id> --kind pentest --lang bi
python -m inkblade report --run <id> --kind remediation --lang en
python -m inkblade export --run <id> --format sarif --out findings.sarif
python -m inkblade rules generate --out rules/ --cni cilium
```

渗透报告给防守方；修复报告给平台组，叙事更短。两者出自同一套证据，所以不会互相打架。报告需要离开项目组时，
用 `--redact` 去掉深层细节。

规则包只有被测过才有用。`rules validate` 会对着 fixture 目标重放，给出每条链的拦截 / 检出 / 漏过。一条什么都拦不住的
规则比没有规则更糟：它看起来像覆盖率。

### 8. 复测与门禁

```bash
python -m inkblade schedule add --cron "0 3 * * 1" --chains <ids>
python -m inkblade schedule run-due
python -m inkblade ci-gate --run <id> --fail-on high --new-only
```

`schedule run-due` 与基线做差异并报告漂移。`ci-gate` 把一次 run 变成退出码，让流水线能因为新增高危失败，
而不会因为你已经接受的存量失败。

### 9. 嵌进别的系统

`inkblade mcp` 用 stdio 说 MCP，只暴露只读工具；`inkblade plan` 产出排序后的建议，但仍需 `lead` 审批。
插件 SDK（`sdk new`、`lint`、`validate`、`trust`、`run`）是给放进你自己仓库的模块用的。信任是你显式接受的
SHA-256 指纹，没有自动信任通道。

### 排障

| 现象 | 多半是 | 怎么办 |
|---|---|---|
| `run` 退出 91 | 没授权、级别不够、或没给备份目标 | 先 `inkblade roe`，再 `quickstart`；补 `--backup-target` |
| `rollback` 退出 3 | 有步骤恢复不了 | 读回执；恢复不了的那一步本身是发现 |
| 找不到 `inkblade` | 装到了另一个解释器 | 改用 `python -m inkblade ...` |
| 8765 端口被占 | 另一个控制台在跑 | `inkblade ui --port 8770` |
| `pilot` 拒绝运行 | 没给 `--kubeconfig` 或 `--snapshot` | 加 `--dry-run` 做离线演练 |
| Windows 控制台乱码 | 旧代码页 | `set PYTHONIOENCODING=utf-8` |
