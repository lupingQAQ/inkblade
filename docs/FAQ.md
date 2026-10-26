# FAQ / 常见问题

> 2026-10 探针架构口径。问题按“能不能跑、怎么跑、证据是什么、边界在哪”排序。

## 中文

### 没有集群能试吗？

不能做完整的渗透结果。`doctor`、模板 schema 校验、mock 靶场可以在本地跑；但 `session` 需要授权目标，`probe` 需要目标 Pod，`report` 需要真实证据。产品不提供 demo/trial 路径，也不把 mock 结果包装成“客户环境结论”。

### 目标 Pod 里要装 Python 吗？

不要。探针是静态链接的 Rust 二进制；模板是 JSON。目标不需要 Python、pip、Bash、curl。只有 `k8s exec/copy` 这条可选路径需要目标镜像里有 `kubectl`；没有就退回 API 读写或换投放方式。

### 为什么用 Rust，不用 Go？

三个原因：静态二进制体积更小、没有运行时；模板解释器和 HTTP/TLS/JSON 可以在一个进程内收口；内存安全和错误处理更适合“在别人 Pod 里跑一次性逻辑”。Go 也能做，但会把 `net/http`、TLS 根证书、cgo 等依赖带进来，发布物更大，行为更容易受构建环境影响。

### 探针是不是后门？

不是。探针不持久化、不写启动项、不改镜像、不驻留、不回连固定 C2。它只在授权 session 内运行，任务来自已注册模板，退出时清理。它和“后门”的区别不是名字，而是：授权、模板白名单、只读默认、写闸门、清理回执、证据可审计。

### 探针怎么进 Pod？

四种方式：授权 RCE（base64 + memfd）、`kubectl cp/exec`、EphemeralContainer、共享卷。每种都有前置条件和痕迹；没有“静默投放”这种承诺。详见 `docs/PROBE-DEPLOY.md`。

### 会不会被 HIDS/EDR 发现？

会。探针不试图隐藏进程、网络连接、文件写入或 kubelet 审计。第 10 层的 11 个 `defense-bypass-*` 模块不是“绕过演示”，而是用良性 marker 测防守方能不能看见这类行为，并输出检测/盲区/硬化建议。

### 第 10 层是不是在教人绕过防护？

不是。它不携带恶意载荷、不做持久化、不关闭安全产品、不提供规避执法的话术。它做的是：在授权环境里发一个带 `INKBLADE-BENIGN` 前缀的 marker，看 Elkeid/Falco/Tetragon/Kyverno/WAF 是否记录；没记录就是盲区，盲区转成规则和配置建议。防守方拿到的价值大于攻击方。

### 为什么有 11 个 defense-bypass 模块？

因为训练集群的防守面不是单一产品：HIDS、运行时 eBPF、准入、镜像扫描、主机代理、WAF、网络可视化各管一段。只测一个产品，会漏掉“部署了但降级”“规则没覆盖”“采样窗口太短”这些真实盲区。11 个模块对应 11 类产品/控制面，每个都输出三类结果。

### 模板和模块是什么关系？

模块是产品目录里的条目，模板是它的执行体。模板键 = 模块键，例如 `defense-bypass-falco`。模块清单写元数据、级别、是否写、所需部署面；模板写 steps/checks/findings/artifacts。注册表拒绝模板模块带 `run.py`。

### 287 个模块都迁移完了吗？

没有。截至 2026-10-27，287 个模块目录中 `template.json` 为 0，迁移进行中。注册表已经强制模板，所以当前分支不能加载旧模块；这是架构切换的中间态。完成度看 `docs/DYNAMIC-VERIFICATION.md`，不看宣传页。

### 动态验证是什么？

每个模板必须在 mock 靶场跑两态：vulnerable 态应产生预期 finding，fixed 态不应产生同一 finding；连续 3 次一致；离线；有证据目录和 manifest。只跑一态、只做静态检查、用参考评估器代替 Rust 探针，都不算。

### 为什么报告里会有 `blocked`？

因为有些模板需要特权 Pod、hostNetwork、GPU、节点访问或真实厂商产品；mock 靶场不具备这些条件。`blocked` 是诚实状态，不是通过。报告会写缺什么部署面；客户环境具备时可以补跑。

### 写操作怎么保证安全？

五道闸门：session 授权覆盖目标/级别/时间窗；探针 `--allow-write`；模板 `meta.writes=true` 且步骤 `write: true`；`mode=backup-write`；备份回执存在。缺一条就 `skipped` 或 `E_DENIED`。写后回读哈希，失败回滚。

### 只读模式能做什么？

采集快照、HTTP/TCP 探测、读文件、执行只读命令、跑只读模板、看 K8s 资源。不能写文件、不能删文件、不能执行非白名单命令、不能 spawn 子探针、不能做 K8s 写动词。

### 探针权限有多大？

等于目标 Pod 的权限，加上探针进程的 capability。它不能超过 Pod 的 SA、namespace、cgroup、挂载。需要节点权限的检测点，必须由具备节点权限的探针或控制端完成；没有就 `blocked`。

### 多探针怎么管？

父子树：每个探针有 `probe_id` / `parent_id`；子探针继承更严格的只读/白名单/预算；最大深度 3、每父最多 8 个子探针；清理先子后父；父探针退出后子探针在 TTL 内退出。

### 支持 Windows/macOS 吗？

控制端可以。探针只支持 Linux；Windows/macOS 不能作为目标执行环境。Windows 上不要运行 `inkblade-probe`，只把它复制到 Linux 目标。

### 能离线吗？

能。控制端不需要外网；探针不需要包索引；模板和规则包随发布物带入。离线安装要带控制器 wheel、Python 解释器、两个架构的探针、模板和规则包；`doctor --offline` 会把网络检查标 `SKIP`，不标 `PASS`。

### 有账号、许可服务器、遥测吗？

没有账号体系（本地 `users.json` 除外）、没有许可服务器、没有遥测。可选集成默认关闭。

### 能商用/ fork 吗？

Apache-2.0 允许商用与 fork；保留 `LICENSE` / `NOTICE`，不要用 InkBlade 商标命名 fork。

### 怎么加模板？

在 `inkblade/modules/<key>/` 放 `module.json` + `template.json`；用 `inkblade template lint` 校验；在 mock 靶场跑两态；补证据；更新覆盖率表。不要加 `run.py`，不要把逻辑写成脚本。

### 误报怎么处理？

先看证据锚和 checks；再看目标版本/配置是否与模板假设一致；最后看动态验证是否覆盖该版本。模板可以在 `fixed` 态回归，但不能靠“把规则改松”降误报。报告里保留限制节和 `blocked` 项。

### 和通用扫描器/主机 Agent 的区别？

通用扫描器看配置和镜像；主机 Agent 看主机行为；InkBlade 在目标 Pod 内跑一次性 Rust 探针，检测 ML 组件、租户隔离、缓存、fabric、供应链和防护产品盲区。它不是 EDR，也不是 C2。

---

## English

### Do I need a cluster?

For a real engagement, yes: a session needs an authorized target and a signed consent record. `doctor`, template schema checks, and the mock range run locally, but mock output is not a customer finding. There is no demo or trial path.

### Does the target need Python?

No. The probe is a static Rust binary; templates are JSON. The only optional dependency is `kubectl` inside the image for the `k8s exec/copy` path.

### Why Rust?

Small static binary, no runtime, one process for the template engine plus HTTP/TLS/JSON, and memory safety for one-shot code in someone else's Pod. Go would work, but brings a larger runtime and build-environment sensitivity.

### Is the probe a backdoor?

No. It does not persist, modify startup, patch images, or call a fixed C2. It runs only inside an authorized session, executes registered templates, defaults to read-only, gates writes, cleans up, and produces auditable evidence.

### How does it get in?

Authorized RCE with base64 and memfd, `kubectl cp`/`exec`, an EphemeralContainer, or a shared volume. Each path has prerequisites and traces. There is no silent deployment claim.

### Will HIDS/EDR see it?

Yes. It does not hide processes, connections, file writes, or kubelet audit. The 11 defense-bypass modules measure whether defenders see benign markers; they do not provide malware or evasion.

### Are 287 modules migrated?

No. As of 2026-10-27 there are 287 module directories and zero `template.json`; the registry already requires templates. The migration is in progress. See `docs/DYNAMIC-VERIFICATION.md`.

### What counts as verified?

Two states against a local mock target, three consistent runs, offline, with a complete evidence directory and manifest. A single state, static review, or reference-evaluator run does not count.

### How are writes controlled?

Five gates: signed authorization, `--allow-write`, `meta.writes` plus `write: true`, `backup-write` mode, and a backup receipt. Missing one yields `skipped` or `E_DENIED`.

### Can it run air-gapped?

Yes. Carry the controller wheel, Python, both probe binaries, templates, and rule packs. `doctor --offline` marks network checks as skipped, not passed.

### Can I use it commercially?

Apache-2.0 permits commercial use and forks; keep `LICENSE` and `NOTICE`, and do not use the InkBlade trademark for a fork.

## 证据 / 限制

**证据**

- 探针能力与限制：`probe/src/`（http/tcp/exec/fs/k8s/net/spawn/collect）。
- 只读与写闸门：`probe/src/config.rs`、`probe/src/exec.rs`、`probe/src/fsops.rs`。
- 11 个 defense-bypass 模块：`inkblade/modules/defense-bypass-*`、`inkblade/core/defenseprobe.py`。
- 动态验证标准：`docs/DYNAMIC-VERIFICATION.md`。
- 投放方式：`docs/PROBE-DEPLOY.md`。

**限制**

- 迁移进行中；命令面与模块数量会变，以 `doctor` 和覆盖率表为准。
- 探针只支持 Linux；控制端可以跨平台。
- 防护产品盲区只对被测版本/配置成立，不外推。
- 良性 marker 不能证明恶意行为不可见；产品不提供恶意载荷。
- 需要特权/GPU/节点访问的检测点在普通环境会 `blocked`，不是通过。
