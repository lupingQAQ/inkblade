# FAQ / 常见问题

[English](#english) · [中文](#中文)

---

## English

### Do I need a cluster to try it?

No. `doctor` and `pilot --dry-run` run entirely offline. The dry run writes an empty profile, a
plan and an approval list, so you can see the shape of the deliverable before you ask anyone for
access. `ui` serves the console on loopback.

### Does it need an API key, an account or a licence server?

No. There is no account system beyond the local `users.json`, no licence check, and no outbound
telemetry. Optional integrations — SIEM, ITSM, the LLM pool — stay off until you configure them.
The scan path never needs a model key.

### Does it need an LLM?

No. Recon, module runs, chains, evidence, exports and report bodies are deterministic, and the
runtime is the Python standard library. A model is optional and off by default. When attached, it
only ranks the candidate modules the rule engine already produced, or runs inside the L3 loop. With
no endpoint the planner falls back to fixed rule order and records the downgrade as `mode: rules`.

One exception is deliberate: `explore autonomy --llm` refuses at preflight when no endpoint exists.
A rehearsal should not pass green while the model was never contacted.

### What data can reach a model?

Prompts can carry candidate module keys, product names, asset counts, eligible chain ids, the RoE
level and the blackboard summaries a lead pinned: finding title, severity, evidence anchor, asset
key, product and address. The narrative report sends counts. Credentials, service-account tokens,
request bodies, evidence archives and report text stay local. Audit rows store endpoint, model,
token count and latency, not prompt text. Point it at a local or approved endpoint; the rest is in
[Agent & LLM](AGENT-LLM.md).

### Can it run on its own?

Only under L3, and only after a lead pre-authorizes it. The consent level must be full-impact demo,
the grant carries a token with a TTL that can be revoked, the module allowlist must be non-empty,
and four budget caps must be positive. At run time the guard stops on a scope miss, an unlisted
module, an unauthorized write, a budget overrun or two consecutive failures. Anything less is
propose-and-wait. See [Agent & LLM](AGENT-LLM.md).

### Why only the Python standard library?

Because a security tool that needs a compiler and forty dependencies is hard to run inside a
bank, and harder to audit. Standard library means `pip install` is optional, the container is
small, and you can read exactly what executes.

The trade-off is real: no numpy, no async framework, no third-party parser. Where that hurt,
we wrote the small thing ourselves and tested it.

### Is it production-ready?

No. It is pre-1.0. Interfaces move between minor versions, there is no HA story, no vendor SLA
and no certification. What it does have is evidence, gates and a written list of gaps. Use it
for pilots and engagements; don't put it in a regulated production path and call it done.

### What does “authorized testing only” mean in practice?

It means the tool will not run without a consent record that names the scope, the level and the
window. That is a technical control, not a suggestion. If you have no written authorization for
the target, the correct action is to get one — not to look for a flag that skips the gate. There
is no such flag.

### How do you decide what goes in the coverage table?

Two conditions: the primitive was reproduced dynamically on a pinned upstream version, and the
novelty check found no matching public advisory. Static-only hits never enter the table.
Current count: 41 verified primitives across 24 components, after merging variants of the same
sink.

### Why is there no exploit code in the coverage table?

Because a version string plus a vulnerability class is enough for a defender to check exposure,
and an exploit is not. The table lists component, class, affected versions and the verification
shape. Code, request bodies and root-cause locations stay out of the published repository.

### Can I verify the claims myself?

Mostly, yes. Numbers on the site come from generated documents and from commands you can run:
`surfaces` for coverage, `rules validate` for replay coverage, `report` for evidence, and the
test suite for behaviour. The coverage table is generated from the same inventory the tool
ships with, so the row count is reproducible. Advisory-handling conversations are the part you
cannot verify from outside.

### Does it work on Windows and macOS?

The control host does. Modules that need Unix sockets or Linux-only tooling are marked and
skipped on other platforms rather than failing halfway. The test suite runs on Windows and Linux
in CI; macOS is a supported host but not a CI target yet.

### Can it run air-gapped?

Yes, and that is the normal case for most users. Install from a wheel or a checkout, carry the
container image with `docker save`, and skip every integration. `doctor` and `pilot --dry-run`
never leave the machine.

### Can I use it commercially? Can I fork it?

Apache-2.0 says yes to both. Keep the notices, including `NOTICE`. The licence does not grant
trademark rights, so don't ship a fork called InkBlade.

### How do I report a vulnerability in InkBlade itself?

Use the hosting platform's private vulnerability reporting, with a 90-day coordination target.
Please don't open a public issue containing exploit detail; a minimal “I need a private channel”
issue is fine if private reporting is unavailable.

### How do I add a module?

`inkblade sdk new` scaffolds one, `sdk lint` and `sdk validate` check it, `sdk trust` records the
fingerprint. Upstream submissions need a manifest, a dry-run path and tests. Modules that need a
live cluster should bring a fixture so CI can exercise them.

### How noisy is it?

It depends on the module. Read-only enumeration is quiet by construction; active probing and
exploit verification produce traffic and logs. The report separates “observed” from “inferred”,
and findings carry evidence anchors, so a reviewer can throw out the ones that don't hold. False
positives are reduced, not eliminated.

### Why are 11 modules quarantined?

They need a surface that none of the six reference profiles has — for example an agent-native
control plane. Keeping them enabled would inflate coverage with modules that can never apply.
They stay in the tree for the deployments that do have those surfaces, and are excluded from the
coverage denominator.

---

## 中文

### 没有集群能试吗？

能。`doctor` 与 `pilot --dry-run` 全部离线。离线演练会写出空画像、计划和审批清单，
你可以在向任何人申请权限之前，先把交付物的形状看一遍。`ui` 只在回环地址上提供控制台。

### 需要 API key、账号或授权服务器吗？

都不需要。除了本地的 `users.json`，没有账号体系，没有许可证校验，也没有外发遥测。SIEM、ITSM、LLM 池这些
可选集成，你不配置就一直关着。扫描路径本身不需要模型 key。

### 需要 LLM 吗？

不需要。侦察、模块执行、链、证据、导出与报告正文都是确定性执行，运行时只用 Python 标准库。模型是可选项，
默认关闭。接上以后，它只给规则引擎已经产出的候选排序，或者在 L3 循环里工作。没有端点时，规划器回到固定
规则顺序，并把降级记成 `mode: rules`。

有一个例外是故意的：`explore autonomy --llm` 在没有端点时于预检阶段直接拒绝。演练不该在模型从未被调用
的情况下显示通过。

### 哪些数据可能发给模型？

提示词里可能有候选模块 key、产品名、资产数量、成立的链 id、RoE 级别，以及 lead 固定到黑板的摘要：发现
标题、严重度、证据锚点、资产 key、产品与地址。叙述型报告只发计数。凭据、ServiceAccount 令牌、请求正文、
证据归档与报告正文留在本地。审计行只记端点、模型、token 数与延时，不记提示词。端点用本地的，或安全团队
批准过的；细节见 [Agent 与 LLM](AGENT-LLM.md)。

### 它能自己跑吗？

只有 L3 可以，而且必须先由 lead 预授权。授权级别要是「全影响演示」，grant 里带一个有 TTL、可撤销的 token，
模块白名单非空，四项预算都为正。运行时护栏在范围不符、模块不在白名单、未授权写、预算越顶、连续两次失败时
都会停。除此之外都是“提议并等待”。细节见 [Agent 与 LLM](AGENT-LLM.md)。

### 为什么只用 Python 标准库？

因为一个需要编译器和四十个依赖的安全工具，在银行里很难跑起来，更难审计。只用标准库意味着 `pip install` 是可选的、
镜像很小，而且你能读清楚到底执行了什么。

代价是真实的：没有 numpy、没有异步框架、没有第三方解析器。疼的地方，就自己写小实现，然后测它。

### 生产可用吗？

不可用。pre-1.0。接口会在次版本间变，没有 HA 方案、没有厂商 SLA、没有认证。它有证据、有闸门、有一份写明白的
缺口清单。拿它做试点和项目可以；别把它塞进受监管的生产路径然后当没事。

### “仅限授权测试”具体是什么意思？

意思是：没有写明范围、级别、时间窗的授权记录，工具就不跑。这是技术控制，不是建议。手上没有书面授权时，
正确动作是去拿授权，而不是找一个跳过闸门的开关——没有这个开关。

### 覆盖表怎么算？

两个条件：在上游固定版本上动态复现成功，且查新没有找到匹配的公开 advisory。纯静态命中不进表。
当前数字：24 个组件、41 条独立原语，已合并同一 sink 的变体。

### 公开的覆盖表里为什么没有可执行利用代码？

因为版本号加漏洞类别，足够防守方判断暴露面；利用代码不够。表里只有组件、类别、受影响版本和验证形态。
代码、请求内容、根因位置不进入公开仓库。

### 我能自己验证这些说法吗？

大部分可以。站上的数字来自生成的文档和你能跑的命令：覆盖率用 `surfaces`，重放覆盖用
`rules validate`，证据用 `report`，行为用测试套件。覆盖表由工具自带的清单生成，行数可复算。
外部无法验证的只有 advisory 的处理过程。

### Windows 和 macOS 能用吗？

控制端可以。需要 Unix socket 或 Linux 专用工具的模块会被标记并在其他平台上跳过，而不是跑到一半失败。
CI 覆盖 Windows 与 Linux；macOS 是受支持的控制端，但还不是 CI 目标。

### 能离线部署吗？

能，而且对多数用户来说这就是常态。用 wheel 或源码检出安装，用 `docker save` 带镜像过去，所有集成都不配。
`doctor` 与 `pilot --dry-run` 都不会出网。

### 可以商用吗？可以 fork 吗？

Apache-2.0 两个都允许。保留声明，包括 `NOTICE`。许可证不授予商标权，所以 fork 别叫 InkBlade。

### InkBlade 自身有漏洞怎么报？

走托管平台的私密漏洞报告通道，协调披露目标 90 天。别开公开 issue 贴利用细节；实在没有私密通道时，
开一个只写“我需要一个私密联系方式”的最小 issue 即可。

### 怎么加模块？

`inkblade sdk new` 生成骨架，`sdk lint`、`sdk validate` 校验，`sdk trust` 记录指纹。向上游提交需要 manifest、
dry-run 路径和测试。只能对着真实集群跑的模块，请附 fixture，否则 CI 没法验证。

### 噪音大吗？

看模块。只读枚举天生安静；主动探测和利用验证会产生流量与日志。报告把“观测到”和“推断出”分开，
每条发现都有证据锚点，审阅者可以把站不住的删掉。误报会减少，不会消失。

### 为什么隔离了 11 个模块？

它们需要的部署面，六个参考画像里都没有——比如 Agent 原生控制面。默认开启它们，只会用永远不适用的模块把覆盖率撑好看。
它们留在树里，给确实有这些部署面的客户用，但不进覆盖率分母。
