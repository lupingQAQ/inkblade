# 动态验证 / Dynamic Verification

> 规则：没有在 mock 靶场跑过两态的模板，不算完成。
> 静态阅读、参考评估器、fixture 单态回放，都不能替代 Rust 探针的动态结果。
> 当前状态：模板迁移进行中，见第 7 节。

## 1. 为什么必须是动态

动态验证不是为了给文档凑一张表。它解决的是一类很具体的问题：模板看起来对，跑起来不对。

最常见的一种，是模板在修复后的服务上照样报“未授权路由”。查下去才发现，它探测的是 `/health`，而那个端点本来就不需要鉴权。另一种相反：模板在漏洞版本上也没命中，因为表达式取的是 `response.json.auth`，实际返回的字段叫 `authentication`。这两种错误，静态检查都看不出来，只有把同一份模板放到两个状态上跑，才会暴露。

模板是声明式程序，错误往往不在语法，而在语义。表达式取不到字段，`when` 就永远为假；步骤顺序反了，读会发生在写之前；期望状态码写成目标永远不返回的值；`findings` 的 evidence 指针指向不存在的步骤。还有一种更隐蔽：模板在 vulnerable 态命中，在 fixed 态也命中，说明它检测的是“服务存在”，不是“漏洞存在”。反过来，两态都不命中，说明它根本没跑到。

所以动态验证的要求很朴素：同一份模板，在两个可控状态上产生可区分的结果。一个状态证明它能检测，另一个状态证明它不是把所有目标都报成漏洞。

**English.** A template is only done when it has run against a mock target in two states: vulnerable and fixed. One state proves it can detect; the other proves it is not just detecting the service. Static review and single-state fixtures are not enough.

## 2. 每个模板的最低标准

mock 靶场要能本地启动，不依赖外网，端口固定。vulnerable 态返回 `status=findings`，至少一条 finding 命中预期 key。fixed 态返回 `status=ok`，而且没有同一条 finding。两态的 steps 和 checks 要能对比，差异能解释。模板声明的每个 `steps[].id` 至少执行一次，每个 `checks[].id` 至少有一次真或假的结果。模板创建的临时文件、连接要全部清理。连续跑 3 次，结果一致。证据里要有结果 JSON、步骤日志、manifest 和运行命令。运行期间不能有外部连接，DNS 只解析 mock 域。

只读模板在 `--read-only` 下跑通。写模板在 `--allow-write`、`mode=backup-write` 和备份回执下跑通；fixed 态验证“写被拒绝或被回滚”，不能只验证“写成功”。需要特权的模板，比如 hostNetwork、GPU、节点访问，mock 靶场不具备条件就标 `blocked`，不标 `verified`。依赖真实厂商产品的模板，比如 Elkeid、Falco、Kyverno，用 fixture 加本地假服务验证判定逻辑，再要求至少一次真实部署态回放；两者分开记录。模板变更后，受影响的验证全部重跑，不能沿用旧结果。

## 3. mock 靶场

靶场按 op 分层，不要求每个模板都起完整集群。HTTP 层是一个本地服务，按版本返回不同端点、头和状态码，覆盖框架、网关、Agent 平台和缓存。TCP 层是一个本地监听，按脚本返回 banner 或响应，覆盖数据库、Ray、NCCL bootstrap 和 SOCKS。文件层是临时目录加预置文件、挂载元数据，覆盖 checkpoint、HF 缓存、SA token 和设备节点。K8s 层用本地 API fixture 或 fake kubectl，覆盖 RBAC、Operator、准入和工作负载。防护产品层用厂商 fixture 加假服务，fabric/GPU 层用仿真快照和受控文件。

靶场只绑回环，不碰真实集群，不读真实云凭据。每个场景有固定随机种子；时间、PID、主机名要可注入，避免结果漂移。靶场启动失败时，验证直接 `blocked`，不能把“没跑起来”算成“模板通过”。目标版本写在场景里；同一模板对不同版本可以有不同的 expected findings。

## 4. 证据格式

每次验证产出独立目录，目录名是模板键加 run-id。里面至少有 `result-vulnerable.json`、`result-fixed.json`、两态的 steps JSONL、`manifest.sha256`、`command.txt` 和 `notes.md`。

结果 JSON 要能支撑复核。它需要 `schema`、`template`、`template_version`、`template_sha256`、`state`、`runtime`、`probe_version`、`protocol`、`target`、`started`、`duration_ms`、`status`、`findings`、`checks`、`steps`、`cleanup`、`environment`。`manifest.sha256` 覆盖目录内所有文件。`command.txt` 记录可复现命令，但不含 token。`notes.md` 记录靶场版本、偏差和未覆盖项。

结果 JSON 必须来自 Rust 探针（`runtime=rust`）。参考评估器结果只能放在 `reference/` 子目录，不进入覆盖统计。失败的 run 也要保留，便于回归。token、SA token、真实凭据不写进证据；必要时只存 SHA-256。报告里的每条 finding 必须能回到 `template + run + step`，不能只写“已验证”。

## 5. 覆盖率表字段

覆盖率表由脚本生成，字段固定。`template` 是模板键，与模块目录同名；`layer` 是 1–10 层；`series` 是模块系列；`min_level` 是四档级别；`writes` 表示是否声明写；`mock` 是靶场场景 id；`vulnerable` 和 `fixed` 各自是 `pass`、`fail`、`blocked`、`not-run`；`runs` 是连续运行次数，至少 3；`last_run` 是 UTC 时间；`status` 是 `verified`、`in-progress`、`blocked`、`failed`；`evidence` 是证据目录相对路径；`notes` 记录偏差、版本和限制。

覆盖率口径要写死：分母是全部 `template` 模板，`blocked` 计入分母、不计入分子；`verified` 要求 vulnerable 与 fixed 都 `pass`，且连续 3 次一致；参考评估器、fixture 单态、静态检查都不计入 `verified`。`blocked` 必须写原因，不能因为“难跑”就标 blocked。

## 6. CI 闸门

合并前必须过六道：模板 schema 校验；mock 靶场 vulnerable/fixed 两态；连续 3 次一致；证据目录完整且 manifest 校验通过；覆盖率表更新；没有 `runtime=reference` 的结果混入。

`failed` 要修模板或修靶场，不合并；`blocked` 可以在 PR 里写明缺什么部署面，可以合并模板，但不能标 `verified`，也不能进覆盖率分子；`flaky` 先定位非确定性来源，不允许用重试掩盖。

## 7. 当前完成度

截至 2026-10-27，迁移进入收尾。以下数字来自当前工作树：模块目录 287 个，其中 286 个有 `template.json`，1 个是 `probe-bootstrap`；迁移窗口内仍保留 286 个旧 `run.py`，注册表在过渡期忽略它们，发布前必须删除。参考评估器已经能跑 286 个模板，`reports/probe-coverage/evidence.json` 里有 286 条两态记录；但这些记录的 `runtime` 都是 `reference`，不是 `rust`。

这里有一个必须说清的差异。`docs/PROBE-COVERAGE.md` 的汇总行写“动态模板验证 286/286（100.0%）”，它统计的是参考评估器两态结果；按本文第 2 节的标准，Rust 探针动态验证仍然是 0。两个数字不矛盾，但口径不同。产品对外只能说“参考评估器两态完成 286/286；Rust 运行时验证待重跑”，不能说“全量 Rust 动态验证完成”。

11 个 defense-bypass 模块已经全部有 `template.json`，也有 fixture 两态评估；它们的证据同样是 `runtime=reference`，不计入 Rust 覆盖率。分层状态因此分两列看：模板迁移接近完成，Rust 运行时验证还没开始。第 1 到第 9 层的模板数按 `PROBE-COVERAGE.md` 的生成结果盘点；第 10 层 11 个模块已迁移，Rust 已验证 0，fixture 评估 11/11。

本文不提供“demo 通过率”或“trial 成功率”；本产品不提供 demo/trial 路径。

## 8. 完成定义

一个模板可以标 `verified`，必须同时满足：`template.json` 通过 schema；在 mock 靶场 vulnerable 态产生预期 finding；在 fixed 态不产生同一 finding；连续 3 次一致；只读/写模式符合声明；清理成功；证据目录完整；覆盖率表更新；没有外部网络依赖。

一个层可以标“完成”，必须满足：该层所有 `template` 模块都 `verified` 或有明确 `blocked` 理由；`blocked` 的模块在报告里可见；组合层至少有一条跨组件链跑通两态；第 10 层 11 个模块全部有 fixture 两态结果，且至少 3 个在真实部署态回放。

## 9. English summary

Every template must run in two states against a local mock target: vulnerable (expected finding) and fixed (no such finding), three times, deterministically, offline. Results are stored with template hash, probe version, protocol version, steps, checks, findings, cleanup, and a SHA-256 manifest. The coverage table counts only Rust probe runs; reference-evaluator and single-state fixture results do not count.

As of 2026-10-27 the migration is in its final window: 287 module directories, 286 `template.json` files, one bootstrap module, and 286 legacy `run.py` files awaiting removal. The reference evaluator has two-state evidence for 286/286 templates, but every entry says `runtime=reference`; Rust-runtime verification is still zero. The 11 defense-bypass modules have fixture-based two-state assessment under the same reference runtime and are not counted as Rust coverage.

生成式覆盖率表见 [`docs/PROBE-COVERAGE.md`](PROBE-COVERAGE.md)；注意其中 `runtime=reference` 与本文的 Rust 标准不同。

## 证据 / 限制

**证据**

- 模板 schema：`probe/schema/probe-template.schema.json`；参考评估器：`inkblade/tpl/engine.py`。
- 模板加载与校验：`inkblade/tpl/schema.py`（`template_path`、`iter_templates`、`validate`）。
- 注册表强制模板：`inkblade/core/registry.py`（缺 `template.json` 报错；迁移窗口内 `run.py` 被忽略，发布门负责删除）。
- 当前计数：模块目录 287，`template.json` 286，bootstrap 1，迁移窗口 `run.py` 286，defense-bypass 模块 11；参考评估器两态证据 286 条，`runtime=reference`。

**限制**

- 参考评估器覆盖率 286/286 不等于 Rust 运行时覆盖率；后者仍为 0。旧 `run.py` 在迁移窗口内保留，不能算作“已删除”或“已 Rust 验证”。
- mock 靶场只能验证判定逻辑和协议行为，不能证明真实集群的版本、配置、权限组合；真实部署态需要单独回放并记录。
- 需要特权、GPU、hostNetwork、节点访问的模板在普通 CI 里会 `blocked`；这不是通过。
- 动态验证不能发现“模板本身设计错了检测点”的问题；那需要人工评审和真实环境对照。
- 结果确定性受时间、PID、网络抖动影响；靶场必须注入固定值，否则标 `flaky` 而不是重试掩盖。
