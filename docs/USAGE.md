# Usage / 使用手册

> 路径：`doctor → session → probe → exec/scan → report`。
> 目标侧执行体：Rust 探针。模板是数据；控制端 Python 不进入目标 Pod。

### Quick reference

`doctor` 检查环境，`session start` 建授权会话，`probe deploy` 投放探针，`exec` 跑单模板或 `scan` 按层扫描，`report` 出双语报告。每一步的输出都是下一步的输入；没有 demo/trial 捷径。

## 先理解五个对象

一次测试由五样东西串起来。`session` 是授权容器，记录目标、范围、级别、时间窗和证据目录；`probe` 是目标 Pod 里的 Rust 执行体，有 `probe_id` 和 `parent_id`；`template` 是声明式检测程序，含 steps、checks、findings、artifacts；`task` 是一次模板执行；`evidence` 是结果、日志和 manifest。它们的关系不复杂：一个 session 可以有多棵探针树，一个探针可以跑多个模板，一个模板可以产生多条 finding，每条 finding 必须指向一个 task + step。

## 五步主路径

### doctor

```bash
python -m inkblade doctor
```

先看 `FAIL`。没有跳过开关，也不要试图用环境变量绕过；那些检查通常对应上一次踩过的坑。再看探针二进制：控制端可以不是 Linux，但目标必须是 Linux，架构要匹配。没有 kubeconfig 时，`doctor` 仍然能跑本地检查，但你不能产出“渗透结果”，只能做模板校验。

### session

```bash
python -m inkblade session start \
  --name pilot-01 \
  --workspace ./work \
  --kubeconfig ~/.kube/config \
  --scope namespace:ml-team \
  --level read-only \
  --window 2026-10-27T09:00/2026-10-27T18:00
```

`--scope` 可以写 namespace、Pod 选择器或 CIDR，越界即拒绝。`--level` 是 `read-only`、`active-probe`、`exploit-verify`、`full-impact` 四档；模板的 `min_level` 高于它时会被拒绝，不会“先跑跑看”。`--window` 是授权时间窗，过期即拒绝。session 目录保存 consent 校验结果、范围、用户和证据根。

查看和关闭：

```bash
python -m inkblade session list
python -m inkblade session show pilot-01
python -m inkblade session close pilot-01
```

### probe

```bash
python -m inkblade probe deploy \
  --session pilot-01 \
  --target ml-team/infer-0 \
  --container inference \
  --method kubectl-exec \
  --binary ./inkblade-probe-linux-amd64 \
  --read-only
```

四个 `--method` 对应四种现实：`rce` 用于有授权代码执行入口但没有 kubectl；`kubectl-exec` 用于有 pods/exec 且容器可写；`ephemeral` 用于不能重启业务容器；`volume` 用于批量 Pod 或没有 exec 权限。每个方法的前置条件和痕迹不同，详见 `PROBE-DEPLOY.md`。部署后先 `probe list` 和 `probe show`，确认目标、容器、只读状态、父子关系都对，再 `probe collect` 拉快照。

```bash
python -m inkblade probe list --session pilot-01
python -m inkblade probe show p-7f3a1c9e --session pilot-01
python -m inkblade probe collect p-7f3a1c9e --session pilot-01
python -m inkblade probe cleanup p-7f3a1c9e --session pilot-01
```

`probe show` 会显示投放方式、只读状态、任务数、最后心跳和清理状态。快照里的 SA、挂载、网络接口、GPU 设备，是后面判断“这个模板适不适用”的依据。

### exec / scan

单模板：

```bash
python -m inkblade exec \
  --session pilot-01 \
  --probe p-7f3a1c9e \
  --template service-account-token-exposure \
  --params '{"path":"/var/run/secrets/kubernetes.io/serviceaccount"}'
```

按层扫描：

```bash
python -m inkblade scan --session pilot-01 --profile ray-vllm --layers 1,2,5,6,8
```

按系列：

```bash
python -m inkblade scan --session pilot-01 --series 侦察,横向利用 --read-only
```

只看计划：

```bash
python -m inkblade scan --session pilot-01 --profile ray-vllm --dry-run
```

`--dry-run` 输出模板键、层、级别、是否写、所需部署面、预计任务数和预算；不投放、不执行、不写证据。它适合在审批前给客户看“我们准备跑什么”，但它不验证目标可达性。

`--params` 是 JSON，也可以 `@params.json` 从文件读。模板的 `inputs` 会从 `params` 解析；必填缺失返回 `skipped`。`--mode probe-only|backup-write` 默认 `probe-only`；写模板必须 `backup-write` 且有备份回执。`--timeout-ms`、`--max-output` 可以覆盖默认预算，但不能超过探针上限。

### report

```bash
python -m inkblade report --session pilot-01 --lang bi --format md
python -m inkblade report --session pilot-01 --lang zh --format html
python -m inkblade export --session pilot-01 --format sarif
python -m inkblade export --session pilot-01 --format ocsf
```

报告里应该有范围与授权、探针树、按层发现、组合链、盲区和修复建议。探针树要能看到投放方式、父子关系、清理状态；发现要带证据锚；盲区要列出未覆盖模板、blocked 部署面和动态验证失败项。没有证据的 finding 不生成。

## 典型场景

### 只读基线

第一次会话建议只做只读基线：一个 namespace、一个 Pod、一个模板，确认通道和证据，再扩到 1、3、5、7 层。产出是部署面、RBAC、镜像/模型来源、缓存配置和防护产品部署态。没有写操作，报告也更容易复核。

```bash
python -m inkblade session start --name baseline --workspace ./work \
  --kubeconfig ~/.kube/config --scope namespace:ml-team --level read-only
python -m inkblade probe deploy --session baseline --target ml-team/infer-0 \
  --method kubectl-exec --binary ./inkblade-probe-linux-amd64 --read-only
python -m inkblade scan --session baseline --profile ray-vllm --layers 1,3,5,7
python -m inkblade report --session baseline --lang bi
```

### 单模板复核

一条 finding 站不站得住，用单模板复核最快：

```bash
python -m inkblade exec --session baseline --probe p-7f3a1c9e \
  --template prefix-cache-cross-tenant-leak \
  --params '{"target":"infer-0.ml-team:8000","tenant":"a","other":"b"}'
```

看 `data.findings`、`data.checks`、`data.steps`。如果 `status=skipped`，看是缺输入还是部署面不存在；不要把它当“安全”。如果 `runtime=reference`，这条结果不能进报告结论。

### 多探针与内部横向

```bash
python -m inkblade probe spawn --session baseline --parent p-7f3a1c9e \
  --target ml-team/infer-0 --probe-id p-child-1
python -m inkblade probe spawn --session baseline --parent p-7f3a1c9e \
  --target ml-team/infer-1 --method k8s-copy --binary ./inkblade-probe-linux-amd64
python -m inkblade probe tree --session baseline
python -m inkblade probe socks --session baseline --probe p-7f3a1c9e \
  --bind 127.0.0.1:1080 --allow-cidr 10.0.0.0/24
```

子探针继承父探针的只读、白名单和预算，只能更严格。跨 namespace 需要 session 范围覆盖，否则拒绝。`socks` 默认只绑回环；对外绑定要显式 `--allow-cidr`。清理用 `probe cleanup --scope subtree`，先子后父。

### 防护绕过评估

```bash
python -m inkblade scan --session baseline --series 情报 --layers 10
```

或者单产品：

```bash
python -m inkblade exec --session baseline --probe p-7f3a1c9e \
  --template defense-bypass-falco \
  --params '{"state":"deployed","fixture":"falco-deployed"}'
```

输出三类：`detected`、`blindspots`、`hardening`。它是良性 marker 验证，不是“绕过演示”；盲区结论只对被测版本和配置成立。不要把它当恶意规避能力，也不要把“没告警”直接写成“可绕过”。

### 写验证

只有确实需要验证写面时才做：

```bash
python -m inkblade exec --session baseline --probe p-7f3a1c9e \
  --template checkpoint-shard-poison \
  --mode backup-write \
  --backup-id b-2026-10-27-001 \
  --params '{"path":"/workspace/ckpt","mode":"backup-write"}'
```

五道闸门：session 级别至少 `exploit-verify`；探针 `--allow-write`；模板 `meta.writes=true`；`--mode backup-write`；备份回执存在。缺任何一条，写步骤 `skipped` 或 `E_DENIED`。写后回读哈希，失败回滚。

## 读结果

一个结果至少有 `status`、`steps`、`checks`、`findings`、`artifacts` 和 `runtime`。`status=ok` 表示模板跑完、没有 finding，不代表目标安全，可能只是没命中；`status=findings` 表示有发现，先看 severity 和 evidence，再看 checks 是否支持；`status=skipped` 表示输入缺失、部署面不存在或写步骤被只读跳过；`status=error` 看 `error.code`、`error.step`。`runtime=reference` 是参考评估器结果，不是 Rust 探针，不能进报告结论。

证据锚有五种：`task:<id>`、`step:<id>`、`artifact:<name>`、`probe:<id>`、`manifest:<sha256>`。报告里每条 finding 至少带一个证据锚；没有证据的 finding 不生成。

## 退出码

| 码 | 含义 |
|---|---|
| 0 | 成功；可能有 findings |
| 1 | 参数/配置错误 |
| 2 | 模板/验证失败 |
| 3 | 部分失败，但报告已生成 |
| 4 | 授权/范围/时间窗拒绝 |
| 5 | 探针不可用/握手失败 |
| 6 | 证据/manifest 校验失败 |
| 91 | 写闸门拒绝（备份/授权/只读） |

CI 里建议把 4、5、6、91 当硬失败；0 和 3 由策略决定。

## 报告与规则包

```bash
python -m inkblade rules generate --session baseline --pack admission
python -m inkblade rules generate --session baseline --pack runtime
python -m inkblade rules generate --session baseline --pack network
python -m inkblade rules validate --session baseline
```

规则包来源要对应盲区：Kyverno/Gatekeeper 管准入豁免/Audit/mutation/子资源；Sigma 管进程、文件、DNS、改名执行；Falco/Tetragon 管 syscall、容器逃逸、敏感路径；Suricata/WAF 管编码、分块、Unicode、超长请求。`rules validate` 输出拦截/检出/漏过矩阵；漏过项要回到模板和靶场，不是改规则文案。

## 排障

`E_AUTH` 先查 token 文件权限、是否为空、父子 token 是否混用。`E_FRAME` 多半是 stdin/stdout 被 shell banner 或 TTY 污染。`E_TIMEOUT` 查目标可达性、模板总超时、探针 CPU 限制。`E_DENIED` 查只读模式、命令白名单、模板是否声明 write。`E_K8S` 查 SA token、RBAC、API server 地址、镜像里有没有 kubectl。`E_DEPLOY` 查架构、可写路径、noexec、memfd。`E_HASH` 查传输截断、块顺序、SHA256SUMS 版本。`skipped` 查输入缺失、部署面不存在、只读跳过写。看到 `runtime=reference`，把它从结论里剔除。

## English summary

Start with `doctor`, create a session with scope and time window, deploy a probe through one of four methods, run one template with `exec` or a layer set with `scan`, then render a report. `--dry-run` shows the plan without execution. Read `status`, `runtime`, `findings`, `checks`, and the evidence anchor; `runtime=reference` never counts as probe evidence.

Probe trees are explicit: child probes inherit stricter limits, cross-namespace spawn needs scope coverage, and cleanup is child-first. Writes need authorization, `--allow-write`, `meta.writes`, `backup-write` mode, and a backup receipt.

## 证据 / 限制

**证据**

- CLI 参数与闸门：`inkblade/cli.py`、`inkblade/core/roe.py`、`inkblade/core/runner.py`。
- 证据锚与 manifest：`inkblade/core/evidence.py`。
- 模板执行语义：`inkblade/tpl/engine.py`、`probe/schema/probe-template.schema.json`。
- 规则包：`inkblade/rules/generate.py`、`inkblade/rules/validate.py`。

**限制**

- 2026-10 迁移进行中，`session/probe/exec/scan` 的最终参数以 CLI 为准；旧命令仍可能存在，但不在本文主路径。
- `scan --layers` 只选择已注册模板；未迁移模板不会出现在结果里。
- `--dry-run` 不验证目标可达性，只验证计划与预算。
- `runtime=reference` 结果不能进报告结论；它只用于 mock/CI 对照。
- 报告可以给出修复建议，但不能替代人工复核；误报和漏报都存在，限制节必须保留。
