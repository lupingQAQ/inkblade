# 探针协议 / Probe Protocol v1

> 适用范围：控制端与 `inkblade-probe` 之间；也适用于父探针与子探针。
> 传输：stdio、TCP 或 Unix 域套接字；同一套帧格式。
> 状态：v1 草案，随探针 CLI 收尾。字段以本文为准，代码以 `probe/src/protocol.rs` 对齐。

## 1. 帧格式

每条消息由两部分组成：4 字节大端长度，加上 UTF-8 JSON 负载。长度字段算的是负载字节数，不含这 4 字节头。负载必须大于 0，且不超过 8 MiB（`MAX_FRAME`）；数组、标量、空负载一律拒绝。协议不做压缩，也不拆帧；大文件走文件分块任务，不靠把一帧撑大。

```
+----------------+------------------------------+
| 4 字节长度 BE  | UTF-8 JSON 负载               |
+----------------+------------------------------+
```

读端遇到 `EINTR` 要重试；读到 0 且没读满 4 字节，视为截断。写端写完立即 flush，不允许把多条帧拼进一个写缓冲后延迟发送。这个约束看起来琐碎，但它决定了 `kubectl exec` 的 stdio 通道能不能稳定工作：shell banner、TTY 回显、管道缓冲，任何一个混进来，帧就会错位。

**English.** Every message is a 4-byte big-endian length followed by a UTF-8 JSON object. The maximum frame is 8 MiB. Large files use chunked file tasks, not oversized frames.

## 2. 消息类型

| 类型 | 方向 | 用途 |
|---|---|---|
| `hello` | probe → controller | 宣告版本、probe_id、能力、nonce、只读状态 |
| `auth` | controller → probe | 用共享 token 对 nonce 做 HMAC 证明 |
| `ready` | probe → controller | 认证通过，报告限制与会话 id |
| `task` | controller → probe | 下发一个模板任务或控制任务 |
| `result` | probe → controller | 返回任务结果或错误 |
| `event` | probe → controller | 异步事件：子探针上线、清理失败、预算告警 |
| `cancel` | controller → probe | 取消在途任务 |
| `ping` / `pong` | 双向 | 保活与 RTT 测量 |
| `pull` / `push` | 双向 | 文件分块读取/写入 |
| `cleanup` | controller → probe | 清理指定资源或整棵子树 |
| `bye` | 双向 | 正常关闭；收到后不再接受新任务 |

`task` 的 `op` 可以是 `template`、`collect`、`http`、`tcp`、`exec`、`fs`、`k8s`、`socks`、`spawn`、`probe.list`、`probe.cleanup` 或 `session.stats`。生产路径优先用 `template`；单 op 任务只用于探针自检、协议调试和 bootstrap 验证。单 op 不绕过授权，也不绕过只读/白名单。

## 3. 握手与认证

探针启动后先发 `hello`：

```json
{
  "v": 1,
  "type": "hello",
  "probe_id": "p-7f3a1c9e",
  "parent_id": null,
  "version": "0.1.0",
  "caps": ["http", "tcp", "exec", "fs", "k8s", "socks", "spawn", "collect"],
  "read_only": true,
  "nonce": "b64:9mK3...",
  "ts": 1793000000.125
}
```

`nonce` 是每次启动新生成的 16 字节随机数，base64url 编码。`probe_id` 由控制端指定或由探针生成，同一 session 内必须唯一。

控制端收到后计算 `proof = HMAC-SHA256(token, nonce || probe_id || parent_id_or_empty)`，再发 `auth`：

```json
{
  "v": 1,
  "type": "auth",
  "id": "a-1",
  "proof": "b64:...",
  "session": "s-2026-10-27-001"
}
```

token 是 32 字节随机值，通过 `--token-file` 传入，文件权限 0600；它不出现在 argv、环境变量、日志或证据里。探针用常量时间比较 proof；失败返回 `E_AUTH`，连续 3 次失败关闭连接。认证前只接受 `hello`、`auth`、`ping`，其他类型一律 `E_AUTH`。每个子探针使用独立 token；父探针只把 token 写入子探针的 token 文件，不转发给控制端。TCP/Unix 通道必须认证，stdio 通道也必须认证，不能因为“本地”跳过。

认证通过后，探针发 `ready`：

```json
{
  "v": 1,
  "type": "ready",
  "probe_id": "p-7f3a1c9e",
  "session": "s-2026-10-27-001",
  "read_only": true,
  "limits": {
    "max_output": 1048576,
    "max_timeout_ms": 30000,
    "max_window": 4,
    "max_frame": 8388608
  },
  "allow_cmds": ["id", "ls", "cat"],
  "ts": 1793000000.131
}
```

控制端收到 `ready` 后才能发 `task`。`limits` 是探针实际生效值，不是控制端请求值；控制端必须以 `ready` 为准。

## 4. 任务与结果帧

一个模板任务长这样：

```json
{
  "v": 1,
  "type": "task",
  "id": "t-0001",
  "op": "template",
  "deadline_ms": 8000,
  "args": {
    "template": "vllm-plugin-auth-bypass",
    "params": {"target": "127.0.0.1:8000", "mode": "probe-only"},
    "max_output": 262144
  }
}
```

`id` 在同一连接内唯一，建议单调递增；`deadline_ms` 是单任务墙钟上限，探针会 clamp 到 `--max-timeout-ms`；`args` 里放模板键、参数和输出上限；`write` 可显式声明该任务可能写，缺省按模板 `meta.writes` 判断。

成功结果：

```json
{
  "v": 1,
  "type": "result",
  "id": "t-0001",
  "ok": true,
  "probe": {"id": "p-7f3a1c9e", "parent_id": null},
  "started": 1793000000.200,
  "finished": 1793000000.412,
  "duration_ms": 212,
  "data": {
    "schema": "inkblade-probe-result-v1",
    "status": "findings",
    "steps": [], "checks": [], "findings": [], "artifacts": [],
    "runtime": "rust"
  }
}
```

失败结果：

```json
{
  "v": 1,
  "type": "result",
  "id": "t-0001",
  "ok": false,
  "probe": {"id": "p-7f3a1c9e", "parent_id": null},
  "error": {
    "code": "E_TIMEOUT",
    "message": "template exceeded 8000ms",
    "retryable": false,
    "step": "probe"
  }
}
```

`ok=true` 不代表“目标安全”，只代表任务执行完成；安全结论看 `data.findings` 和 `data.checks`。`ok=false` 必须带 `code`、`message`，最好带 `step`。`data.status` 只有 `ok`、`findings`、`skipped`、`error` 四种。`data.runtime` 必须是 `rust`；参考评估器返回 `reference`，不得混入探测证据。结果帧必须带 `probe.id`；子探针结果带 `probe.parent_id`。同一 `id` 重发视为重复，控制端保留第一次成功结果，第二次记 `duplicate`。

`event` 用于进度和树变化，不替代结果。需要可靠交付的事实必须放进 `result`。

## 5. 超时与预算

| 预算 | 默认 | 硬上限 | 执行点 |
|---|---:|---:|---|
| 单帧 | 8 MiB | 8 MiB | 读/写两端 |
| 单任务墙钟 | 模板 `limits.timeout_ms` 或 8000ms | `--max-timeout-ms`（默认 30000ms） | 探针 |
| 单请求超时 | 5000ms | 120000ms | http/tcp |
| 单任务输出 | 1 MiB | 16 MiB | 探针 |
| HTTP 请求数 | 256/模板 | 256 | 模板引擎 |
| 在途任务 | 4 | `--max-window` | 探针 |
| 子探针深度 | 3 | 5 | spawn |
| 子探针数量 | 8/父 | 16/父 | spawn |
| 会话总时长 | 由控制端设置 | 24h | 控制端 + 探针 TTL |
| 孤儿 TTL | 120s | 600s | 探针 |

任务超时后，探针杀死当前 op 的子进程或连接，返回 `E_TIMEOUT`；已完成步骤保留在 `data.steps` 里，未完成步骤标 `skipped`。预算超限返回 `E_BUDGET`，不自动降级到无上限。`cancel` 命中在途任务后，探针在下一个检查点停止，结果返回 `E_CANCELLED`，已产生的步骤保留。只有 `retryable=true` 的错误允许控制端重试；`E_AUTH`、`E_DENIED`、`E_TEMPLATE` 不重试。

## 6. 文件分块

文件读写统一用偏移量，不把整个文件塞进一帧。`pull` 从探针读文件：

```json
{
  "v": 1, "type": "pull", "id": "f-1",
  "path": "/workspace/out.bin",
  "offset": 0,
  "length": 1048576,
  "max_chunk": 1048576
}
```

返回结果里带 `path`、`offset`、`bytes`、`total`、整文件 `sha256` 和 `data_b64`。单块上限 1 MiB，`length` 不得超过 `max_chunk`；`sha256` 是整文件哈希，不是块哈希。控制端按 offset 递增拼接，不连续即拒绝；最后一块满足 `offset + bytes == total`。读取失败返回 `E_IO`，文件不存在返回 `E_NOTFOUND`。大文件不自动压缩，需要压缩由控制端在证据层处理。

`push` 从控制端写文件：

```json
{
  "v": 1, "type": "push", "id": "f-2",
  "path": "/tmp/inkblade-probe",
  "offset": 0,
  "total": 5242880,
  "sha256": "9f2c...",
  "data_b64": "AAEC...",
  "final": false,
  "mode": "0700"
}
```

写之前检查 `read_only`；`push` 一律需要 `--allow-write`。只允许写到显式指定的路径；探针拒绝空路径、目录路径和包含 NUL 的路径。每个块带 offset，不连续即拒绝；已写部分不回滚，返回 `E_IO`，由控制端决定是否清理。`final=true` 时校验整文件 SHA-256，不匹配返回 `E_HASH`，文件标为不完整。成功后 `chmod` 到请求的 mode，默认 0600，可执行文件用 0700。写入是覆盖式，不追加；重复 offset 视为错误，防止重放拼接。

## 7. 清理

`cleanup` 任务带 `scope`、`probe_id` 和要删除的类别（`token`、`binary`、`scratch`、`sockets`、`children`）。清理顺序固定：停止接受新任务；取消在途任务；递归清理子探针（先子后父）；关闭监听 socket 和 SOCKS 连接；删除 token 文件、临时二进制、scratch 文件；返回 `cleanup.report`。

`cleanup.report` 包含 `removed`、`failed`、`children`、`idempotent`。清理是幂等的；重复清理返回空 removed 和 `idempotent=true`。清理失败不阻塞退出，但必须回报；控制端把失败写进证据和报告的限制节。探针收到 `bye` 后执行同样的清理；异常退出时，子探针在 orphan TTL 后自行清理。不删除目标原有文件；只删除探针自己创建的文件，路径必须在探针的创建清单里，不能凭控制端一句话删任意路径。

## 8. 错误码

| 码 | 含义 | 可重试 |
|---|---|---|
| `E_AUTH` | token/proof 缺失或不匹配 | 否 |
| `E_FRAME` | 帧长度/JSON/UTF-8 非法 | 否 |
| `E_VERSION` | 协议版本不支持 | 否 |
| `E_DENIED` | 只读、命令白名单、路径/范围拒绝 | 否 |
| `E_NOTFOUND` | 文件、资源、子探针不存在 | 否 |
| `E_TIMEOUT` | 任务/请求超时 | 是（有限次） |
| `E_BUDGET` | 输出、请求数、子探针数、窗口超限 | 是（降规模后） |
| `E_IO` | 读写、socket、进程 IO 失败 | 是（有限次） |
| `E_EXEC` | 命令不存在、退出码非零、被信号杀死 | 视情况 |
| `E_K8S` | API server、kubectl、RBAC 失败 | 视情况 |
| `E_TEMPLATE` | 模板 schema、表达式、输入缺失 | 否 |
| `E_CHILD` | 子探针启动/握手失败 | 是（换投放方式） |
| `E_HASH` | SHA-256 不匹配 | 否 |
| `E_CANCELLED` | 任务被取消 | 否 |
| `E_CLEANUP` | 清理失败 | 是（人工介入） |
| `E_INTERNAL` | 未分类内部错误 | 否 |

错误信息要求很具体：`code` 稳定，`message` 说人话，`step` 指向步骤，`retryable` 明确。不要把堆栈、token、完整响应体塞进 `message`。

## 9. 版本与兼容

`v` 是整数，当前为 `1`；不兼容变更升 `v`。新增可选字段不升版本；删除字段、改变语义升版本。探针在 `hello` 里报二进制版本 `version` 和协议版本 `v`，控制端必须同时检查。控制端遇到更高版本返回 `E_VERSION`，不尝试降级解析。模板 schema 独立版本 `inkblade-probe-template-v1`，结果 schema 是 `inkblade-probe-result-v1`；报告层按 schema 校验，不靠字段猜测。

## 10. 一次完整任务

```
probe  → hello
control→ auth
probe  → ready
control→ task(t-1, template=vllm-plugin-auth-bypass)
probe  → result(t-1, ok=true, status=findings, runtime=rust)
control→ cleanup(scope=subtree)
probe  → result(c-1, cleanup.report)
control→ bye
probe  → bye
```

## 11. English summary

Frames are length-prefixed JSON, capped at 8 MiB. The handshake is `hello` / `auth` / `ready`; authentication is an HMAC-SHA256 proof over a per-start nonce, probe id, and parent id. Tasks carry a template or a single operation; results carry a stable status, findings, checks, artifacts, probe identity, and an error object when `ok` is false.

Budgets are enforced at the probe: per-task wall clock, output size, HTTP request count, in-flight window, child count, and orphan TTL. Files move in 1 MiB chunks with offsets and a whole-file SHA-256. Cleanup is idempotent, child-first, and reports failures instead of hiding them.

架构背景与投放方式见 [`docs/ARCHITECTURE-PROBE.md`](ARCHITECTURE-PROBE.md)、[`docs/PROBE-DEPLOY.md`](PROBE-DEPLOY.md)。

## 证据 / 限制

**证据**

- 帧常量与读写：`probe/src/protocol.rs`（`MAX_FRAME`、4 字节大端、`response`/`failure` 封装）。
- HMAC 与常量时间比较：`probe/src/sha256.rs::hmac_sha256`、`constant_time_eq`。
- 文件分块与校验：`probe/src/fsops.rs::read/write/verify_chunks`。
- 子探针启动参数：`probe/src/spawn.rs::start`（`run --stdio --probe-id --parent-id --token-file`）。

**限制**

- v1 是草案；`probe/src/main.rs` 与 `probe/src/server.rs` 已落地，`hello/auth/ready` 的边界行为以最终实现为准。
- TCP/Unix 通道的 TLS 不在 v1 范围内；跨不可信网络必须由外部隧道保护。
- `event` 不保证可靠交付；需要证据的事实必须走 `result`。
- 文件分块只做完整性与顺序校验，不做加密；证据加密由控制端负责。
- 错误码表是稳定契约，但具体 `message` 文案可能随版本调整，调用方不得解析文案。

## 12. 当前实现兼容层 / Implemented compatibility layer

> 本节记录 `probe/src` 与 `inkblade/channel.py` 的**已实现**线格式；上文是
> v1 目标语义。两者不矛盾时以上文为准，字段名以本节为准，避免“文档先行、
> 代码未跟上”的误读。

当前探针启动帧同时是 `hello`：

```json
{"v":1,"type":"hello","probe_id":"probe-...","parent_id":null,
 "version":"0.1.0","challenge":"<hex>","nonce":"<hex>",
 "auth":"hmac-sha256","read_only":true,"window":4}
```

客户端发送：

```json
{"v":1,"type":"auth","nonce":"<client nonce>",
 "mac":"<hex HMAC(token, 'inkblade-probe/v1|nonce|challenge')>",
 "proof":"<optional b64 HMAC(token, nonce||probe_id||parent_id)>"}
```

探针接受 `mac`（`v1|nonce|challenge`）或目标语义的 `proof`（
`nonce||probe_id||parent_id`）任一；成功后回 `ready`，含 `caps`、`read_only`、
`window`、`max_output`。`LocalFramedClient` 与 Python `ProbeConnection` 使用
`mac` 形式。

请求/响应使用 `req`/`resp` 信封：

```json
{"v":1,"type":"req","id":"t1","op":"task",
 "args":{"task_id":"t1","template":{...},"params":{...}}}
{"v":1,"type":"resp","id":"t1","ok":true,"data":{"ok":true,"steps":[...],
 "vars":{"steps.x":{...}},"probe_id":"probe-..."}}
```

协议也接受目标语义的 `type:"task"`（`op:"template"` 映射为 `task`）；响应仍
使用 `resp`，以保持 `tpl.probe.LocalFramedClient` 的单一读取路径。实际 op：
`ping/beacon/collect/exec/dial/task/upload/download/spawn/cleanup/socks/k8s`。
错误码是 `auth_failed`、`unknown_op`、`exec_failed`、`dial_failed`、
`task_failed`、`upload_failed`、`download_failed`、`spawn_failed`、
`k8s_failed`、`probe_not_found`；控制器按类型映射到上文 `E_*` 语义。
子探针帧带 `probe_id`/`parent_id`；父探针按 `probe` 字段转发。

实际实现见 [`PROBE-CHANNEL.md`](PROBE-CHANNEL.md) 与 `probe/src/server.rs`。
