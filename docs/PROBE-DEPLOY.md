# 探针投放 / Probe Deployment

> 目标：把一个可校验的 Rust 探针放进授权范围内的 Pod，并让它以最小权限、可清理的方式运行。
> 默认只读。写是例外，需要三层同时满足：授权、探针开关、模板写声明。

## 1. 发布物

发布包里应该只有两个 Linux 二进制：`inkblade-probe-linux-amd64` 和 `inkblade-probe-linux-arm64`，外加一个 `SHA256SUMS`。两个二进制都用 musl 静态链接，发布前要去掉调试符号，`ldd` 应该报 “not a dynamic executable”。体积目标小于 8 MiB；当前 release profile 用 `opt-level="z"`、LTO、`panic=abort` 和 `strip`，这不是为了好看，而是为了让“把一个二进制塞进 Pod”这件事尽量不依赖目标环境。

构建命令不复杂，难的是校验构建产物：

```bash
cargo build --release --target x86_64-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-musl
sha256sum target/*/release/inkblade-probe > SHA256SUMS
```

发布前至少看一眼 `file` 的输出。`statically linked` 或 `static-pie linked` 都可以；如果显示 `dynamically linked`，就说明 musl target 没用上，或者链接器偷偷接了系统库。这样的二进制在 distroless 镜像里通常起不来，别把它发出去。

## 2. 投放前检查

投放失败的原因，八成不是探针本身，而是目标环境不满足一个很具体的前提。先查六件事：架构是 amd64 还是 arm64；目标有没有可写目录；挂载是不是 `noexec`；磁盘空间够不够；探针进程的 uid 和 capability 是什么；目标里是不是已经有同名的探针在跑。

架构用 `uname -m` 和 `file` 交叉确认。可写目录优先试 `/dev/shm`，其次 `/tmp`，最后才是业务卷。`noexec` 很常见，`mount` 的输出里带 `noexec` 就不要往那儿放二进制；这种情况下要么换目录，要么走 memfd。空间和权限不用多说，`df`、`id` 各看一眼就行。已有探针要查 `probe list` 和进程表，避免两个探针用同一个 probe_id 或同一个 token 文件。

范围检查不能省。session 的 namespace、Pod 选择器和 CIDR 是硬边界；目标不在范围里就拒绝，不投。这个检查应该发生在控制端，而不是让探针“到了再说”。

## 3. 四种投放方式

### 3.1 RCE 投放：base64 + memfd

有授权的代码执行入口、但没有 kubectl 或可写卷时，用这条路。控制端把二进制切块、base64 编码，每块带序号和整文件 SHA-256；目标进程在内存里拼接，优先用 `memfd_create` 创建匿名文件，写入后通过 `/proc/self/fd/<n>` 执行。这样不需要可写目录，也不会在磁盘上留下二进制。

没有 memfd 时，退到 `/dev/shm` 或 `/tmp`。执行前 `chmod 700`，执行后删除。启动参数用 `run --stdio --token-file <path> --read-only`；stdio 承载协议，审计走 stderr。

这条路径的约束要说清楚：只使用已授权的入口，不内置漏洞利用代码；不写启动项、不写 crontab、不修改镜像、不注入其他进程；传输不经过第三方服务。失败时返回 `E_DEPLOY`，并说明是“无 memfd”“无可执行挂载”还是“无写权限”。不要因为 memfd 失败就改从控制端直连目标——那是另一种执行路径，证据和权限都不一样。

当前实现里，`spawn.materialize` 已经支持 base64 → 文件 → 校验 → chmod；memfd 还在 Rust 运行时收尾。发布说明会把两种路径分开写，不把“临时文件”说成“纯内存”。

### 3.2 kubectl cp / exec

有 kubeconfig、目标容器可写、镜像里有 `kubectl` 时，这条最直接：

```bash
kubectl cp ./inkblade-probe-linux-amd64 \
  <namespace>/<pod>:/tmp/inkblade-probe -c <container>
kubectl exec -n <namespace> <pod> -c <container> -- \
  sha256sum /tmp/inkblade-probe
kubectl exec -n <namespace> <pod> -c <container> -- \
  chmod 700 /tmp/inkblade-probe
kubectl exec -n <namespace> <pod> -c <container> -- \
  /tmp/inkblade-probe run --stdio --read-only --token-file /tmp/.probe-token
```

`kubectl cp` 需要容器里有 `tar`。没有 `tar` 就改 base64 分块，或者走共享卷，不要试图 `cat | base64` 硬拼——stdin/stdout 一旦被 shell 提示符或 banner 污染，帧解析就会失败。执行前必须校验 SHA-256；校验失败不运行。容器重启会丢二进制，长任务用共享卷或可重建的投放脚本。

kubelet 审计会记录 exec，这是预期痕迹。产品不试图隐藏它；如果客户要求“无痕”，正确回答是“做不到，也不应该承诺”。

### 3.3 EphemeralContainer

不能重启业务容器、或者目标容器没有可写层时，用临时容器。最小 spec 形态如下：

```yaml
ephemeralContainers:
  - name: inkblade-probe
    image: <registry>/inkblade-probe:<version>
    command: ["/inkblade-probe", "run", "--stdio", "--read-only"]
    targetContainerName: <business-container>
    stdin: true
    tty: false
    securityContext:
      runAsNonRoot: true
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
```

EphemeralContainer 不能加端口、不能改资源限制、不能当长期服务，它适合一次性探针。默认也不共享目标容器的文件系统；需要看目标挂载时，显式配共享卷或进程命名空间。镜像必须提前存在或可被节点拉取；离线环境用 `imagePullPolicy: IfNotPresent` 加预置镜像。这个方式需要 `pods/ephemeralcontainers` 的 update/patch 权限，是高权权限，必须单独授权；审计会记录 Pod spec 变更，不试图绕过。

### 3.4 共享卷

批量 Pod、没有 exec 权限、或者需要跨容器复用探针时，走共享卷。把二进制复制到卷的挂载点，校验 SHA-256，`chmod 700`，然后通过目标容器的入口、CronJob、初始化容器或已有的 exec 能力启动。卷是 `noexec` 时换 memfd 或 kubectl；hostPath 卷会影响节点，必须单独授权并记录路径；共享卷可能被其他 Pod 读取，token 文件权限 0600，任务结束即删。

清理时只删探针文件和 token，不删卷上的业务数据。卷上的二进制可能被镜像层或 FIM 记录，这是预期痕迹。

### 3.5 怎么选

| 方式 | 需要权限 | 落盘 | 可执行性 | 典型痕迹 |
|---|---|---|---|---|
| base64 + memfd | 代码执行入口 | 否（优先） | 依赖内核 | 进程、网络 |
| kubectl cp/exec | pods/exec | 是 | 依赖可写层与 noexec | kubelet 审计 |
| EphemeralContainer | pods/ephemeralcontainers | 镜像层 | 是 | Pod spec 变更 |
| 共享卷 | 卷写权限 | 是 | 依赖 noexec | 卷写入、FIM |

没有 kubeconfig 时优先 memfd；有 kubeconfig 且容器可写时优先 kubectl；不能重启业务容器时用 ephemeral；批量场景用共享卷。四条路都不通时返回 `E_DEPLOY`，不要静默降级。

## 4. 启动参数与只读默认

| 参数 | 默认 | 说明 |
|---|---|---|
| `--stdio` | 关闭 | 用 stdin/stdout 承载协议；审计走 stderr |
| `--listen <addr:port>` | 关闭 | 监听 TCP；默认只允许回环 |
| `--unix <path>` | 关闭 | 监听 Unix 域套接字；权限 0600 |
| `--token-file <path>` | 无 | 共享 token；权限必须 0600 |
| `--read-only` | 开启 | 只读模式；写 op 返回 `E_DENIED` |
| `--allow-write` | 关闭 | 允许写；仍需模板 `mode=backup-write` |
| `--allow-cmd <name>` | 空 | 追加允许命令；只读命令表仍生效 |
| `--max-output <bytes>` | 1 MiB | 单任务输出上限；clamp 到 16 MiB |
| `--max-timeout-ms <n>` | 30000 | 单任务墙钟上限 |
| `--max-window <n>` | 4 | 在途任务上限 |
| `--probe-id <id>` | 自动 | 探针 id；子探针由父探针指定 |
| `--parent-id <id>` | 无 | 父探针 id |
| `--audit <path>` | 无 | 审计 JSONL；stdio 模式下走 stderr |

只读不是“建议”，是默认值。只读模式下 `fs.write`、`fs.remove`、`fs.mkdir`、K8s 写动词、非白名单 `exec`、`spawn` 全部拒绝。模板里的 `write: true` 步骤在 `probe-only` 模式下直接 `skipped`，不报错；只读探针仍然可以采集快照、跑 HTTP/TCP 探测、读文件、执行只读命令。

## 5. 写闸门

写操作要同时满足五件事：session 的 consent/ROE 覆盖目标、级别和时间窗；探针 `--allow-write`；模板 `meta.writes=true` 且具体步骤 `write: true`；运行模式是 `backup-write`；控制端有备份回执。任何一条缺失，写步骤返回 `E_DENIED` 或 `skipped`，不静默降级为“只读跑一半”。

写只允许落在目标 Pod 的临时目录、授权 scratch 目录或明确的业务路径；不写 `/etc`、不写启动项、不写内核模块、不写其他租户的卷。写前记录路径、大小、哈希；写后回读并记录哈希；失败按备份回滚。

## 6. 校验与握手

投放后按顺序做七件事：`sha256sum` 比对；`inkblade-probe version` 看二进制版本、协议版本和构建目标；发 `hello`；完成 `auth` 的 HMAC 证明；读 `ready` 的 limits 和 allow_cmds；用 `collect` 拉快照确认目标 Pod、namespace、SA、挂载与预期一致；把投放方式、路径、哈希、PID、启动时间、probe_id 写进证据。

失败处理要具体。架构不匹配是 `E_EXEC`，换二进制；无写权限或 `noexec` 是 `E_IO`/`E_EXEC`，换 memfd 或共享卷；哈希不匹配是 `E_HASH`，停止并重新传输；认证失败是 `E_AUTH`，查 token 文件权限；握手超时是 `E_TIMEOUT`，先查 stdin/stdout 是否被 shell 污染；子探针启动失败是 `E_CHILD`，查路径、权限、架构。

## 7. 清理与孤儿

清理顺序固定：停止新任务、取消在途任务、递归清理子探针、关闭监听端口和 SOCKS、删除 token/二进制/scratch、回报 `cleanup.report`。`cleanup.report` 里要有 removed、failed、children 和 idempotent 四个字段；失败不阻塞退出，但必须写进证据和报告的限制节。

控制端断开后，探针进入 120 秒倒计时；期间允许重连。倒计时结束，探针自行清理并退出；子探针在父探针退出后 60 秒内退出。清理失败时，探针把失败写进 stderr 审计并退出；控制端下次连接按 probe_id 收敛。不要把“清理失败”当成成功；残留路径和原因要能被客户看见。

## 8. 发布与离线

发布物包括两个架构的静态二进制、`SHA256SUMS`、模板包、规则包和版本清单。离线环境只需要控制器 wheel、Python 解释器、两个探针二进制、模板和规则包；不需要 Python 目标侧依赖、Rust 工具链或包索引。

升级顺序是：先替换控制端模板与规则，再替换探针。协议 v1 向后兼容一个 minor 版本；跨大版本时先读协议文档，不要假设字段不变。

当前发布流水线已经能构建 Linux 二进制与校验文件；memfd 路径和协议服务仍在收尾。发布页只列实际存在的文件，不提前写“已发布”。

## 9. English summary

Ship two static Linux binaries plus `SHA256SUMS`. Deploy through authorized RCE with base64 and memfd, `kubectl cp`/`exec`, an EphemeralContainer, or a shared volume. Verify the hash before execution, then complete `hello`/`auth`/`ready` and a `collect` snapshot.

Read-only is the default. Writes require five things at once: signed authorization, `--allow-write`, a template that declares `meta.writes`, `backup-write` mode, and a backup receipt. Cleanup is child-first and idempotent; failures are reported.

## 证据 / 限制

**证据**

- 子探针物化、哈希校验、chmod、启动参数：`probe/src/spawn.rs::materialize/start/set_executable/write_token_file`。
- 只读与写开关：`probe/src/config.rs::Options`（`read_only` 默认 `true`，`allows_write`）。
- 写拒绝：`probe/src/fsops.rs::write/remove/mkdir`、`probe/src/exec.rs::validate`。
- 发布构建：`probe/Cargo.toml` 的 release profile（`opt-level="z"`、LTO、`panic=abort`、`strip`）。

**限制**

- `probe/src/main.rs` 与 `--listen/--unix` 的 CLI 接线已落地，边界行为仍在收尾；本文是投放契约，不是“所有方式已实测”的宣称。
- memfd 路径在当前构建中仍是设计项；已实现的是 base64 → 文件 → 校验 → chmod。
- `kubectl cp` 依赖目标容器有 `tar`；没有 `tar` 时必须换方式。
- EphemeralContainer 不共享目标容器的文件系统；需要显式挂载或进程命名空间配置。
- 共享卷的 `noexec`、SELinux/AppArmor、只读根文件系统都会影响投放；失败要如实回报，不静默降级。
- 投放痕迹（kubelet 审计、FIM、进程表、网络连接）是预期行为；产品不提供痕迹清除。
