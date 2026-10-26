# 探针架构 / Probe Architecture

> 2026-10 架构修订。本文只描述一条执行路径；不在这张图上的路径，不是受支持的路径。
> 目标侧：Linux，Pod 内，Rust 静态二进制。控制侧：Python，Pod 外。

## 1. 设计起点

旧架构把模块逻辑放在控制端：模块是 Python 函数，通过 HTTP 或 kubectl 从外面问目标。这个模型有三个硬伤。

第一，控制端看不到 Pod 内的事实。挂载传播、SA token 的 audience、GPU 设备节点、RDMA 网卡、cgroup 限制、`/proc/self/status` 的 capability 集，这些都不是 API 对象能完整回答的。靠外部推断，误报会变成“看起来像”，漏报会变成“没看到”。

第二，目标环境不一定有解释器。推理镜像为了减小攻击面，常常没有 Python、没有 Bash、没有 curl、没有 kubectl。把“在目标里跑一段脚本”当成默认能力，会把大量真实环境排除在外。

第三，执行逻辑和证据逻辑混在一起。模块在控制端跑，读到的结果是“模块说自己看到了什么”；审计只能证明控制端收到了什么，不能证明目标 Pod 里发生了什么。

修订后的答案只有一个：**把执行面放进 Pod，把逻辑做成数据，把证据放在探针边界。**

## 2. 唯一逻辑图

```
┌─────────────────────────────────────────────────────────────────────┐
│ 控制端（Python，Pod 外）                                             │
│ consent/ROE → session → 模板选择 → 参数渲染 → 预算/超时 → 证据/报告   │
└───────────────┬─────────────────────────────────────────────────────┘
                │  ① 立足（RCE / kubectl exec / ephemeral / 共享卷）
                ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 目标 Pod                                                             │
│                                                                     │
│  ┌──────────────────────────────┐                                   │
│  │ Rust 探针（parent）           │  ② 握手 → ③ 任务 → ④ 结果          │
│  │  - 身份/挂载/网络/SA/GPU 快照 │◄──────── 长度前缀 JSON 帧 ────────►│
│  │  - 模板解释器                 │                                   │
│  │  - 子探针管理                 │                                   │
│  └───────┬──────────────┬───────┘                                   │
│          │ spawn        │ k8s exec/copy                             │
│          ▼              ▼                                           │
│  ┌───────────────┐  ┌──────────────────────────────┐                 │
│  │ 子探针（同 Pod）│  │ 子探针（其他 Pod / 节点侧）   │                 │
│  │ parent_id=... │  │ parent_id=...                │                 │
│  └───────────────┘  └──────────────────────────────┘                 │
│          │                          │                               │
│          └──────── ⑤ 内部横向 ──────┘                               │
│                     （socks / k8s / exec / http）                    │
└─────────────────────────────────────────────────────────────────────┘
                │  ⑥ 证据回传（结果 + artifacts + manifest）
                ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 控制端：证据库 → 关联 → 报告 → 规则包                                 │
└─────────────────────────────────────────────────────────────────────┘
```

六个阶段：

1. **立足。** 通过授权范围内的 RCE、`kubectl exec`、EphemeralContainer 或共享卷，在目标 Pod 内获得一次执行机会。
2. **投放。** 把 Rust 探针放到可执行位置；优先内存执行，其次临时目录，最后共享卷。校验 SHA-256 后再运行。
3. **握手。** 探针生成 probe_id 与 nonce，控制端用共享 token 做 HMAC 证明；协商版本、只读模式、命令白名单、输出/超时上限。
4. **任务。** 控制端下发模板任务；探针按模板步骤执行 http/tcp/exec/fs/k8s/socks/spawn，产出 steps/checks/findings/artifacts。
5. **横向。** 探针用 `k8s` 读取或复制到其他 Pod；用 `spawn` 投放子探针；用 `socks` 建立转发；形成父子树。
6. **清理。** 逆序删除子探针、token 文件、临时二进制、scratch 文件、监听端口；每个清理动作都有回执。

这张图是唯一路径。控制端直连目标端口、在目标里跑 Python、在目标里跑 `run.py`、跳过探针直接 `kubectl exec` 执行检测逻辑，都不属于受支持路径。

## 3. 立足方式

| 方式 | 前置条件 | 探针落点 | 适用场景 | 风险/痕迹 |
|---|---|---|---|---|
| RCE（应用漏洞） | 已授权的可执行入口 | memfd 或 `/tmp`、`/dev/shm` | 无 kubectl、无集群权限 | 进程创建、文件写入、网络连接 |
| `kubectl exec` | 有 pods/exec 权限 | 容器可写层或共享卷 | 红队已有 kubeconfig | kubelet 审计、exec 子资源审计 |
| EphemeralContainer | 有 pods/ephemeralcontainers 权限 | 临时容器文件系统 | 不重启业务容器、需共享进程命名空间 | Pod spec 变更、ephemeral 容器审计 |
| 共享卷 | 目标挂载了可写卷 | PVC / emptyDir / hostPath | 批量 Pod、无 exec 权限 | 卷写入、文件完整性监控 |
| 已控工作负载 | 已有可控 Pod | 镜像内或启动脚本 | 供应链或镜像替换场景 | 镜像/工作负载变更 |

产品不内置漏洞利用代码。立足方式来自授权范围内的既有入口；探针只负责“落地后怎么跑”。

## 4. 探针运行时能力

探针是单线程事件循环加有界工作线程，所有 op 都受预算约束。没有动态加载、没有插件、没有 `eval`。

| op | 能力 | 关键限制 | 证据 |
|---|---|---|---|
| `http` | 原生 HTTP(S) 客户端，支持方法、头、body、私钥 CA、重定向上限 | 单请求超时 50–120000ms；响应体上限；重定向 ≤10；默认不校验证书，模板可显式开启 | 状态码、响应头、body 哈希、字节数 |
| `tcp` | 连接、发送、读取固定字节、前缀匹配 | 读上限 16MiB；超时上限 120s | 本地/对端地址、字节数、响应哈希 |
| `exec` | 有界命令执行，stdout/stderr 分离 | 只允许裸命令名；只读命令白名单；写命令需 `--allow-write` + `--allow-cmd`；超时强杀；输出截断 | argv、rc、stdout/stderr、耗时 |
| `fs` | 读、写、列目录、stat、mkdir、remove、哈希 | 写需 `--allow-write`；路径不做沙箱根限制，但模板写步骤需 `mode=backup-write`；单文件上限 | 路径、大小、模式、SHA-256 |
| `k8s` | 用 Pod 内 SA token 直连 API server；list/get；exec/copy 走 kubectl（若有） | 只读动词默认；写动词需授权与显式开关；不打印 token | 资源清单、响应码、操作转录 |
| `socks` | 启动 SOCKS5 服务，支持 CONNECT | 绑定地址/端口显式；无认证时仅限回环或授权网段；生命周期随探针 | 监听地址、连接记录 |
| `spawn` | 物化子探针、校验 SHA-256、chmod 700、启动 `run --stdio` | 写模式；父子 token 分离；最大子代数；孤儿 TTL | 子 probe_id、路径、哈希、启动结果 |
| `collect` | 身份、capability、挂载、cgroup、网络、SA、设备、环境变量脱敏 | 只读；单文件读取上限；敏感环境变量掩码 | 快照 JSON + `files_read` 列表 |

补充约束：

- `exec` 的只读命令表包含 `id`、`hostname`、`uname`、`ps`、`df`、`ls`、`cat`、`ip`、`ss`、`nvidia-smi`、`rocm-smi`、`mount` 等；`find` 禁止 `-exec/-delete`；`printenv` 禁止打印 token/secret/password 类变量。
- `k8s` 的 exec/copy 依赖目标镜像内有 `kubectl`。没有 `kubectl` 时，探针退化为 API 读写，不假装支持流式 exec。
- 所有输出默认 1MiB，硬上限 16MiB；单帧硬上限 8MiB；大文件走分块。
- 模板不能调用任意二进制；`exec` 的 argv 由模板声明，探针按白名单校验。

## 5. 模板：唯一执行逻辑

模板是 JSON，不是脚本。一个模板包含：

```json
{
  "schema": "inkblade-probe-template-v1",
  "key": "example-check",
  "version": "1.0.0",
  "meta": {
    "name": {"zh": "示例检查", "en": "Example check"},
    "series": "侦察",
    "min_level": "只读侦察",
    "writes": false
  },
  "inputs": {
    "target": {"from": "params.target", "required": true}
  },
  "steps": [
    {"id": "probe", "op": "http", "method": "GET", "url": "{{ input.target }}/health",
     "expect": {"status": [200]}}
  ],
  "checks": [
    {"id": "reachable", "when": "steps.probe.ok", "severity": "info",
     "message": "target responded"}
  ],
  "findings": [],
  "artifacts": []
}
```

执行语义：

- `inputs` 从 session 参数解析；必填缺失时返回 `skipped`，不算失败。
- `steps` 顺序执行；`when` 为假则跳过；`write: true` 的步骤在 `probe-only` 模式下跳过。
- `checks` 只做断言，不改环境；`fatal` 失败会终止模板。
- `findings` 只在无错误时生成；每条 finding 带 severity、evidence 指针和模板键。
- `artifacts` 只写控制端证据目录，不写目标文件系统。
- `limits` 控制总超时、HTTP 请求数、输出大小；超限返回明确错误码。

模板与模块同键：`inkblade/modules/<key>/template.json`。模块清单只描述元数据、级别、写属性、所需部署面；执行体只有模板。注册表拒绝同时存在 `run.py` 与 `template.json` 的模块。

**English.** A template is the only executable form of a module. It is data: inputs, ordered steps, assertions, findings, artifacts. The probe evaluates it natively. There is no target-side script, no dynamic import, no module code.

## 6. 通道

探针支持三种通道，语义相同，帧格式相同。

| 通道 | 建立方式 | 适用 | 注意 |
|---|---|---|---|
| stdio | 父进程持有 stdin/stdout | `kubectl exec`、`spawn` 子探针、本地调试 | stdout 只走协议；审计走 stderr |
| TCP | 探针监听或反向连接 | 跨 Pod、跨节点、长任务 | 需显式 bind/connect；默认只绑回环 |
| Unix socket | 探针监听 Unix 域套接字 | 同 Pod 多容器、共享卷 | 文件权限 0600；清理时删除 |

通道只承载帧，不承载“命令字符串”。控制端不能通过通道让探针执行任意 shell；每个任务都必须是已注册的模板或受控 op。

多路复用：

- 一个连接上可以有多个在途任务，窗口默认 4，硬上限由 `--max-window` 控制。
- 任务 id 单调递增，结果按 id 关联；取消按 id 匹配。
- 控制端断开后，探针在 orphan TTL（默认 120s）后退出；子探针随之退出。
- 探针不主动外连控制端，除非显式配置反向通道；默认没有回连地址。

## 7. 多探针父子树

```
parent (probe-a, pod A)
├── child (probe-b, pod A, same namespace)
│   └── grandchild (probe-c, pod B)
└── child (probe-d, pod C)
```

规则：

1. 每个探针有唯一 `probe_id`；子探针带 `parent_id`；控制端用这两个字段重建树。
2. 子探针继承父探针的 `read_only`、`allow_cmds`、`max_output`、`max_timeout_ms`；只能更严格，不能更宽松。
3. 每个子探针使用独立 token 文件，父探针不把 token 写进 argv 或日志。
4. 最大深度默认 3，最大子代数默认 8；超过即拒绝，返回 `E_BUDGET`。
5. 父探针退出时，子探针在 TTL 内自行退出；控制端也可以显式 `cleanup` 整棵树。
6. 子探针的发现归到子探针 id，不归到父探针；报告里可以按树聚合，但证据锚不能串。
7. 跨 namespace / 跨集群的子探针需要额外的授权范围检查；控制端在投放下发前做，探针不替控制端做授权判断。

### 探针投放探针

`spawn` 的语义是“把探针二进制投放到另一个执行点，并把它接入树”，不是“在父探针进程里开线程”。

流程：

1. 控制端把目标二进制（base64）或路径、期望 SHA-256、目标 probe_id、父 probe_id 放进 `spawn` 任务。
2. 父探针物化文件（或使用共享卷已有文件），校验哈希，`chmod 700`。
3. 父探针写独立 token 文件，启动 `inkblade-probe run --stdio --probe-id ... --parent-id ...`。
4. 子探针完成 hello/auth，父探针把子探针的 `ready` 回传给控制端。
5. 后续任务可以直接发往子探针；父探针只做转发或树管理。
6. 清理时先子后父，逆序删除。

跨 Pod 投放走 `k8s copy` + `k8s exec`：把二进制复制到目标 Pod 的可写路径，再 exec 启动。目标 Pod 没有可写路径时，改用 EphemeralContainer 或共享卷；都没有则返回 `E_DEPLOY`，不静默降级到“控制端远程执行”。

## 8. 目标侧零 Python

“零 Python”不是“目标里不能有 Python 进程”，而是“InkBlade 不依赖目标里的 Python”。

具体约束：

- 探针是静态链接的 Rust 二进制，不加载 Python 解释器、不调用 `python`、不调用 `pip`。
- 模板是 JSON，探针自带解析器；不调用目标里的 `jq`、`yq`、`bash`。
- `exec` 只在模板显式声明且命令在白名单内时使用；它不用于执行探针自身逻辑。
- 控制端的 Python 代码、模块仓库、依赖包，一律不下发到目标。
- 历史 `run.py` 只能存在于控制端 bootstrap 模块；注册表禁止模板模块带 `run.py`。
- 如果目标 Pod 里本来就有 Python（例如推理框架），探针不会 import 它、不会复用它的环境、不会把 payload 注入它的进程。

这条约束的产品含义：同一份模板可以在 `python:3.12`、`nvcr.io` 推理镜像、`distroless`、`scratch` + 静态二进制里跑，行为一致。

## 9. 与控制端 Python 的边界

| 事项 | 控制端（Python） | 探针（Rust） |
|---|---|---|
| 授权/ROE 校验 | 是 | 只接收 `read_only`、`allow_cmds` 等结果 |
| 目标选择 | 是 | 只知道自己所在 Pod |
| 模板选择/参数渲染 | 是 | 按已下发模板执行 |
| 预算/超时 | 下发上限 | 强制执行并回报 |
| 命令白名单 | 下发 | 强制校验 |
| 证据归档 | 是 | 产出原始结果与哈希 |
| 报告/规则包 | 是 | 不参与 |
| 子探针树 | 观察/编排 | 维护 parent_id、清理 |
| 漏洞利用 | 不内置 | 不内置 |

控制端不能做而探针能做的：读 Pod 内 `/proc`、挂载、设备、SA token、GPU 设备；在 Pod 网络命名空间内连接 Service/DNS；用 Pod 的 SA 权限访问 API server。
探针不能做而控制端能做的：签名授权、跨 session 关联、报告渲染、规则包生成、长期证据存储。

边界失败模式：

- 控制端以为目标有 `kubectl`，实际没有 → `k8s exec/copy` 返回 `E_K8S`，不自动回退到控制端直连。
- 控制端下发的模板需要写，但探针是 `read_only` → 写步骤 `skipped`，模板返回 `ok` 或 `findings`，不会偷偷写。
- 子探针启动失败 → 父探针返回 `E_CHILD`，树里保留失败节点，不伪造子探针结果。
- 通道断开 → 探针进入 orphan 倒计时；控制端重连后用 probe_id 续接，不重跑已完成任务。

## 10. 安全边界

- 探针只执行注册模板；没有“任意命令”通道。
- 默认只读；写需要 `--allow-write`、模板 `mode=backup-write`、控制端签署授权和备份回执。
- `exec` 默认只允许只读命令；新增命令必须显式 `--allow-cmd`，且仍然受 `read_only` 约束。
- `fs` 写不做全局根限制，但模板写步骤必须声明 `write: true`，并在 probe-only 模式下跳过；控制端在证据里记录目标路径。
- `k8s` 默认只读动词；写动词需要显式开关；不打印 SA token。
- `socks` 默认只绑回环；对外绑定时必须显式指定，并在证据里记录。
- 每个任务有超时、输出上限、HTTP 请求数上限；超限即失败，不无限重试。
- 探针不持久化：不写 crontab、不写 systemd、不写启动脚本、不修改镜像。
- 探针退出时清理自己创建的文件、token、socket、子进程；清理失败会回报，不静默忽略。

## 11. 当前实现状态

| 组件 | 状态 | 代码锚 |
|---|---|---|
| 帧协议（4 字节大端长度 + JSON） | 已实现 | `probe/src/protocol.rs` |
| HTTP / TCP / SOCKS5 | 已实现 | `probe/src/http.rs`、`probe/src/net.rs` |
| exec 白名单与超时 | 已实现 | `probe/src/exec.rs` |
| fs 读/写/分块/哈希 | 已实现 | `probe/src/fsops.rs` |
| k8s list/get/exec/copy | 已实现（exec/copy 依赖 kubectl） | `probe/src/k8s.rs` |
| 子探针物化与启动 | 已实现 | `probe/src/spawn.rs` |
| 快照采集 | 已实现 | `probe/src/collect.rs` |
| 模板解释器（Rust） | 已落地 | `probe/src/template.rs` |
| 协议服务 / CLI 入口 | 已落地，收尾中 | `probe/src/main.rs`、`probe/src/server.rs` |
| 287 个模块模板化 | 收尾中 | 286 个 `template.json` + 1 个 bootstrap；迁移窗口内 286 个 `run.py` 待删除 |

迁移中间态：注册表已经强制 `template.json`，但模块目录尚未全部迁移；当前分支不能加载旧模块。这是架构修订的过渡状态，不是发布状态。完成标准见 `docs/DYNAMIC-VERIFICATION.md`。

## 12. English summary

There is exactly one supported execution path: foothold, Rust probe, framed channel, in-pod tasks, child probes for lateral movement, evidence back to the controller. The probe is a static binary with eight runtime operations: HTTP, TCP, exec, filesystem, Kubernetes API, SOCKS5, spawn, and snapshot collection. Templates are JSON data evaluated by the probe; no Python, shell, or module code is shipped into the target.

The Python controller owns consent, scope, template selection, budgets, evidence storage, reporting, and rule generation. It never executes target-side logic. Child probes inherit stricter limits, get their own token, and are tracked as a tree with `probe_id` / `parent_id`.

## 证据 / 限制

**证据**

- 协议常量与帧实现：`probe/src/protocol.rs`（`MAX_FRAME = 8 MiB`，4 字节大端长度）。
- op 实现：`probe/src/http.rs`、`net.rs`、`exec.rs`、`fsops.rs`、`k8s.rs`、`spawn.rs`、`collect.rs`。
- 模板 schema：`probe/schema/probe-template.schema.json`；控制端参考评估器：`inkblade/tpl/engine.py`（仅 mock/CI，默认拒绝运行）。
- 11 个 defense-bypass 模块：`inkblade/modules/defense-bypass-*`；评估逻辑：`inkblade/core/defenseprobe.py`。

**限制**

- `probe/src/main.rs` 与协议服务已落地，CLI 边界行为仍在收尾；当前文档是架构契约，不是“全部已跑通”的宣称。
- `k8s exec/copy` 需要目标镜像内有 `kubectl`；没有时只支持 API 读写，不提供流式 exec。
- `socks` 不提供认证；对外绑定必须由控制端显式授权并限制网段。
- 模板解释器与 Rust 引擎的行为一致性由 `docs/DYNAMIC-VERIFICATION.md` 的两态测试保证；当前 286/286 证据是参考评估器（`runtime=reference`），不能当作 Rust 探针结果。
- 探针不提供内核级隔离；它依赖 Pod 的 namespace、cgroup、SA 和宿主的既有隔离。目标 Pod 的权限就是探针的权限上限。
