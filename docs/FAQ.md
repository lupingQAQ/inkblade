# FAQ / 常见问题

问题按“怎么接入、怎么跑、证据是什么、边界在哪”排序。

## 接入与安装

### 需要什么环境？

控制端是 Python 3.10–3.13，跑在工作站或跳板机上；目标端是 Linux amd64/arm64 的静态 Rust 探针。目标 Pod 不需要 Python、pip、Bash、curl 或 kubectl。完整的接入步骤见 [`INSTALL.md`](INSTALL.md)。

### 第一次怎么开始？

```bash
python -m pip install -e .
python -m inkblade up --no-consent
```

`up` 创建工作区、打印一次性 admin 密码并在 `127.0.0.1:8765` 提供控制台；浏览器登录后签授权，或执行 `inkblade quickstart`。已有探针直接接入：控制端 `channel listen`，Pod 内探针 `reverse` 主动回连。首次投放用 `session open --mode foothold` 与 `probe deploy --via rce|sa-token`，不需要 kubeconfig。

### 必须要有 kubeconfig 吗？

不。默认立足点是普通、最低权限的 Pod：非 root、无 hostPath/privileged、无 kubeconfig，只有出站 TCP。`foothold` 与 `external` 入口都不需要 kubeconfig；`kubeconfig` 只是可选的首次批量 bootstrap，用于一次给多个 Pod 投放探针。

### 探针怎么回连？

控制端执行 `channel listen`；Pod 内的探针执行 `inkblade-probe reverse --host <controller> --port <port>` 主动建立出站连接。Pod 不需要开监听端口。子探针由父探针用 `probe upload` + `probe spawn` 投放，并以同样方式回连。存在本地命令通道时也可以使用 stdio 通道。

### 目标 Pod 里要装 Python 吗？

不要。探针是静态链接的 Rust 二进制；模板是 JSON。目标不需要 Python、pip、Bash、curl。只有 `kubectl`/`sa-token` 投放路径需要 `kubectl` 和目标 RBAC；没有就换 `manifest`、共享卷或授权 RCE。

### 为什么用 Rust，不用 Go？

三个原因：静态二进制体积更小、没有运行时；模板解释器和 HTTP/TLS/JSON 可以在一个进程内收口；内存安全和错误处理更适合“在别人 Pod 里跑一次性逻辑”。Go 也能做，但会把 `net/http`、TLS 根证书、cgo 等依赖带进来，发布物更大。

### 支持 Windows/macOS 吗？

控制端可以。探针只支持 Linux；Windows/macOS 不能作为目标执行环境。Windows 上不要运行 `inkblade-probe`，只把它复制到 Linux 目标。

### 能离线吗？

能。控制端不需要外网；探针不需要包索引；模板和规则包随发布物带入。离线安装要带控制器 wheel、Python 解释器、两个架构的探针、模板和规则包。

## 探针与通道

### 探针是不是后门？

不是。探针不持久化、不写启动项、不改镜像、不驻留、不回连固定 C2。它只在授权 session 内运行，任务来自已注册模板，退出时清理。区别不在名字，而在：授权、模板白名单、只读默认、写权限校验、清理回执、证据可审计。

### 探针怎么进 Pod？

默认是授权 RCE（base64 + memfd）：适合非 root、无 hostPath/privileged 的最低权限 Pod，只需要可写临时目录或 memfd 与出站 TCP。也可以用 ServiceAccount token、共享卷或 EphemeralContainer 清单；`kubectl` 只是可选的批量 bootstrap。探针启动后主动回连控制器，后续命令都走探针通道，不需要在 Pod 内安装 Python。详见 [`PROBE-DEPLOY.md`](PROBE-DEPLOY.md)。

### 通道能做什么？

默认是探针主动回连的反向通道：控制端 `channel listen`，Pod 内探针 `reverse` 建立出站连接，不需要 Pod 监听端口。存在本地命令通道时也可用 stdio 通道（`channel start`）：它在本地回环上开 SOCKS5 与端口转发，只绑 `127.0.0.1`。`channel status` 查看状态，`channel stop` 关闭。

### 探针权限有多大？

等于目标 Pod 的权限，加上探针进程的 capability。它不能超过 Pod 的 SA、namespace、cgroup、挂载。需要节点权限的检测点，必须由具备节点权限的探针或控制端完成。

### 多探针怎么管？

父子树：每个探针有 `probe_id` / `parent_id`；子探针继承更严格的只读状态、命令白名单和预算；深度与扇出有上限；清理先子后父。

## 检测与结果

### 模板和模块是什么关系？

模块是产品目录里的条目，模板是它的执行体。模板键 = 模块键，例如 `defense-bypass-falco`。模块清单写元数据、级别、是否写、所需部署面；模板写 steps/checks/findings/artifacts。注册表拒绝模板模块带 `run.py`。

### 怎么加模板？

在 `inkblade/modules/<key>/` 放 `module.json` + `template.json`；用 `inkblade template validate` 校验；在授权目标上跑一次只读验证；补证据。不要加 `run.py`，不要把逻辑写成脚本。

### 误报怎么处理？

先看证据锚和 checks；再看目标版本/配置是否与模板假设一致。模板可以在 fixed 态回归，但不能靠“把规则改松”降误报。报告里保留授权边界与不可达部署面说明。

### 读结果先看什么？

先看 `status`，再看 `findings` 的 severity 与 evidence，最后看 `checks` 是否支持这条发现。`status=ok` 表示模板跑完、没有 finding，不代表目标安全；`status=skipped` 表示输入缺失、部署面不存在或写步骤被只读跳过。

### 和通用扫描器/主机 Agent 的区别？

通用扫描器看配置和镜像；主机 Agent 看主机行为；InkBlade 在目标 Pod 内跑一次性 Rust 探针，检测 ML 组件、租户隔离、缓存、fabric、供应链和防护产品盲区。它不是 EDR，也不是 C2。

## 授权与写操作

### 写操作怎么保证安全？

五重校验：session 授权覆盖目标/级别/时间窗；探针 `--allow-write`；模板 `meta.writes=true` 且步骤声明写；`mode=backup-write`；备份回执存在。缺一条就 `skipped` 或 `E_DENIED`。写后回读哈希，失败回滚。

### 只读模式能做什么？

采集快照、HTTP/TCP 探测、读文件、执行白名单内的只读命令、跑只读模板、看 K8s 资源。不能写文件、不能删文件、不能执行非白名单命令、不能做 K8s 写动词。

### 授权记录过期了怎么办？

所有 run 以退出码 91 拒绝。用新时间窗重签；旧证据仍然有效。

### 急停在哪？

`inkblade abort` 置位工作区停止开关，解除用 `inkblade abort --clear`。运行中的 agent 还可以用 `inkblade agent stop --run-id <id>` 停止。

## 平台与交付

### 跨集群怎么工作？

`agent relay add` 注册集群间中继，`agent coverage status` 查看目标图闭合情况，`agent coverage proof` 写出覆盖证明。每个集群仍然需要自己的授权记录。

### 报告有哪些格式？

`report` 输出 PTES 结构渗透报告与修复清单，支持 `--lang bi|zh|en` 和 `--redact`；`export` 输出 SARIF、OCSF、VEX。

### 能商用/fork 吗？

Apache-2.0 允许商用与 fork；保留 `LICENSE` / `NOTICE`，不要用 InkBlade 商标命名 fork。

### 第 10 层做什么？

在授权环境里发一个带 `INKBLADE-BENIGN` 前缀的 marker，覆盖 Elkeid/Falco/Tetragon/Kyverno/WAF 等防守面，输出记录结果、盲区和规则/配置建议。

### 为什么有 11 个 defense-bypass 模块？

因为训练集群的防守面不是单一产品：HIDS、运行时 eBPF、准入、镜像扫描、主机代理、WAF、网络可视化各管一段。11 个模块对应 11 类产品/控制面，每个都输出检测、盲区、硬化建议三类结果。
