# FAQ / 常见问题

问题按接入、探针、检测、授权与交付分组。

## 接入与安装

### 需要什么环境？

控制端是 Python 3.10–3.13，装在工作站或跳板机上；目标端是 Linux amd64/arm64 上的静态 Rust 探针。完整的接入步骤见 [`INSTALL.md`](INSTALL.md)。

### 第一次怎么开始？

```bash
python -m pip install -e .
python -m inkblade up --no-consent
```

`up` 创建工作区、打印一次性 admin 密码，并在 `127.0.0.1:8765` 提供控制台。登录后签授权记录，或执行 `inkblade quickstart`。已有探针可以直接接入：控制端 `channel listen`，Pod 内的探针 `reverse` 回连。首次投放用 `session open --mode foothold` 与 `probe deploy --via rce|sa-token`，不需要 kubeconfig。

### 必须要有 kubeconfig 吗？

不需要。默认立足点是普通的最低权限 Pod：非 root、没有 hostPath 或 privileged、没有 kubeconfig，只需要出站 TCP。`foothold` 与 `external` 入口都不读 kubeconfig；`kubeconfig` 只是一种可选入口，用于一次给多个 Pod 做首次批量 bootstrap。

### 探针怎么回连？

控制端执行 `channel listen` 监听；Pod 内的探针执行 `inkblade-probe reverse --host <controller> --port <port>`，从 Pod 内发起出站连接，所以 Pod 不用开监听端口。子探针由父探针用 `probe upload` + `probe spawn` 投放，回连方式相同。目标环境里已经有本地命令通道时，也可以用 stdio 通道。

### 支持 Windows/macOS 吗？

控制端可以运行在 Windows 与 macOS 上。探针只支持 Linux；Windows/macOS 不能作为投放目标，也不要在上面执行 `inkblade-probe`，把它复制到 Linux 目标即可。

### 能离线吗？

手动执行、模板、探针和报告可以离线；`agent run` 的 LLM 规划需要配置 LLM 端点（本地模型或内网 API），没有配置时就用手动或规则模式。离线安装需要带上控制器 wheel、Python 解释器、两个架构的探针二进制、模板与规则包。

## 探针与通道

### 探针是不是后门？

不是。探针不持久化、不写启动项、不改镜像、不连接固定 C2。它只在授权会话内运行，任务来自已注册模板，默认只读，写操作要过校验，退出时清理。

### 探针怎么进 Pod？

从你已有的立足点投放。默认路径是授权 RCE：把二进制 base64 分块送进 Pod，优先写 `memfd`；没有 `memfd` 就落到 `/dev/shm` 或 `/tmp`，`chmod 700` 后启动。另外还有三条路：`probe deploy --via sa-token` 用已有 ServiceAccount token 生成临时 kubeconfig，再 `kubectl cp` + `exec`；共享卷把二进制放进目标容器已挂载的卷；`probe deploy --via manifest` 生成 Pod、Job 或 EphemeralContainer 清单。`kubectl` 只在批量 bootstrap 时需要。探针启动后执行 `inkblade-probe reverse --host <controller> --port <port>` 回连控制端，之后的命令都走这条通道。细节见 [`PROBE-DEPLOY.md`](PROBE-DEPLOY.md)。

### 通道能做什么？

默认是探针主动回连的反向通道：控制端 `channel listen`，Pod 内的探针用 `reverse` 发起出站连接，Pod 不用监听端口。目标环境里已经有本地命令通道时，也可以用 stdio 通道（`channel start`）；它在本地回环上提供 SOCKS5 与端口转发，只绑定 `127.0.0.1`。`channel status` 查看状态，`channel stop` 关闭。

### 探针权限有多大？

等于它所在 Pod 的权限：同样的 ServiceAccount、namespace、cgroup 与挂载，加上探针进程拿到的 capability，不会更多。需要节点级权限的检测点，得由具备节点权限的探针或控制端完成。

### 多探针怎么管？

按父子树管理。每颗探针有 `probe_id` 与 `parent_id`；子探针继承父探针的只读状态、命令白名单与预算，只能更严格；限制嵌套层数与并发子探针数量；清理先子后父。

## 检测与结果

### 模板和模块是什么关系？

模块是产品目录里的条目，模板是它的执行体，两者用同一个键，例如 `defense-bypass-falco`。`module.json` 写元数据、级别、是否写、需要哪些部署面；`template.json` 写 steps/checks/findings/artifacts。注册表不接受带 `run.py` 的模块。

### 怎么加模板？

在 `inkblade/modules/<key>/` 放 `module.json` 与 `template.json`，用 `inkblade template validate` 校验，然后在授权目标上跑一次只读验证并补齐证据。模板就是执行体，不要写 `run.py`。

### 误报怎么处理？

先看证据锚和 checks，再确认目标的版本与配置是否与模板假设一致。可以在 fixed 环境里回归模板，但不要靠放宽规则来降误报。报告里要保留授权边界，以及不可达的部署面。

### 读结果先看什么？

先看 `status`，再看 `findings` 的 severity 与 evidence，最后看 `checks` 是否支持这条发现。`status=ok` 只说明模板跑完、没有发现，不代表目标安全；`status=skipped` 说明输入缺失、部署面不存在，或者写步骤被只读模式跳过。

### 和通用扫描器、主机 Agent 有什么区别？

通用扫描器看配置与镜像，主机 Agent 看主机行为。InkBlade 在目标 Pod 内跑一次性 Rust 探针，覆盖 ML 组件、租户隔离、缓存、fabric、供应链，以及防护产品的盲区。

## 授权与写操作

### 写操作怎么保证安全？

五道校验：会话授权覆盖目标、级别与时间窗；探针启动时带 `--allow-write`；模板 `meta.writes=true` 且具体步骤声明写；运行模式是 `backup-write`；备份回执已经存在。缺一条，写步骤就是 `skipped` 或 `E_DENIED`。写后回读哈希，失败按备份回滚。

### 只读模式能做什么？

采集快照、HTTP/TCP 探测、读文件、执行白名单内的只读命令、跑只读模板、读取 K8s 资源。不能写文件、不能删文件，不能执行白名单外的命令，也不能做 K8s 写动词。

### 授权记录过期了怎么办？

所有运行都会以退出码 91 拒绝。用新的时间窗重签即可，旧证据仍然有效。

### 急停在哪？

`inkblade abort` 设置工作区级停止开关，`inkblade abort --clear` 解除。运行中的 agent 也可以用 `inkblade agent stop --run-id <id>` 停掉。

## 平台与交付

### 跨集群怎么工作？

`agent relay add` 注册集群间中继，`agent coverage status` 查看目标图的完成情况，`agent coverage proof` 写出覆盖证明。每个集群仍然需要自己的授权记录。

### 报告有哪些格式？

`report` 输出 PTES 结构的渗透报告与修复清单，支持 `--lang bi|zh|en` 与 `--redact`；`export` 输出 SARIF、OCSF、VEX。

### 能商用/fork 吗？

Apache-2.0 允许商用与 fork。保留 `LICENSE` 与 `NOTICE`，fork 不要用 InkBlade 商标。

### 第 10 层做什么？

在授权环境里发一个带 `INKBLADE-BENIGN` 前缀的 marker，经过 Elkeid、Falco、Tetragon、Kyverno、WAF 等防护产品，记录哪些动作被看见、哪些落在盲区，并给出规则与配置建议。

### 为什么有 11 个 defense-bypass 模块？

训练集群的防护不止一个产品：HIDS、运行时 eBPF、准入、镜像扫描、主机代理、WAF、网络可视化各管一段。11 个模块对应这 11 类产品与控制面，每个都输出检测结果、盲区与硬化建议。
