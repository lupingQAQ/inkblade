# Install / 安装

> 控制端：Python 3.10–3.13。目标端：Linux amd64/arm64 静态 Rust 探针。
> 装完后运行 `inkblade up` 打开接入向导。

## 中文

安装 InkBlade 时，把它分成两个独立的部分：控制端和目标端。控制端是 Python 程序，装在工作站或跳板机上，负责授权、编排与报告；目标端是一个静态链接的 Rust 二进制，只放在被授权的 Pod 里，负责执行模板、产出证据。两者通过帧协议通信，不共享文件系统。

### 环境要求

| 组件 | 版本/形态 | 说明 |
|---|---|---|
| 控制端 Python | 3.10 – 3.13 | 只用标准库 |
| InkBlade 控制器 | 源码检出或 wheel | `inkblade` 命令或 `python -m inkblade` |
| 探针二进制 | Linux amd64 或 arm64 | 静态链接 |
| kubectl | 1.26+ | 可选；只有 `kubectl` 批量 bootstrap 路径需要 |
| kubeconfig | 有授权的最小权限 | 可选；foothold/external 接入不需要 |
| 授权记录 | consent/ROE | 没有签署记录不执行 |
| 磁盘 | 约 300 MB 起 | 证据随项目增长 |

目标 Pod 的要求不多：一个 Linux 内核，能执行静态 ELF，有一个可写临时目录或 `memfd_create`，并且探针进程能继承 Pod 的 namespace、cgroup 与 ServiceAccount。

### 安装控制器

```bash
python -m pip install -e .
python -m inkblade --help
```

如果 `pip install` 被策略禁止，就跳过安装，直接在仓库根目录用 `python -m inkblade ...`，功能一样，只是命令长一点。Windows 可以运行控制端；探针只支持 Linux，不要在 Windows 上执行 `inkblade-probe`，把它复制到目标即可。

### 准备探针

发布包通常包含两个架构：

```bash
sha256sum -c SHA256SUMS
```

- `inkblade-probe-linux-amd64`
- `inkblade-probe-linux-arm64`

目标节点是 x86_64 就用 amd64，是 aarch64 就用 arm64。期望结果是静态链接：`file` 显示 statically linked，`ldd` 返回 “not a dynamic executable”。如果 `ldd` 列出一串 `.so`，说明这不是 musl 静态构建，换发布物或重新构建。

只有需要自定义 target 时才在本地构建：

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-musl
```

产物在 `target/<target>/release/inkblade-probe`。构建需要 Rust 1.75+ 与 musl target。

### 第一次接入

```bash
python -m inkblade up --no-consent
```

`up` 创建工作区、打印一次性 admin 密码，并在 `127.0.0.1:8765` 提供本地控制台。在浏览器里登录后签授权记录，或执行：

```bash
python -m inkblade quickstart
```

`quickstart` 会问五个问题，确定目标、范围、级别、用户与签署信息。`inkblade roe` 可以随时查看当前记录。

默认立足点是一个普通的最低权限 Pod：非 root、没有 hostPath 或 privileged、没有 kubeconfig，只需要出站 TCP。已有探针时不用重新投放，也不需要 kubeconfig：

```bash
python -m inkblade probe list
python -m inkblade channel listen
```

在 Pod 内让探针回连：

```bash
inkblade-probe reverse --host <controller> --port <port>
```

首次投放走已有立足点：

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

随后在 Pod 内让探针回连控制端。`--via rce` 适合低权限 Pod；`--via sa-token` 使用已有的 ServiceAccount token。如果只有可达服务，用 `--mode external --proof @proof.json` 先提交有界证明，再经授权 RCE 或回调投放。`probe list` 里出现新的 `probe-...`，并且 `probe collect` 的快照里 SA、挂载、网络接口与 GPU 设备都符合预期，就可以跑检测了。子探针由父探针用 `probe upload` + `probe spawn` 投放并回连。

可选：如果你持有运维 kubeconfig，想一次给多个 Pod 做 bootstrap，可以用 `session open --mode kubeconfig --kubeconfig <path>` 与 `probe deploy --via kubectl`。这是高级路径，首次接入不需要它。

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

默认值偏保守：只读、uid 10001、根文件系统只读、一块 PVC 存证据。写动词需要同时打开 `readOnly=false` 与 `rbac.allowWrite=true`，并且工作区里有签署授权。卸载不会删除 PVC，证据留在集群里。

控制端镜像里不放探针；探针二进制通过挂载或发布包带进目标环境。

### 离线安装

离线环境要带四样东西：控制器 wheel（或源码树）、Python 3.10+ 解释器、两个架构的探针二进制、模板与规则包。手动执行、模板、探针与报告不需要外发端点；`agent run` 的 LLM 规划需要另配本地或内网 LLM 端点。

```bash
python -m pip wheel . --no-deps -w dist/
python -m pip install --no-index --find-links dist/ inkblade
```

容器路线用 `docker save` 与 `docker load`；目标集群没有 Helm 时，用 `helm template` 渲染成普通 YAML。隔离边界两侧各校验一次：

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

`--workspace` 指向这个根目录。证据默认不写到工作区之外，除非你显式导出。审计时先看 `probes/<id>/`：投放方式、token 文件是否删除、子探针是否清理，都记在这里。

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

探针不读这些变量，只认 `--token-file`、`--read-only`、`--allow-write` 这类显式参数，所以目标侧行为更容易复现。

### 指向集群之前

先读 `SECURITY.md` 与 [`FAQ.md`](FAQ.md) 里的授权与安全边界，再确认三件事：consent 覆盖了目标、级别与时间窗；探针投放方式有清理路径；证据目录的保留期与访问权限已经确定。

第一次会话只做只读。这样做是为了把变量分开：先确认探针看到的世界，再决定要不要写。写操作一旦开始，备份、回滚与证据链都会更难处理。

### 卸载

```bash
python -m pip uninstall inkblade
```

工作区不会自动删除。证据与签署记录按你的保留策略处理；Helm 卸载不删除 PVC。

---

## English

Install the controller first, then the probe. The controller is Python 3.10–3.13 and has no third-party dependency. The probe is a static Linux binary for amd64 or arm64, and runs without a target-side runtime.

```bash
python -m pip install -e .
python -m inkblade up
```

`up` creates the workspace, prints a one-time admin password and serves the local console. Sign the record with `quickstart` or in the console. The default foothold is an ordinary least-privilege Pod with outbound TCP only: the controller listens with `channel listen`, the probe connects back with `inkblade-probe reverse`, and the first delivery uses `session open --mode foothold` plus `probe deploy --via rce|sa-token`. No kubeconfig is involved; `session open --mode kubeconfig` is the optional batch bootstrap for several Pods.

Verify the probe hash and architecture before deployment. A dynamically linked build is not a release binary; replace it or rebuild against musl.

Start with a narrow read-only session: one namespace, one Pod, one template. Confirm the probe tree, the snapshot and the evidence path before widening the scope.

For air-gapped installs, carry the controller wheel, a Python interpreter, both probe binaries, templates and rule packs.

Deployment options: `docker build -t inkblade:0.2.0 .` or `helm install inkblade deploy/helm/inkblade --namespace inkblade --create-namespace`. The chart is read-only by default; writes need `readOnly=false`, `rbac.allowWrite=true` and a signed record.

Deployment prerequisites and the write-permission checks: [`PROBE-DEPLOY.md`](PROBE-DEPLOY.md).
