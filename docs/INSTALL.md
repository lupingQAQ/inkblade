# Install / 安装

> 适用版本：2026-10 探针架构。控制端 Python，目标端 Rust。
> 安装完成后，产品路径是 `doctor → session → probe → exec/scan → report`；没有 demo/trial 路径。

## 中文

安装 InkBlade 时，先把它拆成两个独立的东西：控制端和目标端。控制端是 Python 程序，跑在你的工作站或跳板机上，负责授权、编排和报告；目标端是一个静态链接的 Rust 二进制，只存在于被授权的 Pod 里，负责执行模板和产出证据。两者通过帧协议通信，不共享文件系统，也不共享 Python 环境。

这个拆分决定了安装顺序。先装控制端，确认 `doctor` 能跑；再准备探针二进制，确认架构和哈希；最后才创建 session、投放探针。把顺序倒过来，通常会在“目标 Pod 为什么跑不起来”上浪费半天，而真正的问题往往在控制端的探针路径或架构匹配。

### 环境要求

| 组件 | 版本/形态 | 说明 |
|---|---|---|
| 控制端 Python | 3.10 – 3.13 | 只用标准库；不需要编译器 |
| InkBlade 控制器 | 源码检出或 wheel | `inkblade` 命令或 `python -m inkblade` |
| 探针二进制 | Linux amd64 或 arm64 | 静态链接；目标 Pod 不需要 Python |
| kubectl | 1.26+ | 可选；只有 `kubectl cp/exec` 投放需要 |
| kubeconfig | 有授权的最小权限 | 只读盘点也需要 |
| 授权记录 | consent/ROE | 没有签署记录不执行 |
| 磁盘 | 约 300 MB 起 | 证据随项目增长 |

目标 Pod 的底线要求不高：Linux 内核，能执行静态 ELF，有一个可写临时目录或 `memfd_create`，并且探针进程能继承 Pod 的 namespace、cgroup 和 SA。它不需要 Python、Bash、curl 或 kubectl。只有 `k8s exec/copy` 这条可选路径需要镜像里有 `kubectl`；没有就换投放方式，不要试图把 kubectl 复制进去。

### 安装控制器

最省事的方式是从代码检出安装：

```bash
python -m pip install -e .
python -m inkblade --help
```

如果 `pip install` 被策略禁止，跳过它，直接在仓库根目录用 `python -m inkblade ...`。功能完全一样，损失的只是短命令。Windows 控制端可用；探针只支持 Linux，Windows 上不要运行 `inkblade-probe`，只把它复制到目标。

### 准备探针

发布包通常包含两个架构：

```bash
sha256sum -c SHA256SUMS

inkblade-probe-linux-amd64
inkblade-probe-linux-arm64
```

目标节点是 x86_64 就用 amd64，是 aarch64 就用 arm64。不要用 `uname -m` 猜完就直接投放；`file` 和 `ldd` 也要看。期望结果是静态链接，`ldd` 返回 “not a dynamic executable”。如果 `ldd` 列出一串 `.so`，说明你拿到的是动态构建，换发布物或重新构建，不要硬跑。

本地构建只在需要自定义 target 时做：

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-musl
```

构建产物在 `target/<target>/release/inkblade-probe`。构建机需要 Rust 1.75+ 和 musl target；目标机不需要。

### 验证安装

```bash
python -m inkblade doctor
```

`doctor` 的输出按检查项分行：Python 版本、入口、工作区写权限、磁盘、证据目录、探针二进制、架构、SHA-256、kubectl、kubeconfig、模板目录、consent 验签、本地端口。`WARN` 通常可以继续，比如没有 kubeconfig、没有可选依赖；`FAIL` 必须修，而且没有 `--skip` 开关。看到 `FAIL` 时先读修复建议，不要用环境变量绕过检查——那些检查存在的理由，通常是你上一次踩过的坑。

探针自检单独做：

```bash
./inkblade-probe-linux-amd64 version
./inkblade-probe-linux-amd64 run --help
```

`version` 会输出二进制版本、协议版本和构建目标。三者有一个对不上，就不要投放。协议版本尤其重要：控制端和探针的 `v` 不一致时，握手会返回 `E_VERSION`，不会“尽量兼容”。

### 第一次会话

第一次不要直接扫全层。先建一个只读 session，选一个 Pod，跑一个模板，确认通道、权限、证据都通，再扩大范围。

```bash
python -m inkblade session start \
  --name pilot-01 \
  --workspace ./work \
  --kubeconfig ~/.kube/config \
  --scope namespace:ml-team \
  --level read-only
```

`--scope` 可以写 namespace、Pod 选择器或 CIDR。`--level` 是四档：`read-only`、`active-probe`、`exploit-verify`、`full-impact`。模板的 `min_level` 高于 session 级别时会被拒绝，不会“先跑跑看”。时间窗用 `--window` 指定；过期即拒绝，不靠人记得。

投放探针：

```bash
python -m inkblade probe deploy \
  --session pilot-01 \
  --target ml-team/infer-0 \
  --method kubectl-exec \
  --binary ./inkblade-probe-linux-amd64
```

看到 `probe list` 里有 `p-...`，并且 `probe show` 的只读状态、目标、容器、父子关系都对，再做下一步。`probe collect` 会拉一份快照；先看快照里的 SA、挂载、网络接口和 GPU 设备，确认探针看到的世界和你以为的一致。

跑一个只读模板：

```bash
python -m inkblade exec \
  --session pilot-01 \
  --probe p-7f3a1c9e \
  --template service-account-token-exposure \
  --params '{"path":"/var/run/secrets/kubernetes.io/serviceaccount"}'
```

然后按层扫描、出报告：

```bash
python -m inkblade scan --session pilot-01 --profile ray-vllm --layers 1,3,5
python -m inkblade report --session pilot-01 --lang bi --format md
```

命令状态要如实说明：2026-10 迁移完成后，以上是主路径；迁移进行中时，旧的 `module/run/execute` 仍可能存在，但本文不把它们当作产品路径。以 `doctor` 输出的命令面为准。

### 容器与 Kubernetes

控制端可以打成镜像：

```bash
docker build -t inkblade:0.2.0 .
docker run --rm -v inkblade-data:/data inkblade:0.2.0 doctor
```

Helm 安装：

```bash
helm lint deploy/helm/inkblade
helm install inkblade deploy/helm/inkblade \
  --namespace inkblade --create-namespace
helm get notes inkblade --namespace inkblade
```

默认值刻意保守：只读、uid 10001、只读根文件系统、一块 PVC 存证据。写动词要同时打开 `readOnly=false` 和 `rbac.allowWrite=true`，并且工作区里要有签署授权。卸载不会删除 PVC，因为证据要比 release 活得久。

控制端容器不包含探针运行时依赖。探针二进制通过挂载或发布包带进去；不要把探针塞进控制端镜像然后指望它“自动找到目标”。

### 离线安装

离线环境需要带四样东西：控制器 wheel（或源码树）、Python 3.10+ 解释器、两个架构的探针二进制、模板与规则包。除此之外不需要包索引、模型权重或遥测端点。

```bash
python -m pip wheel . --no-deps -w dist/
python -m pip install --no-index --find-links dist/ inkblade
```

容器路线用 `docker save` 和 `docker load`；目标集群没有 Helm 时，用 `helm template` 渲染成普通 YAML。校验在隔离边界两侧都做一次：

```bash
sha256sum -c SHA256SUMS
python -m inkblade doctor --offline
```

`doctor --offline` 不访问网络。需要外网的检查会标 `SKIP`，不会标 `PASS`；不要把 `SKIP` 当成“通过”。

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

先读 `SECURITY.md` 和 `docs/FAQ.md` 的限制节。再确认三件事：consent 覆盖了目标、级别和时间窗；探针投放方式有清理路径；证据目录的保留期和访问权限已经定好。三件事缺一件，就不要开始。

第一次会话只做只读。只读不是“保守”，它是把变量分开：先确认探针看到的世界，再决定要不要写。写操作一旦开始，备份、回滚和证据链都会变复杂；不要在通道还没验证的时候引入这些变量。

### 卸载

```bash
python -m pip uninstall inkblade
```

工作区不会自动删除。证据与签署记录按你的保留策略处理；Helm 卸载不删除 PVC。

---

## English

Install the controller first, then the probe. The controller is Python 3.10–3.13 and needs no compiler. The probe is a static Linux binary for amd64 or arm64. The target Pod needs no Python, shell, curl, or kubectl; only the optional `k8s exec/copy` path needs `kubectl` in the image.

```bash
python -m pip install -e .
python -m inkblade doctor
```

Verify the probe hash and architecture before deployment. A dynamic build is not a release binary; replace it or rebuild with musl.

The first session should be read-only and narrow: one namespace, one Pod, one template. Confirm the probe tree, the snapshot, and the evidence path before widening the scope. There is no demo or trial path: a session requires an authorized target and a signed consent record.

For air-gapped installs, carry the controller wheel, a Python interpreter, both probe binaries, templates, and rule packs. `doctor --offline` marks network checks as skipped, not passed.

## 证据 / 限制

**证据**

- 探针静态构建配置：`probe/Cargo.toml`（musl 目标、LTO、strip）。
- 探针启动参数：`probe/src/spawn.rs`、`probe/src/config.rs`。
- 工作区与证据路径：`inkblade/core/evidence.py`、`inkblade/core/roe.py`。
- 安装自检：`inkblade doctor` 的检查项与输出。

**限制**

- 2026-10 迁移进行中，`session/probe/exec/scan` 命令面以最终 CLI 为准；迁移完成前以 `doctor` 输出为准。
- 探针只支持 Linux；Windows/macOS 只能作为控制端。
- `memfd` 路径依赖内核；老内核退化为临时文件。
- `kubectl cp` 依赖目标容器有 `tar`；没有 `tar` 时改用 base64 或共享卷。
- 控制端容器不内置探针二进制；离线安装需要单独带入。
- 没有 demo/trial；没有真实授权目标时，只能做只读的本地模板校验，不能产出“渗透结果”。
