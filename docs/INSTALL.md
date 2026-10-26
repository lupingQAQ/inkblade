# Install / 安装

[English](#english) · [中文](#中文)

---

## English

### Download

There is no binary to fetch and no package index entry to trust yet. The supported way to get
InkBlade today is a git checkout: clone the repository (or unpack a release archive), then
install from that directory. Publishing a wheel and a container image is wired into the release
workflow, but nothing is announced until the first tagged release exists — when it does, this
page will say so, with the version and the checksum.

That is not modesty. A pre-1.0 security tool should be installed from something you can read.

### Requirements

| Need | Version | Notes |
|---|---|---|
| Python | 3.10 – 3.13 | Standard library only. No compiler, no Rust, no protobuf build step. |
| Disk | ~200 MB | Workspace, reports, bundled console. Real evidence grows with the engagement. |
| Terminal | any POSIX shell, PowerShell or cmd | The commands below work in all three. |
| Docker | 24+ | Optional, only for the container path. |
| Helm | 3.8+ | Optional, only for the chart. |
| kubeconfig | — | Optional. Not needed for `doctor`, `pilot --dry-run` or `ui`. |

No outbound network access is needed at runtime. No API key, no licence server, no account.

### Install from a checkout

```bash
python -m pip install -e .
python -m inkblade --help
```

If `pip install` is blocked by policy, skip it. Every command works as `python -m inkblade ...`
from the repository root; the only thing you lose is the short entry point.

Windows note: if `python` opens the Microsoft Store, Python is not really installed. Install it,
tick “Add to PATH”, or call `py -3.12` explicitly.

### Verify the install

```bash
python -m inkblade doctor
```

`doctor` prints one line per check: interpreter, entry point, write access, free disk, port 8765,
optional dependencies, and whether a cluster is reachable. `WARN` is fine; `FAIL` comes with a
fix line. Then rehearse the first-run path without a cluster:

```bash
python -m inkblade pilot --dry-run --out reports/dry-run
python -m inkblade ui
```

`pilot --dry-run` writes a profile, a plan and an approval list under the output directory and
opens no connection. `ui` serves the console on `127.0.0.1:8765` and stays local.

### Container

```bash
docker build -t inkblade:0.2.0 .
docker run --rm -v inkblade-data:/data inkblade:0.2.0 doctor
docker run --rm -v inkblade-data:/data inkblade:0.2.0 pilot --dry-run --out /data/dry-run
```

The image is a two-stage build: wheels are compiled with the source present, the runtime layer
only receives the installed wheel. It runs as uid/gid 10001, with a read-only root filesystem
and a `HEALTHCHECK` that verifies the entry point and the packaged module data. `/data` is the
only writable path.

To expose the console, publish the port and bind the server to all interfaces:

```bash
docker run --rm -p 8765:8765 -v inkblade-data:/data inkblade:0.2.0 \
  --home /data ui --host 0.0.0.0 --port 8765
```

That is a network service holding evidence. Put it behind your normal access control, not on a
public interface.

### Kubernetes

```bash
helm lint deploy/helm/inkblade
helm install inkblade deploy/helm/inkblade --namespace inkblade --create-namespace
helm get notes inkblade --namespace inkblade
```

Defaults are deliberately boring: `readOnly: true`, `runAsUser: 10001`,
`readOnlyRootFilesystem: true`, one PVC for evidence. Write verbs need two switches flipped
(`readOnly=false` and `rbac.allowWrite=true`) and, even then, the application returns HTTP 423
until a signed consent record exists in the workspace.

`values.yaml` keys worth knowing: `image.repository`, `image.tag`, `persistence.existingClaim`,
`rbac.clusterWide`, `rbac.namespaces`, `usersSecret.name`, `extraArgs`, `probes.*`.

Uninstalling does not delete the PVC. That is intentional: evidence outlives the release.

### Air-gapped install

Three things need to travel: the source tree (or the built wheel), a Python 3.10+ interpreter,
and nothing else. No model weights, no package index, no telemetry endpoint.

```bash
python -m pip wheel . --no-deps -w dist/
# carry dist/inkblade-0.2.0-py3-none-any.whl across the boundary
python -m pip install --no-index --find-links dist/ inkblade
```

For the container path, `docker save` the image and load it on the other side. The Helm chart
can be rendered to plain YAML with `helm template` if the target cluster has no Tiller-era
tooling — or no Helm at all.

### Workspace layout

```
<workspace>/
├── users.json            accounts and role assignments
├── consent/              signed records, one file per engagement window
├── assets.json           incremental asset table
├── inventory.json        software inventory used for CVE applicability
├── evidence/<run>/       context.jsonl.gz, evidence.db, steps/*.tar.gz
├── reports/<run>/        pentest and remediation output
└── rules/<run>/          generated rule packs and replay matrix
```

`--home` points at the root. Most commands also accept `--workspace` for compatibility with
scripts that pass it explicitly. Nothing is written outside this tree.

### Environment variables

| Variable | Purpose |
|---|---|
| `INKBLADE_DATA` | Overrides the data root when a deployment sets one. |
| `INKBLADE_TOKEN` | API token for the local console (optional). |
| `INKBLADE_REPORT_KEY` | Key used to encrypt report bundles (optional). |
| `INKBLADE_LLM_BASE_URL`, `INKBLADE_LLM_API_KEY`, `INKBLADE_LLM_MODEL` | Only read when the LLM pool is enabled; off by default. |
| `INKBLADE_SANDBOX_*` | CPU, memory and network limits for sandboxed probes. |
| `PYTHONIOENCODING=utf-8` | Windows consoles with a legacy code page. |

### Before you point it at a cluster

- Read the security policy in the repository root (`SECURITY.md`) and the boundaries page in
  this folder (`FAQ.md`, section “Limits”).
- Run `pilot` first. Read the approval checklist it produces. If it surprises you, stop.
- Confirm the consent record covers the assets you are about to touch. The tool checks; you
  should too.
- Decide where evidence lives before the first run, not after.

---

## 中文

### 下载

现在没有可下载的二进制，也没有可以信任的包索引条目。当前唯一受支持的方式是源码检出：克隆仓库（或解开
release 压缩包），在目录里安装。wheel 与容器镜像的发布流程已经接进 CI，但第一个 tag 出来之前不会对外宣布；
真到了那天，这一页会写清版本与校验值。

这不是谦虚。pre-1.0 的安全工具，应该从你能读的源码装。

### 环境要求

| 需要 | 版本 | 说明 |
|---|---|---|
| Python | 3.10 – 3.13 | 只用标准库。不要编译器、不要 Rust、不要 protobuf 构建步骤。 |
| 磁盘 | 约 200 MB | 工作区、报告、内置控制台。真实项目的证据会随工期增长。 |
| 终端 | 任意 POSIX shell、PowerShell 或 cmd | 下面的命令三种都能跑。 |
| Docker | 24+ | 可选，只用于容器路线。 |
| Helm | 3.8+ | 可选，只用于 Chart。 |
| kubeconfig | — | 可选。`doctor`、`pilot --dry-run`、`ui` 都不需要。 |

运行时不需要外网、不需要 API key、没有授权服务器、不要账号。

### 从代码检出安装

```bash
python -m pip install -e .
python -m inkblade --help
```

如果策略不允许 `pip install`，跳过它。所有命令都能在仓库根目录用 `python -m inkblade ...` 运行，
损失的只是一个短命令。

Windows 注意：如果 `python` 打开的是 Microsoft Store，说明 Python 其实没装。装上并勾选 “Add to PATH”，
或者显式用 `py -3.12`。

### 验证安装

```bash
python -m inkblade doctor
```

`doctor` 每项检查一行：解释器、命令入口、写权限、可用磁盘、8765 端口、可选依赖、集群是否可达。
`WARN` 不影响使用；`FAIL` 会连同修复方法一起打印。接着做一次无集群的首次演练：

```bash
python -m inkblade pilot --dry-run --out reports/dry-run
python -m inkblade ui
```

`pilot --dry-run` 在输出目录写下画像、计划与审批清单，不建立任何连接；`ui` 只在
`127.0.0.1:8765` 上提供本地控制台。

### 容器

```bash
docker build -t inkblade:0.2.0 .
docker run --rm -v inkblade-data:/data inkblade:0.2.0 doctor
docker run --rm -v inkblade-data:/data inkblade:0.2.0 trial
```

镜像是两阶段构建：有源码时先编 wheel，运行时层只装 wheel。以 uid/gid 10001 运行，根文件系统只读，
`HEALTHCHECK` 会验证入口与打包的模块数据。只有 `/data` 可写。

要暴露控制台，就发布端口并把服务绑到所有网卡：

```bash
docker run --rm -p 8765:8765 -v inkblade-data:/data inkblade:0.2.0 \
  --home /data ui --host 0.0.0.0 --port 8765
```

这是一个装着证据的网络服务。放在你常规的访问控制之后，别挂公网。

### Kubernetes

```bash
helm lint deploy/helm/inkblade
helm install inkblade deploy/helm/inkblade --namespace inkblade --create-namespace
helm get notes inkblade --namespace inkblade
```

默认值刻意保守：`readOnly: true`、`runAsUser: 10001`、`readOnlyRootFilesystem: true`，
一块 PVC 存证据。要写必须同时打开两个开关（`readOnly=false` 与 `rbac.allowWrite=true`），
而且工作区里没有签署记录时应用仍返回 HTTP 423。

值得记住的 `values.yaml` 键：`image.repository`、`image.tag`、`persistence.existingClaim`、
`rbac.clusterWide`、`rbac.namespaces`、`usersSecret.name`、`extraArgs`、`probes.*`。

卸载不会删除 PVC。这是故意的：证据要比 release 活得久。

### 离线安装

需要带过隔离边界的东西只有三样：源码树（或构建好的 wheel）、Python 3.10+ 解释器、以及别的什么都不需要。
不带模型权重、不连包索引、没有遥测端点。

```bash
python -m pip wheel . --no-deps -w dist/
# 把 dist/inkblade-0.2.0-py3-none-any.whl 带过边界
python -m pip install --no-index --find-links dist/ inkblade
```

容器路线用 `docker save` 导出镜像，在对侧 `docker load`。目标集群没有 Helm 时，可以用
`helm template` 渲染成普通 YAML。

### 工作区布局

```
<工作区>/
├── users.json            账号与角色
├── consent/              签署记录，每个授权窗口一份
├── assets.json           增量资产表
├── inventory.json        用于 CVE 适用性判断的软件清单
├── evidence/<run>/       context.jsonl.gz、evidence.db、steps/*.tar.gz
├── reports/<run>/        渗透与修复报告
└── rules/<run>/          生成的规则包与重放矩阵
```

`--home` 指向根目录；多数命令也接受 `--workspace`，方便显式传参的脚本。除了你主动要求的 `--temp`，
不会往这棵树之外写任何东西。

### 环境变量

| 变量 | 用途 |
|---|---|
| `INKBLADE_DATA` | 部署时覆盖数据根目录。 |
| `INKBLADE_TOKEN` | 本地控制台的 API token（可选）。 |
| `INKBLADE_REPORT_KEY` | 报告包加密密钥（可选）。 |
| `INKBLADE_LLM_BASE_URL`、`INKBLADE_LLM_API_KEY`、`INKBLADE_LLM_MODEL` | 仅在开启 LLM 池时读取，默认关闭。 |
| `INKBLADE_SANDBOX_*` | 沙箱探测的 CPU、内存与网络限制。 |
| `PYTHONIOENCODING=utf-8` | Windows 旧代码页控制台。 |

### 指向集群之前

- 读仓库根目录的安全政策（`SECURITY.md`），以及本目录里的边界说明（`FAQ.md` 的“边界”一节）。
- 先跑 `pilot`，读它产出的审批清单。如果有让你意外的东西，停下。
- 确认授权记录覆盖了即将触碰的资产。工具会检查，你也该检查。
- 在第一次 run 之前决定证据放哪，而不是之后。
