# 快速开始 / Quick start

从安装到第一次自主检测：安装 → `inkblade up` → 签授权 → 导入 kubeconfig / 启动探针 → `agent run`。全部步骤面向真实授权环境。

## 1. 安装

```bash
pip install inkblade
```

从源码检出安装：

```bash
bash scripts/install.sh
```

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install.ps1
```

容器：

```bash
docker build -t inkblade:latest .
docker run --rm -it -p 127.0.0.1:8765:8765 -v inkblade-data:/data \
  inkblade:latest --home /data up --host 0.0.0.0 --foreground --no-browser --no-consent
```

## 2. 启动接入向导

```bash
inkblade up --no-consent
```

`up` 做四件事：

1. 自检：Python 版本、工作区可写、磁盘余量、端口可用。
2. 创建工作区：默认 `./inkblade-workspace`，`--home` 可改。
3. 生成 `admin` 随机密码，只打印一次；`users.json` 只存 scrypt 哈希。
4. 启动本地控制台 `127.0.0.1:8765` 并尝试打开浏览器。

`--no-consent` 表示不预签任何范围，授权由下一步显式完成。重复执行是幂等的：不重建工作区、不重印密码、不重复起进程。

## 3. 签授权

```bash
inkblade quickstart
```

五个问题：目标、范围、级别、用户、签署。记录哈希钉存，绑定目标、范围、时间窗和应急联系人。也可以用控制台的授权页签署。`inkblade roe` 查看当前授权状态。

## 4. 导入 kubeconfig 并启动探针

```bash
inkblade session open \
  --mode kubeconfig \
  --workspace ./work \
  --kubeconfig ~/.kube/config \
  --namespace ml-team \
  --pod infer-0

inkblade probe deploy \
  --session <session-id> \
  --via kubectl \
  --binary ./inkblade-probe-linux-amd64 \
  --namespace ml-team \
  --pod infer-0 \
  --allow-write
```

`session open` 绑定入口方式、命名空间、Pod 与凭据指纹；`probe deploy` 不带 `--allow-write` 时只出投放计划，带上后才真正投放并注册探针。`probe collect` 拉取快照，确认 SA、挂载、网卡与 GPU 设备符合预期。

## 5. 自主检测与报告

```bash
inkblade agent run \
  --probe <probe-id> \
  --objective read-only-recon \
  --workspace ./work \
  --budget-steps 40

inkblade report --run <run-id> --lang bi
inkblade export --run <run-id> --format sarif
```

`agent run` 打印 `run_id`；`report` 用它渲染双语渗透报告与修复清单；`export` 输出 SARIF、OCSF 或 VEX。运行中可用 `agent status`、`agent trace` 查看，`agent stop` 急停。

## 6. 日常命令

```bash
inkblade up        # 启动控制台（幂等）
inkblade status    # 进程、授权、用户、证据
inkblade down      # 停止控制台（幂等）
inkblade ui        # 只启动控制台
```

## 7. 常用参数

| Flag | 作用 |
|---|---|
| `--home <dir>` | 工作区目录（默认 `./inkblade-workspace`） |
| `--port <n>` | 本地控制台端口（默认 `8765`） |
| `--host <addr>` | 绑定地址（默认 `127.0.0.1`；容器内用 `0.0.0.0`） |
| `--no-browser` | 不自动打开浏览器 |
| `--no-ui` | 只初始化工作区，不启动控制台 |
| `--foreground` | 前台运行（容器/systemd） |
| `--no-consent` | 不预签任何范围，由 `quickstart` 显式签署 |

## 8. 下一步

- 安装方式、离线与 Helm：[`INSTALL.md`](INSTALL.md)
- 完整命令与工作流：[`USAGE.md`](USAGE.md)
- 检测分层与产出：[`DETECTION-LAYERS.md`](DETECTION-LAYERS.md)
- 常见问题：[`FAQ.md`](FAQ.md)
- 文档总索引：[`DOC-INDEX.md`](DOC-INDEX.md)

## English

Install, run `inkblade up --no-consent`, sign the authorization record with `inkblade quickstart`, open a session with `inkblade session open --mode kubeconfig`, deliver the probe with `inkblade probe deploy`, then run `inkblade agent run --probe <probe-id> --objective read-only-recon`. `report --run <run-id>` renders the bilingual report; `export` produces SARIF, OCSF or VEX.

`up` creates the workspace, prints a one-time admin password, starts the local console on `127.0.0.1:8765` and is idempotent. `--no-consent` leaves authorization to `quickstart`, which binds target, scope, level and time window. Probe delivery without `--allow-write` prints the plan only.
