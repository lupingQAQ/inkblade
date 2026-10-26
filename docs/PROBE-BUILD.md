# PROBE-BUILD — InkBlade Rust 探针构建与动态验证

状态：**已完成**（2026-10-27）。linux-amd64 / linux-arm64 musl 静态二进制由 GitHub Actions
构建，amd64 在 runner 上完成 `--version` / `--help` / `collect` / `exec` / `dial` 自测；
两份产物已取回本机并复核 ELF magic 与 SHA-256。

## 1. 背景与约束

| 项 | 事实 |
| --- | --- |
| 本机 rustc | 被 Smart App Control 拦截（`os error 4551`），`cargo build` 无法启动 `rustc`；`rustc --version` 可执行但实际编译被阻断 |
| 本机 WSL2 | 不可用：`Wsl/Service/CreateInstance/CreateVm/HCS/HCS_E_HYPERV_NOT_INSTALLED`（虚拟化未启用，等待重启） |
| QEMU k3s VM | 在跑（127.0.0.1:2222 SSH / 127.0.0.1:4555 串口均可达），root 口令未知；仅作为备选路径 |
| 结论 | 走 **路径 A：GitHub Actions**，首个成功路径；路径 B 未启用 |

## 2. 构建路径 A（GitHub Actions）

- 仓库：`lupingQAQ/inkblade`（private）
- 分支：`probe-build`（探针源码 + 工作流；`main` 未改动）
- 构建提交：`f28428b`（`build: fix probe self-test exec allow-list`）
- 运行：run **40417044211** — <https://github.com/lupingQAQ/inkblade/actions/runs/40417044211>
- 工作流：`.github/workflows/probe-release.yml`（同时接受 `push: probe-build`、`push: tag probe-v*`、`workflow_dispatch`）

### 2.1 构建环境

| 项 | 值 |
| --- | --- |
| Runner | GitHub-hosted `ubuntu-24.04`（Ubuntu 24.04.5 LTS） |
| Rust | `rustc 1.99.1 (58cf8f9c3 2026-10-13)` / stable-x86_64-unknown-linux-gnu |
| 交叉工具 | `cargo-zigbuild 0.24.0` + `ziglang 0.17.0`（PyPI wheel，自带匹配的 zig） |
| 目标 | `x86_64-unknown-linux-musl`、`aarch64-unknown-linux-musl` |
| 编译参数 | `cargo zigbuild --release --locked`；`opt-level="z"`, `lto=true`, `codegen-units=1`, `panic="abort"`, `strip=true` |

### 2.2 构建命令

```bash
# 工作流内
python3 -m pip install --user cargo-zigbuild        # 0.24.0 + ziglang 0.17.0
cd probe
cargo zigbuild --release --locked --target x86_64-unknown-linux-musl
cargo zigbuild --release --locked --target aarch64-unknown-linux-musl
```

### 2.3 耗时（run 40417044211）

| Job | Job 墙钟 | 其中编译 |
| --- | --- | --- |
| probe (amd64 / x86_64-unknown-linux-musl) | 1m25s | `real 0m57.266s`（user 58.421s） |
| probe (arm64 / aarch64-unknown-linux-musl) | 1m49s | `real 1m23.013s`（user 1m23.219s） |

前置迭代 3 次（失败原因留档）：musl.cc 拉取超时 `curl exit 28`；PyPI `ziglang` 未加入 PATH
导致 `zig: command not found`（改用 `pip install cargo-zigbuild` 自带 zig 后解决）；
`exec -- /bin/sh` 触发 "program must be a bare command name" 白名单校验（改为
`--allow-write --allow-cmd sh -- sh -c ...`）。

## 3. 产物与校验

产物落在 `probe/dist/`（`.gitignore` 第 9 行 `dist/` 命中，**不入源码树**）：

| 文件 | 架构 | 大小 (bytes) | 大小 (KiB) | SHA-256 |
| --- | --- | --- | --- | --- |
| `probe/dist/inkblade-probe-linux-amd64` | x86-64 | 2 063 240 | 2 015 | `7348deb0368c4d85d1cb2daef80a1dbe1c1f331c97544326b5b27aaf304f5f21` |
| `probe/dist/inkblade-probe-linux-arm64` | ARM aarch64 | 1 776 336 | 1 735 | `fc5d28729f4cec7cb4b7e2720473a5826927b77653f90377148d55efb4392f0c` |

取回与复核：

```powershell
gh run download 40417044211 --repo lupingQAQ/inkblade -D probe\dist
# ELF magic（前 4 字节）与 sha256（本机重算 vs artifact 内 .sha256 sidecar）
#   amd64 magic=7f454c46 sha256=7348deb0… sidecar_match=True
#   arm64 magic=7f454c46 sha256=fc5d2872… sidecar_match=True
```

CI 侧 `file` 输出：

```
target/x86_64-unknown-linux-musl/release/inkblade-probe:  ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped
target/aarch64-unknown-linux-musl/release/inkblade-probe: ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), statically linked, stripped
```

工作流在打包前强制断言：ELF magic `7f454c46`、`statically linked`、架构匹配、`size > 100000`，
任一不满足即失败（不是"看起来像 ELF"就放过）。

## 4. 动态验证（amd64，Linux runner 原生执行）

```
== --version ==
inkblade-probe 0.1.0
== --help ==
inkblade-probe 0.1.0
inkblade-probe run --stdio --token-file PATH [--read-only|--allow-write]
inkblade-probe collect [--read-only]
inkblade-probe exec -- <argv...> [--allow-write] [--allow-cmd CMD]
inkblade-probe dial --host HOST --port PORT
inkblade-probe beacon
inkblade-probe cleanup --path PATH...
inkblade-probe socks [BIND] [PORT]
== collect ==
collect keys: ['cgroup', 'devices', 'env', 'files_read', 'host', 'limits', 'mounts', 'network', 'parent_id', 'probe_id', 'read_only', 'service_account']
== exec ==
{"exit_code":0,"rc":0,"stdout":"inkblade-probe-exec-ok\n","stderr":"","truncated":false,"timed_out":false,"duration_ms":10,"argv":["sh","-c","echo inkblade-probe-exec-ok"]}
== dial ==
inkblade-probe: connect 127.0.0.1:1 failed: 127.0.0.1:1: Connection refused (os error 111)
```

解读：

- `collect` 返回容器/主机上下文 12+ 个顶层键（cgroup、devices、env、host、limits、mounts、
  network、probe_id、read_only、service_account…），JSON 可被 `json.load` 直接解析。
- `exec` 走白名单 + 写门：`sh -c` 需 `--allow-write --allow-cmd sh`，返回 `exit_code=0`、
  `stdout` 完整、`timed_out=false`；审计事件与结果 JSON 分离（审计走 stderr，结果走 stdout）。
- `dial` 在无监听端口返回 `Connection refused (os error 111)`，说明 socket 错误路径与 errno
  透传正常（期望失败，非缺陷）。
- arm64 产物无原生 runner，未做执行自测；仅做 ELF/架构/静态链接校验（同上）。

## 5. 复现

```bash
git clone https://github.com/lupingQAQ/inkblade.git
cd inkblade && git checkout probe-build
gh workflow run probe-release.yml --repo lupingQAQ/inkblade   # 或 push probe-build / tag probe-v0.1.0
gh run watch --repo lupingQAQ/inkblade
gh run download <run-id> --repo lupingQAQ/inkblade -D probe/dist
```

本地（Windows）只做只读复核，不执行 Linux 二进制：

```powershell
$b = [IO.File]::ReadAllBytes("probe/dist/inkblade-probe-linux-amd64")[0..3]
($b | % { $_.ToString('x2') }) -join ''      # 7f454c46
(Get-FileHash probe/dist/inkblade-probe-linux-amd64 -Algorithm SHA256).Hash.ToLower()
```

## 6. 路径 B（QEMU VM，未启用）

VM 已就绪（SSH 2222 / 串口 4555 均 `TcpTestSucceeded=True`），原计划经 `lab/qemu-k3s/vm_console.py`
串口登录取回提示符 → 设 root 口令/写临时公钥 → `apk add rust cargo musl-dev build-base` →
上传 `probe.tar.gz` → `cargo build --release` → `scp` 回二进制。因路径 A 一次成功且已在真实
Linux runner 完成自测，未再消耗 VM 构建时间；该路径保留为 CI 额度/权限不可用时的回退方案
（脚本草稿见 `scripts/build-probe-vm.py`）。
