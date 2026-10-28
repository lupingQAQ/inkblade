# PROBE-BUILD — InkBlade Rust 探针构建、产物与原生验证

本文件记录当前发布状态：探针 `0.1.1`，linux-amd64 与 linux-arm64 两个 musl 静态二进制，
由 GitHub Actions 构建；amd64 产物在 QEMU Alpine VM 里跑完 286 个模板的 vulnerable/fixed
两态，每态 3 次结果一致。

## 1. 构建为什么放在 CI

| 环境 | 结果 |
| --- | --- |
| 本机 rustc | 被 Smart App Control 拦截（`os error 4551`），`cargo build` 无法调用 `rustc`，`rustc --version` 也失败 |
| WSL2 | 不可用（`Wsl/Service/CreateInstance/CreateVm/HCS/HCS_E_HYPERV_NOT_INSTALLED`），不能作为构建环境 |
| QEMU k3s VM | 可用（127.0.0.1:2222 SSH / 127.0.0.1:4555 串口），但 guest 内编译只作为备用路径，本次产物以 CI 为准 |
| Docker | 未使用；构建走 GitHub Actions |

结论是：源码入库，二进制由 CI 产出，校验和写进文档。`probe/dist/` 被 `.gitignore`
里的 `dist/` 忽略，二进制不提交进 git。

## 2. CI 构建

- 仓库：`lupingQAQ/inkblade`（private）
- 分支：`main`；发布标签：**`probe-v0.1.1`** → 标签提交 **`1f0f57c`**（`ci: restore probe artifact executable bit before channel tests`）
- 工作流：`.github/workflows/probe-release.yml`（`push: tag probe-v*` / `push: probe-build` / `workflow_dispatch`）
- 本次运行：**run 40430384961** — <https://github.com/lupingQAQ/inkblade/actions/runs/40430384961>
  （首次运行 40429959639 在 `python channel against real probe` 失败：artifact zip 丢了
  可执行位，工作流补 `chmod 0755` 后重跑；两次构建的 sha256 一致，见 §3）

### 2.1 构建环境

| 项 | 值 |
| --- | --- |
| Runner | GitHub-hosted `ubuntu-24.04` |
| Rust | `rustc 1.99.1 (58cf8f9c3 2026-10-13)` / stable-x86_64-unknown-linux-gnu |
| 交叉工具 | `cargo-zigbuild 0.24.0` + `ziglang 0.17.0`（PyPI wheel，自带 zig） |
| 目标 | `x86_64-unknown-linux-musl`、`aarch64-unknown-linux-musl` |
| 构建命令 | `cargo zigbuild --release --locked`（`opt-level="z"`, `lto=true`, `codegen-units=1`, `panic="abort"`, `strip=true`） |

### 2.2 本地复现

```bash
python3 -m pip install --user cargo-zigbuild        # 0.24.0 + ziglang 0.17.0
cd probe
cargo zigbuild --release --locked --target x86_64-unknown-linux-musl
cargo zigbuild --release --locked --target aarch64-unknown-linux-musl
```

### 2.3 耗时（run 40430384961）

| Job | Job 总时长 | 构建步骤 | 备注 |
| --- | --- | --- | --- |
| probe (amd64 / x86_64-unknown-linux-musl) | 108s | 81s（`cargo real 1m20.777s`） | 含 native self-test |
| probe (arm64 / aarch64-unknown-linux-musl) | 89s | 61s | 交叉构建，不执行 self-test |
| python channel against real probe | 20s | 8s | 15 项 framed-channel 测试，`OK` |
| publish probe release | 8s | — | 上传 `SHA256SUMS` 与两个二进制 |

## 3. 产物与校验

产物位于 `probe/dist/`（不入 git）：

| 文件 | 架构 | 大小（bytes） | SHA-256 |
| --- | --- | ---: | --- |
| `probe/dist/inkblade-probe-linux-amd64` | x86-64 | 2 066 112 | `c8d2f118460349a9c4303250b737adb0ccb28a1598e59c16d1f0d3f230b726f3` |
| `probe/dist/inkblade-probe-linux-arm64` | ARM aarch64 | 1 775 584 | `6d4803673bea9004bece7491282f8272a0ae41a2d3583f53704c430546fa38e4` |

本地复核（下载后重新计算，与 CI sidecar 一致）：

```powershell
gh run download 40430384961 --repo lupingQAQ/inkblade -D probe\dist
Get-FileHash probe/dist/inkblade-probe-linux-amd64 -Algorithm SHA256   # c8d2f118…b726f3
Get-FileHash probe/dist/inkblade-probe-linux-arm64 -Algorithm SHA256   # 6d480367…a38e4
```

ELF 结构（本地解析，非仅看 magic）：

```
amd64: magic=7f454c46 class=ELF64 type=ET_EXEC machine=0x3e (x86-64)   PT_INTERP=no → static
arm64: magic=7f454c46 class=ELF64 type=ET_EXEC machine=0xb7 (AArch64)  PT_INTERP=no → static
```

CI 侧同时以 `file` 断言：`ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped`
（arm64 为 `ARM aarch64`），且 `size > 100000`。

**可复现性**：40429959639 与 40430384961 两次独立构建产出的 amd64/arm64 字节与 sha256 完全一致。

## 4. native self-test（amd64 runner）

```
== --version ==
inkblade-probe 0.1.1
== --help ==
inkblade-probe 0.1.1
inkblade-probe run --stdio --token-file PATH [--read-only|--allow-write]
inkblade-probe collect [--read-only]
inkblade-probe exec -- <argv...> [--allow-write] [--allow-cmd CMD]
inkblade-probe dial --host HOST --port PORT
inkblade-probe beacon
inkblade-probe cleanup --path PATH...
inkblade-probe socks [BIND] [PORT]
== collect ==
collect keys: ['cgroup', 'devices', 'env', 'files_read', 'host', 'limits', 'mounts',
               'network', 'parent_id', 'probe_id', 'read_only', 'service_account']
== exec ==
{"exit_code":0,"rc":0,"stdout":"inkblade-probe-exec-ok\n","stderr":"","truncated":false,
 "timed_out":false,"duration_ms":10,"argv":["sh","-c","echo inkblade-probe-exec-ok"]}
== dial ==
inkblade-probe: connect 127.0.0.1:1 failed: 127.0.0.1:1: Connection refused (os error 111)
```

要点：

- `collect` 返回 12+ 个字段的 JSON（cgroup / devices / env / host / limits / mounts / network /
  probe_id / read_only / service_account …），可被 `json.load` 直接消费。
- `exec` 需要显式 `--allow-write --allow-cmd sh`；输出含 `exit_code=0`、`stdout` 原文、
  `timed_out=false`；stderr 与截断标记同样在 JSON 内。
- `dial` 对关闭端口返回 `Connection refused (os error 111)`，说明 socket 路径真实可达且 errno 透传。

## 5. 原生验证（QEMU Alpine VM，286 模板 × 2 态 × 3 次）

- 传输：`ssh root@127.0.0.1:2222 /tmp/inkblade-probe run --stdio`（challenge-HMAC 认证的 framed protocol）
- 二进制：`c8d2f118…b726f3`（即 `probe/dist/inkblade-probe-linux-amd64`），probe `0.1.1`，源码 `1f0f57c`
- 驱动：`tools/native-verify.py --repeat 3`
- 结果：**286/286 `runtime=rust`，0 失败**；每态 3 次规范化摘要一致；耗时与负控边界见
  `docs/PROBE-COVERAGE.md` 与 `reports/probe-coverage/evidence-native.json`

证据文件的 `source_commit` / `binary_sha256` / `probe_version` / `repeat` 字段与本文件一致；
`evidence` 为规范化（端口、日期、顺序、临时路径已脱敏）摘要，可在同一二进制上复算。

## 6. Release

`probe-release.yml` 在 `probe-v*` tag 上额外执行 `release` job：汇总两个架构二进制与 `SHA256SUMS`，
通过 `gh release upload` 发布到该 tag 的 GitHub Release；只有 `ENABLE_COSIGN=true` 时才附加
`SHA256SUMS.sigstore.json`（本次没有启用，仓库仍然私有）。

## 7. 限制

- arm64 产物只做 ELF/架构/静态链接断言，没有在 arm64 机器上执行；全部原生验证由 amd64 产物承担。
- CI runner 是共享虚拟机，构建耗时只作量级参考，不能当性能结论。
- 本机 cargo 不可用是环境限制，与产品无关；源码、锁定文件与构建命令都已入库，可以在任意 Linux 上复现。
