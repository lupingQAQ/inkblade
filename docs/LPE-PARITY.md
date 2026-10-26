# LPE Parity — Trident 内核提权检测库 vs KubeTrail

- 核对日期：2026-10-26
- 目录：`trident/lpe/catalog.py`（**52** 条：kernel 47 + userspace 5）
- 引擎：`trident/lpe/engine.py`（stable 分支感知的版本区间 + 前置面门控）
- 模块：`kernel-lpe-audit`（`--snapshot lab/fixtures/lpe/kernels.json`）
- 测试：`tests/test_kernel_lpe.py`（21 项）
- 边界：**detection-only**，只做版本/配置判定，不下载、不编译、不执行任何 PoC。

## 1. 与 KubeTrail 的对照

KubeTrail README 的 LPE 表含 **16** 条 CVE；Trident 目录是其**严格超集**（16/16），
并扩展到 **52** 条（+36）：

| # | CVE | 组件/类别 | KubeTrail | Trident 修复版本（摘要） |
|---:|---|---|:---:|---|
| 1 | CVE-2022-0847 | Dirty Pipe / pipe | ✓ | 5.16.11 / 5.15.25 / 5.10.102（mainline 5.17） |
| 2 | CVE-2016-5195 | Dirty COW / dirty_cow | ✓ | 4.8.3 / 4.7.9 / 4.4.26（mainline 4.9） |
| 3 | CVE-2024-1086 | nf_tables UAF | ✓ | 6.7.3 / 6.6.15 / 6.1.76 / 5.15.149（mainline 6.8） |
| 4 | CVE-2022-0492 | cgroups v1 release_agent | ✓ | 无单一修复（cgroups v2 / 去 SYS_ADMIN） |
| 5 | CVE-2021-22555 | netfilter heap OOB | ✓ | 5.12.4 / 5.10.46 / 5.4.123（mainline 5.13） |
| 6 | CVE-2023-0386 | overlayfs copy-up | ✓ | 6.1.9 / 5.15.90（mainline 6.2） |
| 7 | CVE-2021-3493 | Ubuntu overlayfs | ✓ | 5.11（Ubuntu 补丁） |
| 8 | CVE-2019-13272 | ptrace | ✓ | 5.1.17 / 4.19.59 / 4.14.133（mainline 5.2） |
| 9 | CVE-2022-2588 | cls_route UAF | ✓ | 5.19.4 / 5.15.61 / 5.10.137（mainline 6.0） |
| 10 | CVE-2023-32233 | nf_tables batch UAF | ✓ | 6.3.2 / 6.2.16（mainline 6.4） |
| 11 | CVE-2023-2640 | Ubuntu overlayfs | ✓ | 6.2（Ubuntu 补丁） |
| 12 | CVE-2023-32629 | Ubuntu overlayfs | ✓ | 6.2（Ubuntu 补丁） |
| 13 | CVE-2024-21626 | runc Leaky Vessels | ✓ | runc 1.1.12 |
| 14 | CVE-2019-5736 | runc overwrite | ✓ | runc 1.0.0 |
| 15 | CVE-2020-15257 | containerd-shim | ✓ | containerd 1.4.3 |
| 16 | CVE-2021-4034 | PwnKit (pkexec) | ✓ | polkit 0.120（或存在即报，版本未知） |
| 17–52 | 其余 36 条 | io_uring/nftables/eBPF/overlayfs/cgroups/… | — | 见 `catalog.py` |

## 2. 目录构成（52 条）

| 类别 | 条数 | 代表 CVE |
|---|---:|---|
| nftables | 12 | 2024-1086 / 2024-1085 / 2023-32233 / 2023-4206/7/8 / 2024-26809 |
| io_uring | 6 | CVE-2024-0582 / CVE-2021-3491 / CVE-2021-41073 / CVE-2022-29582 / CVE-2023-0461 / CVE-2023-2598 |
| overlayfs | 5 | 2023-0386 / 2021-3493 / 2023-2640 / 2023-32629 / 2021-3732 |
| eBPF | 4 | 2021-3490 / 2020-8835 / 2021-31440 / 2022-23222 |
| cgroups | 3 | 2022-0492 / 2021-4154 / 2020-14356 |
| netfilter / net_sched | 5 | 2021-22555 / 2022-25636 / 2022-27666 / 2022-2588 / 2023-3609 |
| Dirty Pipe / Dirty COW | 2 | 2022-0847 / 2016-5195 |
| 其他内核 | 10 | ptrace / dccp / netlink / vsock / iscsi / seq_file / tipc / fs_context / watch_queue / perf |
| 用户态组件 | 5 | pkexec / sudo / runc×2 / containerd |

- **kernel 规则 47 条**（≥30 要求）；**userspace 5 条**。
- 每条含：`cve / name / category / sev / component / introduced / fixed /
  requires / source / note / logic`。
- `fixed` 用 `{"mainline": "5.17", "5.16": "5.16.11", "5.15": "5.15.25"}` 表达
  主线 + stable 分支；**只把同 major.minor 的修复用于该分支**，避免 5.10 的修复
  误消 5.15 的风险。

## 3. 检测逻辑

1. **版本区间**：`introduced` 之下不报；`fixed.mainline` 及以上不报；同分支
   stable 修复边界内报；无分支记录且低于主线修复 → 报（EOL/发行版回移需复核）。
2. **前置面门控**（降低误报，容器场景关键）：
   - `userns` / `userns_or_net_admin`：user namespace 或 `CAP_NET_ADMIN`；
   - `unprivileged_bpf`：`kernel.unprivileged_bpf_disabled < 2`；
   - `net_admin` / `sys_admin` / `sys_ptrace`：生效 capabilities；
   - `cgroups_v1_writable`：cgroups v1 且可写（CVE-2022-0492）；
   - `ubuntu`：`os` 含 Ubuntu（发行版补丁差异）。
3. **用户态组件**：pkexec 采用 presence（版本未知也报，detection-only）；
   sudo/runc/containerd 按版本 `< fixed.mainline`。
4. **输出**：每命中带 `confidence=detection-only`、`fixed_in`、`evidence`、
   `logic`；模块 findings 明确"未执行利用"。

## 4. 效果（`lab/fixtures/lpe/kernels.json`）

| 节点 | 内核 | 命中 CVE 数 | 说明 |
|---|---|---:|---|
| `lab-legacy-3-10` | 3.10.0-1160 | 3 | Dirty COW、DCCP、netlink（老内核） |
| `lab-dirtypipe-5-8` | 5.8.18 | 16 | Dirty Pipe + io_uring/eBPF/overlayfs（unpriv bpf/userns 开启） |
| `lab-nft-6-1-50` | 6.1.50 | 5 | 2024-1086/1085、2023-32233、2023-4569、2024-26809 |
| `lab-modern-6-12` | 6.12.0 | **0** | 新版不误报（对象为零命中） |
| `lab-caps-none-5-15` | 5.15.24 | 5 | 无 userns/无 NET_ADMIN → 2024-1086、2021-3490 不报 |
| `lab-userspace` | 6.12.0 | 4（组件） | pkexec 0.105、sudo 1.8.21p2、runc 1.1.5、containerd 1.3.4 |

汇总：6 节点 / 33 命中 / 31 个唯一 CVE；`detection-only=true`。
`lab-modern-6-12` 的 `hits` 与 `kernel_component_hits` 均为空；`lab-caps-none-5-15`
验证了前置门控（不因版本在区间内就报 nftables/eBPF）。

复现：

```
python -m unittest tests.test_kernel_lpe
```

## 5. 已知偏差与限制

1. **CVE-2023-32233 的 6.1 回移未建模**：上游 6.1.30 已修复，但发行版回移差异大；
   本库只建 6.2/6.3 stable + 6.4 主线，因此 `6.1.50` 会被标为受影响（fixture 故意保留），
   报告须按 `detection-only` 复核 changelog。
2. **EOL 分支**：5.8/5.12 等无 stable 修复的内核按"低于主线修复"报；这是保守策略，
   不代表发行版一定可利用。
3. **CVE-2022-0492 无单一内核修复**：`fixed={}`，仅靠 cgroups v1 可写 + SYS_ADMIN
   前置门控；迁移 cgroups v2/移除权限即不再命中。
4. **用户态版本来源**：fixture/资产清单需提供准确版本；pkexec 版本缺失时按 presence
   报（detection-only，不声称可利用）。
5. **不提供 PoC/利用**：本库不进入"exploitable"列表；动态验证由
   `lab/upstream_verify` 与 exploit-registry 独立把关。
6. **区间数据**：以 NVD/CVE.org 与 kernel.org stable 修复为准；手工录入，新增条目
   必须附 `source`/`fixed`/`note`，并由测试校验字段完整性。
