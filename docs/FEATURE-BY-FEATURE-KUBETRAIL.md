# KubeTrail 逐功能穷举对比（FEATURE-BY-FEATURE-KUBETRAIL）

> 生成自 `tools/extract_features.py`（源码枚举，基线 2026-10-25）。克隆：`.slim/clonedeps/repos/ekkoo-z__KubeTrail`。
>
> 行数 = 提取计数：采集器(含 SA token 审计) 20｜findings 规则函数 25｜启发式标题 58（其中 LPE 20 条）｜敏感三态 0｜schema 字段 10｜CLI 参数 9｜桌面方法 83｜维持模板 7｜MCP 工具 8｜agent 技能 17｜EXP 模板 26｜视图 6｜组件 17｜合计 286 行。
>
> 状态分布：we-have 59 / partial 98 / missing 120 / N/A 9。`missing + 行动项 -` = 刻意不做（内核 LPE CVE 库/执行面植入，锚点见 REFLECTION-ARTEX-KUBETRAIL.md 与 docs/COMPETITIVE-MATRIX.md §5）。

## K1. 采集器/检查器（collectors 注册表 + SA token 审计）（20 项）

| 功能 | 来源锚点 | 工具行为 | InkBlade 状态 | 行动项 | 备注 |
|---|---|---|---|---|---|
| `identity` | internal/collectors/types.go:165 | 采集器 mode=safe | partial（core/roe.py + core/discovery.py） | M | in-pod 身份视角缺（控制面侧等价） [CM-22] |
| `environment` | internal/collectors/types.go:166 | 采集器 mode=safe | partial（modules/metadata-egress 等环境面） | M | in-pod 环境变量面缺 [CM-22] |
| `serviceaccount` | internal/collectors/types.go:167 | 采集器 mode=safe | partial（modules/rbac-mapping + overprivileged-sa-escalation） | M | 挂载 SA token 本地视角缺 [CM-22] |
| `proc` | internal/collectors/types.go:172 | 采集器 mode=safe | missing | M | in-pod /proc /sys 突破面矩阵 [CM-22] |
| `proc_sys_escape` | internal/collectors/types.go:173 | 采集器 mode=safe | missing | M | in-pod /proc /sys 突破面矩阵 [CM-22] |
| `filesystem` | internal/collectors/types.go:174 | 采集器 mode=safe | partial（modules/escape-primitives） | M | in-pod 文件系统挂载面缺 [CM-22] |
| `node_local` | internal/collectors/types.go:175 | 采集器 mode=safe | partial（modules/escape-primitives + gpu-network-operator-posture） | M | 节点本地文件/凭据面缺 [CM-22] |
| `runtime_local` | internal/collectors/types.go:176 | 采集器 mode=safe | we-have（modules/runtime-socket-escape） | M | runtime socket 逃逸已覆盖；in-pod 本地探测视角缺 [CM-22] |
| `lpe_local` | internal/collectors/types.go:181 | 采集器 mode=safe | missing | - | 内核 LPE 采集（内核 LPE CVE 库维持不补，REFLECTION Ruling） |
| `k8s_context` | internal/collectors/types.go:186 | 采集器 mode=safe | partial（core/discovery.py + modules/rbac-mapping） | M | in-cluster pod 视角缺 [CM-22] |
| `k8s_permissions` | internal/collectors/types.go:191 | 采集器 mode=safe | we-have（modules/rbac-mapping + core/auditlog.py 检测器） | M | SSRR/SSAR 权限审查已覆盖；逐 token 审计缺 [CM-05] |
| `k8s_profile` | internal/collectors/types.go:192 | 采集器 mode=safe | partial（core/discovery.py + modules/rbac-mapping） | M | in-cluster pod 视角缺 [CM-22] |
| `k8s_objects` | internal/collectors/types.go:193 | 采集器 mode=safe | partial（core/discovery.py + modules/rbac-mapping） | M | in-cluster pod 视角缺 [CM-22] |
| `credential_sweep` | internal/collectors/types.go:198 | 采集器 mode=safe | partial（modules/supply-chain-credential-theft + cloud-integration-fingerprint） | M | in-pod 凭据文件清扫缺 [CM-22] |
| `admission_dryrun` | internal/collectors/types.go:205 | 采集器 mode=full 副作用=kubernetes_dry_run_create | missing | M | admission dry-run 反推准入边界 [CM-24] |
| `dns_services` | internal/collectors/types.go:209 | 采集器 mode=full 副作用=dns_queries | partial（modules/dns-service-discovery） | - | SRV 探测细分缺 |
| `cloud_metadata` | internal/collectors/types.go:210 | 采集器 mode=full 副作用=http_requests | we-have（modules/metadata-egress + multi-cloud-imds-credentials + ssrf-imds-credential + cloud-sg-imds-exposure） | - | 13 家云元数据端点探测等价（full.go:69-93 枚举） |
| `admission_dryrun` | internal/collectors/types.go:211 | 采集器 mode=full 副作用=kubernetes_dry_run_create | missing | M | admission dry-run 反推准入边界 [CM-24] |
| `syscalls` | internal/collectors/types.go:212 | 采集器 mode=full 副作用=syscall_probes | missing | M | in-pod syscall 矩阵（sysprobe.RunMatrix） [CM-22] |
| `sa_token_audit` | internal/collectors/serviceaccount_token_audit.go:36 | --secretoutput 独立审计文档 kubetrail.sa-token-audit/v1（token 明文+JWT claims+逐 token SSRR/SSAR） | missing | S | legacy SA token 逐 token SSRR/SSAR + JWT claims [CM-05] |

## K2. findings 引擎规则函数（internal/findings）（25 项）

| 功能 | 来源锚点 | 工具行为 | InkBlade 状态 | 行动项 | 备注 |
|---|---|---|---|---|---|
| `EvaluateEscape` | internal/findings/findings.go:33 | findings 引擎规则函数 | partial（modules/escape-primitives） | M | 逃逸规则族入口（部分原语已覆盖） |
| `EvaluateRBAC` | internal/findings/findings.go:87 | findings 引擎规则函数 | we-have（modules/rbac-mapping + core/auditlog.py） | S | RBAC 规则族入口 |
| `evaluateCaps` | internal/findings/findings.go:102 | findings 引擎规则函数 | partial（modules/escape-primitives） | S | cap 位检查细分缺（SYS_ADMIN/SYS_PTRACE/NET_ADMIN/DAC_READ_SEARCH/SYS_RAWIO/SYS_MODULE 6 位） |
| `evaluateSeccomp` | internal/findings/findings.go:150 | findings 引擎规则函数 | partial（modules/escape-primitives + privileged-workloads） | S | seccomp/NNP/命名空间共享信号细分缺 |
| `evaluateNoNewPrivs` | internal/findings/findings.go:169 | findings 引擎规则函数 | partial（modules/escape-primitives + privileged-workloads） | S | seccomp/NNP/命名空间共享信号细分缺 |
| `evaluateNamespaceSharing` | internal/findings/findings.go:188 | findings 引擎规则函数 | partial（modules/escape-primitives + privileged-workloads） | S | seccomp/NNP/命名空间共享信号细分缺 |
| `evaluateCgroupWritable` | internal/findings/findings.go:217 | findings 引擎规则函数 | partial（modules/escape-primitives） | S | cgroup release_agent/设备写面细分缺 |
| `evaluateCgroupDevices` | internal/findings/findings.go:236 | findings 引擎规则函数 | partial（modules/escape-primitives） | S | cgroup release_agent/设备写面细分缺 |
| `evaluateRuntimeSockets` | internal/findings/findings.go:298 | findings 引擎规则函数 | we-have（modules/runtime-socket-escape） | - | runtime socket 可写=逃逸原语等价 |
| `evaluateRuntimeVersions` | internal/findings/findings.go:363 | findings 引擎规则函数 | missing | - | docker/runc/containerd/alpine 版本比对 CVE（版本启发式库不内置；镜像 CVE→CM-13 适配器承接） [CM-13] |
| `evaluateVolumeHints` | internal/findings/findings.go:413 | findings 引擎规则函数 | we-have（modules/privileged-workloads + privileged-gpu-pod-escape） | S | hostPath/privileged/hostPID/hostNetwork 检查等价 |
| `evaluatePodSpec` | internal/findings/findings.go:439 | findings 引擎规则函数 | we-have（modules/privileged-workloads + privileged-gpu-pod-escape） | S | hostPath/privileged/hostPID/hostNetwork 检查等价 |
| `evaluateWritableBindMountsWithoutNosuid` | internal/findings/findings.go:554 | findings 引擎规则函数 | partial（modules/escape-primitives） | S | rw+无 nosuid 挂载细分缺 |
| `evaluateProcSysBreakoutSurfaces` | internal/findings/findings.go:582 | findings 引擎规则函数 | partial（modules/escape-primitives） | M | proc/sys 突破面逐路径检查（core_pattern/modprobe/proc_kcore/apparmor/userns/hostVisibility） |
| `evaluateExpandedWildcards` | internal/findings/findings.go:597 | findings 引擎规则函数 | we-have（modules/rbac-mapping + auditlog _detect_rbac_clusteradmin_binding） | - | cluster-admin 等价 |
| `evaluateHighValueAccess` | internal/findings/findings.go:615 | findings 引擎规则函数 | we-have（modules/overprivileged-sa-escalation + rbac-mapping + auditlog 检测器） | S | 11 条高价值权限规则族 |
| `evaluateCgroupReleaseAgents` | internal/findings/findings.go:664 | findings 引擎规则函数 | partial（modules/escape-primitives） | S | cgroup release_agent/设备写面细分缺 |
| `evaluateKernelHelperPaths` | internal/findings/findings.go:700 | findings 引擎规则函数 | partial（modules/escape-primitives） | M | proc/sys 突破面逐路径检查（core_pattern/modprobe/proc_kcore/apparmor/userns/hostVisibility） |
| `evaluateSensitiveExposures` | internal/findings/findings.go:731 | findings 引擎规则函数 | partial（modules/escape-primitives） | M | proc/sys 突破面逐路径检查（core_pattern/modprobe/proc_kcore/apparmor/userns/hostVisibility） |
| `evaluateSecurityProfiles` | internal/findings/findings.go:786 | findings 引擎规则函数 | partial（modules/escape-primitives） | M | proc/sys 突破面逐路径检查（core_pattern/modprobe/proc_kcore/apparmor/userns/hostVisibility） |
| `evaluateUserNamespaceMapping` | internal/findings/findings.go:842 | findings 引擎规则函数 | partial（modules/escape-primitives） | M | proc/sys 突破面逐路径检查（core_pattern/modprobe/proc_kcore/apparmor/userns/hostVisibility） |
| `evaluateHostVisibility` | internal/findings/findings.go:869 | findings 引擎规则函数 | partial（modules/escape-primitives） | M | proc/sys 突破面逐路径检查（core_pattern/modprobe/proc_kcore/apparmor/userns/hostVisibility） |
| `EvaluateLPE` | internal/findings/lpe.go:11 | findings 引擎规则函数 | missing | - | 内核 LPE 规则族（维持不补 Ruling） |
| `evaluateLPEUserland` | internal/findings/lpe.go:89 | findings 引擎规则函数 | missing | - | 内核 LPE 规则族（维持不补 Ruling） |
| `evaluateLPEKernel` | internal/findings/lpe.go:184 | findings 引擎规则函数 | missing | - | 内核 LPE 规则族（维持不补 Ruling） |

## K3. findings 启发式标题（LPE/escape/RBAC 逐条）（58 项）

| 功能 | 来源锚点 | 工具行为 | InkBlade 状态 | 行动项 | 备注 |
|---|---|---|---|---|---|
| `%s in effective caps` | internal/findings/findings.go:141 | escape 启发式 finding 标题 | partial | S | 未归类启发式 |
| `Seccomp disabled` | internal/findings/findings.go:161 | escape 启发式 finding 标题 | partial（modules/escape-primitives） | M | 逃逸原语逐路径细分缺（部分已覆盖） |
| `NoNewPrivs disabled` | internal/findings/findings.go:180 | escape 启发式 finding 标题 | partial（modules/escape-primitives） | M | 逃逸原语逐路径细分缺（部分已覆盖） |
| `Writable cgroup mount (release_agent escape)` | internal/findings/findings.go:228 | escape 启发式 finding 标题 | partial（modules/escape-primitives） | M | 逃逸原语逐路径细分缺（部分已覆盖） |
| `Block device write access allowed` | internal/findings/findings.go:247 | rbac 启发式 finding 标题 | partial | S | 未归类启发式 |
| `Runtime socket writable: %s` | internal/findings/findings.go:332 | escape 启发式 finding 标题 | we-have（modules/runtime-socket-escape） | - |  |
| `Runtime socket (write unconfirmed): %s` | internal/findings/findings.go:342 | escape 启发式 finding 标题 | we-have（modules/runtime-socket-escape） | - |  |
| `Runtime socket visible: %s` | internal/findings/findings.go:355 | escape 启发式 finding 标题 | we-have（modules/runtime-socket-escape） | - |  |
| `%s %s version range: %s` | internal/findings/findings.go:377 | escape 启发式 finding 标题 | partial | S | 未归类启发式 |
| `hostPath volume mounted: %s` | internal/findings/findings.go:431 | escape 启发式 finding 标题 | we-have（modules/privileged-workloads + escape-primitives） | S | hostPath/hostPID/hostNetwork/hostIPC 信号等价 |
| `Pod spec: hostPID=true` | internal/findings/findings.go:454 | escape 启发式 finding 标题 | we-have（modules/privileged-workloads + escape-primitives） | S | hostPath/hostPID/hostNetwork/hostIPC 信号等价 |
| `Pod spec: hostNetwork=true` | internal/findings/findings.go:461 | escape 启发式 finding 标题 | partial | S | 未归类启发式 |
| `Pod spec: hostIPC=true` | internal/findings/findings.go:468 | escape 启发式 finding 标题 | we-have（modules/privileged-workloads + escape-primitives） | S | hostPath/hostPID/hostNetwork/hostIPC 信号等价 |
| `Privileged container: %s` | internal/findings/findings.go:484 | escape 启发式 finding 标题 | we-have（modules/privileged-workloads + privileged-gpu-pod-escape） | - |  |
| `allowPrivilegeEscalation: %s` | internal/findings/findings.go:493 | escape 启发式 finding 标题 | partial | S | 未归类启发式 |
| `Unconfined seccomp: %s` | internal/findings/findings.go:502 | escape 启发式 finding 标题 | partial | S | 未归类启发式 |
| `Pod spec adds cap %s: %s` | internal/findings/findings.go:513 | escape 启发式 finding 标题 | partial | S | 未归类启发式 |
| `Pod seccomp profile is Unconfined` | internal/findings/findings.go:525 | escape 启发式 finding 标题 | partial | S | 未归类启发式 |
| `Pod spec hostPath: %s` | internal/findings/findings.go:545 | escape 启发式 finding 标题 | we-have（modules/privileged-workloads + escape-primitives） | S | hostPath/hostPID/hostNetwork/hostIPC 信号等价 |
| `Writable bind mount (no nosuid): %s` | internal/findings/findings.go:574 | escape 启发式 finding 标题 | partial（modules/escape-primitives） | M | 逃逸原语逐路径细分缺（部分已覆盖） |
| `Cluster-admin equivalent permissions` | internal/findings/findings.go:607 | escape 启发式 finding 标题 | we-have（core/auditlog.py _detect_rbac_clusteradmin_binding） | - |  |
| `Writable release_agent: %s` | internal/findings/findings.go:679 | escape 启发式 finding 标题 | partial（modules/escape-primitives） | M | 逃逸原语逐路径细分缺（部分已覆盖） |
| `Cgroup release_agent + writable cgroup mount` | internal/findings/findings.go:692 | escape 启发式 finding 标题 | partial（modules/escape-primitives） | M | 逃逸原语逐路径细分缺（部分已覆盖） |
| `Writable kernel path: %s` | internal/findings/findings.go:723 | escape 启发式 finding 标题 | partial（modules/escape-primitives） | M | 逃逸原语逐路径细分缺（部分已覆盖） |
| `Writable sensitive surface: %s` | internal/findings/findings.go:752 | escape 启发式 finding 标题 | partial（modules/escape-primitives） | M | 逃逸原语逐路径细分缺（部分已覆盖） |
| `Readable host memory: %s` | internal/findings/findings.go:768 | escape 启发式 finding 标题 | partial（modules/escape-primitives） | M | 逃逸原语逐路径细分缺（部分已覆盖） |
| `Readable proc surface: %s` | internal/findings/findings.go:777 | escape 启发式 finding 标题 | partial（modules/escape-primitives） | M | 逃逸原语逐路径细分缺（部分已覆盖） |
| `AppArmor profile is unconfined` | internal/findings/findings.go:799 | escape 启发式 finding 标题 | partial（modules/escape-primitives） | M | 逃逸原语逐路径细分缺（部分已覆盖） |
| `AppArmor appears disabled` | internal/findings/findings.go:809 | escape 启发式 finding 标题 | partial（modules/escape-primitives） | M | 逃逸原语逐路径细分缺（部分已覆盖） |
| `SELinux appears disabled` | internal/findings/findings.go:824 | escape 启发式 finding 标题 | partial（modules/escape-primitives） | M | 逃逸原语逐路径细分缺（部分已覆盖） |
| `SELinux is permissive` | internal/findings/findings.go:833 | escape 启发式 finding 标题 | partial（modules/escape-primitives） | M | 逃逸原语逐路径细分缺（部分已覆盖） |
| `User namespace is not remapped` | internal/findings/findings.go:851 | escape 启发式 finding 标题 | partial（modules/escape-primitives） | M | 逃逸原语逐路径细分缺（部分已覆盖） |
| `Container root maps to host root` | internal/findings/findings.go:861 | escape 启发式 finding 标题 | partial | S | 未归类启发式 |
| `Host processes visible: %s` | internal/findings/findings.go:879 | escape 启发式 finding 标题 | partial（modules/escape-primitives） | M | 逃逸原语逐路径细分缺（部分已覆盖） |
| `Host-like /proc and /dev visibility` | internal/findings/findings.go:889 | escape 启发式 finding 标题 | partial（modules/escape-primitives） | M | 逃逸原语逐路径细分缺（部分已覆盖） |
| `Confirmed escape: privileged + host surface` | internal/findings/findings.go:924 | escape 启发式 finding 标题 | we-have（core/chains.py 组合升级链） | S | 组合判定等价 |
| `Probable escape: CAP_SYS_ADMIN + writable host surface` | internal/findings/findings.go:948 | escape 启发式 finding 标题 | partial（modules/escape-primitives） | S | 危险 cap 位细分（6 位枚举）缺 |
| `Probable escape: host PID + writable host path` | internal/findings/findings.go:969 | escape 启发式 finding 标题 | we-have（core/chains.py 组合升级链） | S | 组合判定等价 |
| `No LPE candidates matched` | internal/findings/lpe.go:70 | lpe 启发式 finding 标题 | missing | - | 内核/用户态 LPE CVE 启发式（内核 LPE CVE 库维持不补，REFLECTION-ARTEX-KUBETRAIL Ruling） |
| `Potential CVE-2021-3156 sudo Baron Samedit` | internal/findings/lpe.go:99 | lpe 启发式 finding 标题 | missing | - | 内核/用户态 LPE CVE 启发式（内核 LPE CVE 库维持不补，REFLECTION-ARTEX-KUBETRAIL Ruling） |
| `Potential CVE-2025-32463 sudo chroot LPE` | internal/findings/lpe.go:110 | lpe 启发式 finding 标题 | missing | - | 内核/用户态 LPE CVE 启发式（内核 LPE CVE 库维持不补，REFLECTION-ARTEX-KUBETRAIL Ruling） |
| `Potential CVE-2021-4034 PwnKit pkexec` | internal/findings/lpe.go:138 | lpe 启发式 finding 标题 | missing | - | 内核/用户态 LPE CVE 启发式（内核 LPE CVE 库维持不补，REFLECTION-ARTEX-KUBETRAIL Ruling） |
| `PwnKit exposure signal: setuid pkexec present` | internal/findings/lpe.go:150 | lpe 启发式 finding 标题 | missing | - | 内核/用户态 LPE CVE 启发式（内核 LPE CVE 库维持不补，REFLECTION-ARTEX-KUBETRAIL Ruling） |
| `Potential CVE-2017-5618 setuid screen LPE` | internal/findings/lpe.go:162 | lpe 启发式 finding 标题 | missing | - | 内核/用户态 LPE CVE 启发式（内核 LPE CVE 库维持不补，REFLECTION-ARTEX-KUBETRAIL Ruling） |
| `Potential CVE-2026-41651 PackageKit TOCTOU LPE` | internal/findings/lpe.go:174 | lpe 启发式 finding 标题 | missing | - | 内核/用户态 LPE CVE 启发式（内核 LPE CVE 库维持不补，REFLECTION-ARTEX-KUBETRAIL Ruling） |
| `Potential CVE-2022-0847 Dirty Pipe kernel range` | internal/findings/lpe.go:213 | lpe 启发式 finding 标题 | missing | - | 内核/用户态 LPE CVE 启发式（内核 LPE CVE 库维持不补，REFLECTION-ARTEX-KUBETRAIL Ruling） |
| `Potential CVE-2017-16995 eBPF verifier LPE` | internal/findings/lpe.go:224 | lpe 启发式 finding 标题 | missing | - | 内核/用户态 LPE CVE 启发式（内核 LPE CVE 库维持不补，REFLECTION-ARTEX-KUBETRAIL Ruling） |
| `Potential CVE-2021-3490 eBPF ALU32 LPE` | internal/findings/lpe.go:235 | lpe 启发式 finding 标题 | missing | - | 内核/用户态 LPE CVE 启发式（内核 LPE CVE 库维持不补，REFLECTION-ARTEX-KUBETRAIL Ruling） |
| `Potential CVE-2024-1086 nf_tables LPE` | internal/findings/lpe.go:254 | lpe 启发式 finding 标题 | missing | - | 内核/用户态 LPE CVE 启发式（内核 LPE CVE 库维持不补，REFLECTION-ARTEX-KUBETRAIL Ruling） |
| `CVE-2024-1086 kernel range with nf_tables present` | internal/findings/lpe.go:263 | lpe 启发式 finding 标题 | missing | - | 内核/用户态 LPE CVE 启发式（内核 LPE CVE 库维持不补，REFLECTION-ARTEX-KUBETRAIL Ruling） |
| `Potential CVE-2026-31431 Copy Fail AF_ALG LPE` | internal/findings/lpe.go:275 | lpe 启发式 finding 标题 | missing | - | 内核/用户态 LPE CVE 启发式（内核 LPE CVE 库维持不补，REFLECTION-ARTEX-KUBETRAIL Ruling） |
| `Potential CVE-2026-43284 Dirty Frag xfrm-ESP LPE` | internal/findings/lpe.go:287 | lpe 启发式 finding 标题 | missing | - | 内核/用户态 LPE CVE 启发式（内核 LPE CVE 库维持不补，REFLECTION-ARTEX-KUBETRAIL Ruling） |
| `Potential CVE-2026-43500 Dirty Frag RxRPC LPE` | internal/findings/lpe.go:298 | lpe 启发式 finding 标题 | missing | - | 内核/用户态 LPE CVE 启发式（内核 LPE CVE 库维持不补，REFLECTION-ARTEX-KUBETRAIL Ruling） |
| `Potential CVE-2023-0386 OverlayFS LPE` | internal/findings/lpe.go:312 | lpe 启发式 finding 标题 | missing | - | 内核/用户态 LPE CVE 启发式（内核 LPE CVE 库维持不补，REFLECTION-ARTEX-KUBETRAIL Ruling） |
| `CVE-2023-0386 OverlayFS kernel range` | internal/findings/lpe.go:321 | lpe 启发式 finding 标题 | missing | - | 内核/用户态 LPE CVE 启发式（内核 LPE CVE 库维持不补，REFLECTION-ARTEX-KUBETRAIL Ruling） |
| `Potential CVE-2022-0185 fs_context LPE range` | internal/findings/lpe.go:333 | lpe 启发式 finding 标题 | missing | - | 内核/用户态 LPE CVE 启发式（内核 LPE CVE 库维持不补，REFLECTION-ARTEX-KUBETRAIL Ruling） |
| `Potential CVE-2021-3493 Ubuntu OverlayFS LPE` | internal/findings/lpe.go:344 | lpe 启发式 finding 标题 | missing | - | 内核/用户态 LPE CVE 启发式（内核 LPE CVE 库维持不补，REFLECTION-ARTEX-KUBETRAIL Ruling） |
| `Legacy Dirty COW kernel range` | internal/findings/lpe.go:355 | lpe 启发式 finding 标题 | missing | - | 内核/用户态 LPE CVE 启发式（内核 LPE CVE 库维持不补，REFLECTION-ARTEX-KUBETRAIL Ruling） |

## K4. 敏感值三态（raw/redact/metadata）（0 项）

| 功能 | 来源锚点 | 工具行为 | InkBlade 状态 | 行动项 | 备注 |
|---|---|---|---|---|---|

## K5. dbus.json 导出 schema（model.go）（10 项）

| 功能 | 来源锚点 | 工具行为 | InkBlade 状态 | 行动项 | 备注 |
|---|---|---|---|---|---|
| `kubetrail.server/v1` | internal/model/model.go:5 | dbus.json 导出 schema 常量 | we-have（core/auditlog.py adapt_kubetrail（dbus.json→findings 消费端）） | - | schema 契约已适配 |
| `Document.schemaVersion` | internal/model/model.go:58 | dbus.json 字段（Document） | we-have（core/auditlog.py adapt_kubetrail） | - |  |
| `Document.run` | internal/model/model.go:59 | dbus.json 字段（Document） | we-have（core/auditlog.py adapt_kubetrail） | - |  |
| `Document.target` | internal/model/model.go:60 | dbus.json 字段（Document） | we-have（core/auditlog.py adapt_kubetrail） | - |  |
| `Document.mode` | internal/model/model.go:61 | dbus.json 字段（Document） | we-have（core/auditlog.py adapt_kubetrail） | - |  |
| `SATokenAuditDocument.schemaVersion` | internal/model/model.go:121 | dbus.json 字段（SATokenAuditDocument） | we-have（core/auditlog.py adapt_kubetrail） | - |  |
| `SATokenAuditDocument.run` | internal/model/model.go:122 | dbus.json 字段（SATokenAuditDocument） | we-have（core/auditlog.py adapt_kubetrail） | - |  |
| `SATokenAuditDocument.target` | internal/model/model.go:123 | dbus.json 字段（SATokenAuditDocument） | we-have（core/auditlog.py adapt_kubetrail） | - |  |
| `SATokenAuditDocument.mode` | internal/model/model.go:124 | dbus.json 字段（SATokenAuditDocument） | we-have（core/auditlog.py adapt_kubetrail） | - |  |
| `SATokenAuditDocument.source` | internal/model/model.go:125 | dbus.json 字段（SATokenAuditDocument） | missing | S | SA token 审计文档字段消费 [CM-05] |

## K6. CLI 参数（kubetrail-server）（9 项）

| 功能 | 来源锚点 | 工具行为 | InkBlade 状态 | 行动项 | 备注 |
|---|---|---|---|---|---|
| `--mode` | internal/command/command.go:58 | collection mode: safe or full | we-have（core/runner.py dry-run/live 键） | - | safe/full 分级=ROE 预演/实测 |
| `--output` | internal/command/command.go:60 | output file path, or - for stdout | we-have（export.py + core/evidence.py） | - |  |
| `--secretoutput` | internal/command/command.go:62 | write visible ServiceAccount token Secrets and per-token permission audit JSON to this file | missing | S | SA token 审计独立产物 [CM-05] |
| `--secret` | internal/command/command.go:63 | shorthand for --secretoutput | missing | S | SA token 审计独立产物 [CM-05] |
| `--pretty` | internal/command/command.go:64 | pretty-print output JSON | we-have（export.py + core/evidence.py） | - |  |
| `--timeout` | internal/command/command.go:66 | overall collection timeout | we-have（core/runner.py 超时） | - |  |
| `--sensitive` | internal/command/command.go:68 | sensitive value handling: raw, redact, or metadata | partial（core/redact.py） | S | 三态缺 metadata [CM-06] |
| `--kubeconfig` | internal/command/command.go:72 | kubeconfig path for non-cluster testing | N/A | - | 目标内运行形态差异（InkBlade 控制台侧） |
| `--scan` | internal/command/command.go:78 | scan categories: all, lpe, escape, rbac (comma-separated) | we-have（core/runner.py 模块选择） | - | lpe/escape/rbac 分类=模块族选择 |

## K7. Wails 桌面绑定方法（apps/desktop/app.go）（83 项）

| 功能 | 来源锚点 | 工具行为 | InkBlade 状态 | 行动项 | 备注 |
|---|---|---|---|---|---|
| `ListClusters` | apps/desktop/app.go:89 | Wails 绑定方法（Cluster Persistence） | partial（webui/server.py 多 run + core/discovery.py） | L | 多集群连接管理（InkBlade 单控制台多 run 模型） |
| `SaveCluster` | apps/desktop/app.go:96 | Wails 绑定方法（Cluster Persistence） | partial（webui/server.py 多 run + core/discovery.py） | L | 多集群连接管理（InkBlade 单控制台多 run 模型） |
| `DeleteCluster` | apps/desktop/app.go:113 | Wails 绑定方法（Cluster Persistence） | partial（webui/server.py 多 run + core/discovery.py） | L | 多集群连接管理（InkBlade 单控制台多 run 模型） |
| `TestConnection` | apps/desktop/app.go:121 | Wails 绑定方法（Cluster Persistence） | partial（webui/server.py 多 run + core/discovery.py） | L | 多集群连接管理（InkBlade 单控制台多 run 模型） |
| `ConnectCluster` | apps/desktop/app.go:131 | Wails 绑定方法（Cluster Persistence） | partial（webui/server.py 多 run + core/discovery.py） | L | 多集群连接管理（InkBlade 单控制台多 run 模型） |
| `DisconnectCluster` | apps/desktop/app.go:165 | Wails 绑定方法（Cluster Persistence） | partial（webui/server.py 多 run + core/discovery.py） | L | 多集群连接管理（InkBlade 单控制台多 run 模型） |
| `ListClusterExtensions` | apps/desktop/app.go:206 | Wails 绑定方法（Cluster Persistence） | partial（webui/server.py 多 run + core/discovery.py） | L | 多集群连接管理（InkBlade 单控制台多 run 模型） |
| `ClusterExtensionProxyPath` | apps/desktop/app.go:214 | Wails 绑定方法（Cluster Persistence） | partial（webui/server.py 多 run + core/discovery.py） | L | 多集群连接管理（InkBlade 单控制台多 run 模型） |
| `OpenKubeconfigDialog` | apps/desktop/app.go:220 | Wails 绑定方法（Dialogs） | N/A | - | Wails 桌面对话框（形态差异） |
| `PickSaveFile` | apps/desktop/app.go:237 | Wails 绑定方法（Dialogs） | N/A | - | Wails 桌面对话框（形态差异） |
| `PickOpenFile` | apps/desktop/app.go:243 | Wails 绑定方法（Dialogs） | N/A | - | Wails 桌面对话框（形态差异） |
| `PickDirectory` | apps/desktop/app.go:247 | Wails 绑定方法（Dialogs） | N/A | - | Wails 桌面对话框（形态差异） |
| `ListNamespaces` | apps/desktop/app.go:253 | Wails 绑定方法（Resources） | partial（core/discovery.py + webui /api/v1/assets） | S | ns/pod/node 浏览端点缺 |
| `ListPods` | apps/desktop/app.go:263 | Wails 绑定方法（Resources） | partial（core/discovery.py + webui /api/v1/assets） | S | ns/pod/node 浏览端点缺 |
| `ListNodes` | apps/desktop/app.go:273 | Wails 绑定方法（Resources） | partial（core/discovery.py + webui /api/v1/assets） | S | ns/pod/node 浏览端点缺 |
| `DescribePod` | apps/desktop/app.go:283 | Wails 绑定方法（Resources） | partial（core/discovery.py + webui /api/v1/assets） | S | ns/pod/node 浏览端点缺 |
| `StartTerminal` | apps/desktop/app.go:303 | Wails 绑定方法（Terminal） | missing | - | 交互式 pod 终端/日志流（执行面，规划≠执行 Ruling；桌面后渗透台刻意不做） |
| `WriteTerminal` | apps/desktop/app.go:344 | Wails 绑定方法（Terminal） | missing | - | 交互式 pod 终端/日志流（执行面，规划≠执行 Ruling；桌面后渗透台刻意不做） |
| `ResizeTerminal` | apps/desktop/app.go:357 | Wails 绑定方法（Terminal） | missing | - | 交互式 pod 终端/日志流（执行面，规划≠执行 Ruling；桌面后渗透台刻意不做） |
| `StopTerminal` | apps/desktop/app.go:375 | Wails 绑定方法（Terminal） | missing | - | 交互式 pod 终端/日志流（执行面，规划≠执行 Ruling；桌面后渗透台刻意不做） |
| `StartLogs` | apps/desktop/app.go:453 | Wails 绑定方法（Logs） | missing | - | 交互式 pod 终端/日志流（执行面，规划≠执行 Ruling；桌面后渗透台刻意不做） |
| `StopLogs` | apps/desktop/app.go:491 | Wails 绑定方法（Logs） | missing | - | 交互式 pod 终端/日志流（执行面，规划≠执行 Ruling；桌面后渗透台刻意不做） |
| `ListPodFiles` | apps/desktop/app.go:497 | Wails 绑定方法（Pod Files） | missing | - | pod/节点文件管理（执行面，刻意不做） |
| `ReadPodFile` | apps/desktop/app.go:507 | Wails 绑定方法（Pod Files） | missing | - | pod/节点文件管理（执行面，刻意不做） |
| `DownloadPodFile` | apps/desktop/app.go:521 | Wails 绑定方法（Pod Files） | missing | - | pod/节点文件管理（执行面，刻意不做） |
| `UploadPodFile` | apps/desktop/app.go:531 | Wails 绑定方法（Pod Files） | missing | - | pod/节点文件管理（执行面，刻意不做） |
| `DeletePodFile` | apps/desktop/app.go:541 | Wails 绑定方法（Pod Files） | missing | - | pod/节点文件管理（执行面，刻意不做） |
| `CheckNodeShellAccess` | apps/desktop/app.go:553 | Wails 绑定方法（Node Shell） | missing | - | 节点 shell 落地（执行面刻意不做；节点面侦察已有 escape-primitives/gpu-network-operator-posture） |
| `StartNodeTerminal` | apps/desktop/app.go:563 | Wails 绑定方法（Node Shell） | missing | - | 节点 shell 落地（执行面刻意不做；节点面侦察已有 escape-primitives/gpu-network-operator-posture） |
| `DeleteNodeShellPod` | apps/desktop/app.go:620 | Wails 绑定方法（Node Shell） | missing | - | 节点 shell 落地（执行面刻意不做；节点面侦察已有 escape-primitives/gpu-network-operator-posture） |
| `ListNodeFiles` | apps/desktop/app.go:630 | Wails 绑定方法（Node Shell） | missing | - | pod/节点文件管理（执行面，刻意不做） |
| `ReadNodeFile` | apps/desktop/app.go:640 | Wails 绑定方法（Node Shell） | missing | - | pod/节点文件管理（执行面，刻意不做） |
| `DownloadNodeFile` | apps/desktop/app.go:654 | Wails 绑定方法（Node Shell） | missing | - | pod/节点文件管理（执行面，刻意不做） |
| `UploadNodeFile` | apps/desktop/app.go:664 | Wails 绑定方法（Node Shell） | missing | - | pod/节点文件管理（执行面，刻意不做） |
| `DeleteNodeFile` | apps/desktop/app.go:674 | Wails 绑定方法（Node Shell） | missing | - | pod/节点文件管理（执行面，刻意不做） |
| `ReconCatalog` | apps/desktop/app.go:686 | Wails 绑定方法（Recon） | partial（modules/recon 族 + agent_planner.py 推荐排序） | S | 节点面侦察手册目录化缺 |
| `ReconRead` | apps/desktop/app.go:688 | Wails 绑定方法（Recon） | partial（modules/recon 族 + agent_planner.py 推荐排序） | S | 节点面侦察手册目录化缺 |
| `StartPortForward` | apps/desktop/app.go:709 | Wails 绑定方法（Port Forward） | missing | - | 端口转发 C2 面（刻意不做） |
| `StopPortForward` | apps/desktop/app.go:757 | Wails 绑定方法（Port Forward） | missing | - | 端口转发 C2 面（刻意不做） |
| `ListPortForwards` | apps/desktop/app.go:761 | Wails 绑定方法（Port Forward） | missing | - | 端口转发 C2 面（刻意不做） |
| `ImportScanResult` | apps/desktop/app.go:783 | Wails 绑定方法（Scanner） | we-have（core/auditlog.py adapt_kubetrail（dbus.json→findings）+ export.py） | S | KubeTrail 导入已适配；通用扫描器导入缺 [CM-13] |
| `ImportScanResultPath` | apps/desktop/app.go:799 | Wails 绑定方法（Scanner） | we-have（core/auditlog.py adapt_kubetrail（dbus.json→findings）+ export.py） | S | KubeTrail 导入已适配；通用扫描器导入缺 [CM-13] |
| `StartClusterScan` | apps/desktop/app.go:803 | Wails 绑定方法（Scanner） | we-have（core/auditlog.py adapt_kubetrail（dbus.json→findings）+ export.py） | S | KubeTrail 导入已适配；通用扫描器导入缺 [CM-13] |
| `GetScanResult` | apps/desktop/app.go:822 | Wails 绑定方法（Scanner） | we-have（core/auditlog.py adapt_kubetrail（dbus.json→findings）+ export.py） | S | KubeTrail 导入已适配；通用扫描器导入缺 [CM-13] |
| `ListScanResults` | apps/desktop/app.go:826 | Wails 绑定方法（Scanner） | we-have（core/auditlog.py adapt_kubetrail（dbus.json→findings）+ export.py） | S | KubeTrail 导入已适配；通用扫描器导入缺 [CM-13] |
| `ExportScanResult` | apps/desktop/app.go:830 | Wails 绑定方法（Scanner） | we-have（core/auditlog.py adapt_kubetrail（dbus.json→findings）+ export.py） | S | KubeTrail 导入已适配；通用扫描器导入缺 [CM-13] |
| `DeleteScanResult` | apps/desktop/app.go:844 | Wails 绑定方法（Scanner） | we-have（core/auditlog.py adapt_kubetrail（dbus.json→findings）+ export.py） | S | KubeTrail 导入已适配；通用扫描器导入缺 [CM-13] |
| `ConfigureAgent` | apps/desktop/app.go:850 | Wails 绑定方法（Agent） | missing | - | AI agent 进程管理（对话式 agent 刻意不做；AI 辅助=agent_planner/mcp_server 已有） |
| `GetAgentStatus` | apps/desktop/app.go:858 | Wails 绑定方法（Agent） | missing | - | AI agent 进程管理（对话式 agent 刻意不做；AI 辅助=agent_planner/mcp_server 已有） |
| `GetAgentDisplayConfig` | apps/desktop/app.go:862 | Wails 绑定方法（Agent） | missing | - | AI agent 进程管理（对话式 agent 刻意不做；AI 辅助=agent_planner/mcp_server 已有） |
| `GetAgentRuntimeInfo` | apps/desktop/app.go:866 | Wails 绑定方法（Agent） | missing | - | AI agent 进程管理（对话式 agent 刻意不做；AI 辅助=agent_planner/mcp_server 已有） |
| `CheckAgentRuntime` | apps/desktop/app.go:870 | Wails 绑定方法（Agent） | missing | - | AI agent 进程管理（对话式 agent 刻意不做；AI 辅助=agent_planner/mcp_server 已有） |
| `StopAgent` | apps/desktop/app.go:874 | Wails 绑定方法（Agent） | missing | - | AI agent 进程管理（对话式 agent 刻意不做；AI 辅助=agent_planner/mcp_server 已有） |
| `RestartAgent` | apps/desktop/app.go:878 | Wails 绑定方法（Agent） | missing | - | AI agent 进程管理（对话式 agent 刻意不做；AI 辅助=agent_planner/mcp_server 已有） |
| `AgentLogs` | apps/desktop/app.go:883 | Wails 绑定方法（Agent） | missing | - | AI agent 进程管理（对话式 agent 刻意不做；AI 辅助=agent_planner/mcp_server 已有） |
| `ListAgentSkills` | apps/desktop/app.go:887 | Wails 绑定方法（Agent） | partial（lab/ 脚本 + rules/templates/） | M | 技能 CRUD 缺 |
| `GetAgentSkill` | apps/desktop/app.go:891 | Wails 绑定方法（Agent） | partial（lab/ 脚本 + rules/templates/） | M | 技能 CRUD 缺 |
| `SaveAgentSkill` | apps/desktop/app.go:895 | Wails 绑定方法（Agent） | partial（lab/ 脚本 + rules/templates/） | M | 技能 CRUD 缺 |
| `DeleteAgentSkill` | apps/desktop/app.go:904 | Wails 绑定方法（Agent） | partial（lab/ 脚本 + rules/templates/） | M | 技能 CRUD 缺 |
| `StartAgentChat` | apps/desktop/app.go:912 | Wails 绑定方法（Agent） | missing | - | agent 对话（刻意不做） |
| `StopAgentChat` | apps/desktop/app.go:954 | Wails 绑定方法（Agent） | missing | - | AI agent 进程管理（对话式 agent 刻意不做；AI 辅助=agent_planner/mcp_server 已有） |
| `GetAttackGraph` | apps/desktop/app.go:973 | Wails 绑定方法（Agent） | partial（core/graph.py + core/reachability.py） | M | 攻击图端点缺（自动路径计算→CM-23） [CM-23] |
| `MaterializeSensitive` | apps/desktop/app.go:984 | Wails 绑定方法（Agent） | missing | S | 敏感材料受控物化 [CM-06] |
| `ListExpTemplates` | apps/desktop/app.go:1006 | Wails 绑定方法（EXP Forge） | partial（core/poc.py + core/payloads.py） | M | safe/full 分级 EXP 模板库缺 [CM-35] |
| `GenerateExp` | apps/desktop/app.go:1013 | Wails 绑定方法（EXP Forge） | partial（core/poc.py + core/payloads.py） | M | safe/full 分级 EXP 模板库缺 [CM-35] |
| `ExportAnalysisReport` | apps/desktop/app.go:1040 | Wails 绑定方法（Report Export） | we-have（reports/render.py + export.py） | - |  |
| `PersistenceCatalog` | apps/desktop/app.go:1093 | Wails 绑定方法（Persistence） | missing | - | 权限维持植入执行面（刻意不做；检测等价=auditlog _detect_rbac_clusteradmin_binding/_detect_privileged_pod） |
| `CreatePersistenceSA` | apps/desktop/app.go:1154 | Wails 绑定方法（Persistence） | missing | - | 权限维持植入执行面（刻意不做；检测等价=auditlog _detect_rbac_clusteradmin_binding/_detect_privileged_pod） |
| `CreatePersistenceCronJob` | apps/desktop/app.go:1164 | Wails 绑定方法（Persistence） | missing | - | 权限维持植入执行面（刻意不做；检测等价=auditlog _detect_rbac_clusteradmin_binding/_detect_privileged_pod） |
| `CreatePersistenceDeployment` | apps/desktop/app.go:1174 | Wails 绑定方法（Persistence） | missing | - | 权限维持植入执行面（刻意不做；检测等价=auditlog _detect_rbac_clusteradmin_binding/_detect_privileged_pod） |
| `CreatePersistenceDaemonSet` | apps/desktop/app.go:1184 | Wails 绑定方法（Persistence） | missing | - | 权限维持植入执行面（刻意不做；检测等价=auditlog _detect_rbac_clusteradmin_binding/_detect_privileged_pod） |
| `GenerateShadowKubeconfig` | apps/desktop/app.go:1194 | Wails 绑定方法（Persistence） | missing | - | 权限维持植入执行面（刻意不做；检测等价=auditlog _detect_rbac_clusteradmin_binding/_detect_privileged_pod） |
| `RequestSAToken` | apps/desktop/app.go:1204 | Wails 绑定方法（Persistence） | missing | - | 权限维持植入执行面（刻意不做；检测等价=auditlog _detect_rbac_clusteradmin_binding/_detect_privileged_pod） |
| `InjectPullSecret` | apps/desktop/app.go:1214 | Wails 绑定方法（Persistence） | missing | - | 权限维持植入执行面（刻意不做；检测等价=auditlog _detect_rbac_clusteradmin_binding/_detect_privileged_pod） |
| `ListPersistenceResources` | apps/desktop/app.go:1224 | Wails 绑定方法（Persistence） | missing | - | 权限维持植入执行面（刻意不做；检测等价=auditlog _detect_rbac_clusteradmin_binding/_detect_privileged_pod） |
| `DeletePersistenceResource` | apps/desktop/app.go:1234 | Wails 绑定方法（Persistence） | missing | - | 权限维持植入执行面（刻意不做；检测等价=auditlog _detect_rbac_clusteradmin_binding/_detect_privileged_pod） |
| `GetSAKubeconfig` | apps/desktop/app.go:1244 | Wails 绑定方法（Persistence） | missing | - | 权限维持植入执行面（刻意不做；检测等价=auditlog _detect_rbac_clusteradmin_binding/_detect_privileged_pod） |
| `SaveKubeconfigFile` | apps/desktop/app.go:1254 | Wails 绑定方法（Persistence） | missing | - | 权限维持植入执行面（刻意不做；检测等价=auditlog _detect_rbac_clusteradmin_binding/_detect_privileged_pod） |
| `SaveAgentConfigOnly` | apps/desktop/app.go:1273 | Wails 绑定方法（Agent Config） | missing | - | AI agent 进程管理（对话式 agent 刻意不做；AI 辅助=agent_planner/mcp_server 已有） |
| `TestAgentConnection` | apps/desktop/app.go:1278 | Wails 绑定方法（Agent Config） | missing | - | AI agent 进程管理（对话式 agent 刻意不做；AI 辅助=agent_planner/mcp_server 已有） |
| `EnsureAgentRunning` | apps/desktop/app.go:1354 | Wails 绑定方法（Agent Config） | missing | - | AI agent 进程管理（对话式 agent 刻意不做；AI 辅助=agent_planner/mcp_server 已有） |
| `OpenExternalURL` | apps/desktop/app.go:1562 | Wails 绑定方法（Agent Config Persistence） | N/A | - | Wails 桌面对话框（形态差异） |
| `OpenDirectoryPath` | apps/desktop/app.go:1566 | Wails 绑定方法（Agent Config Persistence） | N/A | - | Wails 桌面对话框（形态差异） |

## K8. 权限维持模板（kube/persistence.go）（7 项）

| 功能 | 来源锚点 | 工具行为 | InkBlade 状态 | 行动项 | 备注 |
|---|---|---|---|---|---|
| `serviceaccount` | apps/desktop/kube/persistence.go:30 | 权限维持模板 ServiceAccount | missing | - | SA+CRB 植入（执行面刻意不做；检测=auditlog cluster-admin binding 检测器） |
| `cronjob` | apps/desktop/kube/persistence.go:31 | 权限维持模板 CronJob | missing | - | 工作负载持久化植入（同上；检测=auditlog 异常 pod/CRB） |
| `deployment` | apps/desktop/kube/persistence.go:32 | 权限维持模板 Deployment | missing | - | 工作负载持久化植入（同上；检测=auditlog 异常 pod/CRB） |
| `daemonset` | apps/desktop/kube/persistence.go:33 | 权限维持模板 DaemonSet | missing | - | 工作负载持久化植入（同上；检测=auditlog 异常 pod/CRB） |
| `shadow-kubeconfig` | apps/desktop/kube/persistence.go:34 | 权限维持模板 ShadowKubeconfig | missing | - | 影子 kubeconfig 生成（执行面刻意不做） |
| `token-request` | apps/desktop/kube/persistence.go:35 | 权限维持模板 TokenRequest | missing | - | TokenRequest 铸币（执行面刻意不做；面分析=rbac-mapping） |
| `pull-secret` | apps/desktop/kube/persistence.go:36 | 权限维持模板 PullSecret | missing | - | pull secret 注入 default SA（执行面刻意不做；供应链面=supply-chain-*） |

## K9. agent MCP 工具（apps/agent）（8 项）

| 功能 | 来源锚点 | 工具行为 | InkBlade 状态 | 行动项 | 备注 |
|---|---|---|---|---|---|
| `kubetrail_load_result` | apps/agent/src/tools/kubetrail.ts:88 | agent MCP 工具 | we-have（core/auditlog.py adapt_kubetrail + mcp_server.py get_findings） | - |  |
| `kubetrail_summary` | apps/agent/src/tools/kubetrail.ts:100 | agent MCP 工具 | we-have（core/auditlog.py adapt_kubetrail + mcp_server.py get_findings） | - |  |
| `kubetrail_list_facts` | apps/agent/src/tools/kubetrail.ts:107 | agent MCP 工具 | partial（mcp_server.py 只读工具 + core/evidence.py） | S | 跨 run 过程/事实检索 [CM-02] |
| `kubetrail_get_fact` | apps/agent/src/tools/kubetrail.ts:121 | agent MCP 工具 | partial（mcp_server.py 只读工具 + core/evidence.py） | S | 跨 run 过程/事实检索 [CM-02] |
| `kubetrail_list_sensitive_refs` | apps/agent/src/tools/kubetrail.ts:132 | agent MCP 工具 | missing | S | 敏感引用与受控物化 [CM-06] |
| `kubetrail_materialize_sensitive` | apps/agent/src/tools/kubetrail.ts:139 | agent MCP 工具 | missing | S | 敏感引用与受控物化 [CM-06] |
| `kubetrail_list_exp_templates` | apps/agent/src/tools/kubetrail.ts:150 | agent MCP 工具 | partial（core/poc.py + mcp_server.py get_chain_plan） | M | EXP 模板规划工具 [CM-35] |
| `kubetrail_generate_exp_plan` | apps/agent/src/tools/kubetrail.ts:157 | agent MCP 工具 | partial（core/poc.py + mcp_server.py get_chain_plan） | M | EXP 模板规划工具 [CM-35] |

## K10. agent 攻击面技能（.claude/skills + AGENTS.md 边界）（17 项）

| 功能 | 来源锚点 | 工具行为 | InkBlade 状态 | 行动项 | 备注 |
|---|---|---|---|---|---|
| `admission-policy-governance` | apps/agent/.claude/skills/admission-policy-governance/SKILL.md:1 | agent 攻击面技能（边界见 apps/agent/AGENTS.md） | partial（modules/defense-bypass-admission） | M | 准入治理面（dry-run 探测→CM-24） [CM-24] |
| `cloud-metadata-analysis` | apps/agent/.claude/skills/cloud-metadata-analysis/SKILL.md:1 | agent 攻击面技能（边界见 apps/agent/AGENTS.md） | we-have（modules/metadata-egress + multi-cloud-imds-credentials + ssrf-imds-credential + cloud-sg-imds-exposure） | - |  |
| `exp-generation` | apps/agent/.claude/skills/exp-generation/SKILL.md:1 | agent 攻击面技能（边界见 apps/agent/AGENTS.md） | partial（core/poc.py + core/payloads.py） | M | EXP 规划技能（模板库→CM-35） [CM-35] |
| `exposed-management-interfaces` | apps/agent/.claude/skills/exposed-management-interfaces/SKILL.md:1 | agent 攻击面技能（边界见 apps/agent/AGENTS.md） | we-have（modules/ray-dashboard-job + model-registry-exposure + observability-exposure + open-webui* + dify* + sglang* + vllm* + djev-open-proxy） | - | ML 平台管理面覆盖更广 |
| `image-registry-supply-chain` | apps/agent/.claude/skills/image-registry-supply-chain/SKILL.md:1 | agent 攻击面技能（边界见 apps/agent/AGENTS.md） | we-have（modules/supply-chain-* + shared-volume-weight-copy） | - |  |
| `k8s-rbac-analysis` | apps/agent/.claude/skills/k8s-rbac-analysis/SKILL.md:1 | agent 攻击面技能（边界见 apps/agent/AGENTS.md） | we-have（modules/rbac-mapping + overprivileged-sa-escalation + vllm-operator-rbac-escalation） | - |  |
| `kubelet-runtime-etcd-bypass` | apps/agent/.claude/skills/kubelet-runtime-etcd-bypass/SKILL.md:1 | agent 攻击面技能（边界见 apps/agent/AGENTS.md） | partial（modules/escape-primitives（runtime socket）） | M | kubelet 10250/etcd 面缺 [CM-08] |
| `network-lateral-movement` | apps/agent/.claude/skills/network-lateral-movement/SKILL.md:1 | agent 攻击面技能（边界见 apps/agent/AGENTS.md） | we-have（modules/cni-aware-reachability-graph + vpc-cni-dual-control-plane-lateral + lws-secrets-lateral + hybrid-cloud-egress-pivot） | - |  |
| `observability-defense-evasion` | apps/agent/.claude/skills/observability-defense-evasion/SKILL.md:1 | agent 攻击面技能（边界见 apps/agent/AGENTS.md） | we-have（modules/defense-bypass-*（11 族）） | - |  |
| `operator-crd-controller-abuse` | apps/agent/.claude/skills/operator-crd-controller-abuse/SKILL.md:1 | agent 攻击面技能（边界见 apps/agent/AGENTS.md） | we-have（modules/kuberay-operator-escalation + vllm-operator-rbac-escalation + gpu-network-operator-posture） | - |  |
| `pod-escape-surface` | apps/agent/.claude/skills/pod-escape-surface/SKILL.md:1 | agent 攻击面技能（边界见 apps/agent/AGENTS.md） | we-have（modules/escape-primitives + runtime-socket-escape + privileged-gpu-pod-escape） | - |  |
| `public-workload-rce-surface` | apps/agent/.claude/skills/public-workload-rce-surface/SKILL.md:1 | agent 攻击面技能（边界见 apps/agent/AGENTS.md） | we-have（modules/areal-* + trl-serve-dev-mode + djev-open-proxy） | - |  |
| `resource-hijack-dos` | apps/agent/.claude/skills/resource-hijack-dos/SKILL.md:1 | agent 攻击面技能（边界见 apps/agent/AGENTS.md） | we-have（modules/kv-oom-bomb + gang-scheduler-abuse + nccl-port-exhaustion + gpu-pool-scheduler-unauth） | - |  |
| `service-ingress-exposure` | apps/agent/.claude/skills/service-ingress-exposure/SKILL.md:1 | agent 攻击面技能（边界见 apps/agent/AGENTS.md） | we-have（modules/exposure-mapping + network-policy-coverage + dns-service-discovery） | - |  |
| `serviceaccount-secret-material` | apps/agent/.claude/skills/serviceaccount-secret-material/SKILL.md:1 | agent 攻击面技能（边界见 apps/agent/AGENTS.md） | partial（modules/lws-secrets-lateral + supply-chain-credential-theft） | S | SA/Secret 材料面细分 |
| `windows-container-surface` | apps/agent/.claude/skills/windows-container-surface/SKILL.md:1 | agent 攻击面技能（边界见 apps/agent/AGENTS.md） | missing | M | Windows 容器/节点面（无任何模块覆盖） [CM-34] |
| `workload-controller-persistence` | apps/agent/.claude/skills/workload-controller-persistence/SKILL.md:1 | agent 攻击面技能（边界见 apps/agent/AGENTS.md） | partial（core/auditlog.py 检测器（ray job pod/CRB）） | S | 持久化植入面=检测侧覆盖 |

## K11. EXP 模板（exp/catalog.ts，safe/full 分级）（26 项）

| 功能 | 来源锚点 | 工具行为 | InkBlade 状态 | 行动项 | 备注 |
|---|---|---|---|---|---|
| `cloud-metadata-verify` | apps/agent/src/exp/catalog.ts:23 | EXP 模板 mode=safe | we-have（modules/metadata-egress + multi-cloud-imds-credentials） | - |  |
| `cloud-identity-verify` | apps/agent/src/exp/catalog.ts:38 | EXP 模板 mode=safe | we-have（modules/metadata-egress + multi-cloud-imds-credentials） | - |  |
| `serviceaccount-token-api-verify` | apps/agent/src/exp/catalog.ts:49 | EXP 模板 mode=safe | missing | S | TokenRequest 铸币验证 [CM-05] |
| `secret-list-get-verify` | apps/agent/src/exp/catalog.ts:60 | EXP 模板 mode=safe | partial（modules/rbac-mapping） | S | Secret 读权限验证模板 |
| `runtime-socket-verify` | apps/agent/src/exp/catalog.ts:71 | EXP 模板 mode=safe | we-have（modules/runtime-socket-escape） | - |  |
| `nodes-proxy-verify` | apps/agent/src/exp/catalog.ts:82 | EXP 模板 mode=safe | partial（modules/escape-primitives + rbac-mapping） | S | nodes/proxy 验证模板 |
| `kubelet-api-verify` | apps/agent/src/exp/catalog.ts:93 | EXP 模板 mode=safe | missing | S | kubelet API 直连验证 [CM-08] |
| `etcd-access-verify` | apps/agent/src/exp/catalog.ts:104 | EXP 模板 mode=safe | partial（modules/escape-primitives） | M | etcd 端点可达验证 |
| `pod-create-job` | apps/agent/src/exp/catalog.ts:115 | EXP 模板 mode=full | missing | - | full 模式执行验证模板（植入/执行面刻意不做；对应面分析模块已覆盖） |
| `pod-hostpath` | apps/agent/src/exp/catalog.ts:127 | EXP 模板 mode=full | missing | - | full 模式执行验证模板（植入/执行面刻意不做；对应面分析模块已覆盖） |
| `pod-privileged` | apps/agent/src/exp/catalog.ts:139 | EXP 模板 mode=full | missing | - | full 模式执行验证模板（植入/执行面刻意不做；对应面分析模块已覆盖） |
| `pod-hostpid` | apps/agent/src/exp/catalog.ts:151 | EXP 模板 mode=full | missing | - | full 模式执行验证模板（植入/执行面刻意不做；对应面分析模块已覆盖） |
| `pod-hostnetwork` | apps/agent/src/exp/catalog.ts:163 | EXP 模板 mode=full | missing | - | full 模式执行验证模板（植入/执行面刻意不做；对应面分析模块已覆盖） |
| `ephemeralcontainers-patch` | apps/agent/src/exp/catalog.ts:175 | EXP 模板 mode=full | missing | - | full 模式执行验证模板（植入/执行面刻意不做；对应面分析模块已覆盖） |
| `pods-exec-verify` | apps/agent/src/exp/catalog.ts:186 | EXP 模板 mode=safe | missing | - | full 模式执行验证模板（植入/执行面刻意不做；对应面分析模块已覆盖） |
| `impersonate-verify` | apps/agent/src/exp/catalog.ts:197 | EXP 模板 mode=safe | missing | - | full 模式执行验证模板（植入/执行面刻意不做；对应面分析模块已覆盖） |
| `rbac-bind-escalate-verify` | apps/agent/src/exp/catalog.ts:208 | EXP 模板 mode=safe | missing | - | full 模式执行验证模板（植入/执行面刻意不做；对应面分析模块已覆盖） |
| `serviceaccount-rbac-persistence` | apps/agent/src/exp/catalog.ts:219 | EXP 模板 mode=full | missing | - | 持久化 EXP（执行面刻意不做；检测=auditlog） |
| `csr-client-cert-persistence` | apps/agent/src/exp/catalog.ts:245 | EXP 模板 mode=dangerous | missing | - | 持久化 EXP（执行面刻意不做；检测=auditlog） |
| `workload-patch-sidecar-persistence` | apps/agent/src/exp/catalog.ts:273 | EXP 模板 mode=dangerous | missing | - | 持久化 EXP（执行面刻意不做；检测=auditlog） |
| `pull-secret-injection` | apps/agent/src/exp/catalog.ts:296 | EXP 模板 mode=full | missing | - | 持久化 EXP（执行面刻意不做；检测=auditlog） |
| `admission-persistence-review` | apps/agent/src/exp/catalog.ts:319 | EXP 模板 mode=safe | missing | - | 持久化 EXP（执行面刻意不做；检测=auditlog） |
| `static-pod-node-persistence-review` | apps/agent/src/exp/catalog.ts:330 | EXP 模板 mode=safe | missing | - | 持久化 EXP（执行面刻意不做；检测=auditlog） |
| `registry-auth-verify` | apps/agent/src/exp/catalog.ts:341 | EXP 模板 mode=safe | partial（modules/supply-chain-credential-theft） | S | registry 凭据验证 |
| `cve-2021-4034-pwnkit` | apps/agent/src/exp/catalog.ts:352 | EXP 模板 mode=dangerous | missing | - | 预置 CVE PoC 二进制（版本/PoC 库不内置，CM-13 适配器承接） [CM-13] |
| `external-cve-poc` | apps/agent/src/exp/catalog.ts:381 | EXP 模板 mode=dangerous | missing | - | 预置 CVE PoC 二进制（版本/PoC 库不内置，CM-13 适配器承接） [CM-13] |

## K12. 桌面视图（Vue views）（6 项）

| 功能 | 来源锚点 | 工具行为 | InkBlade 状态 | 行动项 | 备注 |
|---|---|---|---|---|---|
| `About` | apps/desktop/frontend/src/views/About.vue:1 | 桌面端 Vue 视图 | N/A | - | 桌面壳页面 |
| `Analysis` | apps/desktop/frontend/src/views/Analysis.vue:1 | 桌面端 Vue 视图 | partial（webui SPA 六视图） | M | finding 分析/证据下钻缺 |
| `Cheatsheet` | apps/desktop/frontend/src/views/Cheatsheet.vue:1 | 桌面端 Vue 视图 | we-have（docs/RUNBOOK.md + docs/kb） | - | 速查手册已有 |
| `Cluster` | apps/desktop/frontend/src/views/Cluster.vue:1 | 桌面端 Vue 视图 | partial（webui SPA 资产/总览视图） | S | 集群浏览视图部分对齐 |
| `Settings` | apps/desktop/frontend/src/views/Settings.vue:1 | 桌面端 Vue 视图 | partial（lab/ 配置 + CLI） | S | 设置页缺 |
| `Welcome` | apps/desktop/frontend/src/views/Welcome.vue:1 | 桌面端 Vue 视图 | N/A | - | 桌面壳页面 |

## K13. 桌面组件（Vue components）（17 项）

| 功能 | 来源锚点 | 工具行为 | InkBlade 状态 | 行动项 | 备注 |
|---|---|---|---|---|---|
| `AgentPanel` | apps/desktop/frontend/src/components/AgentPanel.vue:1 | 桌面端 Vue 组件 | missing | - | 对话式 agent 面板（刻意不做；mcp_server/agent_planner 已有） |
| `ClusterSidebar` | apps/desktop/frontend/src/components/ClusterSidebar.vue:1 | 桌面端 Vue 组件 | partial（webui SPA） | S | 扫描/连接 UI 部分对齐 |
| `ConnectionForm` | apps/desktop/frontend/src/components/ConnectionForm.vue:1 | 桌面端 Vue 组件 | partial（webui SPA） | S | 扫描/连接 UI 部分对齐 |
| `ExpForgePanel` | apps/desktop/frontend/src/components/ExpForgePanel.vue:1 | 桌面端 Vue 组件 | missing | - | 交互执行/植入面板（执行面刻意不做，REFLECTION 桌面后渗透台） |
| `NodeDrawer` | apps/desktop/frontend/src/components/NodeDrawer.vue:1 | 桌面端 Vue 组件 | partial（webui 资产视图 + discovery） | S | pod/node 浏览组件缺 |
| `NodeFiles` | apps/desktop/frontend/src/components/NodeFiles.vue:1 | 桌面端 Vue 组件 | missing | - | 交互执行/植入面板（执行面刻意不做，REFLECTION 桌面后渗透台） |
| `NodeList` | apps/desktop/frontend/src/components/NodeList.vue:1 | 桌面端 Vue 组件 | partial（webui 资产视图 + discovery） | S | pod/node 浏览组件缺 |
| `NodeTerminal` | apps/desktop/frontend/src/components/NodeTerminal.vue:1 | 桌面端 Vue 组件 | missing | - | 交互执行/植入面板（执行面刻意不做，REFLECTION 桌面后渗透台） |
| `PersistencePanel` | apps/desktop/frontend/src/components/PersistencePanel.vue:1 | 桌面端 Vue 组件 | missing | - | 交互执行/植入面板（执行面刻意不做，REFLECTION 桌面后渗透台） |
| `PodDrawer` | apps/desktop/frontend/src/components/PodDrawer.vue:1 | 桌面端 Vue 组件 | partial（webui 资产视图 + discovery） | S | pod/node 浏览组件缺 |
| `PodFiles` | apps/desktop/frontend/src/components/PodFiles.vue:1 | 桌面端 Vue 组件 | missing | - | 交互执行/植入面板（执行面刻意不做，REFLECTION 桌面后渗透台） |
| `PodList` | apps/desktop/frontend/src/components/PodList.vue:1 | 桌面端 Vue 组件 | partial（webui 资产视图 + discovery） | S | pod/node 浏览组件缺 |
| `PodLogs` | apps/desktop/frontend/src/components/PodLogs.vue:1 | 桌面端 Vue 组件 | partial（webui 资产视图 + discovery） | S | pod/node 浏览组件缺 |
| `PodTerminal` | apps/desktop/frontend/src/components/PodTerminal.vue:1 | 桌面端 Vue 组件 | missing | - | 交互执行/植入面板（执行面刻意不做，REFLECTION 桌面后渗透台） |
| `PortForwardPanel` | apps/desktop/frontend/src/components/PortForwardPanel.vue:1 | 桌面端 Vue 组件 | missing | - | 交互执行/植入面板（执行面刻意不做，REFLECTION 桌面后渗透台） |
| `Redteam` | apps/desktop/frontend/src/components/Redteam.vue:1 | 桌面端 Vue 组件 | missing | - | 交互执行/植入面板（执行面刻意不做，REFLECTION 桌面后渗透台） |
| `ScanPanel` | apps/desktop/frontend/src/components/ScanPanel.vue:1 | 桌面端 Vue 组件 | partial（webui SPA） | S | 扫描/连接 UI 部分对齐 |
