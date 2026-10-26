# Slurm HPC 攻击面深度（2026-10-26）

> 目标：把 `slurm-hpc` 从“只有 BMC/IB/训练配置”的浅画像，补到覆盖 Slurm 控制面、
> 认证、插件、cgroup、调度配额、共享存储、REST/JWT 与生命周期执行。
> 本文同时给**两个口径**，避免把不同分母混成一个百分比：
>
> 1. **Slurm 专属域覆盖**（本文件第 1 节，17 个域）：基线 **3/17 = 17.6%**，
>    本轮后 **15/17 = 88.2%**（目标 ≥40% 达成）。
> 2. **模块级画像覆盖**（`inkblade surfaces --profile slurm-hpc` 的
>    `coverage_pct`）：基线 **17.67%**，本轮后约 **25.8%**。该分母是全部 264 个
>    默认模块，其中大量模块的必需面是 `k8s-object:Pod/Node`，在“无 Kubernetes API”
>    的 Slurm 画像中**必须**保持 no-surface；把它抬到 40% 只能靠伪造 K8s 面。
>    因此本文不把模块级 25.8% 写成 40%，也不为了数字把 K8s 对象塞进 Slurm 画像。

## 1. Slurm 17 域覆盖（基线 → 本轮）

| # | 域 | 基线 | 本轮后 | 模块 / 说明 |
|---|---|---|---|---|
| 1 | slurmctld 控制面配置 | 缺口 | 覆盖 | `slurmctld-config-audit`：AuthType/CryptoType/SlurmUser/PrivateData/DisableRootJobs/TaskPlugin/StateSaveLocation |
| 2 | slurmd 节点守护进程配置 | 缺口 | 覆盖 | `slurmd-config-audit`：SlurmdUser/spool/config_overrides/HealthCheck/Prolog/Epilog/JobAcctGather |
| 3 | Munge 认证 | 缺口 | 覆盖 | `munge-auth-audit`：密钥权限/属主/年龄/跨集群复用/镜像内嵌/socket/MUNGE_OPTIONS |
| 4 | SPANK 插件加载 | 缺口 | 覆盖 | `spank-plugin-integrity`：相对路径/用户目录/可写 .so/未签名/optional/LD_PRELOAD |
| 5 | cgroup 约束 | 缺口 | 覆盖 | `slurm-cgroup-constraint-audit`：Cores/RAM/Swap/Devices/AllowedRAMSpace/TaskAffinity/MemoryLimitEnforcement |
| 6 | 节点 drain / 分区 / QOS 配额 | 缺口 | 覆盖 | `slurm-node-partition-policy`：DRAIN/DOWN 返池、ALL/ALL、MaxNodes/MaxTime、OverSubscribe、GrpTRES/MaxTRESPerUser |
| 7 | 共享存储客户端（Lustre/GPFS/NFS） | 缺口 | 覆盖 | `slurm-shared-storage-audit`：nosuid/nodev/noexec、root_squash、exports、quota、LNet 加密、UID 映射、world-writable |
| 8 | slurmrestd REST API 暴露 | 部分（只有端点声明） | 覆盖 | `slurmrestd-exposure`：0.0.0.0、无认证、无 TLS、root 运行、debug、连接数、JWT、可选 GET /jobs |
| 9 | JWT 认证与密钥生命周期 | 缺口 | 覆盖 | `slurm-jwt-auth-audit`：AuthAltTypes、HS256 短密钥、key 权限/年龄、轮换、token TTL、audience、泄漏路径 |
| 10 | SlurmDBD / 记账库 | 缺口 | 覆盖 | `slurm-accountingdbd-audit`：明文 StoragePass、DbdHost、root、PrivateData、备份、DB TLS、debug、配置权限 |
| 11 | Prolog/Epilog 生命周期执行 | 缺口 | 覆盖 | `slurm-prolog-epilog-audit`：脚本属主/权限/签名、PrologFlags=Contain、控制器侧钩子 |
| 12 | GRES/GPU 设备隔离 | 缺口 | 覆盖 | `slurm-gres-gpu-isolation`：ConstrainDevices、binding、MIG、device cgroup allowlist、cgroup 联动 |
| 13 | IB / fabric 隔离 | 覆盖 | 覆盖 | 既有 `ib-sm-partition-audit` / `fabric-topology-isolation` / `roce-pfc-storm` |
| 14 | BMC / 固件 / TPM | 覆盖 | 覆盖 | 既有 `bmc-ipmi-exposure` / `firmware-signature-inventory` / `secure-boot-chain` |
| 15 | 训练 / checkpoint / 权重 | 覆盖 | 覆盖 | 既有 `megatron-*` / `checkpoint-*` / `sglang-weight-exfil` 等 |
| 16 | 作业提交包装器（sbatch/srun） | 缺口 | **仍缺口** | 需要客户提交脚本/包装器与 `srun` 参数导出；本轮不虚构 |
| 17 | 容器运行时（Pyxis/Enroot/Apptainer） | 缺口 | **仍缺口** | 需要节点运行时配置与镜像签名导出；列入后续 |

**计算**：基线 3/17 = 17.65%；本轮后 15/17 = 88.24%。第 16/17 域保持缺口并在
客户试点清单中显式登记，不用“有 slurm.conf”冒充覆盖。

## 2. 新增 12 个模块

| 模块键 | 系列 | 级别 | writes | 默认 | 数据源 |
|---|---|---|---|---|---|
| `slurmctld-config-audit` | 侦察 | 只读侦察 | false | on | `slurm/slurm.conf` |
| `slurmd-config-audit` | 侦察 | 只读侦察 | false | on | `slurm/slurm.conf` |
| `munge-auth-audit` | 权限链 | 只读侦察 | false | on | `slurm/munge.conf` + `munge.key.meta` |
| `spank-plugin-integrity` | 权限链 | 只读侦察 | false | on | `slurm/plugstack.conf` |
| `slurm-cgroup-constraint-audit` | 权限链 | 只读侦察 | false | on | `slurm/cgroup.conf` |
| `slurm-node-partition-policy` | 侦察 | 只读侦察 | false | on | `slurm/nodes.json` / `partitions.json` / `qos.json` |
| `slurm-shared-storage-audit` | 窃取与数据泄露 | 只读侦察 | false | on | `storage/lustre/mounts.json` / `gpfs/mounts.json` |
| `slurmrestd-exposure` | 网络架构 | 主动探测 | false | on | `slurm/slurmrestd.env` + `/slurm/v0.0.40/jobs` |
| `slurm-jwt-auth-audit` | 权限链 | 只读侦察 | false | on | `slurm/jwt.json` + `slurm.conf` |
| `slurm-accountingdbd-audit` | 侦察 | 只读侦察 | false | on | `slurm/slurmdbd.conf` |
| `slurm-gres-gpu-isolation` | 权限链 | 只读侦察 | false | on | `slurm/gres.json` + `cgroup.conf` |
| `slurm-prolog-epilog-audit` | 权限链 | 只读侦察 | false | on | `slurm/prolog-epilog.json` + `slurm.conf` |

全部 `requires=[]`、`writes=false`；只解析导出，不连接 slurmctld/slurmd，不执行
`scontrol`/`sbatch`/`srun`，不读取真实 `munge.key`/JWT 私钥内容（只看元数据/指纹）。

## 3. 画像扩展（只加真实存在的 Slurm/AI-HPC 面）

`inkblade/profiles/slurm-hpc.json` 新增的声明都与该画像的组件一致：

- Slurm 控制/认证/插件/cgroup/记账/GRES/生命周期配置与 `runtime-agent/*`；
- slurmrestd 的三个 v0.0.40 端点、`/openapi.json`；
- Lustre/GPFS 挂载导出、节点/分区/QOS 导出；
- 画像本来就声明了 vLLM 推理，因此补 `vllm/config.yaml`、`/v1/chat/completions`；
- AI-HPC 常见的 MLflow 实验跟踪：`mlflow/config.yaml` + `/api`；
- R05/R06 的统一清单：`ai-infra/inventory.json`、`inference/tenant-policy.json`；
- **没有**加入任何 `k8s-object` 面，保持“no Kubernetes API”的画像语义。

模块级覆盖因此从 44/249（17.67%）升到约 68/264（25.8%）：新增 12 个 Slurm 模块、
2 个统一基线模块（R05/R06）和 10 个因 vLLM/MLflow 真实面而可测的既有模块。剩余
不可测模块主要是 K8s 专属（Pod/Node/RBAC/CRD），在 Slurm 上应保持 no-surface。

## 4. Fixture 与两态结果

- `lab/fixtures/slurm/vulnerable/`：弱认证（auth/none）、root SlurmUser、cgroup 全关、
  Munge 0644/跨集群复用/镜像内嵌、SPANK 用户目录插件、drain 节点返池、ALL/ALL 分区、
  UNLIMITED QOS、Lustre/GPFS 无 nosuid/nodev、slurmrestd 0.0.0.0 无认证、HS256 短密钥、
  slurmdbd 明文口令、GRES 全设备放行、prolog 0777。
- `lab/fixtures/slurm/fixed/`：auth/munge + crypto/munge、slurm 用户、cgroup 全约束、
  Munge 0400、root 插件目录、分区/QOS 限额、nosuid/nodev、slurmrestd loopback+JWT+TLS、
  RS256/0600/轮换、StoragePassFile+DB TLS、ConstrainDevices、prolog 0755 签名。
- 12/12 模块在 vulnerable 至少 1 条 high/critical，在 fixed **0 条 high/critical**
  （`tests/test_modules_slurm.py`）。

## 5. 实效与测试

`inkblade/verify-effects.py` 新增：

- `slurm-jwt-weak-key`：短 HS256 + 0644 key + 无轮换/过期 → high；fixed 0 high；
- `slurm-cgroup-device-escape`：Cores/RAM/Devices 全关 → ≥4 high；fixed 0 high。

测试：

- `tests/test_modules_slurm.py`：12 模块契约、两态 fixture、关键字段、画像 verdict；
- `tests/test_slurm_docs.py`：本文覆盖率/模块键/边界声明；
- `tests/test_verify_effects.py` 全量执行时包含上述 2 项。

## 6. 边界（必须随报告一起出现）

- 全部为**配置/快照判定**，不是真实 Slurm 集群实测；没有运行 `scontrol`/`sbatch`，
  没有触发真实作业、drain 或 cgroup 变更。
- Munge/JWT 只读元数据，不读取密钥内容；真实密钥轮换/HA 需客户操作。
- 共享存储只看客户端挂载/导出声明，不验证 Lustre/GPFS 服务端 ACL 与真实 IO。
- 第 16/17 域（提交包装器、容器运行时）仍缺口；不得在投标材料中写“Slurm 全栈覆盖”。
- 模块级 25.8% 与域级 88.2% 是两个口径；对外必须同时给分母，不能只取较高数字。
