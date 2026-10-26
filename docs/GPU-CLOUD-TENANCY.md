# GPU 组卡/池化平台与云平台跨租户测试族

> 适用范围：Kubernetes 上的 GPU 池化调度（HAMi / OrionX / cGPU 风格）、MIG/MPS 共享、
> 以及云身份联邦 / 对象存储 / 快照 / KMS / 安全组跨租户边界。
> 本文件描述隔离模型、风险矩阵、模块↔链映射与实验室验证口径；配套仿真靶场
> `lab/gpu_cloud_sim.py`（仅 127.0.0.1）与 10 个测试模块。

## 1. 威胁模型与边界

测试族关注两类「共享基础设施上的租户边界失效」：

1. **GPU 组卡/池化面**：调度器把物理卡切片（时间片/显存/分数卡/MIG slice）分配给多个
   租户或 namespace。失效点不在 CUDA 本身，而在**分配、释放、重配、可观测性**四个控制面：
   - 谁能调用池调度 admin API；
   - 释放后显存/上下文是否清零；
   - MIG profile 的请求值是否等于设备实际值；
   - DCGM/MPS 等可观测面是否按租户过滤。
2. **云平台租户面**：K8s ServiceAccount 通过 IRSA/RRSA/Workload Identity 换取云角色，
   再访问对象存储、快照、KMS 与网络控制面。失效点是**信任策略、资源策略、共享边界**：
   - trust policy 是否通配 Principal / 缺少 ExternalId 或 OIDC subject 约束；
   - 桶策略/ACL 是否 public 或允许跨账户列目录；
   - 快照是否可共享给任意账户；
   - KMS grant 是否 Principal `*` 或缺少 encryption context；
   - 安全组/IMDS 选项是否允许 Pod 直达 169.254.169.254 取节点角色。

**判定口径**：本测试族不把「有隔离配置」等同于「隔离有效」。每个结论必须有真实 HTTP
差分、服务端状态变更、benign marker 写读回或 sha256 证据；无法在 HTTP 靶场表达的面
（真实 nvidia-smi、真实 STS/S3、真实 RDMA）显式标注为仿真边界，不冒充 live 结论。

## 2. GPU 组卡 / MIG / MPS / vGPU 隔离模型

| 机制 | 隔离粒度 | 典型实现 | 主要残留风险 | 本测试族观测面 |
|---|---|---|---|---|
| 物理卡直通 | 整卡 / Pod | device plugin `nvidia.com/gpu` | 同卡跨 namespace 复用、释放不清零 | `/gpu/pools`、`/gpu/residue` |
| 分数卡（算力/显存） | 百分比 / MiB | HAMi `nvidia.com/gpumem`、`gpucores` | 调度声明与实际配额不一致；释放后配额未回收 | `/gpu/pools`、`/gpu/metrics` |
| vGPU / 时间片 | 时间片 / vGPU 实例 | OrionX vGPU、cGPU | 时间片侧信道、上下文残留、跨租户进程可见 | `/gpu/mps/status`、`/gpu/metrics` |
| MIG 硬件分区 | GPU instance / compute slice | `1g.10gb`…`7g.80gb` | 请求档位 ≠ 生效档位；在线重配改写邻居边界 | `/gpu/mig/profiles` |
| MPS 软件上下文 | MPS server / pipe / context | `nvidia-cuda-mps-control` | 单 server 共享 pipe，client/context 跨租户可见 | `/gpu/mps/status` |
| DRA / ResourceClaim | ResourceClaim / device | DRA kubelet plugin | claim 与 namespace 生命周期不一致 | `/gpu/pools`（pod/namespace 视图） |
| 显存快照 / checkpoint | 进程 / 分配 | 池化平台快照、休眠恢复 | 释放后快照保留，跨租户可读 | `/gpu/residue`、benign marker sha256 |

**关键结论**：

- **MIG 不是默认安全边界**：MIG 只切分硬件资源，不提供跨租户的身份/审计；调度器仍须
  保证 profile 请求值与设备实际值一致，并禁止对已分配设备在线重配。
- **MPS 的默认假设是单用户**：多租户场景必须一租户一 MPS server/pipe，或至少按租户
  隔离 context 与可观测面；共享 pipe 时 `/gpu/mps/status` 会直接暴露他租户 client。
- **释放不等于清零**：显存快照、MPS context、MIG instance 的清理是独立步骤；缺少清理
  时，后续租户可读到前租户的 benign marker/模型标记。
- **可观测面是数据面**：DCGM exporter 的进程名、namespace、模型标签足以做租户画像与
  进程发现，必须与业务面同等鉴权。

## 3. GPU 跨租户风险矩阵

| 风险 | vulnerable 语义 | fixed 语义 | 模块 | 证据 |
|---|---|---|---|---|
| 池调度 admin 无鉴权 | `/gpu/pools` 全租户可见；`/gpu/allocate` 可占用他租户设备并迁移 | 租户 token 过滤；admin + 同租户；已分配 409 | `gpu-pool-scheduler-unauth` | 真实 200 + `previous_tenant` + `state_sha256` |
| 跨租户残留 | 释放后 `/gpu/residue` 仍返回他租户 marker | 释放即删除，读回 404 | `gpu-tenant-residue` | marker 写读回 + 文件 sha256 |
| MIG 档位不匹配 | active ≠ requested；可无鉴权重配已分配设备 | 租户过滤；admin + 同租户；已分配 409 | `mig-profile-mismatch` | profile 差分 + `isolation_downgraded` |
| MPS context 共享 | 多租户共用 pipe，client/pid 可见 | 一租户一 pipe/context | `mps-context-shared` | `/gpu/mps/status` 差分 |
| 指标租户泄露 | DCGM 返回他租户进程名/namespace/模型标记 | 按 X-Tenant 过滤 | `gpu-metrics-tenant-leak` | 进程清单 + 租户标签 |
| 设备跨 namespace | 同一设备 pods 出现多个 namespace/租户 | 设备独占 + 单 namespace | `gpu-device-cross-namespace` | pods/namespace 视图 |

**链**：`gpu-tenant-residue-chain`
（池化调度 → 残留显存/显存快照 → 他租户模型数据）。
链内步骤：`gpu-pool-scheduler-unauth` → `gpu-metrics-tenant-leak` / `gpu-tenant-residue`。

## 4. 云身份联邦与跨账户 AssumeRole

| 机制 | 注解/信任锚 | 常见失效 | 观测面 |
|---|---|---|---|
| EKS IRSA | `eks.amazonaws.com/role-arn` + OIDC provider | trust policy `Principal: "*"`、无 `sts:ExternalId`、sub 未限制 | `/cloud/identity`、`/cloud/identity/assume-role` |
| 阿里 RRSA | `rrssa.alibabacloud.com/role-arn` | RAM 角色信任策略放开到任意账号 | 同上 |
| GKE Workload Identity | `iam.gke.io/gcp-service-account` | GSA 绑定过宽 / `roles/iam.workloadIdentityUser` 通配 | 同上 |
| Azure Workload Identity | `azure.workload.identity/client-id` | federated credential subject 通配 | 同上 |

**跨账户 AssumeRole 链**：`cloud-cross-tenant-role-assume`
（IRSA 通配 → 跨账户角色 → 权重桶）。
链内步骤：`cloud-irsa-trust-wildcard` → `cloud-bucket-cross-tenant`。

**修复基线**：

- trust policy Principal 收敛到具体账号/角色 ARN，禁止 `*`；
- 强制 `sts:ExternalId` 或 OIDC `sub`/`aud` 条件；
- 角色权限最小化（仅目标桶前缀、只读、可选 KMS encryption context）；
- 对 AssumeRole 的 `sourceAccount`/`roleArn` 建立组织级白名单并告警跨账户增量。

## 5. 桶 / 快照 / KMS / 安全组跨租户矩阵

| 面 | vulnerable | fixed | 模块 | 证据 |
|---|---|---|---|---|
| 桶策略 | Principal `*` / public / 可跨租户列目录 | Principal 收敛 owner 账户；Block Public Access | `cloud-bucket-cross-tenant` | policy + 对象清单 |
| 快照共享 | public / 共享给任意账户 | 仅 owner + 同账户 allowlist | `cloud-snapshot-share` | `shared_with` + 跨账户 200 |
| KMS grants | Principal `*` + Decrypt/GenerateDataKey | 同账户 + 仅 Decrypt + encryption context | 由云模块族覆盖（`/cloud/kms/grants`） | grants 清单 |
| 安全组/IMDS | 0.0.0.0/0 入站 + IMDSv1 + hop limit 2 | 内网入站 + IMDSv2 + hop limit 1 | `cloud-sg-imds-exposure` | SG + metadata_options |
| 跨云等价 | S3 / OSS / COS / Blob | 各自 Block Public / 私有 ACL / SAS 最小权限 | `cloud-bucket-cross-tenant` | provider_variants |

**修复基线**：

- 桶：关闭 public access，桶策略 Principal 到账户/角色，禁止 `s3:ListBucket` 跨账户；
- 快照：共享前校验目标账户 allowlist，敏感快照默认加密并限制 KMS grant；
- KMS：grant 绑定 grantee 账户 + encryption context，禁止 `Principal: "*"`；
- 安全组：管理端口仅管理网段；IMDS 强制 v2（`http_tokens=required`）且 hop limit=1；
  GPU 节点安全组与 Pod 级安全组（EKS SG for Pods / Terway / TKE VPC-CNI）双侧核对。

## 6. 模块 ↔ 链 ↔ 规则映射

| 模块 | 系列 | 级别 | writes | 关联链 | 检测规则 |
|---|---|---|---|---|---|
| `gpu-pool-scheduler-unauth` | 网络架构 | 利用验证 | 是 | `gpu-tenant-residue-chain` | Sigma 池调度无鉴权；Falco GPU 跨 ns；Suricata `/gpu/allocate` |
| `gpu-tenant-residue` | 网络架构 | 利用验证 | 是 | `gpu-tenant-residue-chain` | Sigma 池调度无鉴权；Falco GPU 跨 ns；Suricata `/gpu/release` |
| `mig-profile-mismatch` | 网络架构 | 主动探测 | 是 | `gpu-tenant-residue-chain`（requires） | Sigma 池调度；Falco MIG 非常规重配 |
| `mps-context-shared` | 网络架构 | 主动探测 | 否 | — | Falco GPU 跨 ns（同卡 context 面） |
| `gpu-metrics-tenant-leak` | 网络架构 | 主动探测 | 否 | `gpu-tenant-residue-chain`（步骤） | Sigma 池调度；Suricata 管理 URI |
| `gpu-device-cross-namespace` | 网络架构 | 主动探测 | 否 | — | Falco GPU 设备跨 ns 挂载 |
| `cloud-irsa-trust-wildcard` | 混合云 | 利用验证 | 否 | `cloud-cross-tenant-role-assume` | Sigma 跨账户 AssumeRole；Suricata `/cloud/identity` |
| `cloud-bucket-cross-tenant` | 混合云 | 利用验证 | 否 | `cloud-cross-tenant-role-assume` | Sigma 跨账户 AssumeRole；Suricata `/cloud/bucket/list` |
| `cloud-snapshot-share` | 混合云 | 利用验证 | 是 | —（云侧权重桶族横向能力） | Suricata `/cloud/identity` 同族管理面 |
| `cloud-sg-imds-exposure` | 混合云 | 主动探测 | 否 | —（IMDS 凭据面） | Suricata `/cloud/identity`；Falco/Sigma IMDS 既有规则 |

规则 ID：

- Sigma：`sigma-gpu-pool-admin-unauth`、`sigma-cloud-cross-account-assume`
- Falco：`falco-gpu-device-cross-namespace`、`falco-mig-abnormal-reconfig`
- Suricata：`suricata-gpu-cloud-tenant-uri`

## 7. 实验室仿真与证据口径

`lab/gpu_cloud_sim.py` 单进程多路由（仅 127.0.0.1，标准库），两种姿态：

- **vulnerable**：无鉴权、跨租户分配/迁移、MIG/MPS 释放后残留、指标全量、trust policy
  通配、桶 public、快照任意共享、KMS 宽 grants、SG 放开 IMDS；
- **fixed**：租户 token + admin token 双身份、租户过滤、释放清理、最小策略、IMDSv2。

证据要求：

1. **真实 HTTP 差分**：同一请求在 vulnerable 200、fixed 401/403/404/409；
2. **可度量证据**：marker sha256、文件 sha256、`state_sha256`、对象清单、profile 差分；
3. **benign marker**：残留写入一律 `INKBLADE-BENIGN-` 前缀，不含真实模型数据；
4. **写类备份闸门**：`writes=true` 模块必须提供 `backup_targets`，否则 runner 以
   `BackupGateRefused`（退出码 91）拒绝执行；
5. **凭据脱敏**：AssumeRole 凭据仅以 `MOCK****` + 尾 4 位进入 findings，全文只留在
   trace 证据层。

复现命令：

```bash
python -m unittest tests.test_gpu_cloud_sim tests.test_modules_gpu_cloud tests.test_chains_gpu_cloud -v
python -m inkblade.verify-effects --out reports/samples/effects/
python -m unittest tests.test_verify_effects -v
```

## 8. 修复检查清单

- [ ] 池调度 admin API 强制 mTLS/身份 + 租户作用域；禁止跨租户 allocate/migrate。
- [ ] 分配记录带 tenant/namespace/allocation_id；释放路径清理 MIG instance、MPS context、
      显存快照与临时卷。
- [ ] MIG profile 以设备实际值为准做准入校验；已分配设备禁止在线重配。
- [ ] MPS 一租户一 server/pipe；DCGM/MPS 指标按租户过滤并鉴权。
- [ ] device plugin/DRA 保证设备独占；禁止同一设备被多 namespace Pod 同时打开。
- [ ] IRSA/RRSA/Workload Identity trust policy 收敛 Principal + ExternalId/OIDC subject。
- [ ] 桶关闭 public access；快照共享 allowlist；KMS grant 绑定账户与 encryption context。
- [ ] 安全组管理端口限源；IMDSv2 强制 + hop limit=1；GPU 节点 SG 与 Pod SG 双侧核对。
- [ ] Sigma/Falco/Suricata 规则以 monitor 模式试点，按工单/维护窗口建立白名单后转 Enforce。

## 9. 边界声明

本测试族的「PASS」是**本机真实 HTTP 效果级**（`lab/gpu_cloud_sim.py`，仅 127.0.0.1），
不是 live GPU 驱动、真实 nvidia-smi、真实云 STS/S3/KMS 调用。MIG/MPS/vGPU 的硬件行为、
真实 IMDS 与云 API 的最终语义需在授权实验室的 live 集群复核；`fixed` 姿态表达的是修复
后的控制面语义，不替代产品版本级 CVE 复现。
