# 六云契约级验证矩阵（ID / 桶 / 快照 / 网络策略）

> 生成日期：2026-10-25　仿真器：`lab/cloud_six_sim.py`（真 HTTP，仅 127.0.0.1）
> 测试：`tests/test_six_cloud_sim.py`（15 项）　原始矩阵：`lab/bench/out/six-cloud-matrix.json`
> **边界（贯穿全文）**：本文件是**契约级仿真**，不是真实云环境。仿真器用各云公开 API 的字段形状
> （policy document / ACL / security rule / snapshot permission）表达同类跨租户风险，
> **不连接任何云账号、不调用任何云 API、不证明目标云的真实配置**。

## 1. 覆盖矩阵（6 云 × 7 能力）

| 云 | 服务/身份面 | 身份与信任策略 | 角色假设 | 桶策略 | 桶列目录 | 快照 | 快照共享 | 安全组/IMDS |
|---|---|---|---|---|---|---|---|---|
| AWS | EKS + IAM | `GET /api/aws/identity`（IRSA 注解 `eks.amazonaws.com/role-arn`、STS OIDC 信任策略） | `POST /assume-role`（AssumeRoleWithWebIdentity） | `GET /bucket/policy`（S3 bucket policy） | `GET /bucket/list` | `GET /snapshot`（EBS） | `POST /snapshot/share`（createVolumePermission） | `GET /security-group`（SG + MetadataOptions） |
| Azure | AKS + Entra | 联邦身份凭据（`issuer`/`subject`/`audiences`） | 同上（工作负载身份换令牌） | Blob 容器 `publicAccess` | 同上 | 磁盘 SAS（`diskAccessSAS`） | 同上 | NSG `sourceAddressPrefix` |
| 阿里云 | ACK + RAM | OIDC 角色信任策略（`Principal.RAM`） | `sts:AssumeRole` | OSS `AccessControlList.Grant` | 同上 | ECS 快照（`IsPublic`） | 同上 | 安全组 `SourceCidrIp` |
| 腾讯云 | TKE + CAM | 角色信任策略（`principal.qcs`） | `cam:AssumeRole` | COS `ACL` | 同上 | CBS 快照（`SharePermission`） | 同上 | `SecurityGroupPolicySet` |
| GCP | GKE + Workload Identity | `roles/iam.workloadIdentityUser` 绑定（`principal://…`） | 同上（KSA→GSA） | GCS IAM（`allUsers`） | 同上 | 镜像 IAM | 同上 | 防火墙 `sourceRanges` |
| 华为云 | CCE + IAM | agency `trust_domain` + 策略 | `AssumeRole`（委托） | OBS `Acl.Grant` | 同上 | EVS 快照（`share`） | 同上 | 安全组 `remote_ip_prefix` |

路由总数：**49**（6 云 × 8 条 + 1 条 `/api/__matrix__`；其中 `security-group` 分 GET 清单与
POST 放通两条）。所有路由 `writes=false`（不写文件、不改状态）。

## 2. 跨租户场景（4 场景 × 6 云 = 24 项，两姿态各 24 项）

租户 B 的令牌 + `account=333333333333`（不属于 A 也不属于 B）作为攻击者视角。

| 场景 | AWS | Azure | 阿里云 | 腾讯云 | GCP | 华为云 |
|---|---|---|---|---|---|---|
| IRSA/联邦通配 → 跨账户 AssumeRole | 200 wildcard=True → 200 cross_account | 同 | 同 | 同 | 同 | 同 |
| 公共桶策略 → 匿名列目录 | 200 public → 200 cross_tenant | 同 | 同 | 同 | 同 | 同 |
| 快照跨账户共享 → 他租户可挂载 | 200 visible → 200 shared_with=[333…] | 同 | 同 | 同 | 同 | 同 |
| SG 0.0.0.0/0 + IMDS 宽松 | 200 imds_open → 200 cidr=0.0.0.0/0 | 同 | 同 | 同 | 同 | 同 |

fixed 姿态（同一组请求）：

| 场景 | 拒绝点 | 状态码 | 证据 |
|---|---|---|---|
| 跨账户 AssumeRole | `account != 本租户` | **403** | `AccessDenied / cross-account assume denied` |
| 匿名列目录 | 无 `Authorization` | **401** | `unauthorized`；已认证租户仍可列自己的桶（200，`cross_tenant=False`） |
| 快照跨账户共享 | 目标账户非本租户 | **403** | `AccessDenied / cross-account snapshot share denied` |
| 放通 0.0.0.0/0 | CIDR 为世界开放 | **403** | `AccessDenied / world-open ingress denied` |

矩阵断言：`vulnerable.all_as_expected=True`、`fixed.all_as_expected=True`（各 24/24）；
fixed 下四个跨租户动作分别为 403/401/403/403，`cross_tenant_ok=False`。

## 3. 每云判别字段（防「统一抽象层」假覆盖）

| 云 | 判别字段（vulnerable → fixed） |
|---|---|
| AWS | `Principal.Federated="*"` + `Condition StringLike *:sub="*"` → 精确 `sub/aud`；S3 `Principal:"*"` → 账户根 + SecureTransport；`HttpTokens: optional→required` |
| Azure | `subject:"*"/issuer:"*"` → KSA 精确 subject；`publicAccess: Blob → None`；NSG `sourceAddressPrefix "*"` → `10.0.0.0/8` |
| 阿里云 | `Principal.RAM:["*"]` → 角色 ARN + `oidc:sub` 条件；`Grant: public-read → private`；`SourceCidrIp 0.0.0.0/0 → 10.0.0.0/8` |
| 腾讯云 | `principal.qcs:["*"]` → 角色 qcs + `oidc:sub`；COS `ACL: public-read-write → private`；`CidrBlock 0.0.0.0/0 → 10.0.0.0/8` |
| GCP | `members:["principal://…/*"]` → `serviceAccount:proj-a.svc.id.goog[ml/trainer]`；GCS `allUsers` → 具体 GSA；`sourceRanges ["0.0.0.0/0"] → ["10.0.0.0/8"]` |
| 华为云 | `trust_domain:"*"` + `Action/Resource "*"` → `op_svc_cce` + 单对象读；OBS `public-read → private`；`remote_ip_prefix 0.0.0.0/0 → 10.0.0.0/8` |

## 4. 测试证据（15 项）

| 用例 | 断言 |
|---|---|
| 路由覆盖 | 6 云 × 7 类能力路径齐备；49 条路由全 `writes=false` |
| 矩阵端点 | `/api/__matrix__` 返回 6 云 × 7 能力 + 边界文案 |
| 厂商形状 ×6 | 每云 payload 含该云判别字段（见第 3 节），不是统一 schema |
| vulnerable 全可达 | 24/24 `as_expected`，全部 `cross_tenant_ok=True` |
| fixed 全拒绝 | 24/24 `as_expected`，`cross_tenant_ok=False`，拒绝码 403/401/403/403 |
| IRSA 证据 | 六云 `wildcard=True` → `cross_account=True`；fixed 下 `wildcard=False` |
| 桶/快照/SG 证据 | `cross_tenant=True` / `shared_with=[333…]` / `imds_open=True` |
| 匿名列目录差分 | vulnerable 200 + `cross_tenant=True`；fixed 401 |
| 边界文案 | 响应含「契约级仿真」「非真实环境」 |

## 5. 明确未覆盖（不得据此宣称「六云实测」）

| 未覆盖 | 说明 |
|---|---|
| 真实云账号/集群 | 没有 EKS/AKS/ACK/TKE/GKE/CCE 账号，也没有 GPU 节点；矩阵全部来自仿真器 |
| IAM/策略求值引擎 | 不实现 AWS IAM policy 求值、Azure RBAC 继承、RAM/CAM/IAM 条件算子；只比对字段形状与显式通配 |
| STS/令牌真实验签 | `assume-role` 不验签真实 OIDC token（仿真器只认 mock 租户令牌） |
| 云 API 差异/限流/分页 | 不模拟真实 API 版本、限流、分页、最终一致性 |
| 网络数据面 | 安全组只表达控制面规则，不产生真实流量；IMDS 端点仅以字段声明 |
| 审计日志接入 | 未接 CloudTrail / Azure Activity / ActionTrail / CAM 日志，规则的 logsource 仍是设计值 |

## 6. 落地真实环境的验收路径（未执行）

1. 每云 1 个最小集群（EKS/AKS/ACK/TKE/GKE/CCE）+ 1 个 GPU 节点，只读凭据；
2. 用同一组只读探针（`GET identity/bucket policy/snapshot/SG`）替换本仿真器的 4 类调用；
3. 记录 API 版本、返回字段差异、权限边界（哪些字段真实环境不返回）；
4. 把差异回填 `trident/arch-intel/corpus/` 与本文第 3 节的判别字段表；
5. 只在拿到真实返回后，才把 `docs/SOTA-2026-10.md` 的「六云商真实环境实测」从**未达成**改判。
