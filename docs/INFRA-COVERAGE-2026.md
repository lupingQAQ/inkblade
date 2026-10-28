# 2026 infra 覆盖总表（与既有模块去重后）

- 基线快照：本轮开始时 `inkblade/modules/` 既有 **211** 个模块；本轮新增 **16** 个。按本表口径为 **227** 个；工作树中并行任务的模块另计，不并入本表（见第 4 节）。
- 新增模块全部 `writes=false`：9 个「主动探测」只做 GET，7 个「只读侦察」读快照/清单；无写类模块，不触发备份校验。
- 议题证据与逐条覆盖矩阵见 `docs/CONFERENCE-2026-GAPS.md`（65 条议题、16 条落地缺口、7 条残余缺口）。
- 去重原则：**不重复已有能力**。既有模块能判定的，不新建；新模块只补“既有模块没有的采集面/证据面”。

## 1. 覆盖总表

| ID | 模块键 | 系列 | 分级 | writes | 新增采集面 | 与既有模块的边界（去重） | 证据来源 |
|---|---|---|---|---|---|---|---|
| M01 | confidential-containers-attestation | 核心代码 | 主动探测 | false | CoCo/Kata/SEV-SNP 证明报告 + 准入策略 + initdata | 既有 `cgpu-isolation-audit` 只看 GPU CC 租户隔离；`inkblade/tee` 是离线 quote/PKI 验证库，不采集 CoCo 控制面 | USENIX Sec 2026 I09；NDSS 2026 I14/I19；KubeCon EU I40；KubeCon NA I48 |
| M02 | sandbox-runtime-surface | 权限链 | 只读侦察 | false | RuntimeClass/Pod 安全上下文/gVisor/Firecracker 覆盖矩阵 | 既有 `escape-primitives`/`runc-escape-detect` 检测逃逸原语与已知 CVE，不做运行时基线清点 | USENIX Sec 2026 I02/I10；NDSS 2026 I12/I13；BHUSA I32/I36；KubeCon I45/I59/I63 |
| M03 | spiffe-spire-surface | 权限链 | 主动探测 | false | SPIFFE ID/selector/TTL/admin ACL/绑定地址 | 既有 `sa-token-request`/`impersonate-abuse` 是 K8s SA token 与 RBAC，不覆盖 SPIFFE SVID | DEF CON 34 I38；KubeCon EU I41 |
| M04 | cert-manager-webhook-tls | 网络架构 | 主动探测 | false | webhook 证书到期/SAN/CA bundle/轮换/skipVerify | 既有 `admission-webhook-write` 是写类变更面，`crd-conversion-webhook` 是转换 webhook 缺陷；不判 TLS 生命周期 | NDSS 2026 I20；KubeCon EU I46 |
| M05 | gateway-api-ambient-mesh | 网络架构 | 只读侦察 | false | Gateway listener/HTTPRoute/waypoint/ztunnel bypass | 既有 `network-policy-coverage`/`cni-stack-capability` 是 L3-L4 与 CNI 语义；不覆盖 Gateway API L7 与 ambient 数据面 | KubeCon EU I42 |
| M06 | wasm-workload-surface | 核心代码 | 主动探测 | false | SpinKube/wasmCloud 模块能力/签名/WASI 版本 | 既有容器模块不覆盖 WASM 运行时；`dify-code-node-escape` 是应用沙箱，不是 WASM capability | KubeCon EU I47；KubeCon NA I50；BHUSA I34；POC I65 |
| M07 | gitops-supply-chain | 核心代码 | 只读侦察 | false | 明文密钥/漂移/自动同步签名/prune/external-secrets | 既有 `gitops-secret-read` 只读单个 Secret 可见性；不做仓库/漂移/同步策略全链 | IEEE S&P I30；KubeCon EU I43；KubeCon NA I51 |
| M08 | multi-cluster-federation | 混合云 | 只读侦察 | false | Karmada 传播/kubeconfig/审批/failover/ns 隔离 | 既有 `hybrid-cloud-egress-pivot` 是出网横向；不覆盖联邦控制面 | KubeCon EU I44；KubeCon NA I52 |
| M09 | dpu-ipu-offload | 网络架构 | 主动探测 | false | host offload/IOMMU/switchdev/数据面隔离/固件 | 既有 `dpu-smartnic-surface` 只看服务/凭据/SSH/rshim；本模块看 offload 数据面，二者互补不重叠 | NDSS 2026 I16；IEEE S&P I28 |
| M10 | pcie-iommu-dma | 网络架构 | 只读侦察 | false | IOMMU group/ACS/ATS/passthrough/DMA protection | 既有 `cgpu-isolation-audit`/`mig-profile-mismatch` 是 GPU 租户隔离，不判 PCIe 地址翻译 | USENIX Sec I03；NDSS I15；IEEE S&P I22 |
| M11 | tpm-measured-boot | 侦察 | 只读侦察 | false | Secure Boot/measured boot/PCR/eventlog/AK | 既有 `hardware-supply-chain` 校验固件清单签名，不校验启动度量链 | USENIX Sec I03；NDSS I14（根信任侧） |
| M12 | post-quantum-tls-posture | 网络架构 | 主动探测 | false | TLS 版本/KEX/hybrid group/证书签名/HNDL | 既有模块无 PQ 姿态；`aigateway-*` 只看网关鉴权/路由，不看密码套件 | IEEE S&P I28/I29；RSA I57 |
| M13 | model-watermark-backdoor-detect | 情报 | 主动探测 | false | 水印/验证端点/trigger scan/来源签名 | 既有 `model-registry-exposure`/`trust-remote-code-supply-chain` 看暴露与加载 RCE，不判水印/后门 | USENIX Sec I06/I07；IEEE S&P I27 |
| M14 | rag-vector-injection | 窃取与数据泄露 | 主动探测 | false | 注入文档/租户过滤/embedding namespace/清洗 | 既有 `vector-db-exposure` 看未授权访问；不判检索投毒与跨租户检索 | USENIX Sec I05；IEEE S&P I26 |
| M15 | federated-learning-surface | 情报 | 只读侦察 | false | 更新签名/安全聚合/DP/拜占庭过滤/范数 | 既有 `training-data-leak` 是集中式训练数据泄漏；不覆盖联邦聚合 | NDSS 2026 I18 |
| M16 | data-provenance-audit | 情报 | 主动探测 | false | SLSA/in-toto/Sigstore/SBOM/Rekor/drift | 既有 `supply-chain-pinning` 看 pinning/凭据；`inkblade/sigstore_keyless` 是签名验证库，不采集制品证明链 | BHUSA I35；KubeCon NA I49/I53；OWASP I54 |

## 2. 覆盖分布

| 维度 | 数量 | 说明 |
|---|---|---|
| 新增模块 | 16 | 全部纯小写键、`requires=[]`、`writes=false` |
| 主动探测（GET-only） | 9 | CoCo、SPIRE、webhook TLS、WASM、DPU、PQ TLS、水印、RAG、来源证明 |
| 只读侦察（快照/清单） | 7 | sandbox、Gateway、GitOps、多集群、IOMMU、TPM、联邦学习 |
| 既有模块已覆盖议题 | 9 | 缓存、Ray、容器逃逸、网关 guardrail、vLLM 模糊等 |
| 部分覆盖议题 | 19 | 已在矩阵标 `部分:`，不计为已覆盖 |
| 残余缺口 | 7 | R01–R07，需新数据源/控制面采集，未在本轮虚构 |

按系列：核心代码 3、权限链 2、网络架构 5、混合云 1、侦察 1、情报 3、窃取与数据泄露 1。

## 3. 实效与测试

- 实验室：`lab/infra2026_sim.py`，双态 `vulnerable/fixed`，17 个只读面；至少 6 个新面（CoCo 证明、SPIRE、webhook TLS、ambient mesh、WASM、PQ TLS）均有两态差异。
- 实效 +3（`inkblade/verify-effects.py`）：
  - `infra2026-coco-attestation-mismatch`：测量值与预期不一致 + debug + 策略未强制；
  - `infra2026-spire-wildcard-identity`：通配 SPIFFE ID + 空 selector + admin 无 ACL；
  - `infra2026-pq-tls-weak-posture`：TLS1.2 + RSA KEX + 无 hybrid group + HNDL。
- 测试：`tests/test_infra2026_sim.py`（9）、`tests/test_modules_infra2026.py`（6）、`tests/test_verify_effects_infra2026.py`（5）、`tests/test_infra2026_docs.py`（8）。
- 只读证明：仿真 POST/PUT/PATCH/DELETE 一律 405；模块共用库 `_infra2026-common.py` 的 `Trace.call` 拒绝非 GET。

## 4. 与既有覆盖文档的关系

- `docs/HARDWARE-SWITCH-COVERAGE.md`：GPU/BMC/交换机/DPU 的**真实硬件**三级边界；本表新增 DPU offload/IOMMU/TPM 仍属“快照判定”，不声称真实硬件验证。
- `docs/CACHE-SECURITY.md`：多租户缓存；本表 RAG/FL 与之无重叠。
- `docs/PRETRAIN-SFT-RL-COVERAGE.md`：训练栈；本表只补模型水印、联邦聚合、来源证明。
- `docs/KILL-CHAIN.md` / `docs/PRIVESC-MATRIX.md`：攻击链与提权；本表不新增利用链，只补证据面。
- `docs/TEE-ONLINE-VERIFICATION.md`：TEE quote/PKI 离线验证；本表 CoCo 模块补“控制面采集”，二者可串联但不重复实现。

## 4.1 与并行在途模块的边界

工作树中存在另一组并行任务落地的 `*-audit` 模块（`confidential-containers-audit`、`spiffe-spire-audit`、`post-quantum-tls-audit`、`wasm-runtime-audit`、`ambient-mesh-audit`、`model-watermark-backdoor-audit` 等），采集模型偏 `inkblade collect`/`profile`。本表**不重复计数**，合并口径如下：

- 若 `*-audit` 家族最终保留：以它的 collector 作为数据源，本表模块保留“HTTP 双态证据 + 实效项”，二者通过 `target`/`snapshot` 适配，不并行报同一 finding；
- 若 `*-audit` 家族撤销：本表 16 个模块即为唯一实现；
- 在合并完成前，任何覆盖率数字都以本表 16 个模块的测试为准，不把 `*-audit` 家族计入 227。

## 4.2 R01–R07 残余缺口落地（2026-10-26）

| ID | 模块键 | 分级 | 默认 | 采集面 | 效果 |
|---|---|---|---|---|---|
| R01 | `hypervisor-audit-integrity` | 只读侦察 | off（无面） | `audit/hypervisor-audit.json` + `audit-collector` | `residual-hypervisor-audit-race` |
| R02 | `agent-skill-registry-supply-chain` | 只读侦察 | off（无面） | `agent/skills/registry.json` | `residual-agent-skill-poison` |
| R03 | `operator-cross-namespace-reference` | 只读侦察 | on | CRD/Operator/RBAC/CR 引用图 | `residual-operator-cross-namespace` |
| R04 | `mcp-control-plane-governance` | 主动探测 | off（无面） | `mcp/servers.json` + `/mcp/tools` | `residual-mcp-control-plane` |
| R05 | `ai-infra-baseline` | 只读侦察 | on | `ai-infra/inventory.json` + `/v1/models` | 专项测试 + 企业本地补验 |
| R06 | `inference-tenant-isolation-baseline` | 只读侦察 | on | `inference/tenant-policy.json` + 推理端点 | 专项测试 |
| R07 | `agent-native-control-plane` | 只读侦察 | off（无面） | `agent/runtime.json` + `/agents` | 专项测试 |

四个无面模块按「无面 default_enabled=false」隔离，客户部署对应采集面后显式启用；
逐条来源、必要性与边界见 `docs/RESIDUAL-GAPS-2026.md`。本轮 R 专项测试
`tests/test_modules_residual2026.py`，并新增 4 项效果验证（至少 3 项达标）。

## 5. 来源索引（与逐条议题对应）

- USENIX Security 2026 technical sessions: https://www.usenix.org/conference/usenixsecurity26/technical-sessions
- IEEE S&P 2026 program: https://sp2026.ieee-security.org/program.html
- NDSS 2026 accepted papers: https://www.ndss-symposium.org/ndss2026/accepted-papers/
- Black Hat USA 2026 briefings / 回顾: https://blackhat.com/us-26/briefings/schedule/ ；https://www.straiker.ai/blog/black-hat-usa-2026-ai-security-talks
- DEF CON 34 Cloud Village: https://www.cloud-village.org/dc34
- DEF CON 34 AppSec Village: https://www.appsecvillage.com/events/dc-2026
- KubeCon EU 2026 schedule: https://kccnceu2026.sched.com/
- KubeCon NA 2026 schedule: https://events.linuxfoundation.org/kubecon-cloudnativecon-north-america/program/schedule/
- OWASP Agentic Skills Top 10: https://owasp.org/www-project-agentic-skills-top-10/ast02
- RSA Conference 2026 Top-10 sessions: https://www.rsaconference.com/library/blog/rsac-2026-conference-top-10-sessions-every-program-committee-wanted
- KCon 2026 topics: https://www.dwcon.cn/post/5060
- 云栖大会 2026: https://yunqi.aliyun.com/2026/live
- CanSecWest 2026 agenda: https://www.secwest.net/conference-agenda-2026
- POC 2026 talks: https://powerofcommunity.net/

## 6. 诚实边界

- 所有新增模块的“命中”均来自 **HTTP mock / 快照**，不等于在真实 CoCo、SPIRE、cert-manager、Istio、Karmada、BlueField、TPM、PQ TLS 端点验证。
- `fixed` 态无 high 只证明检测逻辑对加固样例不误报，不证明生产加固完整。
- 论文攻击（如 GhostVAE、Confundo、T3C）只作为威胁模型来源；模块检测的是可观测配置/姿态，不复现论文利用。
- 未公开议程的会议（Black Hat Europe 2026、SDC 2026、腾讯 TSec、字节安全沙龙、OffensiveCon 2026）不进入议题计数，避免用二手标题充数。
