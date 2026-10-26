# 企业就绪差距与准入体系（2026-10-26）

> 本文回答一个问题：**Trident 的 demo 能力距离「企业可采购/可运营」还差什么**。
> 结论先行：demo 证明的是「机制可跑、证据可复现、闸门有代码」；企业就绪还要求
> 客户真实环境、规模、数据/变更治理、误报调优、系统集成、合规运营六类证据。
> 本文不把任何单项能力冒充整体就绪，也不把本地 fixture 写成客户生产验证。
>
> 三态定义：
> - 🟢 **绿 = 本地已验证**：仓库内可复现实现 + 自动化测试/本地实测，证据路径可查；
> - 🟡 **黄 = 可本地补验**：有代码/契约/夹具，但缺客户样本、真实版本矩阵或联调；
> - 🔴 **红 = 必须客户环境**：涉及客户网络/账号/数据/合规/规模，本地不能替代。

## 1. 六类差距逐条

### 1.1 真实环境差异

| 维度 | 内容 |
|---|---|
| demo 证明什么 | 本机 mock 靶场真实 HTTP/进程效果验证 20/20；单节点 k3s（QEMU TCG）真 apiserver / Service 网络 / NetworkPolicy 数据面；6/6 侦察模块、16 findings；hostNetwork 绕过 NetworkPolicy 的 `blocked` vs `connected` 对照。 |
| 企业还差什么 | 客户真实 CNI（Calico/Cilium/Antrea）、云托管 K8s（EKS/AKS/ACK/TKE/GKE/CCE）、GPU Operator/device plugin/DRA、内核/eBPF/Falco driver、私有 registry/代理/堡垒机路径均未在客户环境验证。 |
| 本地可测 | `lab/qemu-k3s`（k3s 单节点）、`lab/kind`（Calico 脚本，宿主虚拟化不可用未跑）、`lab/enterprise-fixtures`（生产形态快照/清单）、fake-kubectl 只读采集契约。 |
| 必须客户环境测 | 多节点调度/驱逐/PDB、真实 CNI 策略语义、云厂商 IAM/IRSA/Workload Identity、GPU 设备插件与 DRA、客户镜像仓库与出网代理、生产内核/LSM。 |

**判断**：真实环境差异不是「再写一个模块」能补的；必须以客户只读 kubeconfig 做环境画像，
再按 CNI/云厂商/GPU 版本矩阵分批验证。Pilot 的 P0 只读清点就是为此设计的。

### 1.2 规模

| 维度 | 内容 |
|---|---|
| demo 证明什么 | 100/1,000/5,000/10,000 资产仿真；10k findings 的模块耗时与 RSS；单节点 2 GB k3s；单机 8 租户 + 4 worker + 原子配额/审批压测（17.26 runs/s，隔离违规 0）；10k findings 报告渲染。 |
| 企业还差什么 | 万卡 GPU 真集群、日均百万审计事件、多副本控制面/HA、跨 AZ 队列与租约、长时间 soak（24h/7d）、大规模扫描窗口与限流。 |
| 本地可测 | `lab/bench/scale-bench.py`、`lab/saas/load.py`、`lab/enterprise_lab.py`（345 条审计事件的手工放大版）、报告渲染压测。 |
| 必须客户环境测 | 真实万卡/千节点集群、客户峰值事件流、控制面副本故障切换、跨 region 网络、生产存储 IOPS、GPU 训练/推理负载下的扫描影响。 |

**判断**：本仓库的规模证据是「算法复杂度 + 单机资源」级，不是容量承诺。任何
「支持万卡」的表述都必须附带客户实测；当前只能写「仿真覆盖到 10,000 节点」。

### 1.3 数据敏感与变更窗口

| 维度 | 内容 |
|---|---|
| demo 证明什么 | ROE/consent HMAC 签名、字段篡改即拒绝、命名空间/CIDR 范围、时间窗、级别闸门；写类模块备份回执 + 逐步回滚；工作区 kill switch；载荷统一脱敏；证据三层 + manifest 哈希。 |
| 企业还差什么 | 客户数据分级/标注样本导入、变更窗口/冻结期系统对接、客户 KMS/HSM/信封加密、训练数据与模型权重接触审批、跨境/数据驻留、证据保留/删除的合规执行。 |
| 本地可测 | `roe.py`/`backup.py`/`abort.py` 全链；`trident/pilot.py` 的窗口/停止条件/回滚预案；`report_signing.retention_plan`（dry-run）；`calendar` 窗口登记。 |
| 必须客户环境测 | 客户变更管理（CAB/ServiceNow）、SOC 值班与升级、KMS/HSM 托管密钥、数据分类策略、跨境合规、法务保留/删除指令。 |

**判断**：代码闸门只能保证「未授权不跑」；企业要求的是「在客户治理系统里可审计地跑」。
变更窗口、数据 owner 签字、KMS 托管必须在客户环境落地。

### 1.4 误报漏报与调优

| 维度 | 内容 |
|---|---|
| demo 证明什么 | 三场景 fixture 实测：平台 DaemonSet 噪声、RBAC/NetworkPolicy 常规运维噪声、340 条良性审计事件洪水；逐场景 TP/FP/FN 与 FP/FN 率；审计主体基线调优（CI/扫描器）FP 180→120（-33.3%）；2 个未覆盖风险如实计 FN。 |
| 企业还差什么 | 客户标注真值/盲测、云厂商 DaemonSet 例外清单、Falco/Kyverno 真实生效验证、SIEM 告警闭环/去重、升级后的规则回归、FP≤20%/FN≤10% 的客户验收。 |
| 本地可测 | `lab/enterprise_lab.py` + `ground-truth.json`；`core/auditlog.py` 基线主体；规则包紫队矩阵；`trident enterprise deliver` 干跑。 |
| 必须客户环境测 | 客户真实告警样本、SOC 反馈、例外清单审批、规则版本升级、SIEM 去重/工单闭环、误报/漏报验收。 |

**判断**：fixture 的 FP/FN 只能证明「评测方法可复现」，不能证明客户环境达标。
本仓库当前 fixture 的总体 FP 率很高（见 `docs/ENTERPRISE-LAB-RESULTS.md`），
这是诚实结果，不是可交付的调优结论。

### 1.5 系统集成

| 维度 | 内容 |
|---|---|
| demo 证明什么 | OIDC/LDAP 本地 mock 适配（组→角色、nonce/过期/注入校验）；Splunk HEC / Elastic _bulk / Webhook HMAC / Jira / ServiceNow 本地 HTTP 契约；双签审批链；报告哈希+本机时间戳；保留策略 dry-run。 |
| 企业还差什么 | 生产 OIDC RS256/JWKS、LDAPS/AD 组同步与离职回收、真实 Jira/ServiceNow 字段/工作流、SIEM 证书/代理/白名单、SOAR 回写、CMDB/资产库同步、工单幂等/重试/死信。 |
| 本地可测 | `trident/enterprise/*` 契约测试（真实本地 HTTP 收包）；`approval.py` 哈希链；`report_signing.py` 篡改检测；CLI `trident enterprise` 干跑。 |
| 必须客户环境测 | 客户 IdP 注册/回调/组映射、LDAP 目录、Jira/ServiceNow 项目字段、SIEM 索引/令牌/证书、网络策略、SOAR playbook、工单闭环。 |

**判断**：适配器只保证「请求格式正确」，不保证「客户系统接受」。集成验收必须
在客户预生产环境完成，且要有失败重试/死信/人工兜底。

### 1.6 合规与运营

| 维度 | 内容 |
|---|---|
| demo 证明什么 | 报告映射 NIST/等保/GB/T 20984/OWASP/ATLAS/ISO 42001/EU AI Act（工程归类，非认证）；报告签核 6 项清单；保留策略；HA/升级/备份 runbook 草案；许可证 Apache-2.0 与交付边界。 |
| 企业还差什么 | RFC3161 TSA/HSM 时间戳、客户 IdP 组映射/离职回收、审计证据包按客户模板出具、HA 实际演练、升级/回滚窗口、责任矩阵/保险/合同 SLA、监管报送。 |
| 本地可测 | `docs/OPERATIONS.md` runbook；`report_signing.create_signoff`；`retention_plan`；`trident export --format ocsf|sarif`；合规映射测试。 |
| 必须客户环境测 | 客户法务/合规评审、TSA/HSM、身份生命周期、HA 故障演练、升级窗口、监管沟通、合同责任边界。 |

**判断**：「合规映射」不等于「合规认证」；「runbook」不等于「已演练」。企业交付
必须由客户安全负责人、平台 owner、法务共同签核。

## 2. POC → Lab → Pilot → Production 四阶段准入/退出

> 所有比率为**阶段门槛**，不是营销承诺；未达标不得进入下一阶段。扫描窗口以客户
> 书面约定为准（默认 ≤2h/次）；回滚成功率按写动作逐步统计；报告签核项固定 6 项。

| 阶段 | 准入标准 | 退出标准（可量化） |
|---|---|---|
| POC | 书面授权/NDA；只读 kubeconfig（或客户脱敏 snapshot）；客户指定一名安全负责人；明确不执行写操作。 | 只读通过率 ≥90%（采集命令成功/总数）；环境画像覆盖 100% context；0 写动作；POC 报告初稿交付；客户确认范围无遗漏。 |
| Lab | POC 退出；ROE/consent 完整；客户提供脱敏样本/标注（至少 20 条）；测试窗口与停止条件书面确认。 | 只读通过率 ≥95%；fixture/客户样本误报率 ≤30%；漏报率 ≤15%；回滚演练成功率 100%（mock/备份回执）；SIEM/ITSM 契约测试全过；报告签核 6/6。 |
| Pilot | Lab 退出；客户变更窗口（CAB 批准）；lead→安全负责人双签；备份/回滚预案签字；SOC 值班知会。 | 只读通过率 ≥95%；误报率 ≤20%；漏报率 ≤10%；扫描窗口 ≤客户约定（默认 2h）；写动作回滚成功率 100%；报告签核 6/6；SIEM 投递成功率 ≥99%（测试事件）；客户安全负责人书面验收。 |
| Production | Pilot 退出；连续 2 个变更窗口无 P1 事故；HA/升级/备份 runbook 演练通过；合同/责任矩阵/保险确认；数据保留策略生效。 | 每季度复测：只读通过率 ≥98%；误报率 ≤15%；漏报率 ≤8%；回滚成功率 100%；报告签核 6/6；审计证据保留 ≥合同期限；P1 事故 0；SLA 按合同考核。 |

**阶段禁令**：
- POC 阶段禁止任何写操作（包括「只读验证」名义下的 patch/exec）。
- Lab 阶段的 FP/FN 只能用于调优，不得写进客户验收报告。
- Pilot 未完成双签与备份回执，不得执行 P2 写验证。
- Production 不得用 demo/fixture 数据冒充客户实测；对外材料必须标注证据来源。

## 3. 企业就绪清单（60 项，三态）

> 绿 36 · 黄 3 · 红 21（共 60 项）。绿色只表示「本地有可复现证据」，不表示
> 客户环境已通过；红色项不允许在投标/验收材料中写成「已支持」。

| ID | 检查项 | 类别 | 状态 | 证据 / 缺口 |
|---|---|---|---|---|
| ER-01 | 本机 mock 靶场效果级全链验证 | 真实环境差异 | 🟢 绿 | `docs/EFFECT-VERIFICATION.md`；20/20 PASS（真实进程/HTTP） |
| ER-02 | 单节点 k3s 真 apiserver/CNI/NetworkPolicy | 真实环境差异 | 🟢 绿 | `docs/REAL-CLUSTER-VERIFICATION.md`；6/6 模块、16 findings |
| ER-03 | 多节点调度/驱逐/PDB 验证 | 真实环境差异 | 🔴 红 | 仅单节点 k3s；需客户多节点集群 |
| ER-04 | Calico/Cilium 真数据面策略语义 | 真实环境差异 | 🔴 红 | `lab/kind` 脚本存在但宿主虚拟化不可用；需客户 CNI |
| ER-05 | 六大云托管 K8s 真环境 | 真实环境差异 | 🔴 红 | `docs/SIX-CLOUD-MATRIX.md` 为契约仿真；需客户账号 |
| ER-06 | GPU Operator/device plugin/DRA 兼容 | 真实环境差异 | 🟡 黄 | `trident/enterprise/gpu_contract.py` 本地校验 device plugin v1beta1/DRA schema/版本矩阵；无真实 GPU/device plugin，需客户节点 |
| ER-07 | hostNetwork 绕过 NetworkPolicy 真数据面 | 真实环境差异 | 🟢 绿 | `netpol-proof.json`：普通 Pod blocked / hostNetwork connected |
| ER-08 | 私有 registry/代理/镜像差异 | 真实环境差异 | 🟢 绿 | `trident/enterprise/registry.py`：Bearer challenge/token、manifest digest、tag-only 策略、代理绝对 URI、allowlist；本地 registry mock 实测 |
| ER-09 | 内核/eBPF/Falco driver 兼容矩阵 | 真实环境差异 | 🔴 红 | 仅 fixture 生效状态；需客户节点内核 |
| ER-10 | 客户网络分段/堡垒机/跳板路径 | 真实环境差异 | 🔴 红 | 本机 127.0.0.1/QEMU hostfwd；无客户网络 |
| ER-11 | 100/1k/5k/10k 资产仿真 | 规模 | 🟢 绿 | `docs/SCALE-RESULTS.md`；算法/时延曲线 |
| ER-12 | 10k findings 内存/时延 | 规模 | 🟢 绿 | `lab/bench/scale-bench.py`；RSS 34→54 MB |
| ER-13 | 单节点 2 GB k3s 真集群 | 规模 | 🟢 绿 | QEMU TCG `-m 2048`；非生产规模 |
| ER-14 | 单机 8 租户并发/配额/隔离 | 规模 | 🟢 绿 | `docs/SAAS-LOAD-RESULTS.md`；17.26 runs/s，隔离违规 0 |
| ER-15 | 万卡 GPU 真集群 | 规模 | 🔴 红 | 仅 10k 节点离散事件仿真；需 ≥1,024 GPU 实测 |
| ER-16 | 日均百万审计事件流 | 规模 | 🟢 绿 | `trident/enterprise/scale.py`：100 万合成事件 98.5s、10,148/s、线性容量 8.77 亿/日；非客户流 |
| ER-17 | 多副本控制面/HA/故障转移 | 规模 | 🔴 红 | 单机 SQLite/单 HTTP；无跨副本队列/租约 |
| ER-18 | 大规模并发扫描窗口/限流 | 规模 | 🔴 红 | 仅单机压力；需客户窗口与限流策略 |
| ER-19 | 10k findings 报告渲染 | 规模 | 🟢 绿 | `reports/samples/scale/`；渲染耗时/大小 |
| ER-20 | 24h/7d 长稳 soak | 规模 | 🔴 红 | 未执行；需客户/实验室长稳窗口 |
| ER-21 | ROE/consent HMAC + 范围/窗口 | 数据敏感与变更窗口 | 🟢 绿 | `tests/test_consent_signature.py`；篡改即拒绝 |
| ER-22 | 写类备份回执 + 逐步回滚 | 数据敏感与变更窗口 | 🟢 绿 | `tests/test_backup.py`；restored/pending/unsupported/failed |
| ER-23 | 工作区紧急停止 kill switch | 数据敏感与变更窗口 | 🟢 绿 | `tests/test_cli_ops.py` abort；执行前拒绝 |
| ER-24 | 载荷统一脱敏 | 数据敏感与变更窗口 | 🟢 绿 | `jsonio.redact`；connector/adapters 复用 |
| ER-25 | 客户数据分级/标注样本导入 | 数据敏感与变更窗口 | 🟡 黄 | Pilot 支持 snapshot/ground-truth 格式；无 DLP/分类器 |
| ER-26 | 变更窗口/冻结期系统对接 | 数据敏感与变更窗口 | 🟢 绿 | `governance.ChangeCalendar`：冻结期重叠拒绝 + ICS 导出 + 审计；客户 CAB 仍需人工签核 |
| ER-27 | 证据保留/删除策略 | 数据敏感与变更窗口 | 🟢 绿 | `retention.apply_retention`：dry-run/legal hold/双角色审批/越界拒绝/审计 JSONL；客户法务审批仍在外部 |
| ER-28 | 客户 KMS/HSM/信封加密 | 数据敏感与变更窗口 | 🔴 红 | 本机文件权限；需客户密钥托管 |
| ER-29 | 训练数据/权重接触审批 | 数据敏感与变更窗口 | 🔴 红 | 无数据 owner 流程；需客户审批 |
| ER-30 | 跨境/数据驻留合规 | 数据敏感与变更窗口 | 🔴 红 | 无 region/驻留控制；需客户法务 |
| ER-31 | 审计 Secret/PVC 主体基线 | 误报漏报与调优 | 🟢 绿 | `core/auditlog.py`；benign 样本零报 |
| ER-32 | 三场景 fixture FP/FN 实测 | 误报漏报与调优 | 🟢 绿 | `docs/ENTERPRISE-LAB-RESULTS.md`；FP/FN 逐场景 |
| ER-33 | 审计主体基线调优（CI/扫描器） | 误报漏报与调优 | 🟢 绿 | 实验室 FP 180→120（-33.3%）；需客户批准 |
| ER-34 | 云厂商 DaemonSet 例外清单 | 误报漏报与调优 | 🟢 绿 | `governance.ExceptionPolicy`：digest 钉住 + 精确 ns/SA + 审批 + 到期；客户 DaemonSet 清单仍待导入 |
| ER-35 | 客户标注真值/盲测 | 误报漏报与调优 | 🟡 黄 | Pilot 计划要求 ≥20 条；客户样本未提供 |
| ER-36 | 客户环境误报率 ≤20% | 误报漏报与调优 | 🔴 红 | fixture 总体 FP 率 72.5%；必须客户调优 |
| ER-37 | 客户环境漏报率 ≤10% | 误报漏报与调优 | 🔴 红 | 当前 fixture FN 28.6%；含未覆盖检测面 |
| ER-38 | Falco/Kyverno 真实生效验证 | 误报漏报与调优 | 🔴 红 | fixture 状态 37.5%/57.1%；需客户运行时 |
| ER-39 | SIEM 告警闭环/去重 | 误报漏报与调优 | 🟢 绿 | `delivery.Deduplicator/DeliveryQueue`：指纹去重、重试、死信 JSONL、重放；SOAR 回写需客户联调 |
| ER-40 | 规则升级后的回归 | 误报漏报与调优 | 🟢 绿 | `governance.compare_rule_packs`：链覆盖降级/规则删除即回归；客户规则版本与样本仍需导入 |
| ER-41 | OIDC 登录适配（本地 mock） | 系统集成 | 🟢 绿 | `tests/test_enterprise_integrations.py`；claims/nonce/过期 |
| ER-42 | LDAP 登录适配（本地 mock） | 系统集成 | 🟢 绿 | mock 目录 + 组映射 + 注入拒绝 |
| ER-43 | 生产 OIDC RS256/JWKS | 系统集成 | 🔴 红 | 当前仅 mock HS256；需客户 IdP |
| ER-44 | LDAPS/AD 真目录 | 系统集成 | 🔴 红 | 无真实目录连接；需客户 LDAP |
| ER-45 | Splunk HEC 契约 | 系统集成 | 🟢 绿 | 本地 HTTP 收包验证路径/Authorization/NDJSON |
| ER-46 | Elastic _bulk 契约 | 系统集成 | 🟢 绿 | 本地 HTTP 收包验证 action/source/`errors` |
| ER-47 | Webhook HMAC 契约 | 系统集成 | 🟢 绿 | 签名/时间戳/重放窗口校验 |
| ER-48 | Jira/ServiceNow stub 契约 | 系统集成 | 🟢 绿 | 字段/优先级/关联 fingerprint；本地 HTTP |
| ER-49 | 真实 Jira/ServiceNow 工作流 | 系统集成 | 🔴 红 | 未联调客户项目字段/审批流 |
| ER-50 | SIEM 网络/证书/代理/白名单 | 系统集成 | 🟢 绿 | `delivery.EgressPolicy`：host allowlist、非回环强制 TLS、CA bundle/代理；客户证书与网络策略仍待联调 |
| ER-51 | 双签审批链（lead→安全负责人） | 合规与运营 | 🟢 绿 | `approval.py` 哈希链/顺序/重复签署拒绝 |
| ER-52 | 报告哈希+时间戳（本机） | 合规与运营 | 🟢 绿 | `sign_report`/`verify_report`；篡改检出 |
| ER-53 | 报告签核 6 项清单 | 合规与运营 | 🟢 绿 | `create_signoff`；缺少任一项即拒绝 |
| ER-54 | 保留策略 dry-run | 合规与运营 | 🟢 绿 | `retention_plan`；legal hold 不 purge |
| ER-55 | RFC3161 TSA/HSM 时间戳 | 合规与运营 | 🔴 红 | 本机时钟；需客户 TSA/HSM |
| ER-56 | 客户 IdP 组映射/离职回收 | 合规与运营 | 🔴 红 | mock 组映射；无 SCIM/离职同步 |
| ER-57 | 等保/ISO 审计证据包 | 合规与运营 | 🟢 绿 | `evidence_pack.build_pack/verify_pack`：manifest/控制项索引/zip 哈希；客户模板与评审仍在外部 |
| ER-58 | HA/升级/备份 runbook | 合规与运营 | 🟢 绿 | `docs/OPERATIONS.md`；本机演练项 |
| ER-59 | 许可证/交付边界 | 合规与运营 | 🟢 绿 | Apache-2.0 + NOTICE；`docs/DELIVERY.md` |
| ER-60 | 客户验收/责任矩阵/保险 | 合规与运营 | 🔴 红 | 需合同/法务/客户签核 |

## 3.1 黄项本地补验（2026-10-26）

本轮把 9 项「有代码/契约但缺本地执行证据」的黄项补到绿：ER-08、ER-16、ER-26、
ER-27、ER-34、ER-39、ER-40、ER-50、ER-57。统一执行器：

```bash
python -m trident.enterprise.localcheck --out reports/samples/enterprise-local
```

| 原黄项 | 补验内容 | 证据 |
|---|---|---|
| `ER-08`（registry） | registry Bearer challenge → token → manifest digest；tag-only 策略；代理绝对 URI；host allowlist | `trident/enterprise/registry.py`；`local-checks.json` 的 `er-08-*` |
| `ER-16`（scale） | 20 万事件写入/读回；另跑 100 万事件 98.5s / 10,148 事件每秒 / 线性 8.77 亿每日 | `trident/enterprise/scale.py`；`audit-scale-1m.json` |
| `ER-26`（calendar） | 冻结窗口重叠拒绝、ICS 导出、持久化 | `governance.ChangeCalendar`；`er-26-change-freeze` |
| `ER-27`（retention） | dry-run/legal hold/双角色/越界拒绝/审计 JSONL | `retention.apply_retention`；`er-27-retention-execution` |
| `ER-34`（exception） | digest + 精确 ns/SA + 审批人 + 到期；通配/过期拒绝 | `governance.ExceptionPolicy`；`er-34-vendor-exception-policy` |
| `ER-39`（dedupe） | 指纹去重、重试、死信 JSONL、重放 | `delivery.Deduplicator/DeliveryQueue`；`er-39-siem-dedupe-dlq` |
| `ER-40`（regression） | 规则包升级：覆盖降级/规则删除即回归 | `governance.compare_rule_packs`；`er-40-rule-regression` |
| `ER-50`（egress） | allowlist、非回环强制 TLS、CA/代理 | `delivery.EgressPolicy`；`er-50-siem-egress-policy` |
| `ER-57`（evidence） | manifest + 等保/ISO 控制项索引 + zip 哈希校验/篡改检出 | `evidence_pack.build_pack/verify_pack`；`er-57-evidence-pack` |

仍保持黄项 **3 项**：ER-06（无真实 GPU/device plugin/DRA 注册，仅本地 schema/版本
矩阵）、ER-25（无客户数据分级/DLP 样本）、ER-35（无客户标注真值/盲测样本）。
红项 **21 项**不变。完整边界见 `docs/ENTERPRISE-LOCAL-VERIFICATION.md`。

## 4. 使用方式

```bash
# 1) 只读试点（默认；生成画像/热图/计划/审批清单）
python -m trident pilot --kubeconfig ~/.kube/config --out reports/pilot

# 2) 离线多集群 mock（本地验证合并/画像）
python -m trident pilot --kubeconfig east.yaml --kubeconfig west.yaml \
  --snapshot lab/enterprise-fixtures/clusters/east-prod.json \
  --snapshot lab/enterprise-fixtures/clusters/west-prod.json --out reports/pilot

# 3) 写计划（必须 ROE + 级别 + 备份三闸门；pilot 自身仍只读）
python -m trident pilot --kubeconfig ~/.kube/config --allow-write --role lead
```

**禁止宣称**（与 README 三档能力一致）：
- 不得称「已通过企业生产验证」「支持万卡」「替代客户 SOC/合规认证」；
- 不得把 fixture FP/FN、单节点 k3s、SQLite 多租户压测写成客户 SLA；
- 不得在未双签/未备份时执行 P2 写验证；
- 不得隐藏本清单的 🔴 项；投标材料必须原样附三态计数。
