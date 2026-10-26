# InkBlade（墨刃零）— ML 训练/推理集群渗透测试平台

**InkBlade（墨刃零）** 是面向授权安全测试的 K8s / ML 集群渗透测试平台：七层架构（授权治理 → 编排 → 模块 → 三层证据 → 双语报告 → 可视化 → 规则转化），仅依赖 Python 3.10+ 标准库。

**InkBlade (Chinese brand: 墨刃零)** is an authorized-testing platform for Kubernetes / ML training and inference clusters. It follows a seven-layer architecture (authorization → orchestration → modules → three-layer evidence → bilingual reporting → visualization → rule conversion) and uses only the Python 3.10+ standard library.

> **总文档（先读这篇）**：[`docs/MASTER-REPORT.md`](docs/MASTER-REPORT.md) — 面向非 K8s 安全读者的白话总报告：前置知识、攻击路径、产品流程、Agent 改动、指标、竞品、未达成项、复盘、术语与证据索引。
>
> **终版（证据日期 2026-10-26）**：模块 **275**（默认启用 264 / 隔离 11）· 单元测试 **Ran 1933 · OK**（2 skipped，公开树 1 项在途红除外）· 可利用性 **32 verified / 152** · 六画像覆盖 73.48% / 70.08% / 62.12% / 70.45% / 71.21% / 25.76%（Slurm 域级 88.2%）· 默认 PoC **2** · 无面模块 **12**。未达成 11 条见总报告 §7.7；能力三态矩阵见 [`docs/SOTA-2026-10.md`](docs/SOTA-2026-10.md)（25 真实验证 / 10 模拟验证 / 3 仍未达成）。

> **授权使用 / Authorized use only**：仅可对获得书面授权的资产执行测试。平台内置 consent/ROE 签名、级别闸门、写类操作备份闸门与逐动作审计；未签署授权时 CLI 与 API 均拒绝执行。
>
> **Authorized use only.** Run InkBlade exclusively against assets covered by written authorization. Consent/ROE pinning, technical-level gates, a mandatory backup gate for write modules, and per-action auditing are enforced by design; without signed consent both CLI and API refuse to execute.

---

## 5 分钟上手 / 5-minute quickstart

> 不需要 `pip install`、不需要 kubeconfig、不需要 LLM key、不需要 bash。以下命令在仓库根目录执行（Windows / macOS / Linux 均可）。
>
> 唯一先决条件：**Python 3.10+ 在 PATH**（`python --version` 能看到版本）。Windows 若 `python` 是 Microsoft Store 别名，请先安装 Python 并勾选 “Add to PATH”，或用 `py -3.12` / 完整路径替换下文的 `python`。

```bash
# 1) 环境自检：Python、写权限、端口、可选依赖、mock / 真集群二选一
python -m inkblade doctor

# 2) 一键 demo：建 demo 工作区 → 建 lead/tester → 签 demo 授权 → 起 mock 靶场
#    → 跑 2 模块 + 1 链 → 生成双语报告与规则包
python -m inkblade demo

# 3) 接真实集群：5 问向导（目标 / 范围 / 级别 / 用户 / 签授权；失败可重入）
python -m inkblade quickstart
```

第 2 条命令结束时会直接打印：发现数（按严重度）、链两步状态、双语报告路径、规则包路径、Web UI 路径与下一步。默认只写 `./demo/`，**不读取、不修改真实集群**；`--no-ui` 跳过 UI 导出，`--keep` 保留 mock 靶场进程（Ctrl+C 结束）。

实测（Windows 11 / Python 3.12，本机 mock）：`doctor` 0.3–0.5 秒，`demo` 约 4–5 秒（多次 3.6–5.0 秒；最终复测 5.00 秒，墙钟 5.33 秒），**首次有效结果 ≤5.4 秒**；陌生用户走查基线与改造后对照见 [`docs/ONBOARDING-EVALUATION.md`](docs/ONBOARDING-EVALUATION.md)。

想用 `inkblade ...` 短命令：`python -m pip install -e .` 后即可；不装也能用 `python -m inkblade ...`。
不需要：kubeconfig、外部网络、LLM key、bash、第三方 Python 包。

---

## 能力 / Capabilities

- **七层架构**：授权治理、链编排、模块库、三层证据、双语报告、六视图 SPA、规则包转化。详见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)。
- **攻击链编排**：20 条链（经典攻击链 / 云侧权重桶链 / 网络利用链 / 零日级链），支持 dry-run 预览写面、依赖拓扑、并行执行与逐步回滚。
- **模块库**：侦察、横向利用、权限链、窃取与数据泄露、核心代码、网络架构、混合云、防护绕过、零日级漏洞模块（**共 6 个，均已公开**：dify-* 与 open-webui-*）。
- **证据三层**：上下文摘要（`context.jsonl.gz`）+ SQLite（`evidence.db`）+ 归档层（`steps/*.tar.gz` + `manifest.sha256`），支持篡改检测。
- **报告**：PTES 七段 + 五个 ML 专节 + NIST / 等保 / GB/T 20984 映射 + CVSS 3.1 + 证据锚；中英双语。
- **合规映射（2026-10）**：每条发现映射 OWASP LLM Top 10（2026 正式版，含 2025 编号 crosswalk）、OWASP Agentic AI Top 10（ASI01–ASI10）、MITRE ATLAS、NIST AI RMF、ISO/IEC 42001、EU AI Act GPAI 与 TC260/生成式AI管理办法条款；见 [`inkblade/reports/compliance.py`](inkblade/reports/compliance.py) 与 [`tests/test_compliance.py`](tests/test_compliance.py)。
- **MCP 与 agent 协作**：`inkblade mcp` 提供 5 个只读 stdio JSON-RPC 工具（复用授权锁、零写工具，MCP 2026-07-28 + 旧版 initialize 兼容）；`inkblade plan` 输出证据驱动的链推荐排序，固定 lead 审批、由人触发执行；见 [`inkblade/mcp_server.py`](inkblade/mcp_server.py)、[`inkblade/agent_planner.py`](inkblade/agent_planner.py)。
- **模型供应链与机密计算**：CycloneDX ML-BOM 风格 AI SBOM、cosign 风格 provenance 三元组校验、TDX/SEV-SNP/NVIDIA CC 证明解析与策略断言（本地 fixture 驱动，篡改必失败）；见 [`inkblade/supplychain.py`](inkblade/supplychain.py)。
- **机器可读导出**：`inkblade export --format sarif|ocsf|vex` 输出 SARIF 2.1.0、OCSF 1.x Detection Finding 与 OpenVEX 风格 JSON；见 [`inkblade/export.py`](inkblade/export.py)。
- **规则转化**：Kyverno / Gatekeeper / NetworkPolicy（native、Calico、Cilium）/ Sigma / Falco / Suricata，规则↔链覆盖率硬校验 + 紫队重放矩阵。
- **试点模式（2026-10）**：`inkblade pilot` 导入客户 kubeconfig（多文件/多 context/多 cluster 合并）→ 只读清点（仅 `kubectl get`）→ 环境画像 + 风险热图 + 分阶段测试计划（窗口/停止条件/回滚预案）+ pilot-report 与审批清单；默认只读，`--allow-write` 仍需 ROE/级别/备份三闸门。见 [`inkblade/pilot.py`](inkblade/pilot.py)、[`docs/ENTERPRISE-READINESS.md`](docs/ENTERPRISE-READINESS.md)。
- **企业集成适配（2026-10）**：OIDC/LDAP mock 登录适配、Splunk HEC / Elastic `_bulk` / Webhook HMAC / Jira / ServiceNow 契约、lead→安全负责人双签审批链、报告哈希+时间戳/签核/保留策略；本地 HTTP 契约测试。见 [`inkblade/enterprise/`](inkblade/enterprise/)。
- **企业就绪三态清单**：六类差距（真实环境/规模/数据与窗口/误报漏报/集成/合规运营）60 项，绿 36 / 黄 3 / 红 21，禁止全绿粉饰；黄项本地补验 11/11 PASS 见 [`docs/ENTERPRISE-LOCAL-VERIFICATION.md`](docs/ENTERPRISE-LOCAL-VERIFICATION.md)；POC→Lab→Pilot→Production 四阶段量化门槛见 [`docs/ENTERPRISE-READINESS.md`](docs/ENTERPRISE-READINESS.md)。真实感实验室 FP/FN 见 [`docs/ENTERPRISE-LAB-RESULTS.md`](docs/ENTERPRISE-LAB-RESULTS.md)。
- **SOTA 能力矩阵**：2026-10 公开参照对照与三态（真实验证 / 模拟验证 / 仍未达成）+ 证据路径，见 [`docs/SOTA-2026-10.md`](docs/SOTA-2026-10.md)。**企业就绪单列**，不用任一单项（pilot/适配器/实验室）冒充整体就绪。
- **免费资源补齐（2026-10-25）**：Sigstore keyless 公共验证与 Rekor 写入（[KEYLESS-VERIFICATION](docs/KEYLESS-VERIFICATION.md)）、Intel PCS / AMD KDS / NVIDIA NRAS 公共证书链（[TEE-ONLINE-VERIFICATION](docs/TEE-ONLINE-VERIFICATION.md)）、AWS/Azure/GCP emulator + 阿里/腾讯契约（[CLOUD-FREE-TIER-RUNBOOK](docs/CLOUD-FREE-TIER-RUNBOOK.md)）、1,024–10,000 节点 fabric 仿真（[FABRIC-SIM-RESULTS](docs/FABRIC-SIM-RESULTS.md)）、8 租户 SaaS 本地压测（[SAAS-LOAD-RESULTS](docs/SAAS-LOAD-RESULTS.md)）。除公共 keyless 验证/TEE 公共链外均为模拟/本地，不冒充真实硬件或云账号。
- **实效验证**：`inkblade/verify-effects.py` 在本机真实进程/真实 HTTP 上逐项验证管理面利用、权重投毒、备份回滚、RCE、数据泄露、检测规则、端到端链、长上下文/PD KV、fabric 三项、硬件两项、R01–R07 四项与 Slurm 两项（当前 53/53 PASS）；见 [`docs/EFFECT-VERIFICATION.md`](docs/EFFECT-VERIFICATION.md) 与 [`docs/LONG-CONTEXT.md`](docs/LONG-CONTEXT.md)。
- **硬件/交换机只读面（2026-10-26）**：9 个 `writes=false` 模块覆盖 GPU 驱动/固件、BMC/Redfish/IPMI、NVSwitch/NVLink、DPU/BlueField、SONiC/Cumulus、IB SM/Partition、SHARP、fabric 遥测与固件清单核验；`lab/hardware_sim.py` 配置/遥测双态 mock + fixture；三级矩阵（只读/需授权主动/必须真实硬件）与生产边界见 [`docs/HARDWARE-SWITCH-COVERAGE.md`](docs/HARDWARE-SWITCH-COVERAGE.md)。
- **ARTEX clean-room 功能对齐（2026-10）**：按公开功能描述独立实现 LLM 多模型池、通知渠道与事件规则、任务模板（含从 run 反推）、一次性日历窗口、run 内侧问、图快照/跨 run 差异、跨 run 只读黑板、已批准提议的 bounded 并发执行（1–8，默认 1）；竞争矩阵 S/M backlog 30 项已清零。功能×实现×测试×状态见 [`docs/ARTEX-PARITY.md`](docs/ARTEX-PARITY.md)。

## 能力分档 / Maturity tiers

> 三档是交付证据等级，不是营销标签。**禁止把 demo 或试点能力写成生产已验证**。

| 档位 | 本仓库能做什么（证据） | 不能宣称 / 仍需客户环境 |
|---|---|---|
| **demo** | mock 靶场真实 HTTP/进程效果验证（53/53）、单节点 k3s 真 apiserver/CNI/NetworkPolicy（6/6 模块、16 findings）、规则包 + 紫队矩阵、双语报告/证据 manifest、SPA 离线导出。 | 不能称生产就绪、支持万卡、通过客户合规认证；单节点 k3s ≠ 多节点/客户 CNI。 |
| **试点（Pilot）** | `inkblade pilot` 只读清点客户 kubeconfig（多 context/多 cluster 合并）→ 环境画像/风险热图/分阶段计划/审批清单；默认只读，写计划需 `--allow-write` + ROE/级别/备份三闸门；`docs/ENTERPRISE-READINESS.md` 的四阶段门槛与 60 项三态清单（绿 36/黄 3/红 21）。 | 不能称 pilot 已验收；误报/漏报必须在客户标注样本重测；写验证需双签/备份/窗口；fixture FP/FN 不可外推。 |
| **生产（Production）** | 本仓库提供可运营的基础：授权/证据/回滚/审批/导出/报告签核/保留策略 + HA/升级/备份 runbook。 | **本仓库不是生产发行版**：HA/多副本队列/租户 KMS/客户 IdP/真实 SIEM/ITSM/TSA 需客户环境补齐并演练；SLA/保险/合规认证需合同与客户签核。 |

**禁止宣称清单**：
- 不得称「企业生产验证通过」「万卡实测」「替代 SOC/合规认证」「零误报」；
- 不得把 `lab/saas` 单机压测、fixture FP/FN、单节点 k3s 当作客户 SLA/容量/准确率证据；
- 不得在未双签/未备份/未窗口时执行写验证；不得隐藏三态清单中的 🔴 项。

## 边界 / Boundaries

- **实验室优先**：默认靶场为 `lab/mock_targets.py` 与 `lab/longctx_sim.py`（均仅监听 `127.0.0.1`）。真实集群执行需自行提供 kubeconfig、网络可达性与授权材料。
- **不内置任何真实凭据**：fixture 与 mock 返回值均为 `MOCK*` / `FAKE*` 样值。
- **零日级模块已公开**：6 个 `dify-*` / `open-webui-*` 模块为公开模块（`private: false`），正常打包与展示细节。`inkblade/core/zeroday.py` 仅作为**默认关闭的可选加密扩展**，供未来真正未披露的私有材料使用，不构成这些公开模块的门槛。
- **效果级 vs 集群级**：本机验证为真实进程/真实 HTTP 的**效果级**证据，不等同于 live K8s 集群验证。KIND（hostNetwork 绕过 NetworkPolicy）与 ARTEX 黑盒对标需启用虚拟化后按 `lab/kind/run-proof.sh` 与 `lab/bench/artex-bench.sh` 执行。
- **ARTEX 关系（clean-room）**：ARTEX 仅作为公开功能描述与外部黑盒对标对象；本仓库的 ARTEX 对齐功能均为**独立 clean-room 实现**（依据公开功能矩阵/文档与通用协议知识，**未读取、未复制、未逐行翻译其 AGPL 源码**）。详见 [`NOTICE`](NOTICE) 与 [`docs/ARTEX-PARITY.md`](docs/ARTEX-PARITY.md)。

## Clean-room 声明 / Clean-room statement

InkBlade 的 ARTEX 对齐功能（`inkblade/core/llmpool.py`、`notify.py`、`templates.py`、`calendar.py`、`threads.py`、`graphsnap.py`、`blackboard.py` 及 explorer 并发执行）是**净室实现**：

- 输入仅为公开功能描述（功能矩阵文档、竞争矩阵、公开协议/标准）与 InkBlade 自身架构约束；
- 未读取、未复制、未改编、未逐行翻译 ARTEX（Autumn-27/ARTEX、RuoJi6/ARTEX）的 AGPL-3.0 源码；
- 接口、数据模型、安全闸门与测试均为本项目独立设计；不存在代码级派生关系。

The ARTEX-parity features are clean-room implementations derived solely from public functional descriptions and generic protocol knowledge. No ARTEX (AGPL-3.0) source code was read, copied, adapted, or line-by-line translated; interfaces, data models, gates, and tests are independently designed.

## 完整快速开始（开发者） / Full quickstart (developers)

> 首次接触请先走上面的「5 分钟上手」；本节保留安装、全量测试、前台 mock、UI 与验收脚本的开发者路径。

```bash
# 1) 安装（无运行时第三方依赖）
python -m pip install -e .

# 2) 运行测试
python -m unittest discover -s tests -v

# 3) 启动本地 mock 靶场（仅 127.0.0.1）
python lab/mock_targets.py --mode vulnerable

# 4) 查看模块清单 / 启动控制台
python -m inkblade module list --modules-dir inkblade/modules
python -m inkblade ui --port 8765

# 5) 端到端验收 + 实效验证（本机、可复现）
python inkblade/e2e-check.py
python -m inkblade.verify-effects --out reports/samples/effects/

# 6) 试点只读清点（多 kubeconfig 合并；写计划需 --allow-write + 三闸门）
python -m inkblade pilot --kubeconfig ~/.kube/config --out reports/pilot
```

工作区初始化、授权签署、四角色矩阵、链执行与报告导出的完整示例见 [`docs/RUNBOOK.md`](docs/RUNBOOK.md)。

For a minimal workspace bootstrap, consent signing, role matrix, chain execution and report export, see [`docs/RUNBOOK.md`](docs/RUNBOOK.md).

## 测试 / Tests

```bash
python -m unittest discover -s tests -v
python -m unittest tests.test_verify_effects -v   # 7 项实效验证
python scripts/check-public-tree.py                # 公开树 0 命中（无内部路径/工作区引用）
```

测试覆盖：授权与角色、模块两态（vulnerable/fixed）、链前置与执行、备份/回滚、三层证据与 manifest 篡改检测、双语报告、规则包与紫队矩阵、SPA 静态导出、公开树卫生、实效验证。

## 文档 / Documentation

| 文档 | 内容 |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | 七层架构图与职责边界 |
| [`docs/design.md`](docs/design.md) | 设计基线与漏洞研究分类（中性引用） |
| [`docs/RUNBOOK.md`](docs/RUNBOOK.md) | 安装、授权、模块/链、报告、回滚、实验室边界 |
| [`docs/ONBOARDING-EVALUATION.md`](docs/ONBOARDING-EVALUATION.md) | 陌生用户走查实测：基线 vs 改造后、命令数/耗时/失败、根因与修复清单 |
| [`docs/EFFECT-VERIFICATION.md`](docs/EFFECT-VERIFICATION.md) | 实效验证 PASS/FAIL 表与证据摘要 |
| [`docs/SOTA-2026-10.md`](docs/SOTA-2026-10.md) | 2026-10 SOTA 能力矩阵、诚实差距与追赶路径 |
| [`docs/ENTERPRISE-READINESS.md`](docs/ENTERPRISE-READINESS.md) | 六类企业差距、POC→Lab→Pilot→Production 门槛、60 项三态清单（绿/黄/红） |
| [`docs/ENTERPRISE-LAB-RESULTS.md`](docs/ENTERPRISE-LAB-RESULTS.md) | 真实感实验室：三场景 FP/FN、Kyverno/Falco/NetworkPolicy 生效状态、fixture 与真实集群分列 |
| [`docs/OPERATIONS.md`](docs/OPERATIONS.md) | HA/升级/备份/回滚 runbook、单机多租户压测、许可证与交付边界 |
| [`docs/REFLECTION-XBOW-ARTEX-KUBETRAIL.md`](docs/REFLECTION-XBOW-ARTEX-KUBETRAIL.md) | XBow/ARTEX/KubeTrail 对标反思：已对齐/待补/不补+理由（确定性执行差异化声明） |
| [`docs/DELIVERY.md`](docs/DELIVERY.md) | 交付包结构与样张说明 |
| [`docs/TRIAL.md`](docs/TRIAL.md) | 5 分钟试用 / 5-minute trial：`inkblade trial` 离线 demo、期望产物、排错 |
| [`docs/PILOT-KIT.md`](docs/PILOT-KIT.md) | 试点工具包 / pilot kit：RoE 模板、范围、指标、FP/FN 标注、退出标准 |
| [`docs/FEEDBACK.md`](docs/FEEDBACK.md) | 试用反馈表 / trial feedback form 与分诊 SLA |
| [`docs/PLUGIN-SDK.md`](docs/PLUGIN-SDK.md) | 插件 SDK / plugin SDK：清单契约、信任固定、加载器、示例 |
| [`docs/VERSIONING.md`](docs/VERSIONING.md) | 版本与兼容 / SemVer、支持窗口、LTS、弃用策略 |
| [`docs/AUDIT-PACKAGE.md`](docs/AUDIT-PACKAGE.md) | 自审包 / audit package：威胁模型、攻击面、测试证据、已知限制、外审清单 |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | 开发、测试、模块作者规范 |
| [`SECURITY.md`](SECURITY.md) | 漏洞披露政策（私密渠道 + 90 天） |

## 命名与迁移 / Naming & migration

- 项目名：**InkBlade**，中文名 **墨刃零**。GitHub 仓库名建议 `InkBlade`（当前工作目录名 `trident-2026-10` 仅为审计归档路径）。
- Python 包 / PyPI 发行名：`inkblade`；CLI：`inkblade` 或 `python -m inkblade`。
- 0.2.0 起由旧名 **Trident** 更名而来（历史记录见 [`CHANGELOG.md`](CHANGELOG.md) 与 [`docs/DEV-LOG.md`](docs/DEV-LOG.md)）。
- 兼容期（0.2.x）：旧 `trident` 命令仍保留一个版本，运行时会打印弃用提示；环境变量 `TRIDENT_*` 仍可读取但会触发 `DeprecationWarning`，请迁移到 `INKBLADE_*`。0.3.0 移除旧命令与旧变量前缀。

## 许可证 / License

Apache License 2.0 — 见 [`LICENSE`](LICENSE) 与 [`NOTICE`](NOTICE)。

Apache License 2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
