# 文档索引 / Documentation Index

> 仓库相对路径 + 一句话说明。产品路径按 `doctor → session → probe → exec/scan → report` 排列；
> 研究归档保留历史记录，不代表当前产品接口。

最近修订：2026-10-27，探针架构产品文档集；当前索引覆盖仓库内所有已跟踪文档。

## 1. 产品与使用

| 文档 | 说明 |
|---|---|
| [`docs/PRODUCT.md`](PRODUCT.md) | 产品定位、适用对象、十层检测表、第 10 层防护绕过与检测对抗 |
| [`docs/ARCHITECTURE-PROBE.md`](ARCHITECTURE-PROBE.md) | 唯一执行路径：立足→Rust 探针→通道→内部横向；父子树与零 Python 边界 |
| [`docs/PROBE-PROTOCOL.md`](PROBE-PROTOCOL.md) | 长度前缀 JSON 帧、认证、任务/结果、预算、文件分块、清理与错误码 |
| [`docs/PROBE-CHANNEL.md`](PROBE-CHANNEL.md) | 入口会话与 `kubectl exec -i` 通道：投放、SOCKS/端口转发、权限边界 |
| [`docs/PROBE-DEPLOY.md`](PROBE-DEPLOY.md) | RCE/memfd、kubectl cp/exec、EphemeralContainer、共享卷、发布物与写闸门 |
| [`docs/DYNAMIC-VERIFICATION.md`](DYNAMIC-VERIFICATION.md) | 每个模板的两态 mock 验证标准、证据格式、覆盖率字段与当前完成度 |
| [`docs/PROBE-COVERAGE.md`](PROBE-COVERAGE.md) | 生成式模板覆盖率表：模块、执行载体、两态结果、证据哈希（注意 `runtime=reference`） |
| [`docs/PROBE-MIGRATION-BRIEF.md`](PROBE-MIGRATION-BRIEF.md) | 模块模板化迁移须知：运行时契约、schema、禁止 host fallback |
| [`docs/PROBE-BUILD.md`](PROBE-BUILD.md) | Rust 探针构建：CI musl amd64/arm64、SHA-256、本机限制与自测项 |
| [`docs/INSTALL.md`](INSTALL.md) | 控制器与探针安装、容器/Helm、离线、工作区布局、首次会话 |
| [`docs/USAGE.md`](USAGE.md) | 五步主路径、典型场景、结果阅读、退出码、规则包与排障 |
| [`docs/FAQ.md`](FAQ.md) | 目标依赖、Rust 选择、投放、写闸门、迁移状态、许可与边界 |
| [`docs/DETECTION-LAYERS.md`](DETECTION-LAYERS.md) | 前九层逐层四列表的完整版（检测点/为何独有/模块键/证据） |
| [`docs/DOC-INDEX.md`](DOC-INDEX.md) | 本索引 |
| [`docs/REQUIREMENTS-MATRIX.md`](REQUIREMENTS-MATRIX.md) | **唯一需求事实源**：124 条需求、数字对账、未完成清单与依赖 |

## 2. 架构与工程

| 文档 | 说明 |
|---|---|
| [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) | 控制端七组件架构：治理、编排、模块、证据、报告、可视化、规则（检测模型为十层） |
| [`docs/design.md`](design.md) | 设计基线与早期约束；部分执行模型已被探针架构修订 |
| [`docs/MODULES.md`](MODULES.md) | 模块目录、系列、级别与键的说明 |
| [`docs/FEATURES.md`](FEATURES.md) | 功能清单与能力边界 |
| [`docs/WORKFLOW.md`](WORKFLOW.md) | 控制端工作流与阶段划分 |
| [`docs/HOW-TO-DESIGN-COMMERCIAL-AGENT.md`](HOW-TO-DESIGN-COMMERCIAL-AGENT.md) | 商用 Agent 工程手册；含 2026-10 探针架构修订章 |
| [`docs/PLUGIN-SDK.md`](PLUGIN-SDK.md) | 插件/模板 SDK、manifest、信任与校验 |
| [`docs/VERSIONING.md`](VERSIONING.md) | 版本、兼容、弃用与发布口径 |
| [`docs/OPERATIONS.md`](OPERATIONS.md) | 运营手册：HA、升级、备份、多租户、交付边界 |
| [`docs/RUNBOOK.md`](RUNBOOK.md) | 现场操作手册与故障处置 |
| [`docs/DELIVERY.md`](DELIVERY.md) | 交付包结构、证据与报告清单 |
| [`docs/PILOT-KIT.md`](PILOT-KIT.md) | 真实集群试点的最小步骤与审批清单 |
| [`docs/AUDIT-PACKAGE.md`](AUDIT-PACKAGE.md) | 审计包、发布检查与可复现性记录 |
| [`docs/FEEDBACK.md`](FEEDBACK.md) | 试用反馈模板与渠道说明（历史） |
| [`docs/TRIAL.md`](TRIAL.md) | 历史试用说明；当前产品路径不提供 demo/trial |

## 3. 验证与证据

| 文档 | 说明 |
|---|---|
| [`docs/EFFECT-VERIFICATION.md`](EFFECT-VERIFICATION.md) | 检测/利用实效验证方法与结果矩阵 |
| [`docs/EXPLOIT-VERIFICATION.md`](EXPLOIT-VERIFICATION.md) | 静态根因 + 真实上游动态复现的分类与证据 |
| [`docs/PRIVESC-VERIFICATION.md`](PRIVESC-VERIFICATION.md) | 提权链在真集群与 fake-kubectl 下的验证 |
| [`docs/PRIVESC-MATRIX.md`](PRIVESC-MATRIX.md) | P1–P6 提权链矩阵、前置条件与检测建议 |
| [`docs/REAL-CLUSTER-VERIFICATION.md`](REAL-CLUSTER-VERIFICATION.md) | 真实 k3s 集群上的探测与证据记录 |
| [`docs/ENTERPRISE-LAB-RESULTS.md`](ENTERPRISE-LAB-RESULTS.md) | 企业真实感实验室的结果与偏差 |
| [`docs/DEFENSE-LAB-RESULTS.md`](DEFENSE-LAB-RESULTS.md) | 第 10 层防护绕过在 QEMU k3s 真机的部署与回放结果（4 产品 + 7 个 N/A 原因） |
| [`docs/ENTERPRISE-LOCAL-VERIFICATION.md`](ENTERPRISE-LOCAL-VERIFICATION.md) | 企业黄项的本地补验记录 |
| [`docs/ENTERPRISE-READINESS.md`](ENTERPRISE-READINESS.md) | 企业就绪差距、准入门与 50+ 检查项 |
| [`docs/KILL-CHAIN.md`](KILL-CHAIN.md) | 内网入口到集群最高权限的夺权链与证明 |
| [`docs/SECTION3-METRICS.md`](SECTION3-METRICS.md) | 腾讯 Agent 渗透大赛对标的 OFF/ON 实测 |
| [`docs/SECTION3-TENCENT-AGENT-CONTEST.md`](SECTION3-TENCENT-AGENT-CONTEST.md) | 参赛项目对比、产品化策略与差距 |
| [`docs/ARTEX-BENCH-RESULT.md`](ARTEX-BENCH-RESULT.md) | ARTEX 在虚拟化 k3s 环境中的实跑对标结果 |
| [`docs/ARTEX-PARITY.md`](ARTEX-PARITY.md) | ARTEX clean-room 功能对齐清单 |
| [`docs/KUBETRAIL-PORT.md`](KUBETRAIL-PORT.md) | KubeTrail 最小闭环移植说明与许可边界 |
| [`docs/CHAOS-PARITY.md`](CHAOS-PARITY.md) | 混沌/扰动编排对照：Chaos Mesh、LitmusChaos、Chaos Toolkit |
| [`docs/CIS-PARITY.md`](CIS-PARITY.md) | CIS 基准库与 kube-bench 的对照 |
| [`docs/LPE-PARITY.md`](LPE-PARITY.md) | 内核提权检测库与 KubeTrail 的对照 |
| [`docs/PROBE-PARITY.md`](PROBE-PARITY.md) | LLM 探针对标（garak/PyRIT/promptfoo），与 Pod 探针不是同一层 |
| [`docs/KEYLESS-VERIFICATION.md`](KEYLESS-VERIFICATION.md) | Sigstore keyless 校验记录 |
| [`docs/TEE-VERIFICATION.md`](TEE-VERIFICATION.md) | TEE 证明的本地密码学校验与硬件实测边界 |
| [`docs/TEE-ONLINE-VERIFICATION.md`](TEE-ONLINE-VERIFICATION.md) | TEE 厂商公共证书链的在线验证记录 |
| [`docs/SIX-CLOUD-MATRIX.md`](SIX-CLOUD-MATRIX.md) | 六云契约级验证矩阵：ID、桶、快照、网络策略 |
| [`docs/SAAS-LOAD-RESULTS.md`](SAAS-LOAD-RESULTS.md) | SaaS 多租户本地压测结果 |
| [`docs/SCALE-RESULTS.md`](SCALE-RESULTS.md) | 合成快照与真 k3s 200 对象点的规模压测 |
| [`docs/PERFORMANCE-COMPARISON.md`](PERFORMANCE-COMPARISON.md) | 性能实测矩阵、方法学与未测项 |
| [`docs/OSS-BENCH.md`](OSS-BENCH.md) | 开源工具性能实测与对比 |
| [`docs/UI-PERF.md`](UI-PERF.md) | 10,000 条 findings 的渲染性能与优化 |
| [`docs/UX-EVALUATION.md`](UX-EVALUATION.md) | UX 产品化评估：错误文案、空态、双语、kubeconfig→pilot |
| [`docs/ONBOARDING-EVALUATION.md`](ONBOARDING-EVALUATION.md) | 陌生用户走查与零摩擦改造评估 |
| [`docs/AI-SCAN-RESULT.md`](AI-SCAN-RESULT.md) | 公开文档的 AI 相似度扫描结果、方法与稳定性说明 |

## 4. 研究覆盖与专项

| 文档 | 说明 |
|---|---|
| [`docs/AI-GATEWAY.md`](AI-GATEWAY.md) | AI 网关与配套基建专项：密钥、配额、缓存、上游泄露 |
| [`docs/CACHE-SECURITY.md`](CACHE-SECURITY.md) | 多租户推理缓存安全：前缀、语义、逐出、远程 KV |
| [`docs/CHIP-SECURITY-SCOPE.md`](CHIP-SECURITY-SCOPE.md) | 芯片/加速器安全姿态范围：CC、SPDM、IOMMU、CXL |
| [`docs/CONFERENCE-2026-GAPS.md`](CONFERENCE-2026-GAPS.md) | 2026 安全会议 infra/AI-infra 议题覆盖矩阵 |
| [`docs/CVE-APPLICABILITY.md`](CVE-APPLICABILITY.md) | CVE 适用性：版本区间 × 前置条件 × 环境实测 |
| [`docs/CVE-CATALOG.md`](CVE-CATALOG.md) | 公开 CVE 武器库与适用面目录 |
| [`docs/DEPTH-REVIEW.md`](DEPTH-REVIEW.md) | 研究级深度复核：vLLM、准入、eBPF、GPU、fabric、身份 |
| [`docs/FABRIC-ATTACK-SURFACE.md`](FABRIC-ATTACK-SURFACE.md) | 万卡集群破坏性漏洞面：IB、RoCE、SHARP、NCCL |
| [`docs/FABRIC-SIM-RESULTS.md`](FABRIC-SIM-RESULTS.md) | fabric 仿真结果与 PFC 场景 |
| [`docs/GPU-CLOUD-TENANCY.md`](GPU-CLOUD-TENANCY.md) | GPU 组卡/池化平台与云平台的跨租户测试族 |
| [`docs/HARDWARE-SWITCH-COVERAGE.md`](HARDWARE-SWITCH-COVERAGE.md) | 硬件与交换机面覆盖 |
| [`docs/INFRA-COVERAGE-2026.md`](INFRA-COVERAGE-2026.md) | 2026 infra 覆盖总表与去重说明 |
| [`docs/LONG-CONTEXT.md`](LONG-CONTEXT.md) | 长上下文与大规模训练专项 |
| [`docs/OSS-ML-CLUSTER-TOOLS.md`](OSS-ML-CLUSTER-TOOLS.md) | 开源 ML 集群测试工具全景 |
| [`docs/PRETRAIN-SFT-RL-COVERAGE.md`](PRETRAIN-SFT-RL-COVERAGE.md) | 预训练/SFT/RL 训练栈覆盖矩阵 |
| [`docs/RESEARCH-COVERAGE.md`](RESEARCH-COVERAGE.md) | 万卡语料检索覆盖声明与重收口径 |
| [`docs/RESIDUAL-GAPS-2026.md`](RESIDUAL-GAPS-2026.md) | R01–R07 残余缺口落地 |
| [`docs/SLURM-HPC-COVERAGE.md`](SLURM-HPC-COVERAGE.md) | Slurm HPC 攻击面深度 |
| [`docs/SOTA-2026-10.md`](SOTA-2026-10.md) | SOTA 能力矩阵与差距 |
| [`docs/SURFACE-REALISM.md`](SURFACE-REALISM.md) | 真实部署面、模块可测性与隔离口径 |
| [`docs/WEAPON-READINESS.md`](WEAPON-READINESS.md) | 暴露面分类、验证与一键包的就绪度 |
| [`docs/GAP-ATTACK-SURFACE.md`](GAP-ATTACK-SURFACE.md) | 逐工具的攻击面缺失全量表 |
| [`docs/GAP-FEATURES.md`](GAP-FEATURES.md) | 逐工具的功能缺失全量表 |
| [`docs/GAP-PAYLOADS.md`](GAP-PAYLOADS.md) | 逐工具的 payload 缺失全量表 |
| [`docs/COMPETITIVE-MATRIX.md`](COMPETITIVE-MATRIX.md) | 竞品对比矩阵与能力差距 |
| [`docs/FEATURE-BY-FEATURE-ARTEX.md`](FEATURE-BY-FEATURE-ARTEX.md) | ARTEX 逐功能穷举对比 |
| [`docs/FEATURE-BY-FEATURE-KUBETRAIL.md`](FEATURE-BY-FEATURE-KUBETRAIL.md) | KubeTrail 逐功能穷举对比 |
| [`docs/REFLECTION-ARTEX-KUBETRAIL.md`](REFLECTION-ARTEX-KUBETRAIL.md) | ARTEX × KubeTrail 对标反思 |
| [`docs/REFLECTION-XBOW-ARTEX-KUBETRAIL.md`](REFLECTION-XBOW-ARTEX-KUBETRAIL.md) | XBow × ARTEX × KubeTrail 对标反思 |

## 5. Agent、运营与历史

| 文档 | 说明 |
|---|---|
| [`docs/AGENT-ARCHITECTURE-2026.md`](AGENT-ARCHITECTURE-2026.md) | 2026 Agent 架构研究与差距反思 |
| [`docs/AGENT-ARCHITECTURE-UPGRADE-2026.md`](AGENT-ARCHITECTURE-UPGRADE-2026.md) | Agent 架构升级实施说明 |
| [`docs/AGENT-AUTONOMY.md`](AGENT-AUTONOMY.md) | 事件溯源图运行时、调度/worker/协议/评测与一次授权边界 |
| [`docs/AGENT-EVAL-RESULTS.md`](AGENT-EVAL-RESULTS.md) | deterministic vs supervisor-worker 的评测结果 |
| [`docs/AUTONOMY.md`](AUTONOMY.md) | L3 预授权、硬边界与可回放 |
| [`docs/SWARM-EVAL.md`](SWARM-EVAL.md) | 1 个 vs 4 个角色化 worker 的评测 |
| [`docs/MASTER-REPORT.md`](MASTER-REPORT.md) | 总报告：把 ML 集群渗透测试做成可复述、可复核、可复跑的事 |
| [`docs/DEV-LOG.md`](DEV-LOG.md) | 开发台账与决策记录 |
| [`docs/README-SITE.md`](README-SITE.md) | 站点源码与发布方式 |
| [`docs/CLOUD-FREE-TIER-RUNBOOK.md`](CLOUD-FREE-TIER-RUNBOOK.md) | 六云免费/最小集群 Runbook |
| [`docs/0DAY-PUBLIC.md`](0DAY-PUBLIC.md) | 历史 0day 公开台账（归档，不属于产品路径） |
| [`docs/0DAY-RESERVE.md`](0DAY-RESERVE.md) | 历史 0day 储备台账（归档） |
| [`docs/0DAY-DISCLOSURE.md`](0DAY-DISCLOSURE.md) | 历史披露流程（归档） |
| [`docs/artex-parity-rows.json`](artex-parity-rows.json) | ARTEX 对标行数据（机器可读） |
| [`docs/feature-matrix.json`](feature-matrix.json) | 功能矩阵数据（机器可读） |
| [`docs/gap-matrix.json`](gap-matrix.json) | 差距矩阵数据（机器可读） |
| [`docs/oss-ml-cluster-tools.json`](oss-ml-cluster-tools.json) | 开源工具清单数据（机器可读） |
| [`docs/en/index.html`](en/index.html) | 英文站点首页 |
| [`docs/zh/index.html`](zh/index.html) | 中文站点首页 |
| [`docs/index.html`](index.html) | 站点入口 |
| [`docs/assets/style.css`](assets/style.css) | 站点样式 |
| [`docs/assets/app.js`](assets/app.js) | 站点脚本 |

## 证据 / 限制

**证据**

- 本索引覆盖 `docs/` 下的 Markdown 文档、机器可读 JSON、双语站点页与静态资源；链接目标均可在仓库内解析。
- 产品路径的 10 份文档与 `README.md` / `README.zh-CN.md` 由 `tests/test_docs_index.py` 断言存在并出现在本索引。

**限制**

- 研究归档文档（0day、披露、历史试用）保留原文，不代表当前产品接口或当前发布状态。
- 部分历史文档描述的是探针架构修订前的执行模型；以 `docs/ARCHITECTURE-PROBE.md` 为准。
- 索引只保证链接存在，不保证历史文档中的数字仍与当前工作树一致；当前口径以对应文档的证据节为准。
