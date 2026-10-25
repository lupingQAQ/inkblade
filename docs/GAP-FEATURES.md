# 功能缺失全量表（逐工具）

来源：docs/gap-matrix.json（生成于 2026-10-25）；状态口径：{"we-have": "已有对等能力（maps_to 给出模块/功能键）", "partial": "部分覆盖（missing 字段说明缺什么）", "missing": "未覆盖"}

| 工具 | 类别 | 条目 | 来源 | 我们的状态 | 缺失内容 | 行动项 |
|---|---|---|---|---|---|---|
| XBow | 自主渗透（商业） | 数千 agent 并行自主攻击（无人驱动） | https://xbow.com/ | partial | 我们是单机串行 runner + 并行链调度，无多 agent 并发执行 | CM-31（多租户并发/分布式调度，登记） |
| XBow | 自主渗透（商业） | finding=完整案卷（链路+exploit+请求响应+复现步骤） | https://xbow.com/ | we-have | - | 已对齐（三层证据+双语报告） |
| XBow | 自主渗透（商业） | 确定性复现检查（GA 类 finding 机器复核）+ 免费无限复测 | https://xbow.com/ | partial | 缺 retest 工作流（修复后重放闭环） | CM-14 |
| XBow | 自主渗透（商业） | 工单系统直投 + 代码级修复建议 | https://xbow.com/ | missing | 无 ticketing 连接器 | CM-15 |
| XBow | 自主渗透（商业） | 每步决策/战术全量留档 | https://xbow.com/ | partial | 规划器推荐理由留档未全量入证据库 | CM-03 |
| XBow | 自主渗透（商业） | 范围/限速/测试窗口护栏 + command checker 阻断破坏性动作 | https://xbow.com/ | we-have | - | 已对齐（ROE 锁/备份闸/91 拦截） |
| XBow | 自主渗透（商业） | 持续或按需运行，小时级首批 findings | https://xbow.com/ | missing | 无调度器 | CM-04 |
| XBow | 自主渗透（商业） | 数据驻留（澳/加/日）+ SOC2/ISO27001/ISO42001/PCI/NIS2 | https://xbow.com/blog | missing | 无 SaaS 多驻留形态（刻意不做，单机交付） | 不入 backlog（平台形态差异） |
| ARTEX | 自主渗透（开源） | 多 agent 协作（goals/planner/worker/reporter 分工） | agent/mainagent.go+planner.go+worker.go | partial | 我们有 agent_planner 推荐+lead 审批，但无自主执行 agent 池（Ruling 规划≠执行） | 维持 Ruling，不跟进自主执行 |
| ARTEX | 自主渗透（开源） | 多模型池 llmpool（并发 LLM worker） | llmpool/ 目录 | missing | 刻意不做（REFLECTION-ARTEX-KUBETRAIL §2） | 不入 backlog |
| ARTEX | 自主渗透（开源） | 人工审批拦截 intercept | intercept/ 目录 | we-have | - | 已对齐 |
| ARTEX | 自主渗透（开源） | 探索血缘图（goal→intent→fact→finding 边） | agent/coldgraph.go+blackboard 继承测试 | missing | 血缘边未建 | CM-16 |
| ARTEX | 自主渗透（开源） | 同根因漏洞归并+统一报告 | agent/finding_workflow.go+finding_cases.go | partial | 跨 run 归并工作流缺 | CM-17 |
| ARTEX | 自主渗透（开源） | 任务情报登记（凭据/线索 registry） | agent/intelligence.go+credentials.go | missing | 无 run 级情报集中登记 | CM-01 |
| ARTEX | 自主渗透（开源） | 任务级 REST API + PostgreSQL 持久化 + Web UI | server/ + db/ + web/ | partial | 我们有 WebUI+内部 HTTP API，无对外契约与 DB 持久化 | CM-02（检索 API）；API 契约归 SOTA 未达成项 |
| ARTEX | 自主渗透（开源） | C2 MCP 集成入口（外部 operator 基础设施） | agent/tools.go（C2 工具）+ KubeTrail README 同类注记 | missing | 刻意不做（可审计交付定位） | 不入 backlog（REFLECTION §2） |
| ARTEX | 自主渗透（开源） | retester 复测 agent | agent/retester.go | partial | 无自动 retest | CM-14 |
| NodeZero | 自主渗透（商业） | agentless 内网 Docker host/OVA + 外网云端执行 | https://horizon3.ai/nodezero/ | partial | 我们单机 CLI 控制台，无内网 host 部署形态 | 部署形态差异，不入 backlog |
| NodeZero | 自主渗透（商业） | 每日定时连续测试调度 | https://horizon3.ai/nodezero/ | missing | 无 cron 调度器 | CM-04 |
| NodeZero | 自主渗透（商业） | Sankey 攻击路径图 + 系统性修复优先级（修一处消 N% 路径） | https://horizon3.ai/nodezero/ | missing | WebUI 有攻击链图但无 Sankey+量化修复优先级 | CM-19 |
| NodeZero | 自主渗透（商业） | Quick Verify 修复复测 | https://horizon3.ai/nodezero/ | missing | retest 闭环 | CM-14 |
| NodeZero | 自主渗透（商业） | 实时攻击视图（RealTime View） | https://horizon3.ai/nodezero/ | we-have | - | 已对齐 |
| NodeZero | 自主渗透（商业） | OSINT 定制 + 一次性 VPC 隔离资源 | https://horizon3.ai/nodezero/ | missing | 无 OSINT 集成面 | 不入 backlog（基础设施面正交） |
| NodeZero | 自主渗透（商业） | Fix Action 报告 + Splunk 等下游投递 | https://horizon3.ai/nodezero/ad-password-audit/ | partial | 有双语修复报告，无 SIEM 直投 | CM-15（SIEM 连接器并入） |
| Pentera | 自主渗透（商业） | CTEM 全生命周期（Ingest/Dedupe/Enrich/Prioritize/Assign/Revalidate） | https://pentera.io/pentera-platform/ | partial | 报告叙事未按 CTEM 五阶段章节化 | CM-20 |
| Pentera | 自主渗透（商业） | 自动开单+路由到 owner（ticketing 集成） | https://pentera.io/pentera-platform/ | missing | 无 ticketing 连接器 | CM-15 |
| Pentera | 自主渗透（商业） | 修复后 re-test 出审计级闭环证明 | https://pentera.io/pentera-platform/ | partial | retest 留档闭环 | CM-14 |
| Pentera | 自主渗透（商业） | AI-Web Attack Execution（AI 生成自适应 payload） | https://pentera.io/pentera-platform/ | missing | payload 为确定性 fixture/变体驱动，无生成式自适应（刻意：可审计确定性） | 不入 backlog（确定性口径 Ruling） |
| Pentera | 自主渗透（商业） | 攻击节流/影响上限/紧急停止/只读模式 | https://pentera.io/pentera-platform/ | we-have | - | 已对齐 |
| Pentera | 自主渗透（商业） | 8 类集成（云安全/代码安全/EASM/身份 SSO/工单/平台/自带数据） | https://pentera.io/pentera-platform/ | partial | MCP 只读 5 工具 + SARIF/OCSF/OpenVEX 导出；无 SIEM/工单/SSO 直连 | CM-15 + SOTA D17 未达成项 |
| KubeTrail | K8s 攻防（克隆） | safe/full 双模式（full 含主动探测 dry-run/syscall） | README.en.md Key Features | we-have | - | 已对齐 |
| KubeTrail | K8s 攻防（克隆） | 敏感证据 raw/redact/metadata 三态 | README.en.md Sensitive data egress protection | we-have | - | 已对齐（CM-06） |
| KubeTrail | K8s 攻防（克隆） | rbac-mode focused/full（SSRR/SSAR 全矩阵+通配符展开） | README.en.md Server Options | we-have | - | 已对齐（CM-05） |
| KubeTrail | K8s 攻防（克隆） | in-pod 原生采集（免 kubectl，in-cluster SA） | README.en.md | we-have | - | 已对齐（CM-22） |
| KubeTrail | K8s 攻防（克隆） | AI 动态攻击编排（Claude/Codex + EXP Forge + C2 MCP） | README.en.md AI dynamic attack orchestration | partial | agent_planner 推荐+审批已有；EXP Forge/C2 不做 | 维持 Ruling（自主执行/C2 刻意不做） |
| KubeTrail | K8s 攻防（克隆） | 桌面后渗透工作台（kubeconfig/端口转发/文件访问） | README.en.md Local post-exploitation workbench | missing | 刻意不做（可审计交付 vs 交互后渗透台，REFLECTION §2） | 不入 backlog |
| KubeTrail | K8s 攻防（克隆） | 持久化模板快速生成（SA/RBAC/CSR/sidecar/pull secret/CronJob） | README.en.md Fast persistence workflows | missing | 持久化模板面（演示类）不设 | 不入 backlog（授权演练边界） |
| KubeTrail | K8s 攻防（克隆） | dbus.json 导出 + 交互分析 | core/auditlog.py::adapt_kubetrail（适配器已接） | we-have | - | 已对齐 |
| KubeHound | K8s 攻防（克隆） | dump→ingest→Gremlin 图自动构建 | README + backend/ | we-have | - | 已对齐 |
| KubeHound | K8s 攻防（克隆） | 最短攻击路径/关键节点自动计算 + 图查询 DSL | docs/reference/queries/ + README | we-have | - | 已对齐（CM-23） |
| KubeHound | K8s 攻防（克隆） | KHaaS 服务化（API 多租户） | docs/khaas/ | missing | 多租户 SaaS 未达成（SOTA 同源） | CM-31 同源登记 |
| KubeHound | K8s 攻防（克隆） | MITRE ATT&CK 映射的边语义 | docs/reference/attacks/index.md MITRE 列 | we-have | - | 已对齐 |
| kube-hunter | K8s 攻防（克隆，官方声明停更） | 四种运行模式（remote/pod/interface/CIDR 扫描） | README + kube_hunter/core | partial | 我们有 QEMU 真集群+mock 靶场，无 CIDR 网段远程扫描模式 | CM-08 同源（kubelet CIDR 面） |
| kube-hunter | K8s 攻防（克隆，官方声明停更） | active hunting opt-in（默认只读） | README（active hunting 说明） | we-have | - | 已对齐 |
| kube-hunter | K8s 攻防（克隆，官方声明停更） | VID 漏洞知识库条目 | docs/vid/（VID KB） | we-have | - | 已对齐（CM-07） |
| kube-hunter | K8s 攻防（克隆，官方声明停更） | 停更声明与 Trivy 承接 | README 首行（2026-10-25 核验） | we-have | - | 已对齐（态势记录） |
| Peirates | K8s 攻防（官方 README） | 交互式攻击操作台（sa-context 切换/namespace 切换） | docs/commands/README.md | missing | 刻意不做（可审计交付定位，COMPETITIVE-MATRIX §4 Peirates 行：无补齐项） | 不入 backlog |
| Peirates | K8s 攻防（官方 README） | 一次性模块模式（peirates -m '<command>' 非交互） | docs/commands/README.md | we-have | - | 已对齐 |
| Peirates | K8s 攻防（官方 README） | 多上下文批量尝试（kubectl-try-all-until-success） | docs/commands/README.md | partial | 多凭据上下文轮试面 | 并入 CM-21（凭据验证） |
| kdigger | K8s 攻防（官方 README） | 插件式 bucket 架构（可扩展 template） | README.md How is this tool built | we-have | - | 已对齐 |
| kdigger | K8s 攻防（官方 README） | json/human 双输出 | README.md Usage | we-have | - | 已对齐 |
| kdigger | K8s 攻防（官方 README） | 副作用开关（--side-effects 默认关） | README.md dig flags | we-have | - | 已对齐 |
| CDK | K8s 攻防（官方 README） | evaluate→推荐 exploit 衔接 | README.md Quick Start | we-have | - | 已对齐 |
| CDK | K8s 攻防（官方 README） | 零依赖单二进制 + thin/upx 发行形态 | README.md Overview/Release Document | missing | 部署形态差异（控制台不在目标容器内执行，刻意不跟进） | 不入 backlog（COMPETITIVE-MATRIX §4 已记） |
| KubeletCTL | K8s 攻防（官方 README） | CIDR 网段 kubelet 开放扫描（scan --cidr） | README.md What can it do | missing | CIDR 扫描模式 | CM-08 |
| KubeletCTL | K8s 攻防（官方 README） | 全容器并行命令执行 | README.md What can it do | missing | 并行 exec（同 CM-08 范围） | CM-08 |
| KubeletCTL | K8s 攻防（官方 README） | 全容器 SA token 收割 | README.md What can it do | missing | token 收割面 | CM-08 |
| KubeletCTL | K8s 攻防（官方 README） | RCE 容器扫描（cri exec） | README.md + API_TABLE /cri | missing | 同上 | CM-08 |
| Falco | 运行时/准入（官方文档） | 宏/列表复用编写模型（macro/list 组合降噪） | falco.org/docs/rules | partial | 规则生成无宏/列表复用机制 | CM-09 |
| Falco | 运行时/准入（官方文档） | 多路输出通道（stdout/file/syslog/program/http + falcosidekick） | falco.org/docs/alerting | missing | 输出分发通道 | CM-10 |
| Falco | 运行时/准入（官方文档） | syscall+插件双事件源 | falco.org/docs/concepts | partial | 我们的 Falco 目标以 syscall 语义为主；插件源不适用（我们是生成方） | 域内对齐 |
| Falco | 运行时/准入（官方文档） | maturity 分级与 MITRE 标签体系 | default-rules 页每规则 Maturity/Tags 字段 | we-have | - | 已对齐（结构等价） |
| Tetragon | 运行时/准入（官方文档） | 内核态实时阻断（syscall 完成前 kill 进程） | tetragon.io/docs/overview/（enforcement 原文） | missing | TracingPolicy 规则目标（拦截态入紫队矩阵） | CM-25 |
| Tetragon | 运行时/准入（官方文档） | TracingPolicy CRD（任意内核函数 hook：kprobe/fprobe/tracepoint/LSM） | tetragon.io/docs/overview/ | missing | 同上（rules/generate 新目标） | CM-25 |
| Tetragon | 运行时/准入（官方文档） | K8s 身份感知过滤（namespace/pod 维度策略） | tetragon.io/docs/overview/ | we-have | - | 已对齐（生成方语义） |
| KubeArmor | 运行时/准入（官方 README+官网） | LSM 内联阻断（AppArmor/SELinux/BPF-LSM 三后端） | kubearmor.io + README | missing | KubeArmorPolicy/ClusterPolicy 规则目标 | CM-26 |
| KubeArmor | 运行时/准入（官方 README+官网） | policy-templates 社区模板库 | README Related Repositories policy-templates | missing | 基线模板目录（并入 CM-37） | CM-37 |
| KubeArmor | 运行时/准入（官方 README+官网） | karmor CLI + otel/prometheus/kafka/log-client 生态 | README Related Repositories | partial | 导出侧有 SARIF/OCSF/OpenVEX；遥测消费生态不做 | 域内对齐 |
| KubeArmor | 运行时/准入（官方 README+官网） | modelarmor 子项目（pickle 注入 PoC/对抗演示） | README Specialised projects modelarmor | we-have | - | 已对齐（pickle 面更深） |
| Kyverno | 运行时/准入（官方 docs+政策库） | validate/mutate/generate/verifyImages/cleanup 五种规则类型 + CEL（vpol）新系 | kyverno.io/docs/policy-types | partial | 我们的 Kyverno 目标为 validate 类；CEL/verifyImages 缺 | CM-27 |
| Kyverno | 运行时/准入（官方 docs+政策库） | 存量资源 background 扫描（audit 已有资源） | kyverno.io/docs/policy-types background scans | missing | policy audit 对存量对象 | CM-28 |
| Kyverno | 运行时/准入（官方 docs+政策库） | kyverno CLI apply/test/scan（策略试运行与测试） | kyverno.io/docs/kyverno-cli | partial | 我们的 validate 重放等价 apply/test；scan 对存量并入 CM-28 | CM-28 |
| Kyverno | 运行时/准入（官方 docs+政策库） | generate NetworkPolicy（nap-pol 自动补网隔） | kyverno.io/policies（generate 类目） | partial | 我们有 per-CNI 三变体 NetworkPolicy 输出，无「发现缺失→自动生成建议」闭环 | 并入 CM-28（网隔建议生成） |
| Gatekeeper | 运行时/准入（官方库） | ConstraintTemplate+Constraint 对偶结构 | gatekeeper-library 目录结构 | we-have | - | 已对齐 |
| Gatekeeper | 运行时/准入（官方库） | 存量资源 audit 重扫 | gatekeeper docs audit | missing | 对存量对象审计 | CM-28 |
| Gatekeeper | 运行时/准入（官方库） | mutation 与 external data | gatekeeper docs | missing | 类别外（我们只生成 validate 类） | 记录不做（域外） |
| garak | AI/LLM 安全（克隆） | probe→detector 配对扫描管线（--list_probes/--spec 选择） | garak/README.md + probes/__init__.py 注册 | partial | 无模型行为面探针库（基础设施面为主） | CM-32 |
| garak | AI/LLM 安全（克隆） | JSONL 报告 + 评分（vulnerability rate 汇总） | garak/report/ | we-have | - | 已对齐（结构） |
| garak | AI/LLM 安全（克隆） | buffs/生成器生态（多后端适配） | garak/generators/ + buffs/ | partial | 我们有 lab 仿真器族（真 HTTP 两态）；模型后端适配器不做 | 域内对齐 |
| PyRIT | AI/LLM 安全（克隆） | 开箱多轮攻击编排（Crescendo/TAP/Skeleton Key） | pyrit/executor/attack/multi_turn/ | partial | 链式多轮升级模板（模型行为域） | CM-29 |
| PyRIT | AI/LLM 安全（克隆） | 评分器框架（scorable/score_aggregator） | pyrit/score/ | partial | finding 判定 scoring 框架（我们的 findings 规则判定为固定阈值） | CM-29 并入 |
| PyRIT | AI/LLM 安全（克隆） | DB 记忆（跨会话攻击记忆） | pyrit/memory/ | partial | 跨 run 检索 API（CM-02 同源） | CM-02 同源 |
| PyRIT | AI/LLM 安全（克隆） | CoPyRIT GUI 人在环 | doc/index.md | we-have | - | 已对齐 |
| promptfoo | AI/LLM 安全（克隆） | CI/CD exit code 契约（阈值判定退出码） | src/redteam/ + README CI 文档 | missing | CLI 退出码契约 | CM-11 |
| promptfoo | AI/LLM 安全（克隆） | 声明式 yaml 评估配置 + Web 对比视图 | promptfooconfig.yaml 体系 + web viewer | partial | yaml 驱动评估矩阵缺；Web 对比视图已对齐（SPA 六视图） | CM-12 |
| promptfoo | AI/LLM 安全（克隆） | MCP target/provider 支持 | src/redteam/mcpTargetProvider.ts+mcpToolCall.ts | we-have | - | 形态差异记录 |
| promptfoo | AI/LLM 安全（克隆） | 代码扫描（红队用例生成于代码库） | src/redteams code scanning 文档 | partial | 我们有 python-dangerous-sinks 代码扫描（不同目的）；红队用例派生不做 | 记录不做（域外） |
| AgentDojo | AI/LLM 安全（克隆） | 基准 CLI（suite/task/model/defense/attack 五维参数化评测） | src/agentdojo/benchmark.py+task_suite/ | missing | 套件化基准评分（lab/mocks 已有基础设施） | CM-30 |
| AgentDojo | AI/LLM 安全（克隆） | 防御注入框架（defense 参数化） | src/agentdojo/agent_pipeline/ | partial | 紫队矩阵有攻防对偶；基准化 defense 注入缺 | CM-30 并入 |
| AgentDojo | AI/LLM 安全（克隆） | 结果页 + Invariant Benchmark Registry 挂载 | README results page 声明 | partial | SPA 六视图等价（本地产物）；外部 Registry 不做 | 域内对齐 |
| Trivy | 其他（官方 README） | k8s 集群扫描 + Trivy Operator 常驻 | README trivy k8s + Ecosystem | partial | 我们有 import_scan 适配器路径（CM-13）；常驻 Operator 形态不做 | CM-13；Operator 形态记录不做 |
| Trivy | 其他（官方 README） | CI 集成（GitHub Actions/VS Code） | README Ecosystem | partial | exit code 契约（CM-11）后可接 CI | CM-11 |
| Trivy | 其他（官方 README） | 多格式输出（CycloneDX/SPDX/SARIF 等） | trivy.dev 文档 | we-have | - | 已对齐 |
| Syft | 其他（官方 README） | 多格式 SBOM + 格式互转 | README Features（conversion） | partial | 我们输出 CycloneDX ML-BOM 单格式；转换矩阵缺 | CM-13 并入（格式转换） |
| Syft | 其他（官方 README） | in-toto 签名 attestation | README Features | we-have | - | 已对齐 |
| Syft | 其他（官方 README） | 多扫描目标（镜像/文件系统/归档/OCI/Docker/Singularity） | README Features | partial | 我们 SBOM 面向模型权重链；容器镜像/FS 扫描目标缺 | 并入 CM-13 |
| kube-bench | 其他（官方 README+cfg 枚举） | 版本自适应检查集选择（按 K8s 版本） | README Running | partial | 按 K8s 版本自动选择 profile（当前依赖快照显式 profile） | 已部分对齐（CM-33） |
| kube-bench | 其他（官方 README+cfg 枚举） | job.yaml 集群内执行形态 | README Quick start | partial | 我们是控制台侧快照驱动；节点内执行形态不做 | CM-33 落地时以快照等价实现 |
| kube-bench | 其他（官方 README+cfg 枚举） | JSON/junit 输出 | docs/running.md | we-have | - | 已对齐（导出层） |
| KubiScan | K8s 攻防（新克隆） | risky RBAC 实体枚举（roles/clusterroles/rolebindings/subjects/pods ×any 组合 + -a all） | KubiScan.py risky-* flag 族 | we-have | - | 已对齐（CM-36） |
| KubiScan | K8s 攻防（新克隆） | CVE 扫描开关（-cve，40 条 K8s CVE 库） | KubiScan.py --cve + CVE.json | missing | K8s CVE 检查库 | CM-35（并入原语库） |
| KubiScan | K8s 攻防（新克隆） | join token 提取（-jt） | KubiScan.py --join-token | missing | 节点加入凭据面（类别外：节点攻陷后动作） | 记录不做（域外） |
| KubiScan | K8s 攻防（新克隆） | JSON 导出 + 深度 Pod 扫描（-d deep） | KubiScan.py -j/-d | we-have | - | 已对齐（机制） |
| DeepCE | K8s 攻防（新克隆） | 纯 sh 零依赖单脚本（最大化容器兼容） | README 首段 | missing | 部署形态差异（控制台不在目标容器执行，与 CDK 同 Ruling） | 不入 backlog |
| DeepCE | K8s 攻防（新克隆） | 容器内网络扫描（其他容器+宿主端口扫描） | README Enumerations | partial | in-pod 采集器内含（CM-22） | CM-22 并入 |
| trufflehog | 密钥扫描（新克隆） | 800+ 密钥类型分类归因（identity 映射） | README（classifies over 800 secret types） | missing | 通用密钥分类规则库 | CM-34 |
| trufflehog | 密钥扫描（新克隆） | 700+ 主动验证 detector（对各自 API 验证凭据活性） | README（700 credential detectors with active verification） | partial | 凭据活性验证有场景级（supply-chain-credential-theft 尾4位 + CM-21 规划）；按密钥类型的规模化验证缺 | CM-34 + CM-21 协同 |
| trufflehog | 密钥扫描（新克隆） | 多源扫描（git/s3/gcp 等数十 source） | pkg/sources/ | missing | 仓库/对象存储源扫描 | CM-34 并入（源适配） |
| gitleaks | 密钥扫描（新克隆） | detect/protect 双命令（扫描与 pre-commit 防护） | cmd/ 目录结构 | missing | pre-commit 防护形态不做（攻方定位）；扫描侧见 CM-34 | CM-34（仅扫描侧） |
| gitleaks | 密钥扫描（新克隆） | baseline/.gitleaksignore 抑制机制 | .gitleaksignore 文件 | partial | findings 去重有（evidence 锚）；规则级 baseline 缺 | CM-34 并入 |
| Giskard | AI/LLM 安全（新克隆） | LLM 扫描流水线（scan→generator→评估） | libs/giskard-scan/ | partial | 模型行为面扫描（CM-32 同源） | CM-32 并入 |
| Giskard | AI/LLM 安全（新克隆） | garak/deepteam/lidar 外部扫描器集成 | libs/giskard-scan/src/giskard/scan/integrations/ | missing | 外部 LLM 扫描器导入适配（CM-13 扩展到 LLM 扫描器） | CM-13 扩展登记（LLM 扫描器适配） |
| Giskard | AI/LLM 安全（新克隆） | 知识库+prompt 数据驱动（prompt_injection.jsonl） | generators/data/prompt_injection.jsonl | partial | 注入语料库（探针族子集） | CM-32 并入 |
| Lakera Guard | AI/LLM 安全（商业，官方 docs） | guard API 实时检测端点（输入+输出双向筛查） | docs.lakera.ai/docs/api/guard | we-have | - | 形态差异记录（我们是生成方） |
| Lakera Guard | AI/LLM 安全（商业，官方 docs） | flag/enforce 双模式策略 | docs.lakera.ai/docs/policies | partial | 规则目标 monitor/block 注解已有等价；产品化 enforce 服务不做 | 域内对齐 |
| Lakera Guard | AI/LLM 安全（商业，官方 docs） | agent 工具流筛查（tool response 检查+工具白名单） | docs.lakera.ai/docs/policies（agent workflows 原文） | partial | agent 工具面基准（CM-30 同源） | CM-30 |
| MKAT | K8s 攻防（既有克隆转正） | audit log 驱动分析（EKS 审计日志离线分析） | README | we-have | - | 已对齐 |
| MKAT | K8s 攻防（既有克隆转正） | IRSA/Pod Identity 信任关系图（role_relationships） | pkg/.../role_relationships/ | partial | 我们有 cloud-irsa-trust-wildcard（fixture 级检测）；真实 audit log 驱动信任图重建缺 | CM-38 |
| MKAT | K8s 攻防（既有克隆转正） | 硬编码云凭据扫描（secrets 模块） | pkg/.../secrets/ | partial | supply-chain-credential-theft 为采集级；配置内硬编码凭据扫描规则库缺（CM-34 同源） | CM-34 并入 |
| grype | 其他（官方 README） | SBOM 直扫（syft SBOM 输入） | README The basics（grype sbom:./sbom.json） | partial | CM-13 适配器覆盖 grype JSON 导入（backlog 已引用 grype） | CM-13 |
| grype | 其他（官方 README） | EPSS/KEV/risk scoring 优先级 | README Features | partial | 我们 findings severity 有；EPSS/KEV 外部情报并入缺 | 并入 CM-13（导入字段映射） |
| grype | 其他（官方 README） | OpenVEX 过滤 | README Features | we-have | - | 已对齐 |

**总计：122 条**（工具 31 个）

## 完备性声明

- XBow: mode=official-site-pages, completeness=doc-level-limited（闭源，公开页级）
- ARTEX: mode=clone-source, completeness=list-level-exhaustive（源码+协议逆向，另见 docs/ARTEX-BENCH-RESULT.md 与 progress.md 同靶场任务）
- NodeZero: mode=official-site-pages, completeness=doc-level-limited（闭源）
- Pentera: mode=official-site-pages, completeness=doc-level-limited（闭源，单页能力面已逐条核验）
- KubeTrail: mode=clone-source, completeness=list-level-exhaustive（collectors/scan 类别/LPE CVE 表全枚举）
- KubeHound: mode=clone-source, completeness=list-level-exhaustive（attack 边官方 index 全表枚举）
- kube-hunter: mode=clone-source, completeness=list-level-exhaustive（hunting/discovery 模块 Vuln 类全枚举）
- Peirates: mode=official-docs, completeness=list-level-exhaustive（命令参考全表枚举）
- kdigger: mode=official-docs, completeness=list-level-exhaustive（bucket 全清单）
- CDK: mode=official-docs, completeness=list-level-exhaustive（evaluate/exploit/tool 三表全枚举）
- KubeletCTL: mode=official-docs, completeness=list-level-exhaustive（命令+API 表全枚举）
- Falco: mode=official-docs, completeness=list-level-exhaustive（默认规则页全量解析：99 规则逐条）
- Tetragon: mode=official-docs, completeness=doc-level-limited（overview 单页；策略目录无官方计数页）
- KubeArmor: mode=official-docs, completeness=list-level-exhaustive（README 规范链接全枚举）
- Kyverno: mode=official-docs, completeness=list-level-exhaustive（政策库目录类别全枚举；总数官方未声明）
- Gatekeeper: mode=official-docs, completeness=list-level-exhaustive（general 目录模板全枚举 + PSP 类别登记）
- garak: mode=clone-source, completeness=list-level-exhaustive（probes 目录族+类全枚举）
- PyRIT: mode=clone-source, completeness=list-level-exhaustive（executor/attack 策略全枚举）
- promptfoo: mode=clone-source, completeness=list-level-exhaustive（redteam plugins/strategies 全枚举）
- AgentDojo: mode=clone-source, completeness=list-level-exhaustive（default_suites/attacks 全枚举）
- Trivy: mode=official-docs, completeness=list-level-exhaustive（targets×scanners 官方清单）
- Syft: mode=official-docs, completeness=list-level-exhaustive（Features 官方清单）
- kube-bench: mode=official-docs, completeness=list-level-exhaustive（cfg profile 目录全枚举）
- KubiScan: mode=clone-source, completeness=list-level-exhaustive（CLI flag 全枚举 + CVE.json 计数）
- DeepCE: mode=clone-source, completeness=list-level-exhaustive（README 枚举/exploit/payload 三清单）
- trufflehog: mode=clone-source, completeness=list-level-exhaustive（detectors 目录计数 + README 声明双源）
- gitleaks: mode=clone-source, completeness=list-level-exhaustive（config 规则计数）
- Giskard: mode=clone-source, completeness=list-level-exhaustive（scan generators + 集成枚举；2.x monorepo 检测器移至 docs 面）
- Lakera Guard: mode=official-docs-pages, completeness=doc-level-limited（商业 docs 站；已并入 Check Point AI Security 体系）
- MKAT: mode=clone-source, completeness=list-level-exhaustive（pkg 三模块全枚举）
- grype: mode=official-docs, completeness=list-level-exhaustive（Features 官方清单）

## 不可核验/不存在的工具

- KubeCF: 不存在：github.com/cloudfoundry/kubecf 与 GitHub API 双路 404（2026-10-25 核验）；即便存在亦为 Cloud Foundry 部署项目而非安全工具（https://github.com/cloudfoundry/kubecf → 404）
- fuzzwad: 任务指示跳过（任务口径）
