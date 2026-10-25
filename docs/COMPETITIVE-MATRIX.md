# Trident 竞品对比矩阵（COMPETITIVE-MATRIX 2026-10）

> 基线日期 **2026-10-25**。数据来源 = 各工具**官方** README / 官网 / 官方文档（webfetch 逐源核验，
> 登记见 §1）与本地只读克隆（`.slim/clonedeps/repos/`，登记于 `.slim/clonedeps/clonedeps.json`，
> 零代码复用）。**口径：只声明官方文档可证的能力，未提及一律标 `?` 不臆断**；与 SOTA Ruling #4 同源，
> 不把公开资料阅读等同于现场实测。
>
> 判定标记（矩阵单元唯一合法字符）：
>
> | 标记 | 含义 |
> |---|---|
> | ✓ | 官方文档明证支持 |
> | ◐ | 部分支持（有边界 / 有条件 / 域内近似） |
> | ○ | 官方文档明示无，或静态扫描器按定义无此能力 |
> | — | 类别外（防御产品的攻击维度、攻击产品的防御维度等） |
> | ? | 官方文档未提及（未核实，不视为支持） |
>
> 结构校验：`trident/arch-intel/competitive.py`（`python trident/arch-intel/competitive.py` 退出码即结果），
> 测试 `tests/test_competitive_matrix.py`（fixture 注入核心逻辑 + 本文档断言）。

## 1. 工具全集与来源登记（23 工具 × 5 类）

| 工具 | 类别 | 形态与许可 | 版本/核验锚点 | 来源 | 核验日期 |
|---|---|---|---|---|---|
| XBow | 自主渗透 | 商业 SaaS（自主攻击平台；自有认证 SOC2/ISO27001/ISO42001/PCIDSS/NIS2） | 官网能力页（2026-10 快照：HackerOne #1、Chrome 全链 $250K 案例） | https://xbow.com/ | 2026-10-25 |
| ARTEX | 自主渗透 | 开源 AGPL-3.0（RuoJi6 维护 fork；Go+Next.js+PostgreSQL） | v0.3.23 @ 620ca5d（本地克隆 README+源码；QEMU 实测见 docs/ARTEX-BENCH-RESULT.md） | .slim/clonedeps/repos/RuoJi6__ARTEX | 2026-10-25 |
| NodeZero | 自主渗透 | 商业（Horizon3；agentless；内网 Docker host/OVA + 外网云端，一次性 VPC） | 官网平台页 | https://horizon3.ai/nodezero/ | 2026-10-25 |
| Pentera | 自主渗透 | 商业（Exposure Validation Platform / CTEM） | 官网平台页（注意：pentera.com 为同名慈善营销公司，安全厂商为 pentera.io） | https://pentera.io/ | 2026-10-25 |
| KubeTrail | K8s 攻防 | 开源 Apache-2.0（ekkoo-z；Go+Wails/Vue 桌面+server） | main @ ba8c3cf（本地克隆 README.en.md + internal/ 源码） | .slim/clonedeps/repos/ekkoo-z__KubeTrail | 2026-10-25 |
| KubeHound | K8s 攻防 | 开源 Apache-2.0（DataDog ASE 团队） | main @ b6e43fd（本地克隆 README + docs/reference/attacks/ 25 条攻击边） | .slim/clonedeps/repos/DataDog__KubeHound | 2026-10-25 |
| kube-hunter | K8s 攻防 | 开源 Apache-2.0（Aqua；README 声明**已停止活跃开发**，推荐 Trivy 承接） | main @ bc47f08（本地克隆 README） | .slim/clonedeps/repos/aquasecurity__kube-hunter | 2026-10-25 |
| Peirates | K8s 攻防 | 开源 GPLv2（InGuardians） | 官方 README（main） | https://github.com/inguardians/peirates | 2026-10-25 |
| kdigger | K8s 攻防 | 开源（Quarkslab） | 官方 README（main，~20 bucket 清单） | https://github.com/quarkslab/kdigger | 2026-10-25 |
| CDK | K8s 攻防 | 开源（cdk-team；零依赖单二进制） | 官方 README（main，evaluate/run/tool 三模块与 EXP 清单） | https://github.com/cdk-team/CDK | 2026-10-25 |
| KubeletCTL | K8s 攻防 | 开源（CyberArk） | 官方 README（master，含未文档化 kubelet API 表 API_TABLE.md） | https://github.com/cyberark/KubeletCTL | 2026-10-25 |
| Falco | 运行时/准入 | 开源（CNCF 项目；内核模块/现代 eBPF 双驱动） | 官方文档 What is Falco | https://falco.org/docs/ | 2026-10-25 |
| Tetragon | 运行时/准入 | 开源（Cilium；eBPF 内核态） | 官方文档 Overview（2026-10-23 更新页） | https://tetragon.io/docs/overview/ | 2026-10-25 |
| KubeArmor | 运行时/准入 | 开源（LSM 引擎：AppArmor/BPF-LSM/SELinux） | 官网能力页（2026-07-01 更新） | https://kubearmor.io/ | 2026-10-25 |
| Kyverno | 运行时/准入 | 开源（CNCF 策略引擎；K8s 原生 CRD + CEL） | 官方文档 Introduction | https://kyverno.io/docs/introduction/ | 2026-10-25 |
| Gatekeeper | 运行时/准入 | 开源（Open Policy Agent；OPA v0.60） | 官方 README（master） | https://raw.githubusercontent.com/open-policy-agent/gatekeeper/master/README.md | 2026-10-25 |
| garak | AI/LLM 安全 | 开源 Apache-2.0（NVIDIA） | main @ d6a8be1（本地克隆 README：探针族/生成器/JSONL 报告） | .slim/clonedeps/repos/NVIDIA__garak | 2026-10-25 |
| PyRIT | AI/LLM 安全 | 开源 MIT（microsoft；原 Azure/PyRIT 仓库已迁移为跳转 stub） | main @ 246b659（本地克隆 README + doc/index.md 能力页） | .slim/clonedeps/repos/microsoft__PyRIT | 2026-10-25 |
| promptfoo | AI/LLM 安全 | 开源 MIT（已并入 OpenAI，保持开源） | main @ b4c2404（本地克隆 README） | .slim/clonedeps/repos/promptfoo__promptfoo | 2026-10-25 |
| AgentDojo | AI/LLM 安全 | 开源 MIT（ETH Zurich SRI / Invariant Labs；NeurIPS 2024 D&B，arXiv 2406.13352） | main @ 089ed468（本地克隆 README；PyPI 0.1.35；注意：常被引用的 eth-sri/agent-dojo 404，真实仓库=ethz-spylab/agentdojo，见 §6.5） | .slim/clonedeps/repos/ethz-spylab__agentdojo | 2026-10-25 |
| Trivy | 其他 | 开源（Aqua；综合扫描器） | 官方 README（main）+ trivy.dev v0.76 文档系 | https://github.com/aquasecurity/trivy | 2026-10-25 |
| Syft | 其他 | 开源（Anchore；SBOM 生成） | 官方 README（main） | https://github.com/anchore/syft | 2026-10-25 |
| kube-bench | 其他 | 开源（Aqua；CIS K8s Benchmark 检查器） | 官方 README（main） | https://github.com/aquasecurity/kube-bench | 2026-10-25 |

克隆登记：新增浅克隆 **6 个成功**（KubeHound / garak / PyRIT(microsoft) / promptfoo / kube-hunter /
agentdojo@ethz-spylab），登记见 `.slim/clonedeps/clonedeps.json`；ARTEX / KubeTrail / DataDog MKAT
为既有克隆一并登记。

## 2. 能力维度定义（18 维）与 Trident 基线

Trident 列取自 [`docs/SOTA-2026-10.md`](SOTA-2026-10.md) 的诚实口径（已达成/部分/未达成），
不因竞品对比而上调。

| 键 | 维度 | 说明 | Trident 现状锚点（SOTA-2026-10.md） |
|---|---|---|---|
| D1 | 资产发现 | 目标面/攻击面盘点（资产图、服务发现、暴露面） | 已达成：recon 族 100+ 模块（exposure-mapping/dns-service-discovery 等） |
| D2 | 自主规划 | 多步自主决策规划（无人推动的探索闭环） | 部分：agent_planner 推荐+lead 审批，执行固定人工触发（Ruling「规划≠执行」） |
| D3 | 攻击链编排 | 多步链编排（依赖/并行/回滚/图级路径） | 已达成：core/chains.py 18+ 链 dry-run/依赖并行/逐步回滚 |
| D4 | 权限链逃逸 | K8s RBAC/容器逃逸/节点面权限链 | 已达成：权限链族 6 模块 + escape-primitives 等 |
| D5 | ML 域专长 | ML 训练/推理域原生能力（非通用 web/K8s） | 已达成：九族含 ML 专节、训练框架面模块 |
| D6 | 权重与数据面 | 权重/checkpoint/数据集/模型注册面 | 已达成：权重投毒链/窃取族/AI SBOM |
| D7 | 网络 fabric 面 | IB/RDMA/NCCL/组网拓扑专长（非通用网络横向） | 已达成：nccl/ib/roce/multus 模块族 |
| D8 | 长上下文 | 超长窗口/KV cache/PD 分离面 | 已达成：longctx 8 模块 + docs/LONG-CONTEXT.md |
| D9 | 网关 | AI 网关语义（LiteLLM/Higress 等） | 已达成：aigateway 10 模块 + docs/AI-GATEWAY.md |
| D10 | 云跨租户 | 云身份/桶/快照跨租户面 | 部分：六云契约级仿真（明确非真实环境实测） |
| D11 | 零日策略 | 未知漏洞发现或行为化零日检测姿态 | 已达成：零日族 + is_zeroday 登记 + 行为化规则 |
| D12 | 证据链 | 攻击证据采集/留档/防篡改链 | 已达成：三层证据 + manifest 篡改检测 |
| D13 | 双语合规报告 | 双语报告 + 合规框架映射 | 已达成：PTES 双语 + 七框架 finding→条款矩阵 |
| D14 | 规则转化 | 发现→检测/阻断规则产物 | 已达成：Kyverno/Gatekeeper/NetworkPolicy/Sigma/Falco/Suricata 六目标 |
| D15 | 紫队验证 | 攻击发现 vs 检测覆盖的闭环验证 | 已达成：validate 重放 + coverage-matrix 零漏过 |
| D16 | 多用户工作区 | 多角色/多租户工作区隔离 | 已达成：四角色动作矩阵 + 工作区隔离 |
| D17 | API-first | 程序化集成面（REST/SDK/MCP） | 部分：MCP 只读 5 工具；HTTP API 面 WebUI 内部使用，无对外契约 |
| D18 | 持续化 | 常驻/定时/连续测试与调度 | 未达成：单机 CLI 单次 run，无调度器/通知 |

## 3. 矩阵（维度 × 工具，按类分表；Trident 为基准列）

> 通用说明：策略/检测引擎（Kyverno/Gatekeeper/Falco/Tetragon/KubeArmor）理论上可配置用于任意面，
> 但官方文档未声明 ML/权重/fabric 专长的一律按 ○/— 处理，不以「可配置」推断域专长。

### 3.1 自主渗透类（XBow / ARTEX / NodeZero / Pentera）

| 维度 | Trident | XBow | ARTEX | NodeZero | Pentera |
|---|---|---|---|---|---|
| D1 资产发现 | ✓ | ? | ✓ | ◐ | ✓ |
| D2 自主规划 | ◐ | ✓ | ✓ | ✓ | ✓ |
| D3 攻击链编排 | ✓ | ✓ | ✓ | ✓ | ✓ |
| D4 权限链逃逸 | ✓ | ? | ? | ◐ | ◐ |
| D5 ML 域专长 | ✓ | ? | ? | ? | ? |
| D6 权重与数据面 | ✓ | ? | ? | ○ | ○ |
| D7 网络 fabric 面 | ✓ | ? | ? | ○ | ○ |
| D8 长上下文 | ✓ | ○ | ○ | ○ | ○ |
| D9 网关 | ✓ | ○ | ○ | ○ | ○ |
| D10 云跨租户 | ◐ | ? | ○ | ◐ | ✓ |
| D11 零日策略 | ✓ | ✓ | ? | ◐ | ◐ |
| D12 证据链 | ✓ | ✓ | ✓ | ✓ | ✓ |
| D13 双语合规报告 | ✓ | ◐ | ◐ | ◐ | ✓ |
| D14 规则转化 | ✓ | ○ | ○ | ○ | ◐ |
| D15 紫队验证 | ✓ | ◐ | ◐ | ◐ | ✓ |
| D16 多用户工作区 | ✓ | ? | ✓ | ? | ? |
| D17 API-first | ◐ | ? | ✓ | ? | ? |
| D18 持续化 | ○ | ✓ | ✓ | ✓ | ✓ |

注：XBow「零日策略 ✓」= 官网明证自主发现并证明 3 个未知 Chrome 严重 CVE + 全链沙箱逃逸；
NodeZero/Pentera D4 ◐ = 域内（AD/身份/端点）提权明证、K8s 未提及；Pentera D10 ✓ = 明证云环境跨面
kill-chain 与泄露凭据验证。

### 3.2 K8s 攻防类（KubeTrail / KubeHound / kube-hunter / Peirates / kdigger / CDK / KubeletCTL）

| 维度 | Trident | KubeTrail | KubeHound | kube-hunter | Peirates | kdigger | CDK | KubeletCTL |
|---|---|---|---|---|---|---|---|---|
| D1 资产发现 | ✓ | ✓ | ◐ | ✓ | ? | ✓ | ✓ | ✓ |
| D2 自主规划 | ◐ | ◐ | — | ◐ | ○ | ○ | ◐ | ○ |
| D3 攻击链编排 | ✓ | ◐ | ✓ | ◐ | ◐ | ○ | ◐ | ◐ |
| D4 权限链逃逸 | ✓ | ✓ | ✓ | ✓ | ✓ | ◐ | ✓ | ✓ |
| D5 ML 域专长 | ✓ | ◐ | ○ | ○ | ○ | ○ | ○ | ○ |
| D6 权重与数据面 | ✓ | ◐ | ◐ | ○ | ○ | ◐ | ◐ | ◐ |
| D7 网络 fabric 面 | ✓ | ◐ | ◐ | ◐ | ○ | ◐ | ◐ | ◐ |
| D8 长上下文 | ✓ | ○ | ○ | ○ | ○ | ○ | ○ | ○ |
| D9 网关 | ✓ | ○ | ○ | ○ | ○ | ○ | ○ | ○ |
| D10 云跨租户 | ◐ | ◐ | ○ | ◐ | ○ | ◐ | ◐ | ○ |
| D11 零日策略 | ✓ | ◐ | ○ | ○ | ○ | ○ | ◐ | ○ |
| D12 证据链 | ✓ | ✓ | ◐ | ◐ | ○ | ◐ | ○ | ○ |
| D13 双语合规报告 | ✓ | ◐ | ○ | ○ | ○ | ○ | ○ | ○ |
| D14 规则转化 | ✓ | ◐ | ○ | ○ | ○ | ○ | ○ | ○ |
| D15 紫队验证 | ✓ | ◐ | ○ | ◐ | ◐ | ◐ | ◐ | ◐ |
| D16 多用户工作区 | ✓ | ○ | ◐ | ○ | ○ | ○ | ○ | ○ |
| D17 API-first | ◐ | ◐ | ✓ | ◐ | ○ | ○ | ○ | ○ |
| D18 持续化 | ○ | ○ | ◐ | ○ | ○ | ○ | ○ | ○ |

注：KubeHound D3 ✓ = 图级攻击路径自动计算（dump/ingest→Gremlin 图 + DSL），不执行利用；
kdigger D2 ○ = README 明示「not automatically hack your cluster」；kube-hunter D2/D3 ◐ =
active hunting（opt-in，默认不改集群状态）；CDK D2 ◐ = evaluate 评估后推荐 exploit 但手动执行；
KubeTrail D5 ◐ = 仅有 GPU/资源滥用复核模板（resource-hijack-dos-review），无权重/训练面。

### 3.3 运行时/准入类（Falco / Tetragon / KubeArmor / Kyverno / Gatekeeper）

| 维度 | Trident | Falco | Tetragon | KubeArmor | Kyverno | Gatekeeper |
|---|---|---|---|---|---|---|
| D1 资产发现 | ✓ | — | — | — | — | — |
| D2 自主规划 | ◐ | — | — | — | — | — |
| D3 攻击链编排 | ✓ | — | — | — | — | — |
| D4 权限链逃逸 | ✓ | — | — | — | — | — |
| D5 ML 域专长 | ✓ | ○ | ○ | ○ | ○ | ○ |
| D6 权重与数据面 | ✓ | ○ | ○ | ○ | ○ | ○ |
| D7 网络 fabric 面 | ✓ | ○ | ○ | ○ | ○ | ○ |
| D8 长上下文 | ✓ | ○ | ○ | ○ | ○ | ○ |
| D9 网关 | ✓ | ○ | ○ | ○ | ○ | ○ |
| D10 云跨租户 | ◐ | ◐ | ○ | ○ | ◐ | ○ |
| D11 零日策略 | ✓ | ◐ | ◐ | ◐ | ◐ | ◐ |
| D12 证据链 | ✓ | ◐ | ◐ | ◐ | ◐ | ◐ |
| D13 双语合规报告 | ✓ | ○ | ○ | ○ | ◐ | ◐ |
| D14 规则转化 | ✓ | — | — | — | — | — |
| D15 紫队验证 | ✓ | ○ | ○ | ○ | ◐ | ○ |
| D16 多用户工作区 | ✓ | ○ | ○ | ○ | ○ | ○ |
| D17 API-first | ◐ | ◐ | ○ | ○ | ✓ | ◐ |
| D18 持续化 | ○ | ✓ | ✓ | ✓ | ✓ | ✓ |

注：Falco/Tetragon/KubeArmor/Kyverno/Gatekeeper 的 D1–D4 为攻击维度，防御产品按 — 类别外；
D14 规则转化 — = 它们本身是**规则目标格式**（我们 rules/generate 的输出端），不存在「转化」语义；
D11 ◐ = 行为化/策略化检测可覆盖未知行为，但非漏洞发现；Tetragon 官方明证内核态**阻断**
（kill 进程于 syscall 完成前）与 KubeArmor LSM 内联阻断是 D11/D15 语境下值得对标的执行语义。

### 3.4 AI/LLM 安全类（garak / PyRIT / promptfoo / AgentDojo）

| 维度 | Trident | garak | PyRIT | promptfoo | AgentDojo |
|---|---|---|---|---|---|
| D1 资产发现 | ✓ | — | — | — | — |
| D2 自主规划 | ◐ | ◐ | ✓ | ◐ | ◐ |
| D3 攻击链编排 | ✓ | ◐ | ✓ | ◐ | ◐ |
| D4 权限链逃逸 | ✓ | — | — | — | — |
| D5 ML 域专长 | ✓ | ✓ | ✓ | ✓ | ✓ |
| D6 权重与数据面 | ✓ | ○ | ○ | ○ | ○ |
| D7 网络 fabric 面 | ✓ | ○ | ○ | ○ | ○ |
| D8 长上下文 | ✓ | ○ | ○ | ○ | ○ |
| D9 网关 | ✓ | ◐ | ◐ | ◐ | ○ |
| D10 云跨租户 | ◐ | ○ | ○ | ○ | ○ |
| D11 零日策略 | ✓ | ◐ | ◐ | ◐ | ○ |
| D12 证据链 | ✓ | ◐ | ◐ | ◐ | ◐ |
| D13 双语合规报告 | ✓ | ◐ | ◐ | ◐ | ◐ |
| D14 规则转化 | ✓ | ○ | ○ | ○ | ○ |
| D15 紫队验证 | ✓ | ◐ | ◐ | ◐ | ✓ |
| D16 多用户工作区 | ✓ | ○ | ◐ | ○ | ○ |
| D17 API-first | ◐ | ◐ | ✓ | ✓ | ✓ |
| D18 持续化 | ○ | ○ | ○ | ◐ | ○ |

注：本类为**模型行为面**红队（提示注入/越狱/数据泄露/内容危害），与 Trident 的**基础设施面**
（K8s/权重/网络/网关）正交；D9 ◐ = 任意 REST 目标可打网关端点但无网关语义（无 LiteLLM/Higress
路由/密钥/缓存知识）；AgentDojo D15 ✓ = 官方定位即攻击×防御基准评测（attack/defense 参数化基准）；
PyRIT D2/D3 ✓ = 官方明证开箱即用多轮攻击策略（Crescendo/TAP/Skeleton Key）。

### 3.5 其他类（Trivy / Syft / kube-bench）

| 维度 | Trident | Trivy | Syft | kube-bench |
|---|---|---|---|---|
| D1 资产发现 | ✓ | ◐ | ◐ | — |
| D2 自主规划 | ◐ | ○ | ○ | ○ |
| D3 攻击链编排 | ✓ | ○ | ○ | ○ |
| D4 权限链逃逸 | ✓ | ◐ | ○ | ◐ |
| D5 ML 域专长 | ✓ | ○ | ○ | ○ |
| D6 权重与数据面 | ✓ | ◐ | ◐ | ○ |
| D7 网络 fabric 面 | ✓ | ○ | ○ | ○ |
| D8 长上下文 | ✓ | ○ | ○ | ○ |
| D9 网关 | ✓ | ○ | ○ | ○ |
| D10 云跨租户 | ◐ | ○ | ○ | ○ |
| D11 零日策略 | ✓ | ○ | ○ | ○ |
| D12 证据链 | ✓ | ◐ | ◐ | ◐ |
| D13 双语合规报告 | ✓ | ◐ | ○ | ✓ |
| D14 规则转化 | ✓ | ○ | ○ | ○ |
| D15 紫队验证 | ✓ | ○ | ○ | ◐ |
| D16 多用户工作区 | ✓ | ○ | ○ | ○ |
| D17 API-first | ◐ | ✓ | ✓ | ◐ |
| D18 持续化 | ○ | ✓ | ○ | ◐ |

注：Trivy D18 ✓ = Trivy Operator 常驻集群扫描（Aqua 官方 kube-bench README 交叉印证）；
kube-bench D13 ✓ = 输出即 CIS Benchmark 条目级合规报告（按定义是合规映射，无双语）。

## 4. 每工具一行：对我们启示（补齐项映射模块/功能键）

> 「补齐项」均落入 §5 backlog（去重）；「已对齐/刻意不做」给出锚点，不入 backlog。

| 工具 | 类别 | 对我们启示：补齐项（映射模块/功能键） |
|---|---|---|
| XBow | 自主渗透 | 补齐：①finding 级确定性复现检查 + 免费复测闭环（→ runner/verify-effects 增加 retest 工作流键，CM-14）；②工单系统直投 + 修复建议（→ export.py 连接器，CM-15）；③每步决策/战术全量留档（→ core/evidence.py 决策轨迹 artifact，CM-03）；④千级并行（→ 多租户 SaaS 未达成项同源，CM-31）。自主执行本体维持 Ruling「规划≠执行」不跟进 |
| ARTEX | 自主渗透 | 补齐：⑤探索血缘图 goal→intent→fact→finding 边（→ core/graph.py，CM-16）；⑥同根因漏洞归并+统一报告（→ reports/render.py，CM-17）；⑦全流量 MITM/pcap 录制回放（→ lab 证据增强，CM-18）；⑧任务情报登记（凭据/线索集中 registry，CM-01）；⑨跨 run 过程检索 API（→ evidence 检索，CM-02）。多模型池/C2 维持刻意不做（docs/REFLECTION-ARTEX-KUBETRAIL.md §2） |
| NodeZero | 自主渗透 | 补齐：⑩Sankey 攻击路径图 + 系统性修复优先级（修一处消多少路径）（→ webui 攻击链图 + reports，CM-19）；⑪每日定时连续测试（→ 调度器，CM-04）；Quick Verify 复测并入 CM-14 |
| Pentera | 自主渗透 | 补齐：⑫CTEM 五阶段报告叙事（→ reports/compliance.py 框架章节，CM-20）；⑬泄露凭据有效性验证面（→ modules 凭据验证，CM-21）；IoC 投递并入 CM-15（SIEM/工单连接器）。勒索仿真/AD 密码审计为类别外 |
| KubeTrail | K8s 攻防 | 补齐：⑭in-pod 只读采集器（safe 模式等价物，→ modules/recon kube-in-pod-collector，CM-22）；⑮legacy SA token 逐 token SSRR/SSAR（→ modules/rbac-mapping，CM-05）；⑯敏感证据 metadata-by-reference 三态（→ core/evidence.py，CM-06）。内核 LPE CVE 库维持不补（平台定位 Ruling） |
| KubeHound | K8s 攻防 | 补齐：⑰攻击路径自动计算（最短路径/关键节点/割点排序 + 图查询 API 暴露）（→ core/graph.py + core/reachability.py，CM-23）；KHaaS 服务化形态并入 CM-31 |
| kube-hunter | K8s 攻防 | 补齐：⑱VID 式漏洞知识库条目页（finding→可引用 KB 键，→ docs/kb + reports 锚，CM-07）。竞争态势：官方声明停更，承接方为 Trivy（记录于 §6） |
| Peirates | K8s 攻防 | 无补齐项：交互式攻击操作台与「可审计交付」定位冲突（同 REFLECTION 对桌面后渗透台的刻意不做）；SA token/Secrets 采集面已由 rbac-mapping/审计轨迹分析覆盖 |
| kdigger | K8s 攻防 | 补齐：⑲admission dry-run/fuzz 探测（gen fuzz-pod 式模板 → server dry-run 反推准入边界）（→ rules/validate.py + modules，CM-24）。~20 bucket 采集面已对齐（recon 族） |
| CDK | K8s 攻防 | 已对齐：evaluate→run 推荐衔接 = agent_planner 推荐排序；零依赖单二进制属部署形态差异（Trident 控制台不在目标容器内执行），不设 backlog |
| KubeletCTL | K8s 攻防 | 补齐：⑳kubelet 10250 面扫描（CIDR 扫描开放 kubelet/runningpods/RCE 面/token 收割）（→ modules/recon kubelet-api-surface，CM-08） |
| Falco | 运行时/准入 | 补齐：㉑规则宏/列表复用编写模型（macro/list 组合降噪）（→ rules/generate.py 模板机制，CM-09）；㉒输出多路分发（stdout/file/syslog/program/http）（→ export.py 通道，CM-10）。Falco 本身是我们的规则目标 + defense-bypass-falco 的靶产品 |
| Tetragon | 运行时/准入 | 补齐：㉓TracingPolicy 规则目标（findings→Tetragon 传感器/执行策略，含内核态阻断语义的紫队矩阵拦截态）（→ rules/generate.py 新目标 + validate.py，CM-25）；defense-bypass-tetragon 已有靶面 |
| KubeArmor | 运行时/准入 | 补齐：㉔KubeArmorPolicy/KubeArmorClusterPolicy 规则目标（LSM 内联阻断语义）（→ rules/generate.py 新目标，CM-26）；defense-bypass-kubearmor 已有靶面 |
| Kyverno | 运行时/准入 | 补齐：㉕CEL 表达式校验规则 + verifyImages 镜像签名验证规则生成（→ rules/generate.py Kyverno 目标增强，CM-27）；㉖存量资源 background 合规扫描（policy audit 对存量）（→ rules/validate.py，CM-28）。Kyverno YAML 目标已有（21 规则含 ClusterPolicy×5） |
| Gatekeeper | 运行时/准入 | 补齐：存量 audit 重扫并入 CM-28（ConstraintTemplate/Constraint 对偶输出已有）；无新增独立项 |
| garak | AI/LLM 安全 | 补齐：㉗LLM 行为面探针族（注入/越狱/泄露/毒性探针库，模型行为域）（→ modules 新 llm-probe 族或 bypass 族扩展，CM-32）；探针→检测器配对模型并入紫队矩阵方法论 |
| PyRIT | AI/LLM 安全 | 补齐：㉘多轮攻击策略链模板（Crescendo/TAP 式逐步升级链）（→ trident/chains/*.json 模型行为链，CM-29）；评分器框架（finding 判定 scoring）并入 CM-29；CoPyRIT 人在环 = MCP + lead 审批已对齐 |
| promptfoo | AI/LLM 安全 | 补齐：㉙CI/CD 集成与 exit code 契约（阈值判定退出码）（→ cli.py，CM-11）；㉚声明式评估配置（yaml 驱动评估矩阵 + 对比视图）（→ lab 配置层，CM-12）。Web 对比视图已对齐（SPA 六视图） |
| AgentDojo | AI/LLM 安全 | 补齐：㉛agent 工具面注入基准场景（工具环境内间接注入→执行的套件化基准）（→ lab/mocks + 基准评分，CM-30） |
| Trivy | 其他 | 补齐：㉜外部扫描器输入适配器（import Trivy JSON→findings 归一，镜像 CVE/KBOM 面纳入证据链）（→ trident/import_scan.py 新功能键，CM-13） |
| Syft | 其他 | 补齐：SBOM 格式转换/多输出并入 CM-13 适配器（CycloneDX ML-BOM 已有，差异在格式转换矩阵）；in-toto 签名 attest 已有供应链等价（cosign 风格 bundle）。无独立新增项 |
| kube-bench | 其他 | 补齐：㉝CIS K8s Benchmark 检查模块 + 合规框架条目（→ modules 新 cis-benchmark 族 + reports/standards.json CIS 条目，CM-33） |

## 5. 补齐项 Backlog（去重登记，**不实施**）

> 本表只登记与排序，本任务不实施任何一项。工作量 S=小（≤1 天）/ M=中（1–3 天）/ L=大（>3 天或需新域）。
> **重叠标注**：`gen-27`（XBow 对标任务）正在做其中一部分，凡 XBow 派生项均已标注，
> 落地前先与 gen-27 对齐范围避免重复实现；其余项无重叠。

| ID | 一句话 | 对应维度 | 工作量 | 重叠标注 | 来源工具 |
|---|---|---|---|---|---|
| CM-01 | 任务情报登记：run 级凭据/线索/敏感数据集中 registry（带来源证据绑定） | D12 证据链 | S | - | ARTEX |
| CM-02 | 跨 run 过程检索 API：对 steps/artifacts 全文检索并回链证据锚 | D12 证据链 | S | - | ARTEX |
| CM-03 | 决策/意图留档 artifact：规划器推荐理由与战术选择全量入证据库 | D12 证据链 | S | gen-27（XBow 派生） | XBow |
| CM-04 | 定时调度连续测试：cron 式调度器 + 测试窗口（ROE 约束内） | D18 持续化 | S | - | NodeZero/XBow |
| CM-05 | legacy SA token 逐 token SSRR/SSAR 权限审计 | D4 权限链逃逸 | S | - | KubeTrail |
| CM-06 | 敏感证据 metadata-by-reference 三态（raw/redact/metadata 引用式存储） | D12 证据链 | S | - | KubeTrail |
| CM-07 | VID 式漏洞知识库条目页（finding→可引用 KB 键，含中文条目） | D13 双语合规报告 | S | - | kube-hunter |
| CM-08 | kubelet 10250 面扫描模块（CIDR 扫描开放 kubelet/runningpods/token 收割面） | D1 资产发现 | S | - | KubeletCTL |
| CM-09 | Falco 宏/列表复用规则编写模型（macro/list 组合降噪） | D14 规则转化 | S | - | Falco |
| CM-10 | 规则/告警输出多路分发通道（stdout/file/syslog/program/http[s]） | D17 API-first | S | - | Falco/falcosidekick |
| CM-11 | CI/CD 集成 exit code 契约（阈值判定退出码 + 机器可读摘要） | D18 持续化 | S | - | promptfoo |
| CM-12 | 声明式评估配置（yaml 驱动模块/链评估矩阵与基线对比） | D17 API-first | S | - | promptfoo |
| CM-13 | 外部扫描器输入适配器（import Trivy/Syft/grype JSON→findings 归一入证据链） | D1 资产发现 | S | - | Trivy/Syft |
| CM-14 | finding 级确定性复测闭环（修复后重放验证 + retest 结论留档） | D15 紫队验证 | M | gen-27（XBow 派生） | XBow/NodeZero/ARTEX/Pentera |
| CM-15 | 工单/SIEM 直投连接器（finding+修复建议→ticketing/SIEM 后端投递） | D17 API-first | M | gen-27（XBow 派生） | XBow/Pentera |
| CM-16 | 探索血缘图边（goal→intent→fact→finding 血缘，支撑反查与覆盖度） | D3 攻击链编排 | M | - | ARTEX |
| CM-17 | 同根因漏洞归并 + 统一报告（跨 run 去重、根因确认工作流） | D13 双语合规报告 | M | - | ARTEX |
| CM-18 | 全流量 pcap 级录制与回放器（MITM 留痕，入三层证据） | D12 证据链 | M | - | ARTEX |
| CM-19 | Sankey 攻击路径图 + 系统性修复优先级（修一处消多少路径的量化建议） | D13 双语合规报告 | M | - | NodeZero |
| CM-20 | CTEM 五阶段报告叙事（暴露验证→侦查→攻击→报告→修复验证章节化） | D13 双语合规报告 | M | - | Pentera |
| CM-21 | 泄露凭据有效性验证面（凭据集→租户内有效性判定的 fixture 驱动模块） | D4 权限链逃逸 | M | - | Pentera |
| CM-22 | in-pod 只读采集器（safe 模式等价物：/proc /sys cgroup socket 本地扫） | D1 资产发现 | M | - | KubeTrail |
| CM-23 | 攻击路径自动计算（最短路径/关键节点/割点排序 + 图查询 API） | D3 攻击链编排 | M | - | KubeHound |
| CM-24 | admission dry-run/fuzz 探测（fuzz-pod 模板→server dry-run 反推准入边界） | D15 紫队验证 | M | - | kdigger |
| CM-25 | Tetragon TracingPolicy 规则目标（findings→传感器/执行策略，拦截态入紫队矩阵） | D14 规则转化 | M | - | Tetragon |
| CM-26 | KubeArmorPolicy/ClusterPolicy 规则目标（LSM 内联阻断语义） | D14 规则转化 | M | - | KubeArmor |
| CM-27 | Kyverno CEL 校验表达式 + verifyImages 镜像签名验证规则生成 | D14 规则转化 | M | - | Kyverno |
| CM-28 | 存量资源 background 合规扫描（policy audit 对存量对象的覆盖矩阵） | D15 紫队验证 | M | - | Kyverno/Gatekeeper |
| CM-29 | LLM 行为面多轮攻击策略链（Crescendo/TAP 式升级链 + 评分器框架） | D5 ML 域专长 | M | - | PyRIT |
| CM-30 | agent 工具面注入基准场景（工具环境间接注入→执行的套件化基准与评分） | D5 ML 域专长 | M | - | AgentDojo |
| CM-31 | 多租户并发/分布式调度（与 SOTA 未达成项「多租户 SaaS」同源，登记不重复实施） | D18 持续化 | L | gen-27（XBow 派生·并发规模对照） | XBow |
| CM-32 | LLM 行为面探针族（注入/越狱/泄露/毒性探针库，garak 级广度） | D5 ML 域专长 | L | - | garak |
| CM-33 | CIS K8s Benchmark 检查模块族 + 合规框架 CIS 条目（standards.json） | D13 双语合规报告 | L | - | kube-bench |

计数：**33 项 = S 13 · M 17 · L 3**；其中 gen-27 重叠 4 项（CM-03/14/15/31）。

## 6. 竞争态势与数据源备注（诚实声明）

1. **kube-hunter 已停止活跃开发**（README 首行声明，2026-10-25 核验）：Aqua 官方推荐迁移 Trivy
   （K8s misconfig + KBOM 扫描承接）。对标价值保留（VID KB、active hunting 口径），新投资建议指向 CM-13。
2. **PyRIT 仓库迁移**：`Azure/PyRIT` 已变为跳转 stub（本地克隆核验），真实仓库为 `microsoft/PyRIT`
   （登记 clonedeps.json）。
3. **DataDog/kubetrail 不存在**：GitHub 404（2026-10-25 核验，详见
   docs/REFLECTION-ARTEX-KUBETRAIL.md）；真实锚点为 ekkoo-z/KubeTrail 与 DataDog MKAT。
4. **pentera.com ≠ Pentera 安全厂商**：pentera.com 为同名慈善营销公司；安全厂商官网为 pentera.io。
   （域名撞名已实测，来源登记以 pentera.io 为准。）
5. **AgentDojo 仓库地址勘误**：任务口径与常见引用中的 `eth-sri/agent-dojo` **不存在**（git ls-remote
   → Repository not found，2026-10-25 核验；早先两轮克隆卡在连接重置，掩盖了 404 事实）。真实仓库为
   **`ethz-spylab/agentdojo`**（官方文档站 agentdojo.spylab.ai 的源码链接与 shields 徽章交叉确认，
   MIT，main@089ed468 已克隆）。能力面双源核验一致（本地 README + PyPI 0.1.35 官方页），矩阵判定不变。
6. **XBow/NodeZero/Pentera 为商业产品**：能力以官网公开声明为限，无二进制实测；「?」= 官网未声明，
   不等于不具备。商业产品的 K8s/ML 面未声明处一律保守标注。
7. 本矩阵为**文档级对标**，不把阅读等同于实测；Trident 列以 SOTA-2026-10.md 诚实口径为锚，
   逐项证据锚见 §2。
