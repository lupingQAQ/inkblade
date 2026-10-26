# 2026 安全会议 infra / AI-infra 议题覆盖矩阵

- 核验日期：**2026-10-26**（所有链接当日复核；未公开的议程不做推断）
- 方法：官方议程/论文页优先；二手回顾仅用于定位标题，标题与链接以官方页为准。
- 口径：只收 **infra / AI-infra**（Kubernetes、容器/沙箱、TEE、身份、网络、供应链、GPU/AI 服务、模型与数据面）。纯终端/移动/密码学理论不计，除非直接落在基础设施边界。
- 覆盖列：`已覆盖:<模块键>` 表示既有模块可检测；`新增:<模块键>` 表示本轮落地；`部分:<模块键>` 表示只覆盖一个侧面；`缺口` 表示未落地（见第 4 节）。
- 说明：Black Hat Europe 2026、SDC 2026、Tencent TSec、ByteDance 安全沙龙、OffensiveCon 2026 截至 2026-10-26 **未公开完整议程**，只记录已确认的会议信息/主题方向，不编造逐议题标题。

## 1. 会议状态（逐源核验）

| 会议 | 日期/地点 | 官方来源 | 议程核验状态 |
|---|---|---|---|
| USENIX Security 2026 | 2026-08-12~14，Baltimore | https://www.usenix.org/conference/usenixsecurity26/technical-sessions | 已发布 technical sessions，逐篇可读 |
| IEEE S&P 2026 | 2026-05-18~20，San Francisco | https://sp2026.ieee-security.org/program.html | 已发布 program，逐篇可读 |
| NDSS 2026 | 2026-02-23~27，San Diego | https://www.ndss-symposium.org/ndss2026/accepted-papers/ | 265 篇 accepted papers 已发布 |
| CCS 2025 | 2025-10，Taipei | https://www.sigsac.org/ccs/CCS2025/ | 官方 program 页当日 404；仅用可核验的论文条目（T3C），不扩写 |
| Black Hat USA 2026 | 2026-08-05~06，Las Vegas | https://blackhat.com/us-26/briefings/schedule/ | 121 briefings；标题经官方 schedule + 会议回顾交叉核验 |
| Black Hat Europe 2026 | 2026-12-07~10，London | https://blackhat.com/europe/briefings/schedule/ | 未公开完整议程（JS 页面仅壳）；只记 Cloud/AI tracks |
| DEF CON 34 | 2026-08-06~09，Las Vegas | https://www.cloud-village.org/dc34；https://www.appsecvillage.com/events/dc-2026 | Cloud Village/AppSec Village 议程已发布 |
| KubeCon + CloudNativeCon EU 2026 | 2026-03-23~26，Amsterdam | https://kccnceu2026.sched.com/ | 已结束，session 页可读 |
| KubeCon + CloudNativeCon NA 2026 | 2026-11-09~12，Salt Lake City | https://events.linuxfoundation.org/kubecon-cloudnativecon-north-america/program/schedule/ | 已公布议程（会前，标注 upcoming） |
| OWASP Global AppSec EU 2026 | 2026-06-22~26，Vienna | https://owasp.glueup.com/en/event/owasp-global-appsec-eu-2026-vienna-austria-162243/ | sched 被 Cloudflare 拦截；用 OWASP 项目页 + 回顾定位主题 |
| OWASP Global AppSec USA 2026 | 2026-11-05~06，San Francisco | https://genai.owasp.org/event/owasp-global-appsec-usa-2026/ | 未公开逐议题议程 |
| RSA Conference 2026 | 2026-03-23~26，San Francisco | https://www.rsaconference.com/library/blog/rsac-2026-conference-top-10-sessions-every-program-committee-wanted | Top-10 session 已公布并可读 |
| KCon 2026 | 2026-11-01，北京 | https://kcon.knownsec.com/；https://www.dwcon.cn/post/5060 | 公布 10 大方向，逐议题标题未发布 |
| 看雪 SDC 2026 | 2026（第十届） | https://bbs.kanxue.com/thread-289688.htm | 仅 CFP/主题方向，未公开议程 |
| 腾讯 TSec / 安全沙龙 | 2026 系列 | https://zc.tencent.com/salon；https://tsecbench.zc.tencent.com/ | 页面为 JS/空壳，未取得逐议题 |
| 阿里云栖大会 2026 | 2026-09-22~24，杭州 | https://yunqi.aliyun.com/2026/live | 主论坛/分论坛主题已公布；安全分论坛逐议题未公开 |
| 字节跳动安全沙龙 | 2026 | 未检索到公开议程页 | **未公开完整议程**，不编造 |
| OffensiveCon 2026 | 2026-05，Berlin | https://www.offensivecon.org/ | 2026 agenda 页 404；只记会议已售罄/训练信息 |
| CanSecWest 2026 | 2026-09-30~10-01，Vancouver | https://www.secwest.net/conference-agenda-2026 | 已发布 presentations，逐篇可读 |
| POC 2026 | 2026，Seoul | https://powerofcommunity.net/ | Talks 列表已发布 |

## 2. 议题 × 覆盖矩阵

> 覆盖判断以「能否从外部只读证据/快照判定」为准；论文提出攻击不等于我们能复现，标 `部分` 的不计为已覆盖。

| ID | 议题 | 会议/日期 | 来源 | 技术点 | 我们是否覆盖 |
|---|---|---|---|---|---|
| I01 | HyperAudit: User Transparent and Highly Efficient System Auditing for Cloud Platforms | USENIX Security 2026 | https://www.usenix.org/conference/usenixsecurity26/technical-sessions | 审计采集器在 guest 内核内可被 rootkit 竞态篡改；需 hypervisor 侧可信采集 | 部分:kubetrail-collector（仅 K8s 审计），hypervisor 侧缺口 R01 |
| I02 | kSFS: in-kernel sandboxed file systems | USENIX Security 2026 | https://www.usenix.org/conference/usenixsecurity26/technical-sessions | FUSE 作为内核内沙箱边界；WebAssembly 泛化沙箱；文件系统攻击面 | 新增:sandbox-runtime-surface |
| I03 | Physical-page use-after-free across CPU/GPU/IOMMU page tables | USENIX Security 2026 | https://www.usenix.org/conference/usenixsecurity26/technical-sessions | 异构地址翻译域不同步导致物理页 UAF；DMA remap 绕过 | 新增:pcie-iommu-dma |
| I04 | The Art of Hide and Seek: Pickle-Based Model Supply Chain Poisoning | USENIX Security 2026 | https://www.usenix.org/conference/usenixsecurity26/technical-sessions | 22 条 pickle 加载路径、EDP 绕过、133 个 gadget | 已覆盖:trust-remote-code-supply-chain + torch-weights-bypass-rce（扫描绕过为残余缺口） |
| I05 | Confundo: Learning to Generate Robust Poison for Practical RAG Systems | USENIX Security 2026 | https://www.usenix.org/conference/usenixsecurity26/technical-sessions | 预处理分片后的 RAG 投毒仍有效；多目标毒化 | 新增:rag-vector-injection |
| I06 | Robust Watermarks Meet Backdoored Models (GhostVAE) | USENIX Security 2026 | https://www.usenix.org/conference/usenixsecurity26/technical-sessions | 在 VAE encoder 植入后门以规避语义水印检测 | 新增:model-watermark-backdoor-detect |
| I07 | PVMark: Public Verifiability for LLM Watermarking | USENIX Security 2026 | https://www.usenix.org/conference/usenixsecurity26/technical-sessions | ZKP 证明水印检测正确执行，不泄露密钥 | 新增:model-watermark-backdoor-detect |
| I08 | "Do Not Mention This to the User": Malicious Agent Skills in the Wild | USENIX Security 2026 | https://www.usenix.org/conference/usenixsecurity26/technical-sessions | 98,380 个 skill 中 157 个恶意；RCE+文档注入 | 部分:supply-chain-pinning；agent skill 注册表缺口 R02 |
| I09 | Improving Safety with Privacy: Confidential Computing for Cloud Inference | USENIX Security 2026 | https://www.usenix.org/conference/usenixsecurity26/technical-sessions | 加密、远程证明、confidential computing 支撑云推理 | 新增:confidential-containers-attestation |
| I10 | Breaking the Lethal Trifecta: Causal Isolation Architecture | USENIX Security 2026 | https://www.usenix.org/conference/usenixsecurity26/technical-sessions | 读不可信输入+敏感上下文+外联三者隔离 | 新增:sandbox-runtime-surface（部分：应用层因果隔离未覆盖） |
| I11 | Breaking the Bulkhead: Cross-Namespace Reference Vulnerabilities in Kubernetes Operators | NDSS 2026 | https://www.ndss-symposium.org/ndss-paper/breaking-the-bulkhead-demystifying-cross-namespace-reference-vulnerabilities-in-kubernetes-operators/ | Operator 跨 namespace 引用导致越权/凭据读取 | 部分:rbac-mapping；Operator 引用图缺口 R03 |
| I12 | Losing the Beat: Desynchronization Risks in Container Isolation | NDSS 2026 | https://www.ndss-symposium.org/ndss-paper/losing-the-beat-understanding-and-mitigating-desynchronization-risks-in-container-isolation/ | 容器生命周期与隔离配置不同步 | 新增:sandbox-runtime-surface |
| I13 | Bit of a Close Talker: Serverless Cloud Co-Location Attacks | NDSS 2026 | https://www.ndss-symposium.org/ndss-paper/bit-of-a-close-talker-a-practical-guide-to-serverless-cloud-co-location-attacks/ | 无服务器共置侧信道/资源争用 | 新增:sandbox-runtime-surface（部分：宿主侧共置未覆盖） |
| I14 | SoK: Analysis of Accelerator TEE Designs | NDSS 2026 | https://www.ndss-symposium.org/ndss-paper/sok-analysis-of-accelerator-tee-designs/ | GPU/NPU TEE 威胁模型与证明边界 | 新增:confidential-containers-attestation；GPU TEE 细节部分:cgpu-isolation-audit |
| I15 | Exploiting TLBs in Virtualized GPUs for Cross-VM Side-Channel Attacks | NDSS 2026 | https://www.ndss-symposium.org/ndss-paper/exploiting-tlbs-in-virtualized-gpus-for-cross-vm-side-channel-attacks/ | vGPU TLB 跨 VM 侧信道 | 部分:cgpu-isolation-audit + pcie-iommu-dma |
| I16 | Janus: Expressive and Efficient ACLs in High-speed RDMA Clouds | NDSS 2026 | https://www.ndss-symposium.org/ndss-paper/janus-enabling-expressive-and-efficient-acls-in-high-speed-rdma-clouds/ | RDMA 云 ACL 表达力/执行点 | 部分:ib-sm-partition-audit + dpu-ipu-offload |
| I17 | Cache Me, Catch You: Cache Related Security Threats in LLM Serving Frameworks | NDSS 2026 | https://www.ndss-symposium.org/ndss-paper/cache-me-catch-you-cache-related-security-threats-in-llm-serving-frameworks/ | 前缀/语义缓存跨租户泄漏与投毒 | 已覆盖:cache-salt-policy-audit + prefix-cache-cross-tenant-leak + cache-poison-persistence |
| I18 | Unified Defense Against Membership Inference in Federated Learning | NDSS 2026 | https://www.ndss-symposium.org/ndss-paper/a-unified-defense-framework-against-membership-inference-in-federated-learning-via-distillation-and-contribution-aware-aggregation/ | 联邦成员推断防御/贡献感知聚合 | 新增:federated-learning-surface |
| I19 | EXIA: Trusted Transitions for Enclaves via External-Input Attestation | NDSS 2026 | https://www.ndss-symposium.org/ndss-paper/exia-trusted-transitions-for-enclaves-via-external-input-attestation/ | 外部输入绑定证明，防状态转换欺骗 | 新增:confidential-containers-attestation |
| I20 | CTng: Secure Certificate and Revocation Transparency | NDSS 2026 | https://www.ndss-symposium.org/ndss-paper/ctng-secure-certificate-and-revocation-transparency/ | 证书/撤销透明日志；PKI 信任 | 新增:cert-manager-webhook-tls |
| I21 | Parasites in the Toolchain: Attacks on the MCP Ecosystem | IEEE S&P 2026 | https://sp2026.ieee-security.org/program.html | MCP server/tool 供应链投毒与权限滥用 | 部分:trident/probes（提示注入）；MCP 控制面缺口 R04 |
| I22 | GHost in the SHELL: GPU-to-Host Memory Attack and Mitigation | IEEE S&P 2026 | https://sp2026.ieee-security.org/program.html | GPU 写宿主内存；IOMMU/驱动边界 | 新增:pcie-iommu-dma |
| I23 | Beyond the Control Plane: Cross-Service Flaws in Cloud Identity Service | IEEE S&P 2026 | https://sp2026.ieee-security.org/program.html | 云身份服务跨服务组合缺陷 | 部分:cloud-role-overprivilege + cloud-irsa-trust-wildcard |
| I24 | Rain: Transiently Leaking Data from Public Clouds Using Old Vulnerabilities | IEEE S&P 2026 | https://sp2026.ieee-security.org/program.html | 旧漏洞组合击穿公有云隔离 | 部分:sandbox-runtime-surface（宿主逃逸检测） |
| I25 | It's a Feature, Not a Bug: Secure and Auditable State Rollback for Confidential Cloud | IEEE S&P 2026 | https://sp2026.ieee-security.org/program.html | 机密云应用可审计回滚；状态完整性 | 新增:confidential-containers-attestation |
| I26 | GraphRAG under Fire | IEEE S&P 2026 | https://sp2026.ieee-security.org/program.html | 图 RAG 投毒/检索污染 | 新增:rag-vector-injection |
| I27 | Your Compiler is Backdooring Your Model: DL Compiler Inconsistency | IEEE S&P 2026 | https://sp2026.ieee-security.org/program.html | 编译器不一致导致模型后门 | 部分:supply-chain-pinning + model-watermark-backdoor-detect |
| I28 | Designing Transport-Level Encryption for Datacenter Networks | IEEE S&P 2026 | https://sp2026.ieee-security.org/program.html | 数据中心传输层加密与策略 | 新增:post-quantum-tls-posture（部分：DPU 线速卸载） |
| I29 | Revisiting PQ WireGuard / X-Wing | IEEE S&P 2026 | https://sp2026.ieee-security.org/program.html | 后量子 KEM/混合握手安全分析 | 新增:post-quantum-tls-posture |
| I30 | Cosseter: GitHub Actions Permission Reduction | IEEE S&P 2026 | https://sp2026.ieee-security.org/program.html | CI token 权限最小化/静态分析 | 新增:gitops-supply-chain |
| I31 | T3C: Typed Trust Contracts for Containers and Clusters | CCS 2025 | https://www.researchgate.net/publication/415840266_T3C_Typed_Trust_Contracts_for_Containers_and_Clusters | 容器/集群类型化信任契约 | 新增:confidential-containers-attestation（部分：契约验证未覆盖） |
| I32 | A Billion-User Blast Radius: Owning ChatGPT's Secure Sandbox | Black Hat USA 2026 | https://www.straiker.ai/blog/black-hat-usa-2026-ai-security-talks | 文件解析持久化、python.exec 注入、Task Scheduler URL 洗白、跨租户 | 新增:sandbox-runtime-surface |
| I33 | When AI Attacks AI: ShadowRay 2.0 Botnet | Black Hat USA 2026 | https://www.straiker.ai/blog/black-hat-usa-2026-ai-security-talks | Ray 集群被武器化为自传播 botnet | 已覆盖:ray-control-plane + ray-dashboard-job（自传播检测部分） |
| I34 | When Agentic Glue Melts: Exploiting Cloudflare CodeMode and Workers | Black Hat USA 2026 | https://www.straiker.ai/blog/black-hat-usa-2026-ai-security-talks | V8 isolate/Workers 沙箱逃逸、跨租户 | 新增:wasm-workload-surface（部分：V8 isolate 非 WASM） |
| I35 | Promptware EOD: Skillful Agent Detonation | Black Hat USA 2026 | https://www.straiker.ai/blog/black-hat-usa-2026-ai-security-talks | skill/MCP 供应链恶意载荷、rug pull | 部分:data-provenance-audit；agent skill 缺口 R02 |
| I36 | Caging the Agent: Roblox Multi-Layer Sandboxes for Claude Code | Black Hat USA 2026 | https://www.straiker.ai/blog/black-hat-usa-2026-ai-security-talks | 文件系统虚拟化、网络策略、凭据隔离、行为监控 | 新增:sandbox-runtime-surface |
| I37 | The Hidden Cost of Agentic Connectivity: 19,000 MCP Servers | DEF CON 34 Cloud Village | https://www.cloud-village.org/dc34 | MCP server 默认部署风险、策略绕过、云基础设施操控 | 部分:aigateway-auth-bypass；MCP 控制面缺口 R04 |
| I38 | The Polymorphic Agent: Cross-Agent Escalation on Azure | DEF CON 34 Cloud Village | https://www.cloud-village.org/dc34 | 工具描述投毒→跨 agent IAM 提权→凭据层拦截 | 新增:spiffe-spire-surface（身份面）；IAM 部分:cloud-role-overprivilege |
| I39 | Container Escapes 101 | DEF CON 34 AppSec Village | https://www.appsecvillage.com/events/dc-2026/container-escapes-101-1238105 | 容器逃逸原语与防护 | 已覆盖:escape-primitives + runc-escape-detect + runtime-socket-escape |
| I40 | Confidential Platforms for Regulated Industries | KubeCon EU 2026 | https://kccnceu2026.sched.com/event/2CW45/confidential-platforms-for-regulated-industries-william-rizzo-mirantis | CoCo + 硬件证明 + mutating webhook 注入 confidential runtime | 新增:confidential-containers-attestation |
| I41 | SPIFFE Meets OAuth: Federated Identity for Cloud Native Workloads | KubeCon EU 2026 | https://kccnceu2026.sched.com/event/2CW5g/spiffe-meets-oauth-federated-identity-for-cloud-native-workloads-yoshiyuki-tabata-hitachi-ltd | SPIFFE/SPIRE 与 OAuth 联邦；工作负载身份 | 新增:spiffe-spire-surface |
| I42 | Istio's Ambient Mesh: The Real Cost of Security | KubeCon EU 2026 | https://kccnceu2026.sched.com/event/2CW2a | ambient 无 sidecar 的安全成本/策略覆盖 | 新增:gateway-api-ambient-mesh |
| I43 | GitOps and Secrets: State of the Union | KubeCon EU 2026 co-located | https://colocatedeventseu2026.sched.com/event/2DY22/gitops-and-secrets-state-of-the-union-kostis-kapelonis-octopus-deploy | Argo CD 3.x 密钥外置、GitOps 密钥管理 | 新增:gitops-supply-chain |
| I44 | Achieving Resilient Multi-Cluster AI Inference with Karmada and KubeRay | KubeCon EU 2026 | https://kccnceu2026.sched.com/event/2CW5v/achieving-resilient-multi-cluster-ai-inference-on-kubernetes-with-karmada-and-kuberay-wei-cheng-lai-bloomberg-han-ju-chen-anyscale | Karmada 放置/副本/故障转移 + KubeRay | 新增:multi-cluster-federation |
| I45 | Sandbox Operator: Session-aware MCP Tool Execution in Kubernetes | KubeCon EU 2026 | https://kccnceu2026.sched.com/event/2CW1c/sandbox-operator-enabling-session-aware-efficient-mcp-tool-execution-in-kubernetes-mingshan-zhao-zhen-zhang-alibaba | MCP 工具执行沙箱/checkpoint-restore | 新增:sandbox-runtime-surface |
| I46 | cert-manager ContribFest / Gateway API 证书 | KubeCon EU 2026 | https://cert-manager.io/docs/contributing/contribfest-kubecon-eu-2026/agenda/ | webhook 证书生命周期、Gateway API 证书 | 新增:cert-manager-webhook-tls |
| I47 | WasmCon / wasmCloud v2.0.1 | KubeCon EU 2026 | https://wasmcloud.com/blog/wasmcloud-at-kubecon-cloudnativecon-eu-2026/ | Wasm 组件在 K8s 的运行时与能力边界 | 新增:wasm-workload-surface |
| I48 | If It's Shared, It's Vulnerable: Is Kubernetes Right for Confidential Compute? | KubeCon NA 2026（upcoming） | https://events.linuxfoundation.org/kubecon-cloudnativecon-north-america/program/schedule/?id=1250838 | 证明能验证工作负载但不能验证共享拓扑；三层隔离模型 | 新增:confidential-containers-attestation |
| I49 | Signed, Sealed, Denied: Attestation-Driven Admission with Kyverno + CEL | KubeCon NA 2026（upcoming） | https://events.linuxfoundation.org/kubecon-cloudnativecon-north-america/program/schedule/?id=1247300 | Sigstore 证明 + Kyverno ImageValidatingPolicy 准入 | 新增:data-provenance-audit |
| I50 | The Spin Sandbox: Secure Execution of AI-Generated Code with Spin/WASI | KubeCon NA 2026（upcoming） | https://events.linuxfoundation.org/kubecon-cloudnativecon-north-america/program/schedule/?id=1362597 | WASI capability-based 沙箱执行 AI 代码 | 新增:wasm-workload-surface |
| I51 | GitOps Without You Writing YAML: Flux Grounds AI Agents | KubeCon NA 2026（upcoming） | https://events.linuxfoundation.org/kubecon-cloudnativecon-north-america/program/schedule/?id=1289630 | Flux MCP/schema grounding、GitOps Agent Skills | 新增:gitops-supply-chain |
| I52 | Cluster API / Karmada Multi-Cluster Updates | KubeCon NA 2026（upcoming） | https://events.linuxfoundation.org/kubecon-cloudnativecon-north-america/program/schedule/?id=1289885 | 多集群放置、GitOps pull、故障转移 | 新增:multi-cluster-federation |
| I53 | In-Toto: Experiences a Few Million Attestations Later | KubeCon NA 2026（upcoming） | https://events.linuxfoundation.org/kubecon-cloudnativecon-north-america/program/schedule/?id=1289646 | in-toto/SLSA/Sigstore 证明规模化 | 新增:data-provenance-audit |
| I54 | OWASP MCP Top 10 / Agentic Skills Top 10 / AI-BOM | OWASP Global AppSec EU 2026 | https://owasp.org/www-project-agentic-skills-top-10/ast02 | MCP/agent skill 供应链、AI-BOM 可追溯 | 部分:data-provenance-audit；agent skill 缺口 R02 |
| I55 | AI Security in the Wild: 2 Years of Hacking AI Infrastructure | RSA 2026 | https://www.rsaconference.com/library/blog/rsac-2026-conference-top-10-sessions-every-program-committee-wanted | 真实 AI 基础设施攻击面（Ray/Notebook/模型服务） | 部分:ray-control-plane + exposure-mapping；统一 AI infra 基线缺口 R05 |
| I56 | AI Guard: Securing LLMs, Agents, and AI Apps at Uber Scale | RSA 2026 | https://www.rsaconference.com/library/blog/rsac-2026-conference-top-10-sessions-every-program-committee-wanted | 大规模 LLM/agent 网关与 guardrail | 已覆盖:aigateway-guardrail-bypass + aigateway-auth-bypass（规模面部分） |
| I57 | Post-Quantum Migration / TLS & PKI | RSA 2026 | https://pqshield.com/rsa-conference-2026-views-on-quantum-safe-migrations/ | 证书寿命、混合 KEM、PKI 迁移 | 新增:post-quantum-tls-posture |
| I58 | 多租户 AI 推理安全 | KCon 2026（方向） | https://www.dwcon.cn/post/5060 | 多租户推理隔离、缓存/权重/资源边界 | 部分:cache-salt-policy-audit + gpu-tenant-residue + vllm-timing-oracle；统一多租户推理缺口 R06 |
| I59 | 智能体进程隔离 | KCon 2026（方向） | https://www.dwcon.cn/post/5060 | Agent 进程/工具执行隔离 | 新增:sandbox-runtime-surface |
| I60 | Agentic Cloud / MaaS & Agent 基础设施 | 云栖大会 2026 | https://yunqi.aliyun.com/2026/live | Agent 原生基础设施、MaaS 控制面 | 部分:aigateway-*；Agent 原生控制面缺口 R07 |
| I61 | AI Security at Scale: Memory Safety Across the ML Inference Stack | CanSecWest 2026 | https://www.secwest.net/csw26-presentations/ai-security-at-scale-memory-safety-across-the-ml-inference-stack | vLLM/SGLang/ONNX/Triton 原生内存安全 | 部分:vllm-surface-fuzz + vllm-sglang-patch-matrix |
| I62 | Dude, Where's My Git Secrets: .git in Docker Images | CanSecWest 2026 | https://www.secwest.net/csw26-presentations/dude-where-is-my-git-secrets-and-commits-left-behind-in-docker-images | 50 万镜像层中的 .git/CI token | 部分:supply-chain-credential-theft + secret-scanner |
| I63 | Forever Chemicals / Agents Broke Out of Sandboxes | CanSecWest 2026 | https://www.secwest.net/csw26-presentations/forever-chemicals-life-after-the-ai-event-horizon | 四个前沿实验室 agent 逃逸沙箱并联合作战 | 新增:sandbox-runtime-surface |
| I64 | One Bit to Escape: QNX Hypervisor Guest-to-Host VM Escape | POC 2026 | https://powerofcommunity.net/ | 虚拟化边界 guest→host 逃逸 | 部分:sandbox-runtime-surface（VM 边界检测） |
| I65 | Sand-Unboxing: Breaking the V8 Sandbox 10+ Times | POC 2026 | https://powerofcommunity.net/ | V8 沙箱时间性设计缺陷 | 部分:wasm-workload-surface（WASM/V8 isolate 边界） |

## 3. 覆盖统计

- 议题条目：**65**（I01–I65；官方议程/论文页可核验；upcoming 的 KubeCon NA 单独标注）
- 覆盖列引用：`新增:` **41** 处、`已覆盖:` **5** 条、`部分:` **21** 条（同一行可同时含“新增+部分”，故不相加为 65）
- 未覆盖清单：**G01–G16** 16 条（全部已落地模块）+ **R01–R07** 7 条残余缺口
- 会议覆盖：USENIX Security、IEEE S&P、NDSS、CCS、Black Hat USA、DEF CON、KubeCon EU/NA、OWASP、RSA、KCon、云栖、CanSecWest、POC 均有条目；Black Hat Europe/SDC/TSec/字节/OffensiveCon 仅记录状态，不编造标题。

## 4. 未覆盖清单与模块映射

| ID | 未覆盖缺口 | 证据议题 | 落地模块 | 分级 | 关键检测点 |
|---|---|---|---|---|---|
| G01 | CoCo/Kata/SEV-SNP 容器证明只到“有 TEE”层，缺少测量值/策略/debug 判定 | I09,I14,I19,I25,I31,I40,I48 | confidential-containers-attestation | 主动探测 | measurement≠expected、debug、report_data 未绑定、require_attestation=false、allowed_images=* |
| G02 | 只有 runc/容器逃逸检测，缺 gVisor/Firecracker 运行时与 Pod 安全上下文矩阵 | I02,I10,I12,I13,I24,I32,I36,I45,I59,I63,I64 | sandbox-runtime-surface | 只读侦察 | runtime=runsc/firecracker、seccomp、SYS_ADMIN、hostPID/hostNetwork |
| G03 | 无 SPIFFE/SPIRE 工作负载身份审计 | I38,I41 | spiffe-spire-surface | 主动探测 | 通配 ID、空 selector、TTL=0、admin ACL、0.0.0.0 |
| G04 | 无 cert-manager webhook 证书/SAN/CA bundle 审计 | I20,I46 | cert-manager-webhook-tls | 主动探测 | 过期、SAN 不匹配、caBundle、insecureSkipVerify、轮换 |
| G05 | 无 Gateway API/ambient mesh 策略缺口审计 | I42 | gateway-api-ambient-mesh | 只读侦察 | 明文 HTTP、通配 host、跨 ns route、waypoint L7、ztunnel bypass |
| G06 | 无 WASM（SpinKube/wasmCloud）能力边界审计 | I34,I47,I50,I65 | wasm-workload-surface | 主动探测 | 宿主 fs/net、env 继承、WASI unstable、未签名 |
| G07 | 只有 gitops-secret-read，无 GitOps 密钥/漂移/签名全链审计 | I30,I43,I51 | gitops-supply-chain | 只读侦察 | 明文密钥、drift、auto-sync 未签名、prune、external-secrets |
| G08 | 无 Karmada/Cluster API 多集群联邦审计 | I44,I52 | multi-cluster-federation | 只读侦察 | 通配传播、kubeconfig 共享、审批、failover、ns 隔离 |
| G09 | dpu-smartnic-surface 只看服务/凭据，未看 offload 数据面/IOMMU | I16,I28 | dpu-ipu-offload | 主动探测 | host_offload、host services、IOMMU、switchdev、固件 |
| G10 | 无 PCIe IOMMU/ACS/DMA 隔离审计 | I03,I15,I22 | pcie-iommu-dma | 只读侦察 | IOMMU off、共享 group+passthrough、ACS、ATS、DMA protection |
| G11 | 无 TPM measured boot/PCR/eventlog 审计 | I03,I14（根信任侧） | tpm-measured-boot | 只读侦察 | Secure Boot、measured boot、PCR mismatch、SHA-1 bank、AK |
| G12 | 无后量子 TLS 姿态审计 | I28,I29,I57 | post-quantum-tls-posture | 主动探测 | TLS<1.3、RSA KEX、无 X25519MLKEM768、非 PQ 签名、HNDL |
| G13 | 无模型水印/后门检测审计 | I06,I07,I27 | model-watermark-backdoor-detect | 主动探测 | 水印缺失、验证端点、trigger scan、来源签名 |
| G14 | 只有 vector-db-exposure，无 RAG 注入/检索隔离审计 | I05,I26 | rag-vector-injection | 主动探测 | 未签名外部文档、共享 embedding ns、tenant filter、清洗/上限 |
| G15 | 无联邦学习聚合面审计 | I18 | federated-learning-surface | 只读侦察 | 更新未签名、secure aggregation、DP、拜占庭过滤、范数异常 |
| G16 | 无 SLSA/in-toto/Sigstore 来源证明审计 | I35,I49,I53,I54 | data-provenance-audit | 主动探测 | 签名无效、builder、materials、SBOM、SLSA、Rekor、drift |
| R01 | hypervisor 侧可信审计/日志竞态 | I01 | 未落地（需 hypervisor 采集器） | — | — |
| R02 | agent skill/MCP 注册表供应链（安装前静态+动态） | I08,I35,I54 | 未落地（需注册表数据源） | — | — |
| R03 | Kubernetes Operator 跨 namespace 引用图 | I11 | 未落地（需 CRD 引用图采集） | — | — |
| R04 | MCP 控制面/工具权限统一治理 | I21,I37 | 未落地（需 MCP 配置采集） | — | — |
| R05 | AI 基础设施统一基线（Ray/Notebook/推理运行时） | I55 | 部分由既有模块覆盖，未统一 | — | — |
| R06 | 多租户推理统一隔离基线（缓存/权重/计时/资源） | I58 | 部分由缓存/GPU 模块覆盖 | — | — |
| R07 | Agent 原生控制面（MaaS/Agent 运行时） | I60 | 未落地 | — | — |

## 5. 新增模块汇总（16）

| 模块键 | 系列 | 分级 | writes | 对应缺口 |
|---|---|---|---|---|
| confidential-containers-attestation | 核心代码 | 主动探测 | false | G01 |
| sandbox-runtime-surface | 权限链 | 只读侦察 | false | G02 |
| spiffe-spire-surface | 权限链 | 主动探测 | false | G03 |
| cert-manager-webhook-tls | 网络架构 | 主动探测 | false | G04 |
| gateway-api-ambient-mesh | 网络架构 | 只读侦察 | false | G05 |
| wasm-workload-surface | 核心代码 | 主动探测 | false | G06 |
| gitops-supply-chain | 核心代码 | 只读侦察 | false | G07 |
| multi-cluster-federation | 混合云 | 只读侦察 | false | G08 |
| dpu-ipu-offload | 网络架构 | 主动探测 | false | G09 |
| pcie-iommu-dma | 网络架构 | 只读侦察 | false | G10 |
| tpm-measured-boot | 侦察 | 只读侦察 | false | G11 |
| post-quantum-tls-posture | 网络架构 | 主动探测 | false | G12 |
| model-watermark-backdoor-detect | 情报 | 主动探测 | false | G13 |
| rag-vector-injection | 窃取与数据泄露 | 主动探测 | false | G14 |
| federated-learning-surface | 情报 | 只读侦察 | false | G15 |
| data-provenance-audit | 情报 | 主动探测 | false | G16 |

## 6. 限制与不编造声明

- **CCS 2025**：官方 program 页当日 404，仅收录可核验的 T3C 条目；未用二手列表补数。
- **Black Hat Europe 2026 / OWASP Global AppSec USA 2026 / SDC 2026 / 腾讯 TSec / 字节安全沙龙 / OffensiveCon 2026**：截至 2026-10-26 未公开完整议程，本文只记录会议状态与主题方向，**不编造逐议题标题**。
- **KubeCon NA 2026**：2026-11-09 才举行，表中标 `upcoming`；只引用已公布的 session 页面。
- **KCon/云栖**：官方只公布方向/分论坛，不把方向名当作具体演讲标题；已在表中标注“方向”。
- **论文≠可利用**：覆盖列只表示我们能从外部证据判定配置/姿态，不代表复现论文攻击。需要真实 TEE/GPU/DPU/TPM 的验证仍在 `docs/HARDWARE-SWITCH-COVERAGE.md` 的三级边界内。
