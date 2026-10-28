# InkBlade（墨刃零）总报告：把 ML 集群渗透测试做成可复述、可复核、可复跑的事

> 版本：2026-10-27（终版）　读者：没做过 K8s 安全、但需要判断这套东西是否可信的人
> 读法：第一至三章讲“是什么、为什么、怎么走”；第四至六章讲“改了什么、数字如何、和谁比”；第七至十章讲“哪里没做到、错在哪、词怎么解释、证据在哪”。
> 状态标记：`[已测]` 有可复现实验或测试；`[模拟]` 只在仿真器、夹具或本机回环上验证；`[未测]` 没有可复现数据，不写成已支持。
> 全文字数约 1.8 万汉字（含表格与代码共 5.3 万字符）。所有数字给出来源文件；没有来源的数字不写。
> **证据日期：2026-10-27（终版）**。本轮计数与仓库当前实际同步，复跑命令见 §10.7。

> **终版计数（证据日期：2026-10-27；唯一事实源为 [`REQUIREMENTS-MATRIX.md`](REQUIREMENTS-MATRIX.md) §1）**
>
> | 项 | 当前实际 | 来源 |
> |---|---:|---|
> | 模块 / 模板 | **287 / 286**（默认启用 276 / 隔离 11；bootstrap 1） | `inkblade/modules/*/module.json`、`docs/SURFACE-REALISM.md` |
> | 旧 `run.py` | **0（工作树）/ 0（HEAD，已提交删除）** | 目录扫描 + `git ls-tree HEAD` |
> | 单元测试 | 见 `REQUIREMENTS-MATRIX.md` §5 实测块（迁移后稳定快照） | `python -m unittest discover -s tests`（§10.7） |
> | 可利用性核验 | **37 verified / 6 exposure-verified / 87 static-only / 22 unsupported**（共 152） | `inkblade/core/exploit-registry.json` |
> | 画像覆盖（production，6 画像） | 70.65% / 67.39% / 59.78% / 67.75% / 68.48% / **25.00%**（Slurm 域级 88.2%） | `docs/SURFACE-REALISM.md`、`docs/SLURM-HPC-COVERAGE.md` |
> | 默认 PoC | **11**（六画像默认可利用 3/2/3/2/4/0） | `exploit-registry.json` + `SURFACE-REALISM.md` |
> | 无面模块 | **19**（11 个已隔离 + 8 个待 owner） | `docs/SURFACE-REALISM.md` §2 |
> | 语料 | **80 源**（cn 24 / en 42 / paper 14） | `inkblade/arch-intel/coverage-matrix.json` |
> | 需求矩阵 | **129 条**：done **94** / partial **28** / not-done **0** / blocked-resource **7** | `REQUIREMENTS-MATRIX.md` §2.4、§3.5 |
> | 未达成项 | **11 条**（见 §7.7） | 本文 §7、`docs/SOTA-2026-10.md` |
>
> **分层口径**：检测模型为**十层**（1–9 业务面 + 第 10 层防护绕过）；「七组件」只指控制端
> （治理、编排、模块、证据、报告、可视化、规则），不是另一套产品分层，也不存在并行的「九层」版本。
>
> 口径：模块/画像/无面为静态统计；测试为全量 `unittest discover` 实测（迁移已收口，无在途红测）；
> verified 只认 `exploit-registry.json` 的 `verified`；exposure-verified 与 static-only/unsupported 不计入可利用清单。
> 历史测试计数（1933/1891/1904/2003）为不同快照，逐项归因见 `DEV-LOG.md` §D 与 `progress.md`。
>
> **探针架构口径**：模块现在只有 `module.json` + `template.json`，执行载体是目标 Pod 内 Rust 探针；
> **286/286 模板已在静态 musl 探针上跑完 vulnerable/fixed 两态，每态连续 3 次一致，0 失败**
> （二进制 `c8d2f118…`，源码 `1f0f57c`，probe 0.1.1）。不要把参考评估器结果写成 Rust 结果，
> 也不要把已删除的 `run.py` 写成「仍是 Python 模块成品」；fixed 态负控边界见 `PROBE-COVERAGE.md` §6。
>
> **0.2.0 改名（2026-10-27）**：项目由 Trident 更名为 InkBlade（墨刃零）；本报告中的
> 包路径、命令示例与规则命名空间已同步，改名记录见 [`CHANGELOG.md`](../CHANGELOG.md)。

---

## 一、前置知识：12 个概念，用白话讲清

这一章不要求你会 K8s，也不要求你懂 GPU。你只需要记住一件事：**ML 集群是“普通云原生”加“昂贵加速器”加“会流动的模型权重”三件事叠在一起**。下面 12 个词，是读懂后面所有章节的最小集合。

### 1.1 K8s（Kubernetes）

K8s 是一个“集群操作系统”。你把“我要跑一个服务、要几块 GPU、要多少内存”写成配置交给它，它负责找机器、拉起容器、在挂掉后重启。它把很多台机器伪装成一台大电脑。代价是：它自己有一套身份、网络、权限和 API，这些面都可能被配错。K8s 不是“安全边界”，它只是“调度器加 API 服务器”。

### 1.2 Pod

Pod 是 K8s 里最小的运行单元。一个 Pod 里可以有一个或多个容器，它们共享网络地址和挂载卷。你可以把 Pod 想成“一个进程组加一个共享文件夹”。攻击者拿到 Pod 里的一个 token，往往就能用这个 Pod 的身份去问 K8s：“我是谁、我能干什么”。所以 Pod 不是“一个临时容器”，它是**身份载体**。

### 1.3 RBAC

RBAC 是 K8s 的“谁能对什么做什么”的权限表。它由角色（Role/ClusterRole）和绑定（RoleBinding/ClusterRoleBinding）组成。比如“允许在 ml 命名空间里读 Secret”。RBAC 的危险点不是“有没有权限”，而是“权限是不是通配符、是不是绑给了不该绑的服务账号”。很多集群不是被攻破的，是被“本来就过大的权限”放大的。

### 1.4 Service

Service 是 K8s 给一组 Pod 起的稳定入口。Pod 会重启、IP 会变，Service 的虚拟 IP 和名字不变。它像“公司总机”：你不需要知道分机搬到哪，只要拨总机。Service 可以只在集群内可见（ClusterIP），也可以暴露到节点端口（NodePort）或云负载均衡（LoadBalancer）。暴露面越大，被扫到的概率越高。

### 1.5 NetworkPolicy

NetworkPolicy 是 K8s 的“防火墙规则”，用来规定哪些 Pod 能访问哪些 Pod。它默认不是“全拒”，而是“没被策略选中的流量照常走”。更关键的是：不同网络插件（CNI）对策略的支持不一样；`hostNetwork` 的 Pod 直接走主机网络，常常绕过策略。所以“我写了 NetworkPolicy”不等于“网络已经隔离”。

### 1.6 GPU 训练与推理

训练是“用大量数据反复算梯度、更新权重”，通常跨很多 GPU、跑几天到几个月。推理是“把训练好的模型拿来回答请求”，要求低时延、高吞吐。训练怕中断、怕数据错、怕权重被改；推理怕密钥泄露、怕缓存串租户、怕被超长请求打爆。两者共用 GPU、网络和存储，但故障后果不同：训练事故烧的是时间和钱，推理事故漏的是数据和密钥。

### 1.7 NCCL 集合通信

NCCL 是 NVIDIA 的集合通信库。训练时很多 GPU 要“一起算一个结果”，比如把所有 GPU 的梯度加起来，这叫 all-reduce。NCCL 负责建连接、选路径、把数据从一个 GPU 发到另一个 GPU。它默认信任“同一个作业里的 rank 都是自己人”。如果攻击者能加入集合通信、伪造 rank、或者把某个 rank 拖慢，训练就会变慢、算错，甚至静默产出坏模型。

### 1.8 KV cache

大模型推理时，每个 token 都要算注意力。为了避免重复计算，系统会把历史 token 的 Key/Value 向量缓存起来，这就是 KV cache。它很占显存，也很值钱：缓存命中能显著降低时延。危险在于“缓存键”如果只按文本前缀算、不区分租户，A 租户就可能命中 B 租户的缓存，读到别人的上下文。KV cache 不是“临时文件”，它是**跨请求的数据面**。

### 1.9 prefill 与 decode

推理分两段。prefill 是“把用户输入一次性读进去、建立 KV cache”，算力密集；decode 是“一个 token 一个 token 往外吐”，显存带宽密集。把两段拆到不同机器上跑，叫 PD 分离。PD 分离能提高利用率，但也多了一条“KV 传输通道”：谁能写这条通道，谁就能改别人的推理上下文。很多长上下文攻击打的就是 prefill 队列和 KV 通道。

### 1.10 AI 网关

AI 网关是“模型 API 的统一前台”。它负责鉴权、限流、配额、路由、缓存、日志、把请求转给 OpenAI、Anthropic 或自建模型。它像“模型世界的反向代理”。一旦网关的 master key 是默认值、管理 API 没鉴权、`X-Forwarded-User` 可伪造，攻击者就能看到所有租户的 key、日志和缓存。网关不是“外围组件”，它是**密钥和流量的交汇点**。

### 1.11 租户

租户是“共享同一套基础设施、但彼此不能看见对方数据”的客户单位。在 ML 集群里，租户可能是一个训练团队、一个业务线、一个外部客户。租户隔离不只是“命名空间隔离”：还包括 GPU 显存残留、权重桶、KV cache、网关日志、快照共享。很多事故不是“攻破集群”，而是“从一个租户滑到另一个租户”。

### 1.12 证据链

证据链是“从结论回到原始事实的路”。一条“发现”不能只说“这里有漏洞”，还要能点开：哪次运行、哪一步、什么请求、什么响应、文件哈希是多少、谁批准的、有没有回滚。证据链的作用不是“好看”，而是让甲方、审计、监管和修复团队能复核同一件事。没有证据链，渗透报告就是意见；有证据链，才是可验收的工程交付。

### 1.13 把 12 个词串起来

K8s 调度 Pod；Pod 带着 RBAC 身份；Service 把 Pod 暴露成入口；NetworkPolicy 试图限制流量；GPU 上的训练用 NCCL 通信；推理用 KV cache 和 prefill/decode；AI 网关把请求分给租户；租户之间共享权重、缓存和日志；一旦某个环节被放大，最后要靠证据链把“怎么发生的”讲清楚。后面的攻击路径和产品流程，都是这条链上的节点。

**证据索引（本章）**：[架构说明](ARCHITECTURE.md) · [SOTA 能力矩阵](SOTA-2026-10.md) · [长上下文威胁模型](LONG-CONTEXT.md) · [AI 网关威胁模型](AI-GATEWAY.md) · [GPU 与云租户](GPU-CLOUD-TENANCY.md)

---

## 二、我们要解决什么问题：从进入内网到破坏训练/推理

### 2.1 一个故事：攻击者不需要“攻破 K8s”，只需要找到一条被信任的路

下面是一个授权演练里的典型路径。人物、时间、IP 都是虚构的，但每一步都能在真实集群里找到对应物。

周一 9:40，红队拿到一个低权限员工的 VPN。10:05，他们在内网扫到一个 JupyterHub。这个 JupyterHub 的 `/hub/api` 没有做细粒度鉴权，攻击者能用普通账号创建一个 Notebook Pod。10:20，Notebook Pod 里挂着一个服务账号 token。这个 token 本来只该“读自己的 Pod”，但集群给它的 RoleBinding 带了 `secrets list`。攻击者用这个 token 调 K8s API，读到了 Ray 集群的 dashboard token。

10:40，攻击者用 dashboard token 打开 Ray Dashboard。Ray Dashboard 没有认证，而且允许提交 Job。11:00，攻击者提交一个“看起来很正常的训练任务”，这个 Job 的 Pod 模板里写了 `hostPath: /` 和 `privileged: true`。11:20，Pod 起来后，攻击者读到节点上的 kubelet 凭据和容器运行时 socket。此时他已经从“一个 Notebook”走到了“节点”。

11:40，攻击者顺着节点的云身份（IRSA 或节点角色）访问对象存储。他发现权重桶的 trust policy 是 `Principal: "*"`，而且没有 ExternalId。他不需要知道模型的架构，只需要把 `model.safetensors` 下载下来，改几个字节，再传回去。12:00，训练任务继续跑，loss 曲线看起来更平滑了，但验证集精度在两周后掉了 3 个点。没有人报警，因为“训练本来就会波动”。

13:00，攻击者又去看推理侧。AI 网关的管理 API 没有鉴权，`/config` 直接返回上游 OpenAI 和 Anthropic 的 key。网关的语义缓存键只按 prompt 前缀算，不区分租户；A 租户的请求命中了 B 租户的缓存。13:20，攻击者用伪造的 `X-Forwarded-User: admin` 看到了全租户的日志。到这里，他既拿到了密钥，也拿到了数据，还不需要碰 GPU 驱动。

这个故事的重点不是“攻击者多厉害”，而是：**每一步都踩在一个“本来就被信任”的组件上**。K8s 信任 Pod 的身份，Ray 信任 dashboard，节点信任 hostPath，云信任 trust policy，网关信任转发头。InkBlade 要做的，就是把这些“被信任的假设”逐条变成可验证的发现，并且在验证时留下证据、控制影响。

### 2.2 普通 K8s 扫描器为什么不够

普通 K8s 扫描器回答的是“这个集群有没有配错”。比如“有没有特权 Pod”“有没有匿名 API”“有没有过大的 Role”。这些很重要，但 ML 集群还有四类它们通常不回答的问题：

第一，**权重和数据面**。模型权重放在哪、谁能写、写了之后训练会不会静默变坏、备份能不能回滚。普通扫描器看到的是 PVC 和桶，不是“这个 checkpoint 属于哪个作业、写坏后影响哪个模型”。

第二，**GPU 和集合通信面**。MIG 档位、MPS 共享、GPU 显存残留、NCCL 端口、IB Partition、SHARP 会话、PFC 风暴。这些不是 K8s API 对象，普通扫描器的清单里没有它们。

**芯片/加速器能力边界（必要性分级，2026-10-26 收紧）**：只有 A 类算“芯片渗透能力”——A1 IOMMU/SMMU 直通与 DMA、A2 BMC/DPU/IPMI 带外接管（补 Redfish UpdateService/FirmwareInventory 只读面）、A3 GPU 显存/MIG/MPS 跨租户残留与隔离绕过。B 类是保障性检测：GPU CC 证明链（NRAS JWKS/nonce/claims）、固件签名/安全启动/TPM/微码吊销；报告写“检测到 false trust/持久化风险”，不写“攻破”。C 类 SPDM 细项、NVLink/IMEX、CXL 标 `research-only`、默认关闭，**不计入芯片渗透能力**；D 类 RTL/GDSII/DFT、功耗电磁/毛刺/开盖、Rowhammer/微架构侧信道实操明确不做。详见 `docs/CHIP-SECURITY-SCOPE.md`。

第三，**推理与网关面**。KV cache 跨租户、prefix cache 复用、prefill 队列打爆、网关 master key、语义缓存键、配额绕过。这些是“请求级”问题，不是“资源配置级”问题。

第四，**证据与影响**。甲方要的不是“疑似有漏洞”，而是“我能在不改坏生产的前提下，证明这条链能走到哪、影响是什么、怎么回滚、怎么复测”。普通扫描器给的是清单，InkBlade 给的是案卷。

### 2.3 甲方为什么需要它

**第一，ML 集群的安全预算很高，但验证手段很少。** 一张 GPU 卡很贵，一次训练中断很贵，一次权重污染更贵。甲方不能靠“红队手工试”来覆盖几十个团队、几百个命名空间。他们需要一个可重复、可授权、可回滚的测试流程。

**第二，合规和审计需要“可复核的证据”。** 等保、ISO/IEC 42001、NIST AI RMF、EU AI Act、TC260 都要求“风险被识别、措施被验证、过程被记录”。一份只有截图的报告过不了审。InkBlade 的三层证据、manifest 哈希、审批记录和双语报告，就是为这个场景设计的。

**第三，ML 团队和 Security 团队说的不是一种语言。** ML 团队关心“我的训练会不会停、我的模型会不会坏”；Security 团队关心“权限、网络、密钥”。InkBlade 的报告把同一条发现同时映射到 PTES、CVSS、MITRE ATLAS、OWASP LLM/Agentic 和等保条款，目的不是“堆框架”，而是让两个团队能在同一页上对话。

**第四，测试本身必须安全。** 写类动作要有备份，不可逆写要逐动作审批，未授权时 CLI 和 API 都要拒绝执行。甲方最怕的不是“没测出问题”，而是“测出问题的方式把生产搞坏了”。InkBlade 的四道闸门就是为此存在的。

### 2.4 边界：它不是“万能攻击平台”

InkBlade 只做**授权测试**。它不内置真实凭据，不提供 C2，不自动武器化零日，不把无人审批的写操作放进生产。它的实验室靶场只监听 `127.0.0.1`。真实集群执行需要甲方提供 kubeconfig、网络可达性和授权材料。它擅长“ML 基础设施面的组合验证”，不擅长“通用 Web 漏洞挖掘、AD 域渗透、浏览器零日”。这些边界在第六章会逐项对照。

**证据索引（本章）**：[控制端架构](ARCHITECTURE.md) · [检测十层](DETECTION-LAYERS.md) · [攻击面与模块映射](GAP-ATTACK-SURFACE.md) · [效果验证](EFFECT-VERIFICATION.md) · [真实集群验证](REAL-CLUSTER-VERIFICATION.md) · [授权与运行手册](RUNBOOK.md)

---

## 三、产品怎么工作：从授权到复测的 11 步

这一章按真实使用顺序讲。每一步都回答三个问题：**做什么、为什么这样做、不这样做会怎样**。你可以把它当成“操作手册的骨架”，也可以当成“评审时的提问清单”。

### 3.1 授权：先证明“你有权测”

**做什么**：甲方在工作区里签署 consent，写明测试级别、命名空间、CIDR、时间窗、联系人。consent 用工作区密钥做 HMAC 签名；字段被改过就标记 `tampered`。CLI 和 API 在执行前都会检查授权锁。

**为什么这样做**：渗透测试的第一风险不是“打不进去”，而是“打错目标”。授权文件把“谁能测、测哪里、测到什么时候、能造成多大影响”变成可执行的条件，而不是口头承诺。

**不这样做会怎样**：测试人员可能误伤生产；出了事故无法界定责任；甲方审计时拿不出“这次测试被批准过”的证据。代码在 `inkblade/core/roe.py`，测试在 `tests/test_roe.py`、`tests/test_consent_signature.py`、`tests/test_runner_scope_audit.py`。

### 3.2 资产：先知道“有什么可测”

**做什么**：从种子（域名、CIDR、kubeconfig、云账号）出发，发现命名空间、Service、Pod、Ingress、GPU 节点、模型端点、权重桶、网关。资产表记录 `added / updated / removed`，删除用软删除，保留历史。

**为什么这样做**：ML 集群的资产是动态的。今天有一个 Ray Dashboard，明天可能被删；今天有一个权重桶，明天可能换了 owner。没有增量资产库，扫描就会“打空气”或“漏掉新东西”。

**不这样做会怎样**：报告里的目标对不上现网；复测时不知道“上次那个 Service 还在不在”；多个模块各自解析目标，结果互相矛盾。代码在 `inkblade/core/discovery.py`，测试在 `tests/test_discovery.py`。

### 3.3 侦察：先看清楚，不急着动手

**做什么**：跑只读模块。包括暴露面、网络策略覆盖、RBAC、ServiceAccount、kubelet 面、Ray/vLLM/SGLang 管理面、AI 网关、GPU 池、云身份、审计日志。模块默认只读；需要写的时候必须单独声明 `writes=true`，并走备份闸门。

**为什么这样做**：侦察是“低成本、高信息”的阶段。先把“谁能访问什么、哪里没鉴权、哪里权限过大”摸清楚，后面的利用才有依据。只读也意味着可以反复跑，不会改变目标状态。

**不这样做会怎样**：直接上利用脚本，噪音大、风险高、还容易把“配置错”误判成“可利用”。代码在 `inkblade/modules/` 与 `inkblade/core/registry.py`，真实集群的 6 个模块例子见 `docs/REAL-CLUSTER-VERIFICATION.md`。

### 3.4 组合判定：把“单点”拼成“链”

**做什么**：把多条发现放在一起判断。比如“Ray Dashboard 无认证”单独看是 medium；“这个 Dashboard 绑定的 ServiceAccount 能读 Secret”就变成 high；“这个 Secret 里有权重桶的写凭据”就变成 critical。平台用组合签名、可达性图和前置条件，把单点发现升级成“链是否成立”的判定。

**为什么这样做**：甲方真正怕的不是“有一个配置错”，而是“这个配置错能走到核心资产”。组合判定能降低误报，也能让修复优先级从“按严重度”变成“按可达性”。

**不这样做会怎样**：报告变成“一百条中危”，修复团队不知道先修哪个；或者把“理论可达”当成“已验证”，导致过度承诺。代码在 `inkblade/core/combo.py`、`inkblade/core/reachability.py`、`inkblade/core/graph.py`，测试在 `tests/test_chains.py`、`tests/test_reports_network_layers.py`。

### 3.5 链路计划：先出图纸，再施工

**做什么**：从链目录里选一条链，生成 DAG：哪些步骤先做、哪些可以并行、哪些有前置条件、哪些是写操作、失败怎么回滚。`dry-run` 只输出计划，不执行。`agent_planner` 根据已有发现给候选链排序，并附上理由。

**为什么这样做**：ML 集群的利用步骤往往有严格顺序。先读 token，才能调 API；先确认备份，才能写权重。计划把“顺序、依赖、回滚”显式化，避免“做到一半发现前置不成立”。

**不这样做会怎样**：写操作做到一半失败，无法回滚；并行步骤互相覆盖；报告里说不清“为什么选这条链”。代码在 `inkblade/core/chains.py`、`inkblade/agent_planner.py`，测试在 `tests/test_chains.py`、`tests/test_planner_policy.py`。

### 3.6 审批：让人在“要造成影响”之前介入

**做什么**：lead 审批提议。只读动作可以批量批准；写动作要看到 dry-run 预览；不可逆写要逐动作确认。审批记录包含谁批的、什么时候、批了哪些动作、理由是什么。

**为什么这样做**：自动化越强，越需要“人类在环”。审批不是形式，而是把“意图”与“执行”分开：Agent 可以提议，但不能自己放行。OWASP Agentic Top 10 把“身份滥用、工具滥用、人机信任利用”单列，审批是其中一道最少成本的护栏。

**不这样做会怎样**：一个错误的提议直接变成生产写操作；出了事无法追责；甲方不敢把工具放进真实环境。代码在 `inkblade/core/agent_policy.py`、`inkblade/core/explorer.py`，测试在 `tests/test_agent_policy.py`、`tests/test_explorer_policy.py`。

### 3.7 执行：四道闸门，一个都不能少

**做什么**：执行器按“授权 → 级别 → 备份 → 审计”四道闸门跑模块。授权不通过就拒绝；级别不够就拒绝；写类模块没有备份回执就以退出码 91 拒绝；每个动作都落审计。执行默认走确定性模块，不让模型直接下令。

**为什么这样做**：这四道闸门分别对应四类事故：测错目标、越权测试、写坏数据、无法追责。把它们放在执行器里，而不是放在“操作规范”里，才能保证不会被绕过。

**不这样做会怎样**：一次“只是试试”的写操作可能覆盖生产权重；一次“忘记记录”的测试可能无法复现；一次“越权”的测试可能触发合同纠纷。代码在 `inkblade/core/runner.py`、`inkblade/core/backup.py`，测试在 `tests/test_runner_scope_audit.py`、`tests/test_backup.py`。

### 3.8 证据：把“我说”变成“你看”

**做什么**：每次运行落三层证据：上下文摘要（`context.jsonl.gz`）、SQLite（`evidence.db`）、归档层（`steps/*.tar.gz` + `manifest.sha256`）。每条 finding 带证据锚：步骤 + manifest 哈希前缀。归档做确定性处理：gzip mtime 归零、tar 的 mtime/uid/gid 归零，同样输入得到同样字节。

**为什么这样做**：证据要能“离线复核”。甲方拿到报告后，不依赖平台也能校验：这个文件是不是当时那个文件、这条发现对应哪次请求、哈希有没有变。确定性归档还让样张可以 diff，方便回归。

**不这样做会怎样**：报告里的截图无法证明来源；同一次测试两次生成的文件不一致，无法判断“是环境变了还是代码变了”；manifest 被改了也发现不了。代码在 `inkblade/core/evidence.py`、`inkblade/sampledet.py`，测试在 `tests/test_evidence.py`、`tests/test_sample_determinism.py`。

### 3.9 报告：让不同角色读到同一件事

**做什么**：生成 PTES 七段式报告，加五个 ML 专节：训练面、推理面、权重与数据面、网络 fabric 面、AI 网关面。每条发现给 CVSS 3.1 向量、证据锚、修复建议，并映射到七个合规框架。报告中英双语。

**为什么这样做**：甲方内部至少有三种读者：做修复的工程师、做审计的合规、做决策的管理层。工程师要请求响应，合规要条款，管理层要风险和优先级。双语是为了跨团队、跨地区交付。

**不这样做会怎样**：报告只有“高危 12 个”，修复团队不知道从哪下手；合规看不懂映射；海外团队拿不到英文版。代码在 `inkblade/reports/render.py`、`inkblade/reports/compliance.py`，测试在 `tests/test_reports.py`、`tests/test_compliance.py`。

### 3.10 规则：把一次发现变成长期检测

**做什么**：把发现转成可部署的规则：Kyverno、Gatekeeper、NetworkPolicy（native/Calico/Cilium）、Sigma、Falco、Suricata。生成后做覆盖率校验：每条链至少有一条规则；再做紫队重放：用靶场流量验证规则是否命中。

**为什么这样做**：渗透测试的终点不是“报告”，而是“同类问题不再发生”。规则是把“这次怎么打进来的”固化成“下次怎么发现/阻断”。

**不这样做会怎样**：修完这一次，下一次换个命名空间又来一遍；检测团队拿不到可落地的规则；报告和 SOC 之间断链。代码在 `inkblade/rules/generate.py`、`inkblade/rules/validate.py`，测试在 `tests/test_rules.py`。

### 3.11 复测：用同一把尺子量“修好了没有”

**做什么**：按计划或手动触发复测。复测只跑原链的相关步骤，比较 `new / fixed / unchanged`，输出 drift 报告。PoC 可以重放，比对预期证据。复测同样走授权、审批、证据链。

**为什么这样做**：甲方最常问的一句话是“你上次说的那个问题，修了吗？”没有复测，只能靠“配置看起来改了”来判断。复测把“修复”变成可验证的状态变化。

**不这样做会怎样**：同一个问题反复出现在不同季度的报告里；修复团队做了功但无法证明；管理层看不到风险曲线的变化。代码在 `inkblade/core/retest.py`、`inkblade/core/scheduler.py`、`inkblade/core/poc.py`，测试在 `tests/test_scheduler.py`、`tests/test_poc.py`。

### 3.12 一次端到端运行是什么样

`inkblade/e2e-check.py` 在本机 mock 靶场上跑完整闭环：18 个代表模块、29 条链的 dry-run、权重投毒链的真实执行、三层证据、双语报告、规则包、紫队矩阵、四角色隔离。结果是 **15/15 PASS**，证据在 `reports/samples/e2e/e2e-check.json`。真实集群另有一条验证：QEMU 里的单节点 k3s，6 个侦察模块跑真实 kubectl，得到 16 条 findings；NetworkPolicy 默认拒绝普通 Pod，但 `hostNetwork` Pod 可达，判定 `bypass-confirmed`。这两条证据的边界不同：前者证明“流程能闭环”，后者证明“真 API/真数据面能跑”，都不是“万卡生产环境”。

**证据索引（本章）**：[运行手册](RUNBOOK.md) · [端到端验收](../reports/samples/e2e/e2e-check.json) · [真实集群验证](REAL-CLUSTER-VERIFICATION.md) · [效果验证](EFFECT-VERIFICATION.md) · [授权代码](../inkblade/core/roe.py) · [执行器](../inkblade/core/runner.py) · [证据库](../inkblade/core/evidence.py) · [报告渲染](../inkblade/reports/render.py) · [规则生成](../inkblade/rules/generate.py)

---

## 四、Agent 到底改了什么

### 4.0 先给结论：改的是“运行时”，不是“放权”

这一轮之前，InkBlade 的执行环是稳的：确定性链、四道闸门、三层证据。问题是**认知环是空的**：没有 durable journal，没有分层记忆，没有技能库，没有沙箱，没有评测。模型只能“提一次建议”，失败就靠人重来。等于把 2026 年主流的 agent 运行时（持久化、记忆、技能、沙箱、评测）连同“自主执行”一起砍掉了。

这一轮改动的核心判断是：**执行环继续确定性，认知环外挂 agent 运行时**。Agent 只影响“选哪个模块、传什么参数、下一步试什么”，不生成新的执行原语；所有执行仍走 `runner` 的四道闸门。下面分“方法论 / 代码逻辑 / 新增功能”三类讲。

### 4.1 方法论：五个转变

| # | 旧做法 | 新做法 | 影响指标 | 前后对比 | 原因 |
|---|---|---|---|---|---|
| M1 | 用 18 个能力维度描述差距 | 用 801 行逐功能矩阵 + 260 行缺口表 + 逐行处置 | 可核对的功能行 | 26 项能力 → 801 行功能 + 260 行缺口 | 维度是地图，不是清单；维度会掩盖“具体缺哪个功能” |
| M2 | 单进程 explorer，串行跑动作 | supervisor-worker + 持久队列 + 有界并发 1–8 + 失败重派 | 15 任务成功率、耗时 | 93.3% → 100%；4,844ms → 2,899ms | 并行与重派能吃掉瞬时故障；但审批从 1 次涨到 32 次 |
| M3 | 记忆靠队列 JSON 和当次 findings | 三层记忆：working / episodic / semantic | 跨 run 检索 | 0 命中 → 1 命中（夹具） | 渗透是经验密集型；每次都从零推理会重复发现、重复付费 |
| M4 | 新手法必须发版加模块 | 成功 run 提炼 playbook，审批后入技能库 | 新手法上线路径 | 发版 → 提取 1 次 + lead 批准 | 程序性知识应该可复用，但不能绕过审批 |
| M5 | 模块在宿主进程 `exec_module` | 子进程沙箱 + 默认禁网 + 超时 + 审计 | 不可信代码执行面 | 宿主执行 → 隔离子进程；默认禁网 2/2 | 第三方技能/LLM 生成代码不能直接进宿主 |

方法论转变的代价也要讲清楚：supervisor 的审批次数从 1 次涨到 32 次，token 从 4,288 涨到 4,387（+2.3%）。这不是“免费的性能提升”，而是“用更多审批换更高的任务完成率”。在真实甲方环境里，审批次数是人力成本，必须用分级审批和去重把它压下来；这就是 4.4 节“腾讯三项改进”的由来。

### 4.2 代码逻辑：改了哪些文件，关键函数是什么

| 文件 | 关键类/函数 | 一句话原理 | 对旧路径的影响 |
|---|---|---|---|
| `inkblade/core/journal.py` | `Journal.append/verify/resume/replay` | append-only JSONL，每条带前一条哈希，形成链式 SHA256；`resume` 给出 completed/failed/incomplete | 新增；不改变执行语义，只记录“执行到哪” |
| `inkblade/core/supervisor.py` | `Supervisor.submit/run` | 持久队列 + 1–8 worker + 失败重派；`submit` 校验每个动作已批准 | 新增；默认执行器仍是 `runner.run_module` |
| `inkblade/core/memory.py` | `Memory.retrieve/compact`、`WorkingMemory` | working 有界；episodic 查 evidence DB；semantic 查资产/模块/技能图；按分数融合 | 新增；只读检索，不写证据 |
| `inkblade/core/skills.py` | `SkillLibrary.extract/submit/approve/search` | 从成功 run 抽 playbook；draft→pending→approved；版本递增 | 新增；审批前不可检索 |
| `inkblade/core/reflexion.py` | `reflect/propose_skill/render_md` | 读失败/降级动作，生成建议；零执行 | 新增；不 import runner |
| `inkblade/core/a2a.py` | `A2AServer/agent_card/MCPClient` | agent card + task 状态机；只读技能白名单；MCP 只接受 `readOnlyHint=true` | 新增；写技能/写工具拒绝 |
| `inkblade/core/sandbox.py` | `Sandbox.run_python/run_untrusted` | `python -I` 子进程；墙钟超时；默认禁网；POSIX rlimit；审计代码 sha256 | 新增；不替代内核级隔离 |
| `inkblade/core/agent_policy.py` | `classify_action/decide/decompose/retry_plan` | L0–L3 分级；混合动作取最弱；瞬时错误有界重试，闸门错误立即停 | 提议路径可开关；OFF 复现旧语义 |
| `inkblade/core/observation.py` | `build/action_key/dedupe/compress/is_dead_end` | 动作/结果/证据/下一步/claim 五段式；`ok` 必须有证据指针 | 新增；JSONL 只追加 |
| `inkblade/core/cost.py` | `plan_cost/Budget/degrade/CostTracker` | token/时延/审批/干预四维预算；超支先丢 optional，再砍写，至少留 1 个 | 新增；确定性降级 |
| `inkblade/core/agentops.py` | `run_approved_plan` | 门面：审批计划 → supervisor（journal）→ reflexion → 技能提案 | 新增；不绕闸门 |
| `inkblade/webui/api_section3.py` | `/api/v1/agent/*` | 只读视图：等级、阶段、证据指针、下一步、预算 | 新增；仅 GET |
| `lab/tencent-compare/` | `run_eval.py` | 8 任务 OFF/ON 微评测；OFF 复现旧语义 | 新增；确定性，不调用外部 LLM |
| `lab/agent-eval/` | `run_eval.py` | 15 任务 deterministic vs supervisor-worker | 新增；故障注入显式标注 |

这里有一个容易误解的点：`agent_policy.py`、`observation.py`、`cost.py` 不是“让模型更自由”，而是“让提议更可审计”。它们把“为什么选这个动作、证据在哪、花多少钱、什么时候停”变成结构化字段。模型仍然不能执行；执行仍然要审批。

### 4.3 新增功能：10 项逐项拆解

下面每一项都按同一格式写：动机、关键实现、影响指标、前后对比、原因分析。对比数字来自测试夹具或已落盘评测，不把“设计目标”写成“实测”。

#### 4.3.1 durable journal（持久执行日志）

**动机**：旧 runner 失败就整链重跑。写类步骤重跑会重复备份、重复写，甚至覆盖上一次的回滚点。审批等待也不能跨进程存活。

**关键实现**：`inkblade/core/journal.py::Journal`。每个 `step.started` / `step.finished` 追加一行 JSONL，带 `prev` 和 `hash`；`verify()` 逐行重算哈希链，能定位到具体行号；`resume()` 把步骤分成 completed / failed / incomplete；`checkpoint()` 标记可恢复边界。

**影响指标**：崩溃恢复时重复执行的已完成步骤数；篡改定位能力。

**前后对比**：夹具里 3 步流程在第 3 步中断，旧行为重跑前 2 个成功步骤（重复 2 次），新行为 `resume` 跳过 2 个成功步骤（重复 0 次）；篡改第 3 行能被 `broken_at=3` 定位（旧行为 0 定位）。来源：`tests/test_journal.py`。

**原因分析**：把“发生过什么”（证据库）和“下一步该做什么”（journal）分开存。证据库是事实源，journal 是恢复点；两者职责不同，不能互相替代。

#### 4.3.2 supervisor-worker（分层执行）

**动机**：单进程串行 explorer 只能一个目标一个目标跑；一个瞬时故障就让整个任务失败；多目标场景没有并发。

**关键实现**：`inkblade/core/supervisor.py::Supervisor`。持久队列 `supervisor/queue.json`；worker 数 1–8；`submit()` 校验 `approval.status == approved`；失败按 `max_attempts` 重派；每个事件写 journal；控制面重启后 running 复位为 pending。

**影响指标**：15 任务成功率、总耗时、审批次数、重派次数。

**前后对比**：deterministic 14/15（93.3%）、4,844ms、审批 1 次、重派 0；supervisor-worker 15/15（100%）、2,899ms、审批 32 次、重派 1 次。来源：`docs/AGENT-EVAL-RESULTS.md`。

**原因分析**：并发把独立任务叠起来，重派把瞬时故障吃掉。代价是审批粒度变细（逐动作），所以审批次数上升。这不是“越自动越好”，而是“用可控的审批换完成率”。

#### 4.3.3 三层记忆（working / episodic / semantic）

**动机**：旧 explorer 每次从 findings 重算，跨 run 不记得“上次哪条路走不通”“这个产品的指纹是什么”。等于把专家记忆清零。

**关键实现**：`inkblade/core/memory.py::Memory.retrieve/compact`。working 是本轮上下文，超容量时保留头尾并生成摘要；episodic 从 evidence DB 检索跨 run 的 findings/steps；semantic 从资产、模块、技能图谱检索；`retrieve` 按分数融合三层。

**影响指标**：跨 run 检索命中；工作记忆上限；压缩后引用保留。

**前后对比**：跨 run 检索 0 命中 → 1 命中（夹具中 `run-memory` 的“宿主逃逸”被找回）；working 10 条 → 上限 6 条；压缩 8 条 → ≤3 条，且 `ref-9` 仍保留。来源：`tests/test_memory.py`。

**原因分析**：上下文是稀缺资源。索引常驻、正文按需、产物外置，才能在长任务里不丢目标。记忆只读检索，不直接写证据，避免“记忆污染证据”。

#### 4.3.4 技能库（playbook）

**动机**：旧系统只有模块，没有“怎么组合、先试什么、失败信号是什么”的程序性知识。新手法必须发版。

**关键实现**：`inkblade/core/skills.py::SkillLibrary`。`extract()` 从成功 run 抽步骤、参数、写面、证据引用；`submit()` 进入 pending；`approve()` 只能 lead/admin；版本递增；`search()` 只返回 approved。

**影响指标**：新手法上线路径；版本数；未审批检索；越权批准。

**前后对比**：新手法从“改代码发版”变成“run 提取 1 次 + lead 批准 1 次”；同一技能第二次提交版本 1→2；未审批检索 1 条→0 条；tester 批准 1 次→0 次（`PermissionError`）。来源：`tests/test_skills.py`。

**原因分析**：技能是“包”，不是提示词。它有版本、有审批、有成功统计，才能被信任和复用。

#### 4.3.5 reflexion（运行后反思）

**动机**：旧 explorer 记录了结果，但 `propose()` 不读历史结果。失败不学习，同一提议反复出现，人审负担不降。

**关键实现**：`inkblade/core/reflexion.py::reflect`。只读 evidence DB，把失败动作、备份闸门拒绝、零发现归纳成 failure/degraded；生成 `action + rationale + refs` 建议；`propose_skill()` 转成 pending 技能，仍需 lead 批准。测试用 monkeypatch 把 `runner.run_module` 换成炸弹，证明零执行。

**影响指标**：失败识别数；建议数；执行调用数；健康 run 误报。

**前后对比**：2 个失败动作 → ≥1 条建议；执行调用 1 次→0 次（炸弹未触发）；健康 run 的 failures 0 条（不硬造问题）。来源：`tests/test_reflexion.py`。

**原因分析**：反思只对“可观察的失败”做归纳，不做“模型自我评分”。这样既能让失败变经验，又不会把主观评价写进证据。

#### 4.3.6 A2A 与 MCP 只读协作

**动机**：旧系统只有 MCP 只读工具，不能被客户 SOC 或其他 agent 平台当对等体调用；侦察/计划/验证不能拆成可替换服务。

**关键实现**：`inkblade/core/a2a.py::A2AServer` 提供 agent card 和 task 状态机（submitted → working → completed / rejected / canceled）；内置技能白名单只读；`MCPClient` 只接受 `annotations.readOnlyHint=true` 或读前缀工具，写工具/未知工具拒绝。

**影响指标**：只读任务完成；写技能拒绝率；MCP 写工具拒绝。

**前后对比**：`list_runs` 任务 1 个完成；`execute_module/run_chain/delete_run/sudo` 4/4 拒绝；MCP 3 个工具中 1 个写工具被拒、1 个无注解但 `list_` 前缀被接受。来源：`tests/test_a2a.py`。

**原因分析**：跨组织协作的第一步不是“开放执行”，而是“开放只读事实”。只读委派能带来集成价值，又不会把执行权交出去。

#### 4.3.7 沙箱（不可信代码执行）

**动机**：旧 runner 用 `spec_from_file_location + exec_module` 在宿主进程执行模块。接入第三方技能或 LLM 生成代码后，这等于把宿主交给外部内容。

**关键实现**：`inkblade/core/sandbox.py::Sandbox.run_python/run_untrusted`。`python -I` 子进程；墙钟超时；默认注入禁网（socket/urllib 抛 `NetworkDisabled`）；POSIX 下 rlimit 限制内存；每次执行记录代码 sha256、untrusted 标记、网络策略、结果、耗时。Windows 没有 rlimit，`limits.memory=false` 如实标注。

**影响指标**：不可信代码是否进宿主；默认禁网；超时终止；审计覆盖率。

**前后对比**：不可信代码宿主执行 1→0（改为子进程）；默认禁网 2/2（socket 与 urllib 都拦）；1 秒死循环被超时终止；审计条目 0→1 条/次。来源：`tests/test_sandbox.py`。

**原因分析**：子进程 + import 隔离 + 网络拒绝能挡住大部分“误伤”，但它**不是内核级隔离**，不能宣称能挡逃逸。文档和测试都明确这个边界。

#### 4.3.8 agent_policy（自主度分级）

**动机**：旧审批只有“整包批/不批”。只读侦察和不可逆写共享同一档权限，人要么全信，要么全不信。

**关键实现**：`inkblade/core/agent_policy.py::classify_action/decide/decompose/retry_plan`。L0 观察、L1 建议、L2 监督执行、L3 只读自治；混合动作取最弱链路；无备份写动作 L1、逐动作确认；`retry_plan` 把瞬时/永久/非法/预算错误分开。

**影响指标**：混合批次等级；审批次数；审阅项；人工干预；成功率。

**前后对比**：只读批次 L3（审批 1 次）→ 只读+不可逆写混合批次 L1（审批 2 次）；审阅项 24→20；人工干预 4→0；成功率 0.5→1.0。来源：`tests/test_agent_policy.py`、`docs/SECTION3-METRICS.md`。

**原因分析**：档位是“动作能力”，不是“模型自由度”。把不可逆写单独提级，能让人只看真正需要看的东西。

#### 4.3.9 observation（结构化观察）

**动机**：旧 `execute` 返回 `{module,status,result,run,step,audit}`，失败原因和证据指针混在 dict 里；下一次提议无法复用，人审也看不出“结论有没有证据”。

**关键实现**：`inkblade/core/observation.py::build/action_key/dedupe/compress/is_dead_end`。五段式 `action / result / evidence[] / next[] / claim`；`ok` 无证据直接拒绝；失败降级 `hypothesis`；`action_key` 去重；同模块 2 次失败判死胡同；`compress` 按 confirmed 优先、步号倒序输出。

**影响指标**：证据覆盖率；审阅项；重复动作；死胡同重试。

**前后对比**：证据覆盖 0→1.00；审阅项 24→20；重复动作 1→0（同键只留一条）；死胡同任务 OFF FAIL→ON PASS。来源：`docs/SECTION3-METRICS.md`、`tests/test_observation.py`。

**原因分析**：把“观察到什么”固化，而不是继续堆聊天记录。`claim` 强制区分 confirmed / hypothesis / planned，避免“模型说发现了”被当成事实。

#### 4.3.10 cost（成本预算与降级）

**动机**：旧 explorer 只有 `MAX_ACTIONS=5`，没有 token/时延估算，也没有超支降级。多 agent/长上下文会 15× token 失控。

**关键实现**：`inkblade/core/cost.py::plan_cost/Budget/degrade/CostTracker`。四维预算：20,000 token、120,000ms、6 次审批、2 次干预；`plan_cost` 按动作估算；`degrade` 先丢 optional，再砍写动作，最后砍尾部，至少保留 1 个，并标记 `over_budget`。

**影响指标**：token、时延、预算超支任务的动作数。

**前后对比**：8 任务总 token 12,423→9,111（-26.7%）；总时延 31,500→19,200ms（-39.0%）；`budget-crunch` 任务 token 4,440→963（-78.3%）；任何情况下动作数 ≥1。来源：`docs/SECTION3-METRICS.md`、`tests/test_cost.py`。

**原因分析**：成本要“先估算、再降级”，而不是让模型“自觉省一点”。确定性降级能保证结果可解释、可复现。

### 4.4 腾讯大赛对照的三项产品化改进

这一节对应 `docs/SECTION3-TENCENT-AGENT-CONTEST.md` 的 G1–G14。参赛项目的强项不在“某个漏洞脚本”，而在编排层：任务分解、观察空间、错误恢复、成本预算、证据可追溯、交互心流。我们只挑三项最能落地、且不破坏“执行确定性”的改进。

#### 改进一：自主度分级，把审批放在“有影响”的地方

**改了什么**：`agent_policy.py` 的 L0–L3；`decompose()` 把动作分成“只读侦察 → 受控写验证”；`observation.action_key` 先去重；`cost.apply_budget` 再裁剪可选/尾部动作；最后才生成审阅项。

**数字**：审阅项 24→20（-16.7%）；审批决策点 8→9（+1，来自不可逆写护栏）；人工干预 4→0；成功率 0.5→1.0。来源：`docs/SECTION3-METRICS.md`。

**原因**：参赛项目 P3 把 HITL 卡在“计划”而不是每个工具调用；P1 的 Observer 只纠偏不抢权；P5 的 Supervisor 只在 checkpoint 介入。共同点是“有边界的自主”。我们把“边界”做成档位，而不是做成一句提示词。

#### 改进二：结构化观察，把“证据”变成一等字段

**改了什么**：`observation.py` 的五段式；`claim` 三态；`is_dead_end`；`compress`。

**数字**：证据覆盖 0→1.00；死胡同任务 OFF FAIL→ON PASS；`gateway-auth` 瞬时故障 OFF FAIL→ON PASS；人工干预 4→0。来源：`docs/SECTION3-METRICS.md`。

**原因**：参赛项目 P5 的因果图明确“无证据不能升级为结论”；P1 把 Idea 与 Memory 分仓；P2 把 Fact / Intent / Hint 分开。我们不需要照搬图数据库，但必须把“结论”和“证据”解耦。

#### 改进三：成本预算，把“超支”变成可解释的降级

**改了什么**：`cost.py` 的四维预算；`degrade()` 的三级裁剪。

**数字**：token 12,423→9,111（-26.7%）；时延 31,500→19,200ms（-39.0%）；`budget-crunch` 4,440→963（-78.3%）。来源：`docs/SECTION3-METRICS.md`。

**原因**：P7 用 700 元打完两届，P2 用 7,692 元换唯一 AK，说明“预算必须显式”。我们的默认预算是 20k token / 120s / 6 次审批 / 2 次干预；超支不是失败，而是“先丢可选、再砍写、至少留一个”的可解释降级。

#### 微评测的边界

8 个任务、确定性成本、故障注入各一次。它证明“策略有效”，不证明“模型在真实靶场上的决策质量”。下一轮要在冻结模型版本上重跑端到端。逐任务结果见 `docs/SECTION3-METRICS.md`：`tenant-recon` token 1,320→727；`gateway-auth` 782→1,016；`litellm-chain` 1,440→1,284；`gpu-tenant` 969→1,242；`budget-crunch` 4,440→963；`evidence-audit` 1,680→1,496；`dead-end` 832→1,527；`irreversible-write` 960→856。注意：不是每个任务都更省，`dead-end` 反而增加，因为它多试了一条回退路径；总账下降来自预算裁剪和去重。

### 4.5 没改什么：三条硬边界

第一，**没有把执行环交给模型**。`explorer.propose` 不建 run、不写 actions；`agent_planner` 只输出计划；`supervisor` 只执行已批准动作。第二，**没有做无人审批的写操作**。不可逆写仍然逐动作确认。第三，**没有做 C2、自动武器化、持久化后门**。这些与“可审计交付”的定位冲突。

**证据索引（本章）**：[Agent 架构研究](AGENT-ARCHITECTURE-2026.md) · [升级实施说明](AGENT-ARCHITECTURE-UPGRADE-2026.md) · [评测结果](AGENT-EVAL-RESULTS.md) · [腾讯对标](SECTION3-TENCENT-AGENT-CONTEST.md) · [微评测指标](SECTION3-METRICS.md) · [journal](../inkblade/core/journal.py) · [supervisor](../inkblade/core/supervisor.py) · [memory](../inkblade/core/memory.py) · [skills](../inkblade/core/skills.py) · [reflexion](../inkblade/core/reflexion.py) · [a2a](../inkblade/core/a2a.py) · [sandbox](../inkblade/core/sandbox.py) · [agent_policy](../inkblade/core/agent_policy.py) · [observation](../inkblade/core/observation.py) · [cost](../inkblade/core/cost.py) · [agent 评测](../lab/agent-eval/run_eval.py) · [腾讯微评测](../lab/tencent-compare/run_eval.py)

---

## 五、指标总表

### 5.1 先讲口径：这些数字不是同一种东西

这张表混了三类数据：**策略级微评测**（8 个任务，确定性成本，不调用外部 LLM）、**Agent 架构评测**（15 个任务，deterministic vs supervisor-worker）、**同宿主性能对比**（ARTEX 在 QEMU TCG 里，InkBlade 在 Windows 宿主）。把它们放在一张表里，是为了回答“改动有没有用”，不是为了证明“产品比谁快”。跨行相减没有意义；每行的来源和口径都要看。

### 5.2 主指标表

| 指标 | 前值 | 后值 | 变化% | 原因 | 来源 |
|---|---:|---:|---:|---|---|
| 任务成功率（腾讯 8 任务，策略级） | 50.0% | 100.0% | +100.0% | 分级审批 + 结构化观察 + 预算降级；4 个失败任务恢复 | [SECTION3-METRICS.md](SECTION3-METRICS.md) |
| 任务成功率（Agent 15 任务） | 93.3% | 100.0% | +7.2% | supervisor 重派吃掉注入的瞬时故障 | [AGENT-EVAL-RESULTS.md](AGENT-EVAL-RESULTS.md) |
| 总时延（腾讯 8 任务） | 31,500 ms | 19,200 ms | -39.0% | 去重、裁剪、失败快速切换 | [SECTION3-METRICS.md](SECTION3-METRICS.md) |
| 总时延（Agent 15 任务） | 4,844 ms | 2,899 ms | -40.2% | 有界并发 1–8 + 失败重派 | [AGENT-EVAL-RESULTS.md](AGENT-EVAL-RESULTS.md) |
| Token（腾讯 8 任务） | 12,423 | 9,111 | -26.7% | 预算裁剪 + 观察压缩；不是每个任务都更省 | [SECTION3-METRICS.md](SECTION3-METRICS.md) |
| Token（Agent 15 任务） | 4,288 | 4,387 | +2.3% | 逐动作审批与重派带来额外上下文 | [AGENT-EVAL-RESULTS.md](AGENT-EVAL-RESULTS.md) |
| 审批次数（决策点，腾讯 8 任务） | 8 | 9 | +12.5% | 不可逆写多 1 次确认，属安全护栏 | [SECTION3-METRICS.md](SECTION3-METRICS.md) |
| 审批次数（决策点，Agent 15 任务） | 1 | 32 | +3,100% | 从整批 1 次改为逐动作审批 | [AGENT-EVAL-RESULTS.md](AGENT-EVAL-RESULTS.md) |
| 人工干预（腾讯 8 任务） | 4 | 0 | -100.0% | 死胡同识别、瞬时重试、预算自动降级 | [SECTION3-METRICS.md](SECTION3-METRICS.md) |
| 证据覆盖（腾讯 8 任务） | 0.00 | 1.00 | 新增 | `ok` 必须有证据指针，否则降级 hypothesis | [SECTION3-METRICS.md](SECTION3-METRICS.md) |
| API 中位延迟（只读端点网格） | 11.19 ms | 2.12 ms | -81.1% | InkBlade 单进程 + SQLite；ARTEX 含 PG 与 TCG | [PERFORMANCE-COMPARISON.md](PERFORMANCE-COMPARISON.md) |
| 并发吞吐（16 并发） | 17.4 rps | 286.3 rps | +1,545% | backlog 5→256；ARTEX 端点与请求密度不同 | [PERFORMANCE-COMPARISON.md](PERFORMANCE-COMPARISON.md) |
| 冷启动到可登录 | 37.85 s | 0.805 s | -97.9% | InkBlade 无外部数据库；ARTEX 含 PG 初始化与 TCG | [PERFORMANCE-COMPARISON.md](PERFORMANCE-COMPARISON.md) |
| 空闲内存 | 169.8 MiB | 28.1 MB | -83.5% | 单进程 vs Go 服务 + PostgreSQL；ARTEX 新起栈为 75.2 MiB | [PERFORMANCE-COMPARISON.md](PERFORMANCE-COMPARISON.md) |
| 磁盘足迹 | 2.892 GB | 8.9 MB | -99.7% | 镜像是 ARTEX 两容器；8.9 MB 是 InkBlade 代码树，不含证据库 | [PERFORMANCE-COMPARISON.md](PERFORMANCE-COMPARISON.md) |
| 同靶场扫描时延 | 13,510 ms | 105.6 ms | -99.2% | 确定性链 vs 多 agent 编排；含 QEMU TCG 放大 | [ARTEX-BENCH-RESULT.md](ARTEX-BENCH-RESULT.md) |
| 10k 对象分析总耗时 | 330.8 ms | 46.5 ms | -85.9% | 三处 O(n²) 改索引，findings 逐条一致 | [SCALE-RESULTS.md](SCALE-RESULTS.md) |
| 10k 对象峰值 RSS | 34 MB | 54 MB | +58.8% | 快照本体与索引占用增加；不是泄漏 | [SCALE-RESULTS.md](SCALE-RESULTS.md) |

### 5.3 Agent 架构专项表

| 指标 | deterministic | supervisor-worker | 变化 | 说明 |
|---|---:|---:|---:|---|
| 成功/总数 | 14/15 | 15/15 | +1 | 同一故障注入：`gateway-auth` 首次 `TimeoutError` |
| 成功率 | 93.3% | 100.0% | +6.7 个百分点 | 重派恢复瞬时故障 |
| 耗时 | 4,844 ms | 2,899 ms | -40.2% | 有界并发 |
| Token | 4,288 | 4,387 | +2.3% | 确定性估算，不是账单 |
| 审批次数 | 1 | 32 | +31 | 整批 vs 逐动作 |
| 重派 | 0 | 1 | +1 | 只重派失败动作 |
| 发现数 | 225 | 230 | +5 | 重派后补齐 5 条 |

来源：[AGENT-EVAL-RESULTS.md](AGENT-EVAL-RESULTS.md)。这张表最重要的读法是：**成功率提升不是免费的**。审批从 1 次涨到 32 次，token 也涨了 2.3%。如果甲方不能接受 32 次审批，就应该用分级审批把只读动作批量放行，而不是否定整个 supervisor 架构。

### 5.4 规模与资源表

| 对象数 | 侦察 11 模块 | 可达性图 | 规则生成 | 总耗时 | 峰值 RSS | findings |
|---:|---:|---:|---:|---:|---:|---:|
| 100 | 1.0 ms | 0.07 ms | 46.3 ms | 290 ms | 34 MB | 117 |
| 1,000 | 5.0 ms | 0.5 ms | 52.3 ms | 432 ms | 36 MB | 1,088 |
| 5,000 | 19.0 ms | 1.1 ms | 59.4 ms | 909 ms | 42 MB | 5,459 |
| 10,000 | 40.4 ms | 2.2 ms | 93.9 ms | 1,645 ms | 54 MB | 10,891 |

来源：[SCALE-RESULTS.md](SCALE-RESULTS.md)。这是**合成 K8s 对象**，不是 10,000 张 GPU。它的用途是证明分析算法近似线性，不是证明万卡集群能跑。

### 5.5 怎么读这些数字

第一，`+1,545%` 的吞吐差距不是“产品快 15 倍”。ARTEX 测的是 `/api/agents`，InkBlade 测的是 `/api/v1/graph`；ARTEX 跑在 QEMU TCG，InkBlade 跑在宿主。第二，`-99.2%` 的同靶场时延不是“产品快 128 倍”。它包含 TCG 放大、ARTEX 的 planner debounce、worker 轮询和 3 秒状态轮询。第三，`-83.5%` 的内存不是“同等功能下省 6 倍”。ARTEX 的值是长跑实例（含 PG 缓存），新起栈是 75.2 MiB；InkBlade 是单进程。第四，`-99.7%` 的磁盘不是同口径。ARTEX 是镜像，InkBlade 是代码树；证据库会随 run 增长。第五，`53/53` 是 `docs/EFFECT-VERIFICATION.md` 与 `reports/samples/effects/effects.json` 当前落盘的口径（2026-10-26 运行，含 chip 与硬件批次）；此前 17/17、20/20、31/31、34/34、47/47 为历史阶段值，不再引用。

**证据索引（本章）**：[腾讯微评测](SECTION3-METRICS.md) · [Agent 评测](AGENT-EVAL-RESULTS.md) · [性能对比](PERFORMANCE-COMPARISON.md) · [ARTEX 同靶场](ARTEX-BENCH-RESULT.md) · [规模压测](SCALE-RESULTS.md) · [效果验证](EFFECT-VERIFICATION.md) · [真实集群](REAL-CLUSTER-VERIFICATION.md)

---

## 六、竞品对比：功能、攻击面、payload、性能

### 6.1 对比方法与样本

对比分四层。第一层是**功能**：23 个工具 × 18 个能力维度，另加 ARTEX 515 行、KubeTrail 286 行的逐功能矩阵，共 801 行。第二层是**攻击面**：31 个工具、82 条攻击面条目。第三层是**payload**：31 个工具、56 条 payload 条目。第四层是**性能**：同宿主、同靶场、全端点网格。腾讯大赛 8 个项目单独做架构对比，因为它们代表“编排层”的最新实践。

所有矩阵只采信官方文档或本地只读克隆；未声明一律标 `?`，不臆断。商业产品（XBow/NodeZero/Pentera）没有二进制实测，能力以官网公开声明为限。KubeTrail 构建未完成，性能记 N/A。

### 6.2 功能差距：801 行矩阵与 260 行缺口

**801 行矩阵**来自 `docs/feature-matrix.json`：ARTEX 515 行（37 已有 / 201 部分 / 180 缺失 / 97 不适用），KubeTrail 286 行（59 已有 / 98 部分 / 120 缺失 / 9 不适用）。它不是“功能数量”，而是“逐路由、逐表、逐组件、逐 CLI 参数的对照”。

ARTEX 的 180 条 `missing` 已逐行处置：70 条 clean-room 等价实现、6 条技术不可行、104 条不适用、0 条未分类。处置后按行统计：等价已有 107、部分 201、不适用 201、技术不可行 6。这个结果说明：**“missing 归零”不等于“功能全有”**。70 条是补上的，110 条是“不做”或“做不了”，201 条仍是部分。

**260 行缺口表**来自 `docs/gap-matrix.json`：功能 122 条（36 已有 / 47 部分 / 39 缺失）、攻击面 82 条（35 / 29 / 18）、payload 56 条（21 / 18 / 17）。合计 92 已有、94 部分、74 缺失。缺的最多的不是“漏洞利用脚本”，而是“广度”：通用 Web、AD、浏览器零日、模型行为探针、密钥规则库。

### 6.3 攻击面差距

K8s 攻防类的对手很强，但强在不同地方。KubeHound 有 26 类攻击边和 Gremlin 图查询；kube-hunter 有 47 个检查项，我们对齐 29 个；KubeTrail 有 19 类采集、16 个内核 LPE 检测、dbus.json 导出；CDK 有 30 个 EXP、13 类逃逸；KubeletCTL 有 15 组 kubelet API。我们的策略是“检测面 + 证据面 + ML 面”，不把“交互式后渗透台”和“持久化模板”产品化。

ML 面是我们的差异化：权重桶、checkpoint、NCCL、IB/SHARP、PFC、KV cache、PD 通道、AI 网关、GPU 池、云跨租户。这些在 23 个工具里大多标 `?` 或 `○`。但差异化不等于全面领先：通用 K8s 攻击面的广度仍不如 KubeHound/KubeTrail。

### 6.4 Payload 差距

我们的弹药是“103 条版本矩阵 + 150 个参数变体 + 47 个武器包（含 6 个公开零日漏洞模块）”。对手的弹药是“库”：garak 41 族/170 类探针，PyRIT 9 种多轮策略/~90 个转换器，promptfoo 49 个插件/~35 个策略，trufflehog 892 个 detector，gitleaks 222 条规则，Falco 99 条默认规则。我们在“ML 基础设施 payload”上有针对性，但在“模型行为探针”（87 探针，约为 garak 146 类的 60%）和“通用密钥规则”上是明显短板。这些短板登记为 L 级 backlog（CM-32/34），部分已落地、部分仍是差距，不假装全部补齐。

### 6.5 性能差距

已测维度：冷启动、空闲内存、全端点中位延迟、16 并发吞吐、同靶场扫描、磁盘。InkBlade 在“单机、确定性、零 token”上占优；ARTEX 在“自然语言意图驱动的开放面探索”上占优。不可比维度：ARTEX 的 32 个 0-2xx 端点有效载荷、30 分钟稳定性、UI 首屏、10 万行查询、KubeTrail 构建。未测就是未测，不外推。

### 6.6 腾讯大赛 8 个项目：它们强在哪，我们补到哪

| 项目 | 赛季/名次 | 核心做法 | 我们可以学什么 | 我们还没超过什么 |
|---|---|---|---|---|
| BreachWeave | 第二届第 1 | Manager / Solver / Observer；Idea 与 Memory 分仓；18+ skills；ralph 有界重试 | 监督者不抢执行权；压缩用结构化清单 | 线下决赛一等奖、线上 1/613 的真实战绩 |
| Cairn | 第二届第 3（唯一 AK） | 无角色黑板 Fact / Intent / Hint；worker 容器；stigmergy | 把“未知”建模成 Intent；人类 Hint 是一等公民 | 54/54 AK、7,692 元成本下的涌现式搜索 |
| aide-for-pentest | 第二届第 7 | explore → plan（checkpoint）→ execute；HITL/autoapprove 两档 | 批计划，不批每个工具调用 | 50/54 解题率、Kali worker 工具面 |
| CyberStrikeAI | 第一届第 17 | Go + Eino；100+ 工具配方；MCP；HITL；RBAC；攻击链工作台 | 审批 + 工具白名单 + 审计复核的最小集 | 产品化工作台、8k+ stars 生态 |
| LuaN1aoAgent | 第一届第 3 | Planner / Executor / Observer；因果证据图；Artifact；预算 | 无证据不能升级为结论；任务/动作分离 | 因果图工作台、第一届第 3 |
| tinyctfer | 第一届第 4 | Meta-Tooling；Docker 沙箱；约百行核心 | 高确定性场景可用“意图脚本”代替多次工具往返 | 极简运行时、CTF 实战成绩 |
| CHYing-agent | 第一届第 9；第二届零界第 1 | Orchestrator + 4 子 Agent；MCP 可见性；Prompt/Progress/Retry 编译器 | 工具可见性比工具数量重要；压缩交给独立 Agent | XBOW 104 题 57%、700 元成本控制 |
| xbow-competition | 第一届第 7 | MCP 平台 + 多模型 CLI；尝试历史；防沉迷 | 平台能力与模型能力解耦；硬预算 | 7/238 的竞赛战绩 |

这张表要诚实读：我们在“策略层”补了分级审批、结构化观察、成本预算，在 8 任务微评测上拿到了 0.5→1.0；但参赛项目的优势是**真实比赛里的长程决策**，不是三个模块。我们的微评测不调用外部 LLM，不能替代“冻结模型 + 真实靶场”的端到端跑分。下一轮必须补这一块。表内名次、题数、成本均来自 `docs/SECTION3-TENCENT-AGENT-CONTEST.md` 的逐项目小节与官方导航；未独立复核。

### 6.7 已补齐项：哪些差距真的关掉了

**ARTEX 方向**：8 个功能族（LLM 池、通知、模板、日历、侧问、图快照、黑板、bounded 并发）全部 clean-room 实现；S/M backlog 30/30 清零；180 条 missing 逐行处置，0 条未分类。默认安全：新功能默认关闭或只读，执行仍走 RoE/角色/备份三闸门。

**K8s 攻防方向（KubeTrail/KubeHound/kube-hunter/CDK 等）**：21 个模块移植（KubeHound 26 边/最短路径、kdigger 20 bucket + admission、CDK 30/13 分类、kube-hunter 29/47、KubeletCTL 15 API、Peirates 37 原语、kube-bench CIS 26 项、KubiScan/密钥/K8s CVE/云 token、KubeTrail 5 项）；许可检查与 NOTICE 已补。注意：286 行原矩阵没有重算，120 条 missing 不能因为“移植了 21 个模块”就宣称清零。

**XBow 方向**：资产自动发现、审批制 explorer、调度器、流量录制回放、验证级 PoC、API-first、十视图。自主执行本体仍不跟进。

**腾讯方向**：`agent_policy` / `observation` / `cost` 三个策略件 + 8 任务微评测。补的是“编排层的可解释性”，不是“竞赛成绩”。

**性能方向**：`ThreadingHTTPServer` backlog 5→256，16 并发从 29 rps 提到 286 rps；三处 O(n²) 改索引，10k 对象 330.8ms→46.5ms。来源：`docs/PERFORMANCE-COMPARISON.md`、`docs/SCALE-RESULTS.md`。

### 6.8 仍未超过的项与原因

| # | 未超过的项 | 对手强在哪 | 我们的现状 | 为什么没超过 | 是否计划追 |
|---|---|---|---|---|---|
| 1 | 无人驱动的自主规划 | XBow 宣称数千 agent 并行；ARTEX 有 planner/worker；P2 图上的 Intent 运行时 | 提议制，lead 审批，人触发执行 | 交付物必须是可复核证据；写操作必须有人类/策略批准 | 不追“无人”，只追“少人” |
| 2 | 千级并发/分布式 | XBow 千级并行；ARTEX worker 并发 | supervisor 1–8 worker，单机 | 单机进程内队列，无跨副本租约/配额 | 需工程资源，L 级 |
| 3 | 真实竞赛战绩/模型决策质量 | P1 第 1、P2 54/54 AK、P5 第 3 | 8 任务策略级微评测，不调外部 LLM | 没有冻结模型 + 真实靶场的端到端跑分 | 下一轮 |
| 4 | 通用 Web/AD/浏览器零日 | XBow 有 Chrome 全链、MSRC CVE；NodeZero/Pentera 有 AD | 专注 ML 基础设施面 | 类别外，刻意不做 | 不追 |
| 5 | 平台化多租户 SaaS | ARTEX 有 PG 任务实体 + Next.js；CyberStrike 有工作台 | 单机 CLI + 本地 WebUI | 没有跨副本队列、租户配额、按租户加密 | 需工程资源 |
| 6 | ARTEX 功能全等价 | 515 行里 201 条部分、180 条曾缺失 | 70 条补上，110 条不做/不可行，201 条仍部分 | 产品形态差异 + clean-room 边界 | 只补与定位一致的 |
| 7 | KubeTrail 全等价 | 286 行里 98 部分、120 缺失 | 59 已有 + 21 模块移植 | 桌面后渗透台/C2/持久化刻意不做；原矩阵未重算 | 部分追 |
| 8 | Payload 广度 | garak 41/170、PyRIT ~90、trufflehog 892、gitleaks 222、Falco 99 | 103 条版本矩阵 + 150 变体 + 47 武器包（87 探针） | L 级规则库/探针库，需持续投入 | 登记 CM-32/34 |
| 9 | 检测规则广度 | Falco 99 条默认规则 | 5 条 ML 面 Falco 规则 | 我们做“ML 面精准规则”，不做通用规则全集 | 不追全集 |
| 10 | 裸机性能 | ARTEX 可跑裸机/真实集群 | 只有 QEMU TCG 同宿主数据 | 无裸机/真实集群同口径复跑 | 需资源 |
| 11 | 生产信任链 | cosign keyless + Fulcio/Rekor；真实 TEE | 验证侧已接公共 Fulcio/Rekor 样本；签名侧仍是 HMAC fixture | 本仓库产物没有 OIDC 身份，未向公共 Fulcio 签发 | 见第七章 |
| 12 | 真实六云 | 各家云原生工具 | 契约级仿真 24/24 | 无账号/GPU 节点 | 见第七章 |

这张表是“仍未超过”的清单，不是“永远不追”的清单。每行的判断依据见 `docs/COMPETITIVE-MATRIX.md`、`docs/GAP-FEATURES.md`、`docs/GAP-ATTACK-SURFACE.md`、`docs/GAP-PAYLOADS.md`、`docs/ARTEX-PARITY.md` 与 `docs/SECTION3-TENCENT-AGENT-CONTEST.md`；数字与状态以这些落盘文档为准。

### 6.9 结论

功能上，我们在“ML 基础设施面 + 证据 + 规则”有差异化；在“通用攻击面、payload 库、平台化、规模”明显不如对手。攻击面上，K8s 广度不如 KubeHound/KubeTrail，ML 面强于它们。Payload 上，ML 面有针对性，模型行为面和密钥规则库是短板。性能上，已测维度占优，但绝对值含 TCG 放大，不能当产品倍率。腾讯 8 项目在“编排层”领先，我们补了策略件，还没补“真实长程决策”的账。

**证据索引（本章）**：[竞品矩阵](COMPETITIVE-MATRIX.md) · [功能矩阵 JSON](feature-matrix.json) · [ARTEX 逐功能](FEATURE-BY-FEATURE-ARTEX.md) · [KubeTrail 逐功能](FEATURE-BY-FEATURE-KUBETRAIL.md) · [功能缺口](GAP-FEATURES.md) · [攻击面缺口](GAP-ATTACK-SURFACE.md) · [Payload 缺口](GAP-PAYLOADS.md) · [ARTEX 对齐](ARTEX-PARITY.md) · [腾讯 8 项目](SECTION3-TENCENT-AGENT-CONTEST.md) · [性能对比](PERFORMANCE-COMPARISON.md)

---

## 七、未达成 5 项：真实、模拟、未达成三态

### 7.0 三态怎么定义

**真实**：在客户或厂商的真实环境里跑过，有原始数据、有环境描述、能复跑。**模拟**：在仿真器、夹具、本机回环或合成数据上跑过，能证明算法/接口/闸门，不能证明真实环境。**未达成**：没有可复现实验，只有设计、脚本或公开资料。下面五项里，四项是“真实未达成、模拟已做或部分做”；cosign 是“签名侧未达成、验证侧已真实（第三方样本），但本仓库产物仍未取得公共 Fulcio 身份”。我们逐项写“能证明什么、不能证明什么”，避免把“模拟通过”写成“生产可用”。

### 7.1 万卡/超大规模实测

**目标**：在 ≥1,024 GPU 的集群上跑链和证据库吞吐，再扩到 12,288 GPU 复刻 MegaScale 拓扑，记录网络/存储瓶颈。

**终态**：真实：未达成。模拟：已做。未达成：10K+ GPU 裸机、真实 NCCL/RDMA/SHARP 数据面、真实故障域。

**已做验证**：`docs/SCALE-RESULTS.md` 用合成 100/1,000/5,000/10,000 个 K8s 对象跑 11 个侦察模块、可达性图和规则生成：10,000 对象总耗时 1.645s，侦察 40.4ms，峰值 RSS 54MB，findings 10,891；三处 O(n²) 改索引后，同输入 330.8ms→46.5ms（×7.11），findings 逐条一致。真 k3s 只到 204 个对象：采集 6.4s，11 模块 199.7ms，145 findings。`docs/FABRIC-ATTACK-SURFACE.md` 用 `lab/fabric_dos_sim.py` 做 11 个 fabric 面的控制面/数据面语义仿真（SHARP 会话、IB SM、PFC、NCCL 端口、checkpoint IO、IMDS、KV OOM、梯度、gang、Xid、rail）；`docs/EFFECT-VERIFICATION.md` 与 `reports/samples/effects/effects.json` 当前落盘 **53/53 PASS**（2026-10-26 运行，含 chip 与硬件批次），旧 17/20/31/34/47 口径为历史阶段值。`docs/FABRIC-SIM-RESULTS.md` 已落盘：1,024/10,000 节点 rail/多平面离散事件仿真（1,024 mixed：PFC 76,801,033、ECN 74、跨 rail 37、worst/median 9.04/2.06ms；10,000 mixed：PFC 102,401,629、ECN 133、跨 rail 64、worst/median 8.95/1.38ms），并调用真实 `fabric-topology-isolation` / `roce-pfc-storm` / `nccl-straggler-injection` 模块裁决（PFC/straggler 均 high）。**这些是仿真，不是真实交换机计数器。**

**能证明什么**：分析算法在对象规模上近似线性；10k 对象的分析不是瓶颈；fabric 控制面的“语义同构”可以被计数器验证；规则生成在 10,891 findings 下仍是 94ms。

**不能证明什么**：不能证明 10,000 张 GPU 的训练能跑；不能证明真实 NCCL 集合通信会被同样方式影响；不能证明真实 IB/SHARP 交换机的故障域；不能把“10k 对象”说成“万卡”。

**下一步**：①≥1,024 GPU 集群跑链 + 证据库吞吐；②扩到 12,288 GPU 复刻 MegaScale 拓扑；③产出可复现 BENCH 报告（硬件、拓扑、版本、原始数据）。验收标准写在 `docs/SOTA-2026-10.md` 的“剩余硬缺口（仍未达成）”。

### 7.2 硬件 TEE 实测（TDX / SEV-SNP / NVIDIA CC）

**目标**：在真实 TDX/SEV-SNP/H100-CC 机器上采集 quote/report，接 Intel PCS / AMD KDS / NVIDIA NRAS 的证书链，验证 nonce 重放、测量值白名单、TCB 降级、debug 开启都被拒。

**终态**：真实：未达成。模拟：已做。未达成：真实硬件 quote/report、厂商 PKI、端到端“证明→密钥释放”。

**已做验证**：`docs/TEE-VERIFICATION.md` 记录了 `inkblade/tee/` 的实现：TDX Quote v3/v4 解析 + ECDSA P-256/P-384 验签 + AK→中间→根链；SEV-SNP report v2/v3 的 1184B 布局 + P-384 验签 + VCEK→ASK→ARK；NVIDIA NRAS JWT 的 RS256 + JWKS + claims。`tests/test_tee.py` 43 项，覆盖合法通过、篡改字段、篡改签名、过期、nonce 不符、DEBUG=1、TCB 降级、换根、换 JWKS、`alg=none`。所有 fixture 都是**自签**，私钥公开在源码里；证书主体是 `InkBlade Fixture`，`kid=nras-fixture-2026`。这是刻意的：fixture 只用于测试解析与验签逻辑，不能被当作证据。本轮新增 `inkblade/tee/online.py`：对 Intel PCS TDX TCB Info、AMD KDS ASK/ARK/VCEK/CRL、NVIDIA NRAS JWKS 的**官方公共样本**实网抓取并本地验签（Intel ECDSA、AMD RSA-PSS-SHA384、NVIDIA EC P-384/ES384），`tests/test_tee_online.py` 21 项；边界见 `docs/TEE-ONLINE-VERIFICATION.md`。

**能证明什么**：解析器能处理真实格式的字段；签名/证书链/策略断言在篡改时会失败；不是“有 key 就过”。

**不能证明什么**：不能证明 quote 来自真实 TDX/SEV-SNP 机器；不能证明 QE report 对 PCK 的签名；不能证明 TCB 已打补丁；不能证明 GPU 处于 CC 模式；不能证明“证明→密钥释放”链路。

**下一步**：①接 Intel PCS / AMD KDS / NVIDIA NRAS；②在实机采集 quote/report；③把真实报告纳入 CI（有硬件时）；④保留 fixture 作为离线单测。`docs/SOTA-2026-10.md` 明确：真实硬件 TEE 仍是“仍未达成”；公共厂商 PKI 已转为真实验证。

### 7.3 六云商真实环境实测

**目标**：每云 1 个最小集群（EKS/AKS/ACK/TKE/GKE/CCE）+ GPU 节点，跑只读侦察与网络策略语义矩阵，记录 API 差异与权限边界。

**终态**：真实：未达成。模拟：已做。未达成：真实云账号、真实 IAM 求值、真实 STS 验签、真实网络数据面、真实审计日志。

**已做验证**：`docs/SIX-CLOUD-MATRIX.md` 用 `lab/cloud_six_sim.py` 做 49 条路由的契约级仿真：6 云 × 7 类能力（身份/信任、角色假设、桶策略、桶列目录、快照、快照共享、安全组/IMDS）。4 个跨租户场景 × 6 云：vulnerable 24/24 可达，fixed 24/24 拒绝（403/401/403/403）。每云有判别字段，不是统一 schema：AWS 的 `Principal.Federated`、Azure 的 `subject/issuer`、阿里云的 `Principal.RAM`、腾讯云的 `principal.qcs`、GCP 的 `principal://`、华为云的 `trust_domain`。`tests/test_six_cloud_sim.py` 15 项。本轮新增 `lab/cloud_free/`：AWS SigV4 / Azure SharedKey / GCP JSON API 适配器 + Python mock 端点 + LocalStack/Azurite/fake-gcs compose（本机无 Docker，实际跑 mock），`tests/test_cloud_free.py` 14 项；`docs/CLOUD-FREE-TIER-RUNBOOK.md` 给出 AWS/Azure/GCP 最小集群与成本边界，以及阿里/腾讯试用说明。**没有真实云账号/集群**，SOTA 仍为「模拟验证」。

**能证明什么**：六云的字段形状差异被显式建模；同一组跨租户动作在 vulnerable/fixed 两态下有可复现的差分；拒绝点可定位。

**不能证明什么**：不能证明任何真实云账号的配置；不能证明 AWS IAM policy 求值、Azure RBAC 继承、RAM/CAM 条件算子；不能证明真实 OIDC token 验签；不能证明真实网络流量；不能证明 CloudTrail/Activity/ActionTrail 接入。

**下一步**：①每云最小集群 + GPU 节点；②用同一组只读探针替换仿真器；③记录 API 版本、字段差异、权限边界；④回填 corpus 与判别字段表；⑤只在拿到真实返回后才改判 SOTA。

### 7.4 生产级模型签名（cosign keyless / OIDC / Rekor）

**目标**：接 cosign keyless + Fulcio + Rekor，在 CI 对权重/镜像签名并验签，提供 trust root 轮换与吊销流程。

**终态**：真实：部分（验证侧真实，签名侧未达成）。模拟：已做。未达成：本仓库产物经公共 Fulcio keyless 签发、OIDC 身份、SCT/CRL/OCSP。

**已做验证**：`docs/KEYLESS-VERIFICATION.md` 记录了 `inkblade/sigstore_keyless.py` 的实现：Fulcio v2 签发接口、Rekor v1 日志条目、Sigstore bundle v0.3、Fulcio 链/SAN/OIDC issuer、SET JCS 验签、RFC6962 inclusion proof、checkpoint note、在线重取。验证侧对 Sigstore 公共实例的真实产物做了端到端验证：sigstore/cosign v3.1.4 的 `cosign_checksums.txt`，SHA-256 `e70e59b3…f4c0`，Rekor `logIndex=3341269697`，Fulcio SAN `keyless@projectsigstore.iam.gserviceaccount.com`，issuer `https://accounts.google.com`，证书链、证书时间、身份、issuer、SET、inclusion、checkpoint、在线重取全部通过。另做了一次真实的公共 Rekor 写入/回读（key-based，`logIndex=3462554806`），`tlog-*` 全过，但 `keyless-certificate` 与 `certificate-chain` 明确失败——没有把它冒充 keyless。`tests/test_sigstore_keyless.py` 19 项（1 项在线重取默认 skip）。我们自己的产物仍走本地 Fulcio 兼容 CA fixture；因为当前环境没有 OIDC 身份，没有向公共 Fulcio 申请证书。`tests/test_supplychain.py` 仍覆盖 HMAC 三元组（artifact/source/builder）与篡改拒绝。

**能证明什么**：验证器能正确处理公共 Fulcio 短生命周期证书、Rekor 透明日志、SET、inclusion、checkpoint 与在线一致性；第三方真实 keyless 样本能验过；公共 Rekor 写入/回读能验过；篡改、过期、错误身份/issuer、吊销 serial 会失败。

**不能证明什么**：不能证明本仓库产物已经用公共 Fulcio keyless 签发；不能证明我们拥有 OIDC 身份；不能证明 SCT/CT 审计；不能证明真实 CRL/OCSP；不能证明生产 CI 已接 cosign CLI。SOTA 总项仍按“模拟验证”记，不写成“已达成”。

**下一步**：①在 CI 里用 OIDC 身份向公共 Fulcio 申请短期证书并写入 Rekor；②接 SCT 校验与真实 CRL/OCSP；③trust root 轮换与吊销流程；④保留本地 fixture 作为离线单测。

### 7.5 分布式调度 / 多租户 SaaS

**目标**：任务队列 + worker 池 + 每租户配额；证据库按租户加密隔离；审批与审计跨副本一致；压测 100 并发链与故障恢复。

**终态**：真实：未达成。模拟：部分。未达成：跨副本队列、租户配额、按租户加密、跨副本审批一致性。

**已做验证**：单机有界并发已测：`inkblade/core/supervisor.py` 支持 1–8 worker；`docs/PERFORMANCE-COMPARISON.md` 记录 `/api/v1/graph` 在 16 并发下 286.3 rps（1/4/16/32 为 138.6/297.7/286.3/268.0），`ThreadingHTTPServer` backlog 从 5 提到 256 后，同端点从 29 rps 提到 286 rps；空闲 28.1MB，16 并发峰值 33.0MB。本轮新增 `lab/saas/`：ThreadingHTTP + 多进程 worker + SQLite WAL 原子配额/审批 + 每租户 `EvidenceStore`；8 租户 × 8 并发实测 422 done / 858 quota 429 / 隔离违规 0 / 重复审批 8 拒绝 / 17.26 runs/s（`docs/SAAS-LOAD-RESULTS.md`，`tests/test_saas.py` 14 项）。**单机本地模拟，不是跨副本分布式/商业 SLA。**

**能证明什么**：单机进程内有界并发可用；backlog 是真实瓶颈；证据库在单写者下是线性审计；资源占用可控。

**不能证明什么**：不能证明跨副本任务队列；不能证明租户配额；不能证明按租户加密；不能证明跨副本审批/审计一致；不能证明 100 并发链的故障恢复。单机 286 rps 不等于分布式调度。

**下一步**：①任务队列 + worker 池 + 每租户配额；②证据库按租户加密隔离；③审批与审计跨副本一致；④压测 100 并发链与故障恢复。`docs/SOTA-2026-10.md` 把“跨副本分布式 SaaS”列为仍未达成；本地多进程/8 租户压测已落为模拟验证，真实验收标准仍是 100 并发链 + 故障恢复。

### 7.6 五项汇总

| 项 | 本轮三态 | 已做验证 | 仍未达成部分 | 能证明 | 不能证明 |
|---|---|---|---|---|---|
| 万卡 | **模拟验证** | 1,024/10,000 节点 fabric 仿真 + 真实模块裁决 | 10K+ GPU 裸机、真实 NCCL/RDMA | 分析近似线性、fabric 语义可测 | 万卡训练、真实故障域 |
| TEE | **真实验证（公共 PKI）/ 仍未达成（硬件）** | Intel PCS/AMD KDS/NVIDIA NRAS 官方样本验签；本地 fixture 43 项 | 真实硬件 quote/report、密钥释放 | 公共链/CRL/TCB 能验；篡改/降级/吊销会拒 | 硬件来源、厂商认证、真实 GPU CC |
| 六云 | **模拟验证** | AWS/Azure/GCP emulator 适配器；阿里/腾讯契约 24/24 两态 | 真实账号/IAM/STS/日志 | 字段形状、差分、拒绝点 | 真实云配置与求值 |
| cosign | **模拟验证**（验证侧真实，签名侧未达成） | 公共 keyless 样本验证、Rekor 写入/回读、本地 fixture | 本仓库产物的公共 Fulcio 签发、OIDC、SCT/CRL | 验证链能处理真实 keyless/Rekor | 我们的签名身份、生产 CI |
| SaaS | **模拟验证** | 8 租户 × 8 并发、多进程 worker、原子配额/审批 | 跨副本队列/HA/租户加密 | 单机隔离/配额/审批可测 | 分布式调度与商业 SLA |

### 7.7 未达成清单（终版，证据日期 2026-10-27）

以下 11 条是**当前仍未达成**项，写死在终版里；未达成不等于失败，但不允许被“模拟通过”覆盖。

| # | 未达成项 | 当前状态 | 验收标准（达成后再改口径） |
|---|---|---|---|
| 1 | 真实 10K+ GPU / 裸机性能 | 1,024–10,000 节点离散事件仿真；无真实 NIC/交换机/光模块/故障率 | ≥1,024 GPU 真集群跑链 + 12,288 复刻 MegaScale + 原始计数器 |
| 2 | 硬件 TEE 实测 | 公共 PKI 真实验证；无 TDX/SEV-SNP/H100-CC 实机 quote/report | 实机采集 + nonce/measurement/TCB/debug 负例 + 「证明→密钥释放」 |
| 3 | 真实六云 | 契约仿真 + AWS/Azure/GCP mock；无账号/IAM/STS/日志 | 每云最小集群 + 只读侦察 + 网络策略矩阵 |
| 4 | 自有 Fulcio keyless 签发 | 第三方公共样本验证通过；本仓库产物无 OIDC 身份 | CI OIDC 向公共 Fulcio 签发并写 Rekor + 轮换/吊销 |
| 5 | 跨副本分布式 SaaS | 单机 8 租户压测；无跨副本队列/租约/HA/租户 KMS | Postgres/队列 + 按租户加密 + 100 并发链故障恢复 |
| 6 | 模型注册中心 / 权重仓库直连 | 只读本地清单/权重 | HF/OCI 拉取 + 在线验签 + 断网/篡改/吊销负例 |
| 7 | SIEM/SOAR 真实投递 | 只有 SARIF/OCSF/VEX 产物 | Splunk HEC/Elastic/Sentinel 投递 + 幂等/回压/审计 |
| 8 | 漏洞挖掘披露闭环 | 已建 CVE 适格筛选、CVE 5.1 请求体、脱敏证据包、90 天发布计划（未外发） | 人工发送 + 厂商回执 + CVE 分配 + 公开 advisory |
| 9 | 无面模块治理 | 19 个六画像全无面；11 个已隔离，8 个待 owner 决定 | 8 个模块隔离或补面；面闸门默认开启 |
| 10 | 画像覆盖缺口 | `slurm-hpc` 25.00%（Slurm 17 域覆盖 88.2%），其余 59.78%–70.65% | 六画像 production coverage ≥90% |
| 11 | 可利用性核验缺口 | 152 条中 37 verified / 6 exposure-verified / 87 static-only / 22 unsupported | 真实 GPU/内核/硬件环境升级 static-only/unsupported |

> 2026-10-27 关闭：第 12 条「Rust 探针运行时」已完成——286 模板 × 两态 × 每态 3 次一致，0 失败，
> 证据 `reports/probe-coverage/evidence-native.json`；fixed 态负控边界见 `docs/PROBE-COVERAGE.md` §6。

**证据索引（本章）**：[SOTA 与追赶路径](SOTA-2026-10.md) · [规模压测](SCALE-RESULTS.md) · [Fabric 攻击面](FABRIC-ATTACK-SURFACE.md) · [TEE 验证](TEE-VERIFICATION.md) · [六云矩阵](SIX-CLOUD-MATRIX.md) · [性能对比](PERFORMANCE-COMPARISON.md) · [供应链代码](../inkblade/supplychain.py) · [TEE 代码](../inkblade/tee/) · [六云仿真](../lab/cloud_six_sim.py)

---

## 八、复盘：这个项目自己犯过的错

这一章不复盘“对手”，只复盘“我们”。每条都写四件事：当时怎么想、错在哪、如何纠正、教训。这些错误有的已经修好，有的还在影响文档口径；写出来是为了让下一轮不重复。

### 8.1 用能力维度代替逐功能

**当时怎么想**：SOTA 用 39 项能力（当前 26 真实验证 / 10 模拟验证 / 3 仍未达成）和 18 个能力维度，已经能说明“我们有什么、缺什么”。维度清楚、好汇报。

**错在哪**：维度是地图，不是清单。ARTEX 有 515 行逐路由/逐表/逐组件的功能，我们却用“多 agent 协作”一个维度概括；结果 180 条具体缺失被藏在“partial”里。甲方问“你有没有某个页面/某个 API”，维度答不了。

**如何纠正**：补 `docs/feature-matrix.json`（801 行）和 `docs/gap-matrix.json`（260 行）；ARTEX 的 180 条 missing 逐行处置：70 条 clean-room 实现、6 条技术不可行、104 条不适用、0 条未分类。`tests/test_artex_parity.py` 锁定行数与证据文件存在。

**教训**：能力维度用来讲战略，逐功能矩阵用来交付。两者都要有；只用维度，就会把“没做”说成“部分”。

### 8.2 用九族代表性子集代替全网格

**当时怎么想**：九族各挑 2 个代表模块，共 18 个，跑通就说明“九族都覆盖”。e2e 也是这么写的：`module-family-subset`。

**错在哪**：18 个代表模块 ≠ 全量模块。`DEV-LOG.md` C.3 记录当时工作树已有 138 个模块；18/138 只证明了“接口通”，没有证明“每个模块的两态、每个链的前置、每个参数变体都通”。后来并行任务确实在未覆盖的模块里发现了问题。

**如何纠正**：全量 `unittest discover` 跑到 1,140 个测试；补 260 行缺口表、801 行功能矩阵；对未覆盖模块逐项登记 `partial/missing`，不把“代表性子集”写成“全覆盖”。真实集群验证也只声明 6 个模块、16 条 findings，不 extrapolate 到全模块。

**教训**：代表性子集适合做冒烟，不适合做验收。验收要有“全量清单 + 逐项状态”，否则 coverage 是自我安慰。

### 8.3 把启动基准当对标完成

**当时怎么想**：ARTEX 已经跑起来了，冷启动、内存、API 延迟、任务提交都测到了，可以写“对标完成”。

**错在哪**：第一轮 mock LLM 只会回固定文本，ARTEX 任务停在 `running`，worker 没启动，靶场 0 请求。一个“任务没跑完”的基准，只能证明“服务能启动”，不能证明“扫描能对比”。当时文档一度把它写成“同靶场对比”，这是过度解读。

**如何纠正**：把 mock LLM 升级为 v2 脚本化计划器，按 ARTEX 协议返回 `set_goals → add_intent → Bash → report_finding → prove_goal`；任务 13,510ms 走完，靶场 3 个真实请求全 200，1 条 high finding；InkBlade 同链 105.6ms。`docs/ARTEX-BENCH-RESULT.md` 第 6.2 节保留首轮失败历史，`tests/test_artex_same_target.py` 锁定 dispatch-once / prove-once / turn-cap。

**教训**：benchmark 的第一条验收不是“数字好看”，而是“工作负载完整跑完”。启动、健康检查、任务提交，都只是前置条件。

### 8.4 把公开零日模块误判为“私有零日”

**当时怎么想**：6 个 `dify-*` / `open-webui-*` 模块是“零日”，应该默认隐藏、加密、需要 `zeroday.enable` 才能看。这样显得“有独家门路”。

**错在哪**：这些模块的能力已经公开，`private:true` 不产生安全价值，反而让交付不可复现、让客户无法验证。把“公开模块”包装成“私有零日”，是分类错误，也是诚信问题。

**如何纠正**：6 个模块全部 `private:false`，正常打包与展示；`inkblade/core/zeroday.py` 降为“默认关闭的可选加密扩展”，只供未来真正未披露的私有材料使用，不再是这 6 个模块的门槛。`README.md` 的“边界”段落明确写了这一点。

**教训**：分类要看证据，不要看命名。把公开东西说成私有，短期好看，长期毁信任。

### 8.5 代理空转：没有终止条件的 agent 就是压测器

**当时怎么想**：给 ARTEX 一个 mock LLM，让它自己规划，应该能跑出扫描结果。只要协议通，任务就会自然收敛。

**错在哪**：v1 mock 只会回固定文本，planner 收到终止文本后空转，任务停在 `running`，靶场 0 请求。v2 第一版脚本又走到另一个极端：planner 在单会话里连派 400+ 意图，3 个 worker 并发空转，靶场被打 167 次。这不是“模型笨”，是“没有终止条件”。

**如何纠正**：在 mock 计划器里加三条硬规则：`dispatch-once`（本轮派发过意图就收口）、`prove-once`（有 finding 就 prove_goal）、`turn > 4` 硬顶；runner 自适应 curl→wget→python3；最终一轮任务恰好 3 个请求、12 次 LLM 调用。`tests/test_artex_same_target.py` 锁定这三条。

**教训**：agent 循环必须有预算、有终止、有幂等。否则它不是“自主”，是“压测器”。

### 8.6 并行提交冲突：`git add -A` 会卷入别人的在途文件

**当时怎么想**：多个 agent 在同一个工作树里干活，提交时 `git add -A` 最省事，能把“我改的都带上”。

**错在哪**：`git add -A` 不分所有权。`f315160` 卷入了并行任务的 `test_chains.py`；`188e0f1` 把另一个任务的 41 个文件先行提交；`7f02967` 的内容虽然逐字节一致，但历史已经被污染。更糟的是，未完成的模块目录会让 `load_modules` 硬失败，全量测试被别人的在途状态拖红。

**如何纠正**：禁用 `git add -A`，只 `git add` 显式路径；共享文件用增量编辑，不整体重写；全量测试在“HEAD + 本轮显式 overlay”的干净树里度量，另行记录工作树中的在途红测；提交说明逐条标注。`DEV-LOG.md` 的 Ruling 段落记录了这些规则。

**教训**：共享工作树需要所有权边界。提交不是“保存”，是“对外声明这些文件属于这次改动”。

### 8.7 把 fixture 当生产证据

**当时怎么想**：供应链签名和 TEE 证明都有 fixture，测试也过了，可以在报告里写“支持签名/证明验证”。

**错在哪**：fixture 的私钥是公开的，任何人可以伪造“合法”证明。HMAC fixture 不是 sigstore keyless；自签 TEE 证书不是厂商 PKI。把 fixture 通过写成“生产信任链通过”，是越界。

**如何纠正**：SOTA 把“模型签名与 provenance”“TEE 证明解析”标为“部分”，把“硬件 TEE 实测”“生产级 cosign keyless”标为“未达成”；`docs/TEE-VERIFICATION.md` 用一整节写“没有验证什么”；`tests/test_tee.py::FixtureBoundaryTest` 把 fixture 主体锁成断言。

**教训**：证据的可信度取决于来源，不取决于测试是否绿。fixture 只能证明“代码路径通”，不能证明“生产信任链通”。

### 8.8 把 QEMU TCG 倍率当产品性能

**当时怎么想**：同靶场 13,510ms vs 105.6ms，约 128×；冷启动 37.85s vs 0.805s，约 47×。这些数字很直观，可以拿来讲性能优势。

**错在哪**：ARTEX 跑在 QEMU TCG 纯软件仿真里，所有 guest 内动作都慢一个量级；13,510ms 里大头是 planner debounce、worker 领取轮询、3 秒状态轮询，不是 ARTEX 的真实计算。把 128× 当产品倍率，会误导甲方。

**如何纠正**：`docs/PERFORMANCE-COMPARISON.md` 在方法学里写“TCG 放大声明”；结论边界写“≈128×（TCG 放大，非产品倍率）”；未测项逐条登记 N/A；`docs/ARTEX-BENCH-RESULT.md` 第 4 节写“不应把 13,510/105.6 直接当作产品级倍率”。

**教训**：性能数字必须带环境。没有环境描述的数字，不是性能，是故事。

### 8.9 文档数字不同步

**当时怎么想**：每个任务写自己的文档，数字各自落盘；最后总有人会合并。

**错在哪**：README 写“11/11 PASS”，`docs/EFFECT-VERIFICATION.md` 是 17/17；性能文档里 InkBlade 内存有 49–50MiB 的旧采样，也有 28.1MB 的新采样；ARTEX 内存有 169.8MiB 的长跑值，也有 75.2MiB 的新起栈值。读者不知道哪个是真的。

**如何纠正**：以“当前落盘报告 + 原始 JSON”为单一来源；`8da8bd9` 把性能数字对齐到 committed live grid；本报告在第五章逐行标来源，并明确“17/17 与 20/20 未合并”。后续应该把生成文档纳入 CI，数字从 JSON 渲染，而不是手写。

**教训**：数字有生命周期。没有单一来源，文档越写越不可信。

**证据索引（本章）**：[开发台账](DEV-LOG.md) · [进度台账](../progress.md) · [ARTEX 对标](ARTEX-BENCH-RESULT.md) · [性能对比](PERFORMANCE-COMPARISON.md) · [TEE 边界](TEE-VERIFICATION.md) · [SOTA](SOTA-2026-10.md) · [README](../README.md)

---

## 九、术语表

这一章把文中出现的缩写和黑话逐条翻译成白话。每条一句，不追求学术定义，只追求“下次看到能想起来”。

| 缩写/黑话 | 白话解释 |
|---|---|
| K8s | Kubernetes 的缩写，一个把多台机器当成一台大电脑来调度容器的系统。 |
| Pod | K8s 最小的运行单元，一个或多个容器共享网络和挂载，也是身份的载体。 |
| RBAC | K8s 的“谁能对什么做什么”的权限表，由角色和绑定组成。 |
| Service | 给一组 Pod 起的稳定入口，Pod 换了 IP 也不影响访问。 |
| NetworkPolicy | K8s 的防火墙规则，但默认不是全拒，且不同 CNI、hostNetwork 的行为不一样。 |
| GPU 训练 | 用大量数据反复算梯度、更新权重，通常跨很多 GPU 跑很久。 |
| GPU 推理 | 用训练好的模型回答请求，关心时延、吞吐、缓存和密钥。 |
| NCCL | NVIDIA 的集合通信库，负责 all-reduce 等跨 GPU 通信。 |
| RDMA | 远程直接内存访问，绕过 CPU 直接读写对方内存，常用于高性能网络。 |
| SHARP | 交换机在网聚合协议，把 all-reduce 的一部分计算下沉到交换机。 |
| PFC | 优先级流控，用暂停帧防止丢包；配错会变成“暂停风暴”。 |
| DRA | K8s 的动态资源分配，用来声明 GPU 等特殊资源。 |
| IMEX | NVIDIA 的 GPU 内存导出/共享通道，用于跨进程或跨容器共享显存。 |
| EPP | Gateway API Inference Extension 的端点选择器，决定推理请求发给哪个后端。 |
| KV cache | 推理时缓存历史 token 的 Key/Value 向量，省算力但占显存，可能跨租户泄露。 |
| prefill | 推理的第一段，把输入一次性读进去并建立 KV cache，算力密集。 |
| decode | 推理的第二段，一个 token 一个 token 输出，显存带宽密集。 |
| AI 网关 | 模型 API 的统一前台，负责鉴权、限流、路由、缓存、日志和密钥。 |
| 租户 | 共享同一套基础设施但彼此不能看见对方数据的客户单位。 |
| 证据链 | 从结论回到原始事实的路，包含运行、步骤、请求、响应、哈希、审批和回滚。 |
| ROE | Rules of Engagement，授权测试的交战规则，写明范围、级别、时间窗和联系人。 |
| SSRR | SelfSubjectRulesReview，问 K8s“我这个身份在这个命名空间能做什么”。 |
| SSAR | SelfSubjectAccessReview，问 K8s“我这个身份能不能对某个资源做某个动作”。 |
| IMDS | 实例元数据服务，常见地址 169.254.169.254，常被用来偷云凭据。 |
| IRSA | IAM Roles for Service Accounts，EKS 里把 K8s 服务账号映射到 IAM 角色。 |
| PoC | Proof of Concept，能证明漏洞存在的最小可复现步骤或代码。 |
| Payload | 实际发送给目标的请求、参数或代码片段，不是“漏洞名称”。 |
| MCP | Model Context Protocol，模型调用外部工具的协议。 |
| A2A | Agent2Agent，agent 之间互相委派任务和取结果的协议。 |
| OCSF | Open Cybersecurity Schema Framework，安全事件的通用数据模型。 |
| SARIF | Static Analysis Results Interchange Format，静态分析结果的通用 JSON 格式。 |
| VEX | Vulnerability Exploitability eXchange，说明某个漏洞“是否真的可被利用”的声明格式。 |
| CVSS | Common Vulnerability Scoring System，漏洞严重度评分。 |
| ATT&CK | MITRE 的攻击战术与技术知识库，偏企业 IT。 |
| ATLAS | MITRE 的对抗性 AI 威胁知识库，偏 ML 系统。 |
| 等保 | 中国网络安全等级保护制度，按级别要求做安全建设和测评。 |
| PTES | Penetration Testing Execution Standard，渗透测试执行标准。 |
| CIS | Center for Internet Security，发布系统安全基线（Benchmark）的组织。 |
| TCG | QEMU 的 Tiny Code Generator，纯软件指令翻译，性能远低于硬件虚拟化。 |
| CNI | Container Network Interface，K8s 的网络插件标准，Calico/Cilium 都是 CNI。 |
| MIG | Multi-Instance GPU，把一张 GPU 切成多个隔离实例。 |
| MPS | Multi-Process Service，让多个进程共享一张 GPU 的服务。 |
| TEE | Trusted Execution Environment，可信执行环境，用硬件隔离保护代码和数据。 |
| TDX | Intel 的 Trust Domain Extensions，一种 CPU 侧 TEE。 |
| SEV-SNP | AMD 的安全加密虚拟化加安全嵌套分页，一种 CPU 侧 TEE。 |
| cosign | Sigstore 的签名/验签工具，支持 keyless 和密钥对两种模式。 |
| Fulcio | Sigstore 的证书颁发机构，把 OIDC 身份签成短期证书。 |
| Rekor | Sigstore 的透明日志，记录签名事件，便于审计和发现篡改。 |
| SBOM | Software Bill of Materials，软件物料清单，列出组件和依赖。 |
| CVE | Common Vulnerabilities and Exposures，公开漏洞编号。 |
| IAM | Identity and Access Management，云上的身份与权限系统。 |
| OIDC | OpenID Connect，建立在 OAuth 2.0 上的身份认证协议。 |
| JWT | JSON Web Token，一种带签名的 JSON 令牌，常用于身份和证明。 |
| JWKS | JSON Web Key Set，一组公钥，用来验 JWT 签名。 |
| KMS | Key Management Service，云上的密钥管理服务。 |
| RPS | Requests Per Second，每秒请求数。 |
| RSS | Resident Set Size，进程实际占用的物理内存。 |
| SOTA | State of the Art，当前公开可见的最先进水平；本报告只把它当“参照”，不当“自称”。 |

**证据索引（本章）**：[SOTA](SOTA-2026-10.md) · [架构](ARCHITECTURE.md) · [长上下文](LONG-CONTEXT.md) · [AI 网关](AI-GATEWAY.md) · [TEE](TEE-VERIFICATION.md) · [供应链代码](../inkblade/supplychain.py)

---

## 十、证据索引

这一章是全文的“目录的目录”。每个链接都是相对路径，可以在仓库里直接点开。**本报告不引用未落盘的结果**；并行任务生成中的文档，在第七章逐项标注“进行中”，等落盘后再回填。

### 10.1 总纲与架构

| 文档 | 内容 |
|---|---|
| [README](../README.md) | 项目入口、快速开始、能力与边界 |
| [REQUIREMENTS-MATRIX.md](REQUIREMENTS-MATRIX.md) | **唯一需求事实源**：129 条需求（done 94 / partial 28 / blocked-resource 7）、数字对账、未完成清单与依赖 |
| [ARCHITECTURE.md](ARCHITECTURE.md) | 控制端七组件与职责边界（检测模型为十层，见 DETECTION-LAYERS） |
| [SOTA-2026-10.md](SOTA-2026-10.md) | 39 项能力矩阵：26 真实验证 / 10 模拟验证 / 3 仍未达成（附证据路径） |
| [design.md](design.md) | 设计基线与漏洞研究分类 |
| [RUNBOOK.md](RUNBOOK.md) | 安装、授权、模块/链、报告、回滚、实验室边界 |
| [DELIVERY.md](DELIVERY.md) | 交付包结构与样张说明 |
| [DEV-LOG.md](DEV-LOG.md) | 开发台账、里程碑、Ruling、测试与提交记录 |
| [progress.md](../progress.md) | 逐任务进度台账 |

### 10.2 攻击面、模块与链

| 文档 | 内容 |
|---|---|
| [GAP-FEATURES.md](GAP-FEATURES.md) | 31 个工具、122 条功能缺口 |
| [GAP-ATTACK-SURFACE.md](GAP-ATTACK-SURFACE.md) | 31 个工具、82 条攻击面缺口 |
| [GAP-PAYLOADS.md](GAP-PAYLOADS.md) | 31 个工具、56 条 payload 缺口 |
| [FABRIC-ATTACK-SURFACE.md](FABRIC-ATTACK-SURFACE.md) | 万卡 fabric 的 11 个攻击面与模块映射 |
| [LONG-CONTEXT.md](LONG-CONTEXT.md) | 长上下文、KV cache、PD 分离威胁模型 |
| [AI-GATEWAY.md](AI-GATEWAY.md) | AI 网关、模型注册表、向量库威胁模型 |
| [GPU-CLOUD-TENANCY.md](GPU-CLOUD-TENANCY.md) | GPU 池化与云跨租户威胁模型 |
| [KUBETRAIL-PORT.md](KUBETRAIL-PORT.md) | KubeTrail 只读移植与许可说明 |

### 10.3 证据与验证

| 文档 | 内容 |
|---|---|
| [EFFECT-VERIFICATION.md](EFFECT-VERIFICATION.md) | 本机真实进程/HTTP 效果验证，当前落盘 53/53 PASS |
| [EXPLOIT-VERIFICATION.md](EXPLOIT-VERIFICATION.md) | 152 条可利用性核验：37 verified / 6 exposure-verified / 87 static-only / 22 unsupported |
| [SURFACE-REALISM.md](SURFACE-REALISM.md) | 256 模块 × 6 画像：production 覆盖、默认 PoC、无面/隔离清单 |
| [REAL-CLUSTER-VERIFICATION.md](REAL-CLUSTER-VERIFICATION.md) | QEMU k3s 真集群：6 模块、16 findings、hostNetwork 绕过 |
| [SCALE-RESULTS.md](SCALE-RESULTS.md) | 合成 100–10,000 对象曲线 + 真 k3s 204 对象点 |
| [TEE-VERIFICATION.md](TEE-VERIFICATION.md) | TDX/SEV-SNP/NVIDIA CC 的本地密码学校验与边界 |
| [KEYLESS-VERIFICATION.md](KEYLESS-VERIFICATION.md) | Sigstore keyless 验证：公共 Fulcio/Rekor 真实验证 + 本地 fixture |
| [SIX-CLOUD-MATRIX.md](SIX-CLOUD-MATRIX.md) | 六云契约级矩阵：24/24 两态 |
| [DEFENSE-BYPASS-PATH.md](DEFENSE-BYPASS-PATH.md) | 防护感知绕过执行路径：QEMU k3s 真机 Kyverno+Falco，6 技术 5 bypass-confirmed / 1 detected / 0 失败，无原语产品 `policy-refused` |
| [FILE-AUDIT.md](FILE-AUDIT.md) | 文件与操作审计：`audit-exec`/`read-file`/`list-files`、`file_ops`、`timeline.json`、报告台账与 SOC 审计键 |
| [PERFORMANCE-COMPARISON.md](PERFORMANCE-COMPARISON.md) | 冷启动、内存、API、吞吐、磁盘、同靶场 |
| [ARTEX-BENCH-RESULT.md](ARTEX-BENCH-RESULT.md) | ARTEX 同靶场 13,510ms vs 105.6ms 与边界 |
| [reports/samples/effects/](../reports/samples/effects/) | 效果验证原始 JSON/MD |
| [reports/samples/real-cluster/](../reports/samples/real-cluster/) | 真集群证据：cluster-info、snapshot、recon-findings、netpol-proof |
| [reports/samples/artex-bench/](../reports/samples/artex-bench/) | ARTEX 基准与同靶场对比 |
| [reports/samples/perf/grid/](../reports/samples/perf/grid/) | 全端点延迟与并发网格 |
| [reports/samples/scale/](../reports/samples/scale/) | 规模压测原始数据 |

### 10.4 Agent 运行时

| 文档/代码 | 内容 |
|---|---|
| [AGENT-ARCHITECTURE-2026.md](AGENT-ARCHITECTURE-2026.md) | 2026 agent 谱系、12 个落伍点、16 个设计点、蓝图 |
| [AGENT-ARCHITECTURE-UPGRADE-2026.md](AGENT-ARCHITECTURE-UPGRADE-2026.md) | 7 个核心模块、硬边界、组合用法 |
| [AGENT-EVAL-RESULTS.md](AGENT-EVAL-RESULTS.md) | 15 任务 deterministic vs supervisor-worker |
| [AGENT-AUTONOMY.md](AGENT-AUTONOMY.md) | 事件溯源运行时：EventLog/checkpoint/replay、PlanGraph 证据门控、调度器与四角色 worker、四维预算 |
| [AGENT-COVERAGE.md](AGENT-COVERAGE.md) | 覆盖图、四条闭包判据 + objective 门控、停止条件、跨集群中继 |
| [COVERAGE-CLOSURE.md](COVERAGE-CLOSURE.md) | 两集群闭包样例（4 资产 / 3 权限边 / 2 探针 / 0 缺口），由 `coverage-proof.json` 渲染 |
| [SECTION3-TENCENT-AGENT-CONTEST.md](SECTION3-TENCENT-AGENT-CONTEST.md) | 腾讯 8 项目、14 条反思、改进清单 |
| [SECTION3-METRICS.md](SECTION3-METRICS.md) | 8 任务 OFF/ON：成功率、时延、token、审批、干预、证据 |
| [journal.py](../inkblade/core/journal.py) | append-only 日志、哈希链、resume/replay |
| [supervisor.py](../inkblade/core/supervisor.py) | 持久队列、1–8 worker、重派、审批门 |
| [memory.py](../inkblade/core/memory.py) | working/episodic/semantic 三层记忆 |
| [skills.py](../inkblade/core/skills.py) | playbook 提取、版本、审批 |
| [reflexion.py](../inkblade/core/reflexion.py) | 零执行反思 |
| [a2a.py](../inkblade/core/a2a.py) | agent card、task 状态机、MCP 只读客户端 |
| [sandbox.py](../inkblade/core/sandbox.py) | 子进程、超时、禁网、审计 |
| [agent_policy.py](../inkblade/core/agent_policy.py) | L0–L3、阶段分解、重试分类 |
| [observation.py](../inkblade/core/observation.py) | 五段式观察、证据指针、去重、压缩 |
| [cost.py](../inkblade/core/cost.py) | 四维预算、超支降级 |
| [agentops.py](../inkblade/core/agentops.py) | 审批计划到技能提案的门面 |

### 10.5 竞品与矩阵

| 文档/数据 | 内容 |
|---|---|
| [COMPETITIVE-MATRIX.md](COMPETITIVE-MATRIX.md) | 23 工具 × 18 维度、33 项 backlog、来源登记 |
| [feature-matrix.json](feature-matrix.json) | 801 行逐功能矩阵（ARTEX 515 + KubeTrail 286） |
| [gap-matrix.json](gap-matrix.json) | 260 行缺口（功能 122 + 攻击面 82 + payload 56） |
| [FEATURE-BY-FEATURE-ARTEX.md](FEATURE-BY-FEATURE-ARTEX.md) | ARTEX 逐路由/表/组件枚举 |
| [FEATURE-BY-FEATURE-KUBETRAIL.md](FEATURE-BY-FEATURE-KUBETRAIL.md) | KubeTrail 逐采集器/规则/CLI 枚举 |
| [ARTEX-PARITY.md](ARTEX-PARITY.md) | 8 功能族、180 条 missing 处置、S/M 30/30 |
| [artex-parity-rows.json](artex-parity-rows.json) | 180 行机读处置 |
| [REFLECTION-ARTEX-KUBETRAIL.md](REFLECTION-ARTEX-KUBETRAIL.md) | ARTEX/KubeTrail 源码深潜与差距反思 |
| [REFLECTION-XBOW-ARTEX-KUBETRAIL.md](REFLECTION-XBOW-ARTEX-KUBETRAIL.md) | XBow/ARTEX/KubeTrail 产品能力面对标 |

### 10.6 测试与复现

| 测试/脚本 | 内容 |
|---|---|
| [tests/test_journal.py](../tests/test_journal.py) | 日志追加、崩溃恢复、篡改定位 |
| [tests/test_supervisor.py](../tests/test_supervisor.py) | 审批门、并发峰值、重派、队列恢复 |
| [tests/test_memory.py](../tests/test_memory.py) | 三层记忆检索、压缩、引用保留 |
| [tests/test_skills.py](../tests/test_skills.py) | 提取、审批、版本、越权拒绝 |
| [tests/test_reflexion.py](../tests/test_reflexion.py) | 失败归纳、零执行、技能提案 |
| [tests/test_a2a.py](../tests/test_a2a.py) | agent card、只读任务、写技能拒绝 |
| [tests/test_sandbox.py](../tests/test_sandbox.py) | 子进程、禁网、超时、审计 |
| [tests/test_agent_policy.py](../tests/test_agent_policy.py) | L0–L3、最弱链路、重试分类 |
| [tests/test_observation.py](../tests/test_observation.py) | 证据强制、去重、死胡同、压缩 |
| [tests/test_cost.py](../tests/test_cost.py) | 预算、降级、确定性 |
| [tests/test_tencent_compare.py](../tests/test_tencent_compare.py) | 8 任务阈值、护栏、接线 |
| [tests/test_agent_eval.py](../tests/test_agent_eval.py) | 15 任务评测结构与故障注入 |
| [lab/tencent-compare/run_eval.py](../lab/tencent-compare/run_eval.py) | OFF/ON 微评测生成器 |
| [lab/agent-eval/run_eval.py](../lab/agent-eval/run_eval.py) | deterministic vs supervisor 评测 |
| [inkblade/e2e-check.py](../inkblade/e2e-check.py) | 端到端验收 15/15 |
| [inkblade/verify-effects.py](../inkblade/verify-effects.py) | 效果验证 53 项 |
| [tests/test_docs_master.py](../tests/test_docs_master.py) | 本报告的结构与底线断言 |

### 10.7 复现命令

```bash
# 全量测试
python -m unittest discover -s tests -v

# 腾讯 8 任务微评测
python lab/tencent-compare/run_eval.py --write
python -m unittest tests.test_tencent_compare -v

# Agent 15 任务评测
python lab/agent-eval/run_eval.py --write
python -m unittest tests.test_agent_eval -v

# 效果验证
python -m inkblade.verify-effects --out reports/samples/effects/
python -m unittest tests.test_verify_effects -v

# 规模压测
python lab/bench/scale-bench.py run --scales 100,1000,5000,10000 \
  --out-md lab/bench/out/scale-bench.md

# 真集群（需 QEMU/k3s，按 REAL-CLUSTER-VERIFICATION.md 准备）
powershell -ExecutionPolicy Bypass -File lab/qemu-k3s/run-real-cluster-check.ps1

# 本报告结构测试
python -m unittest tests.test_docs_master -v
```

### 10.8 终版落盘状态

终版（2026-10-26）不再保留“进行中”文档；此前三项并行文档均已落盘并回填数字：

| 文档 | 对应章节 | 当前状态 |
|---|---|---|
| [FABRIC-SIM-RESULTS.md](FABRIC-SIM-RESULTS.md) | 7.1 万卡/fabric | 已落盘；1,024/10,000 节点仿真 + 真实模块裁决 |
| [SAAS-LOAD-RESULTS.md](SAAS-LOAD-RESULTS.md) | 7.5 SaaS 负载 | 已落盘；8 租户 × 8 并发、原子配额/审批 |
| [CLOUD-FREE-TIER-RUNBOOK.md](CLOUD-FREE-TIER-RUNBOOK.md) | 7.3 六云免费额度 | 已落盘；AWS/Azure/GCP mock + 阿里/腾讯试用边界 |

仍未达成项见 §7.7；未落盘不等于可引用，后续新增证据必须先落盘再改本表。

### 10.9 一句话总结

InkBlade 已经把“授权、侦察、组合、计划、审批、执行、证据、报告、规则、复测”串成一条可复跑的链；Agent 运行时补上了 journal、supervisor、memory、skills、reflexion、A2A、sandbox、policy、observation、cost；指标上，策略级任务 0.5→1.0、时延 -39%、token -26.7%、人工干预 4→0；竞品上，ML 面和证据面有差异化，规模、通用攻击面、payload 广度、平台化、真实战绩仍未超过。**能证明的写“已测”，只能仿真的写“模拟”，没有数据的写“未测”**——这句话比任何“最先进”都重要。

---

*本报告由 InkBlade 项目维护。数字以文中来源文件为准；发现不一致时，先改来源，再改本文。*

