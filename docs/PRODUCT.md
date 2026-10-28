# InkBlade 产品定义 / Product Definition

> 授权对象：训练与推理集群 · 执行面：Pod 内 Rust 探针 · 控制端：Python

## 1. 一句话

InkBlade 是一套面向训练与推理集群的授权渗透测试产品：在目标 Pod 内投放静态链接的 Rust 探针，用声明式模板完成检测、利用验证与证据采集，控制端只负责授权、编排、预算和报告。

**English.** InkBlade is an authorized testing product for training and inference clusters. A statically linked Rust probe runs inside the target Pod; declarative templates carry the checks. The Python controller never ships code into the Pod and never relies on a Python interpreter being present there.

## 2. 定位

通用 Kubernetes 扫描器回答的是“这个 namespace 是否特权、那个 API 是否匿名、镜像有没有 CVE”。这些问题成立，但训练集群的风险重心不在这里。

训练集群把 GPU、RDMA、权重、KV 缓存、集合通信、模型仓库、租户调度器拼成一个系统。单个组件看起来合规，组合起来仍可能把权重、显存残留或跨租户缓存暴露出去。InkBlade 的产品边界就是这些“只有 ML 集群才成立”的检测点，以及它们之间的组合。

三条产品原则：

1. **执行面在 Pod 内，不在控制端。** 控制端看不到目标 Pod 的 `/proc`、挂载、网卡、SA token 和 GPU 设备；把这些事实交给控制端猜测，误报和漏报都会升高。
2. **目标侧没有解释器。** 探针是唯一执行逻辑。模板是数据，不是脚本；目标 Pod 不需要 Python、Bash、curl、kubectl 才能跑检测。
3. **证据在探针边界产生。** 每个任务的结果、耗时、错误码、输出哈希和探针身份一起回传；控制端只做归档、关联和渲染。

## 3. 适用对象

| 对象 | 典型问题 | InkBlade 的交付 |
|---|---|---|
| ML 平台安全团队 | 多租户推理集群是否真的隔离；GPU 池化调度器是否绕过 RBAC | 按 10 层组织的检测结果、租户隔离证据、修复优先级 |
| 红队 / 攻防演练 | 拿到一个 Pod 后能走到哪；能否跨节点、跨租户、跨云身份 | 立足点→探针→通道→内部横向的完整链路和证据 |
| 合规与审计 | 准入策略、运行时检测、镜像扫描是否只是“部署了” | 防护产品的部署态、降级态、盲区与硬化建议 |
| 框架 / 推理网关研发 | 自家 vLLM、SGLang、LiteLLM 版本的默认面是否安全 | 版本相关的端点、鉴权、序列化与缓存检测 |
| 防守方（蓝队） | 现有 EDR、Falco、Kyverno、WAF 能不能看见这类行为 | 良性 marker 的两态验证、规则包反哺、覆盖缺口清单 |

不适用：未授权资产、互联网通用漏洞扫描、以持久化和横向控制为目的的 C2、对目标内核植入 rootkit、对第三方厂商产品做破坏性压测。

## 4. 十层检测点

前九层回答“训练集群哪里和普通 K8s 不一样”，第十层回答“防守方是否真的看得见”。模板键与模块键同名；一个模板就是一个可独立执行、独立验证、独立出证据的最小单元。

每一层按三件事描述：**能做什么**、**检测什么**、**产出什么**。

### 第 1 层：架构层

- **能做什么**：审计万卡拓扑与 rail 布线，验证 PD 分离通道与 IMEX 域边界，检查集合通信入组与长上下文 KV 生命周期，测绘多集群联邦信任。
- **检测什么**：rail/多平面错配、PD KV 通道无鉴权、跨节点 GPU 内存共享越界、EP 组默认信任、KV 驻留与逐出窗口、联邦身份与权重信任。
- **产出什么**：拓扑快照与 rail 映射、通道可达性与传输前后差异、域成员与权限快照、入组记录与时序偏差、驻留采样、联邦信任图。
- **代表模板**：`rail-mismatch-forcing`、`prefill-decode-kv-channel-unauth`、`nvlink-imex-isolation`、`imex-computedomain-gpu-memory-crossing`、`nccl-collective-join`、`nccl-straggler-injection`、`remote-kv-pool-isolation`、`multi-cluster-federation`。

### 第 2 层：产品 / 框架层

- **能做什么**：枚举推理框架、训练框架、推理网关与 Agent 平台的管理面，检查插件路由、开发模式、反序列化与权重导出路径。
- **检测什么**：vLLM 插件路由绕过与 RL 控制路由、SGLang 管理面 fail-open 与 ZMQ pickle、TRL 的 `vllm-serve` dev 模式、verl 的 `prime_math`/`prime_code`/`recv_pyobj`/HDFS 注入、AReaL 的 `/set_env`→`/create_engine`→`/call`、SkyRL 的 `Tinker` 控制面与权重拉取、OpenRLHF 的 `serve_rm`、slime 的 `pull_weights`、LLaMA-Factory 与 Megatron/DeepSpeed 的 checkpoint loader、ms-swift 的 `trust_remote_code`、transformers 的动态模块导入、LiteLLM/Higress/Envoy AI 的密钥与配置面、Dify/Open WebUI 的沙箱与默认密钥。
- **产出什么**：路由与鉴权矩阵、端点响应、loader 轨迹、执行 marker、写入文件哈希、配置差异、密钥作用域、缓存命中记录。
- **代表模板**：`vllm-plugin-auth-bypass`、`sglang-admin-failopen`、`verl-prime-code-exec`、`areal-setenv-engine-rce`、`skyrl-fetch-weights-traversal`、`openrlhf-serve-rm`、`slime-weight-pull-poison`、`llamafactory-checkpoint-rce`、`msswift-trust-remote-code`、`litellm-default-key-exfil`、`dify-local-sandbox-unauth-rce`。

### 第 3 层：组件 / Operator 层

- **能做什么**：检查训练与推理周边的控制面、设备管理、存储与带外管理。
- **检测什么**：Ray Dashboard 与 LWS leader 端点、GPU Operator 与驱动容器、DRA 设备策略与 MIG profile、CSI 节点插件、BMC/Redfish 默认凭据、IPMI cipher 0、DPU/SmartNIC offload 策略落点。
- **产出什么**：作业提交记录、Secret 差异、DaemonSet 与挂载审计、ResourceClaim 策略快照、卷挂载图、端点态势、凭据有效性、offload 清单。
- **代表模板**：`ray-dashboard-job`、`ray-control-plane`、`lws-leader-endpoint-audit`、`gpu-operator-driver-audit`、`gpu-operator-driver-escape`、`gpu-dra-mig-policy`、`csi-node-plugin-escape`、`redfish-default-credentials`、`ipmi-cipher-zero-bypass`、`dpu-ipu-offload`。

### 第 4 层：网络 / fabric 层

- **能做什么**：验证非标准接口上的策略旁路，测绘双 CNI 控制面、InfiniBand 与 RoCE 配置、在网聚合与集合通信 bootstrap。
- **检测什么**：hostNetwork/SR-IOV/macvlan 流量绕过策略钩子、VPC 路由与集群策略漂移、IB 子网管理器与分区、RoCE PFC/ECN 无损配置、SHARP 会话信任、NCCL 入组与 straggler、DNS 服务发现面。
- **产出什么**：接口清单、可达性证明、可达图与漂移清单、分区表与成员证明、PFC 计数与队列遥测、会话表与配置差异、入组记录与时序偏斜。
- **代表模板**：`multus-sriov-rdma-bypass`、`network-policy-coverage`、`vpc-cni-dual-control-plane-lateral`、`ib-sm-partition-audit`、`ib-subnet-manager-hijack`、`roce-pfc-storm`、`sharp-in-network-poison`、`nccl-collective-join`、`nccl-port-exhaustion`、`dns-service-discovery`。

### 第 5 层：数据 / 权重层

- **能做什么**：检查训练状态、数据集管道、模型缓存、权重存储与注册表的信任边界。
- **检测什么**：checkpoint 与优化器分片在加载时被信任、数据集 pickle 解析、共享 HF 缓存跨租户写入、权重桶的云 IAM、模型注册表暴露面、KV 与前缀缓存跨租户。
- **产出什么**：分片差异与 loader 轨迹、管道配置与加载结果、缓存写入路径与读回证明、对象 ACL 与拉取转录、签名链、缓存键作用域与命中样本。
- **代表模板**：`checkpoint-shard-poison`、`checkpoint-optimizer-state-poison`、`msswift-dataset-pickle-rce`、`cache-poison-persistence`、`shared-pvc-supply-chain-poison`、`skyrl-fetch-weights-traversal`、`sglang-weight-exfil`、`cloud-bucket-cross-tenant`、`model-registry-exposure`、`prefix-cache-cross-tenant-leak`。

### 第 6 层：租户 / 隔离层

- **能做什么**：度量 GPU 分区与池化调度器的隔离效果，检查缓存 salt 与路由指标。
- **检测什么**：MIG/MPS 残留显存与上下文、HAMi/cGPU 在 Kubernetes RBAC 之外的调度决策、`cache_salt` 缺失或按部署复用、Router/EPP 指标泄露队列与命中模式。
- **产出什么**：残留探测样本、profile 映射、调度器 API 态势、salt 配置与碰撞测试、指标抓取与推断结果。
- **代表模板**：`mig-profile-mismatch`、`mps-context-shared`、`gpu-tenant-residue`、`hami-scheduler-auth-gap`、`cgpu-isolation-audit`、`gpu-pool-scheduler-unauth`、`cache-salt-policy-audit`、`router-cache-metrics-leak`、`gpu-metrics-tenant-leak`。

### 第 7 层：供应链 / 身份层

- **能做什么**：核验模型代码信任、revision 固定、证明链、物料清单与云身份。
- **检测什么**：`trust_remote_code` 与自定义 modeling 文件在加载时执行、浮动 revision、TDX/SEV/NVIDIA CC 证明链、ML SBOM 缺失、IRSA/Workload Identity 通配、IMDS 可达性、Pod 内并存凭据。
- **产出什么**：导入轨迹与文件哈希、commit/revision 对照、证明链与策略断言、物料清单与缺失项、trust policy 图、IMDS 可达性与凭据作用域。
- **代表模板**：`trust-remote-code-supply-chain`、`msswift-trust-remote-code`、`supply-chain-pinning`、`gpu-cc-attestation-chain`、`confidential-containers-attestation`、`ml-bom-coverage`、`cloud-irsa-trust-wildcard`、`imds-credential-reachability`、`service-account-token-exposure`、`cloud-credential-in-pod`。

### 第 8 层：缓存安全层

- **能做什么**：测试推理缓存的租户隔离、命中边界与逐出行为，测量时序侧信道。
- **检测什么**：跨租户前缀缓存、近似/语义缓存误命中、逐出后残留、远程 KV 池命名空间、PD KV 通道、EPP 指标、TTFT 时序。
- **产出什么**：缓存键与命中样本、相似度分数与响应差异、逐出前后读取结果、池端点与租户标签、时序样本与统计偏差。
- **代表模板**：`prefix-cache-cross-tenant-leak`、`similarity-cache-false-hit`、`approx-cache-cross-tenant-chain`、`cache-eviction-residue`、`remote-kv-pool-isolation`、`pd-kv-poison`、`cache-timing-sidechannel`、`router-cache-metrics-leak`。

### 第 9 层：跨组合层

- **能做什么**：把只在组合下成立的发现装配成一条链，标注前置条件并去重。
- **检测什么**：插件鉴权 + 权重导出、IMEX + ComputeDomain + GPU 内存、长上下文 + 前缀缓存、GPU 租户残留 + 节点逃逸、网络旁路 + 控制面、云身份 + 权重桶。
- **产出什么**：组合链、两步或多步证据锚、前置条件、修复顺序。
- **代表组合**：`vllm-plugin-auth-bypass` + `sglang-weight-exfil`、`imex-computedomain-gpu-memory-crossing`、`long-context-cache-leak`、`gpu-tenant-residue-chain`、`multus-sriov-rdma-bypass` + `ray-control-plane`、`ssrf-sa-token-cloud-metadata` + `aws-role-weight-bucket`。

组合层只有一条计数规则：两个组件同时成立才算问题的，只报一次，报在组合上；不拆成两条低危重复项。

### 第 10 层：防护绕过与检测对抗

- **能做什么**：在授权环境中用良性 marker 验证防守方是否看得见这类行为，并把盲区转成规则、配置与回归用例。
- **检测什么**：HIDS agent/driver 指纹与规则盲区、运行时策略降级、准入豁免与 mutation 顺序、镜像扫描分层与改名、主机代理离线窗口、推理面 WAF 归一化、网络可视化采样缺口。
- **产出什么**：每个技术类别的 **检测（detected）**、**盲区（blind spot）**、**硬化建议（hardening）**，以及可直接加载的规则包。

| 产品 / 模块键 | 检测（部署态可见） | 盲区（动态验证重点） | 硬化建议 | 规则包反哺 |
|---|---|---|---|---|
| Elkeid HIDS / `defense-bypass-elkeid` | 敏感路径访问、受监控路径写入 | 白名单路径、工具改名、编码命令变体、ephemeral 容器 | 保留敏感路径/写入规则；白名单目录二次研判；改名执行启发式；补 ephemeral 事件宏 | Sigma（进程/文件）、Falco（路径/容器） |
| AgentSmith-HIDS / `defense-bypass-agentsmith` | 受监控路径写入 | 白名单路径、改名执行、良性 DNS 查询 | file-create kprobe 入规则链；execve 改名启发式；DNS hook 入规则 | Sigma（文件/进程/DNS） |
| veinmind 容器扫描 / `defense-bypass-veinmind` | 常规分层样本 | 深层覆盖、改名工具层、压缩样本、白名单样本名 | 全层解析；层内内容/哈希匹配；压缩解包递归；收窄排除清单 | Trivy/grype 配置、CI 扫描门 |
| Falco / `defense-bypass-falco` | 敏感路径访问、受监控路径写入 | 无 driver 降级、规则语法缺口、ephemeral 容器、改名执行 | 规则加载校验；ephemeral 宏；spawned_process 改名启发式；driver 健康检查 | Falco 规则、Sigma 转译 |
| Tetragon / eBPF / `defense-bypass-tetragon` | LSM 钩子路径、exec 事件 | 策略未挂载命名空间、hostNetwork、短生命周期进程 | TracingPolicy 命名空间全覆盖；hostNetwork 工作负载策略；exec 改名匹配 | Tetragon TracingPolicy、Falco |
| KubeArmor / `defense-bypass-kubearmor` | posture 已覆盖路径 | 未覆盖命名空间、hostNetwork、默认放行 | 默认兜底策略；未打 posture 注解视为拒绝；KubeArmorHostPolicy 覆盖 hostNetwork | KubeArmorPolicy、Kyverno 门 |
| Kyverno / Gatekeeper / `defense-bypass-admission` | 已 enforce 策略路径 | 豁免命名空间、Audit 模式、注解绕过、mutation 顺序、子资源缺口 | 豁免清单最小化；Audit 仅限过渡期；清除绕过注解；mutate→validate 顺序审计；子资源策略 | Kyverno 策略、Gatekeeper ConstraintTemplate |
| Trivy / grype 镜像扫描 / `defense-bypass-imagescan` | 常规分层样本 | 深层覆盖、改名工具、白名单样本名、压缩样本 | 深层/被覆盖文件内容匹配；按内容/哈希识别改名；收窄排除；压缩递归 | Trivy/grype 配置、CI 门 |
| Wazuh / Osquery / `defense-bypass-hostagent` | 受监控路径写入 | 规则集覆盖缺口、agent 停用窗口、改名执行 | 监控目录覆盖 `/tmp`、`/dev/shm`；离线即告警；命令审计改名启发式 | Sigma、Wazuh 规则、Osquery 表 |
| ModSecurity / Coraza / 雷池 / `defense-bypass-waf-inference` | 明文良性请求 | 编码、分块、Unicode、超长请求变体 | URL/hex 解码后再匹配；反分块缓冲；Unicode 规范化；超长直接拒绝 | Suricata、CRS/WAF 规则 |
| Cilium Hubble / Calico flows / `defense-bypass-netobserv` | 常规 Pod 路径流 | hostNetwork、多网卡、短生命周期流 | hostNetwork 纳入采集；SR-IOV/RDMA 接口纳入；缩短采样窗口 | Hubble/Calico 采集配置、流验证用例 |

规则包反哺关系：

| 盲区类型 | 反哺目标 | 产物 |
|---|---|---|
| 准入豁免、Audit、mutation 顺序、子资源 | Kyverno / Gatekeeper | `rules generate` 生成策略与测试用例 |
| 进程、文件、DNS、改名执行 | Sigma（转 Falco/Wazuh/Elkeid） | `rules generate` 生成 Sigma 规则与字段映射 |
| 运行时 syscall、容器逃逸、敏感路径 | Falco / Tetragon | `rules generate` 生成 Falco 规则与 Tetragon TracingPolicy 建议 |
| 编码、分块、Unicode、超长请求 | Suricata / WAF | `rules generate` 生成 Suricata 规则与 WAF 归一化建议 |
| hostNetwork、多网卡、短流 | Hubble / Calico | 采集配置建议与流验证用例 |

第 10 层使用良性 marker、只读探测或授权 scratch 内的写入，覆盖 HIDS、运行时 eBPF、准入、镜像扫描、主机代理、WAF 与网络可视化，输出检测结果、盲区与规则/配置建议。

## 5. 产品框架

```
授权与范围
   │
   ├─ Session：入口方式（foothold/external，kubeconfig 可选）、目标、时间窗、级别、证据目录
   │
   ├─ Probe：Rust 静态二进制，Pod 内唯一执行体
   │     ├─ 采集快照（身份/挂载/网络/SA/GPU）
   │     ├─ 执行模板（http/tcp/exec/fs/k8s/socks/spawn）
   │     └─ 投放子探针（父子树）
   │
   ├─ Agent：目标图、预算、决策轨迹、恢复与回放
   │
   ├─ Evidence：任务结果 + 步骤归档 + manifest
   │
   └─ Report / Rules / Console：双语报告 + 规则包 + 可视化
```

控制端是 Python，但控制端不在目标 Pod 内执行任何逻辑。它做四件事：授权校验、模板选择与参数渲染、预算与超时、证据归档与报告。目标 Pod 内没有 Python、没有模块代码、没有 `run.py`。

### 5.1 三种入口

| 入口 | 使用前提 | kubeconfig |
|---|---|---|
| `foothold` | 默认：普通/最低权限 Pod（非 root、无 hostPath/privileged、无 kubeconfig、仅出站 TCP），已有 Pod shell、ServiceAccount token 或授权 RCE | 不需要 |
| `external` | 目标可达；先提交有界可达性/版本/路由证明，再经授权 RCE 或回调投放探针 | 不需要 |
| `kubeconfig` | 持有运维 kubeconfig，需要一次给多个 Pod 做首次批量 bootstrap | 可选 |

探针优先：默认立足点是普通、最低权限的 Pod（非 root、无 hostPath/privileged、无 kubeconfig，仅出站 TCP）。已有探针用 `probe list` 发现在册探针，控制端 `channel listen`，Pod 内探针 `reverse` 主动回连；存在本地命令通道时也可用 `channel start` 的 stdio 通道。首次投放用 `session open --mode foothold` 与 `probe deploy --via rce|sa-token`。探针就绪后，检测、逃逸、横向、子探针（`upload` + `spawn` 后回连）与跨集群都经探针通道，不再依赖 kubeconfig。

## 6. 与“通用扫描器 + 主机 Agent”的区别

| 维度 | 通用 K8s 扫描器 | 主机 Agent / HIDS | InkBlade |
|---|---|---|---|
| 执行位置 | 控制端调用 API | 节点常驻 | 目标 Pod 内一次性探针 |
| 目标依赖 | kubectl / API | 预装 agent、内核模块 | 无解释器；一个静态二进制 |
| 检测对象 | 配置与镜像 | 主机行为 | ML 组件、租户、缓存、fabric、防护产品 |
| 证据 | 配置快照 | 告警流 | 任务级结果 + 探针身份 + 哈希清单 |
| 组合能力 | 弱 | 弱 | 跨层组合签名 |
| 防护对抗 | 无 | 自身即防守方 | 以良性 marker 验证防守方盲区 |

## 7. 交付物

- 一份双语报告：PTES 叙事 + 修复清单，发现带证据锚。
- 一份探针树：每个探针的 id、parent_id、目标、权限、任务数、清理状态。
- 一份覆盖矩阵：模板 × 层 × 部署画像，说明哪些节点可测、哪些不可达。
- 一份规则包：准入、运行时、网络三类，附重放结果（拦截 / 检出 / 漏过）。
- 一份覆盖证明：跨集群目标图里已闭合与不可达的节点。

## 8. English summary

InkBlade is a probe-centric testing product for ML clusters. The target-side runtime is a single static Rust binary; templates are data. The controller is Python but stays outside the target and never ships code into it. The product is organized around ten layers: architecture, framework, operator, fabric, data/weights, tenant isolation, supply chain/identity, cache, cross-component combinations, and defense bypass.

Eleven `defense-bypass-*` modules measure whether Elkeid, AgentSmith, veinmind, Falco, Tetragon, KubeArmor, Kyverno/Gatekeeper, Trivy/grype, Wazuh/Osquery, ModSecurity/Coraza/SafeLine, and Hubble/Calico actually see benign, authorized activity. Each module returns detected techniques, blind spots, and hardening advice, and feeds Kyverno, Sigma, Falco, and Suricata rule packs.
