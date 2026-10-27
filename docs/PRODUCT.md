# InkBlade 产品定义 / Product Definition

> 版本：2026-10-27 · 架构：Pod 内 Rust 探针 · 授权对象：训练与推理集群
> 本文是产品口径，不是功能许愿单。已实现、迁移中、未覆盖，分别标注。

## 1. 一句话

InkBlade 是一套面向训练与推理集群的授权渗透测试产品：在目标 Pod 内投放一个静态链接的 Rust 探针，用声明式模板完成检测、利用验证与证据采集，控制端只负责授权、编排、预算和报告。

**English.** InkBlade is an authorized testing product for training and inference clusters. A statically linked Rust probe runs inside the target Pod; declarative templates carry the checks. The Python controller never ships code into the Pod and never relies on a Python interpreter being present there.

## 2. 定位

通用 Kubernetes 扫描器回答的是“这个 namespace 是否特权、那个 API 是否匿名、镜像有没有 CVE”。这些问题成立，但训练集群的风险重心不在这里。

训练集群把 GPU、RDMA、权重、KV 缓存、集合通信、模型仓库、租户调度器拼成一个系统。单个组件看起来合规，组合起来仍然可能把权重、显存残留或跨租户缓存暴露出去。InkBlade 的产品边界就是这些“只有 ML 集群才成立”的检测点，以及它们之间的组合。

三条产品原则：

1. **执行面在 Pod 内，不在控制端。** 控制端看不到目标 Pod 的 `/proc`、挂载、网卡、SA token 和 GPU 设备；把这些事实交给控制端猜测，误报和漏报都会升高。
2. **目标侧没有解释器。** 探针是唯一执行逻辑。模板是数据，不是脚本；目标 Pod 不需要 Python、Bash、curl、kubectl 才能跑检测。
3. **证据在探针边界产生。** 每个任务的结果、耗时、错误码、输出哈希和探针身份一起回传；控制端只做归档、关联和渲染，不补写“应该看到什么”。

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

### 第 1 层：架构层

| 检测点 | 为何训练推理集群独有 | 模块/模板键 | 证据产出 |
|---|---|---|---|
| Rail / 多平面错配 | GPU 与网卡按 rail 布线，错配会把集合通信静默挤到错误平面 | `rail-mismatch-forcing`、`fabric-topology-isolation` | 拓扑快照、rail 映射、错配项 |
| PD 分离 KV 通道 | prefill 与 decode 分节点传输 KV block，通道常无鉴权 | `prefill-decode-kv-channel-unauth`、`pd-kv-poison` | 通道可达性、传输前后 block 差异 |
| IMEX / ComputeDomain | 跨节点 GPU 内存共享是设计能力，不走进程边界 | `nvlink-imex-isolation`、`imex-computedomain-gpu-memory-crossing` | 域成员、权限快照、跨域访问记录 |
| MoE / EP 集合通信 | 加入 EP 组默认信任，专家分片可被替换 | `nccl-collective-join`、`nccl-straggler-injection` | 入组记录、梯度/时序偏差 |
| 长上下文 KV 生命周期 | 上下文越长，KV 驻留越久，逐出策略决定泄露窗口 | `remote-kv-pool-isolation`、`kv-oom-bomb`、`cache-eviction-residue` | 驻留采样、逐出残留 |
| 多集群联邦 | 联邦在集群边界之外信任身份与权重 | `multi-cluster-federation`、`federated-learning-surface` | 联邦信任图、跨集群主体 |

### 第 2 层：产品 / 框架层

| 检测点 | 为何训练推理集群独有 | 模块/模板键 | 证据产出 |
|---|---|---|---|
| vLLM 插件路由 | 插件路由可能挂在 `--api-key` 之外；RL 控制面直接挂在 `/` | `vllm-plugin-auth-bypass`、`vllm-pickle-pipe-rce`、`vllm-timing-oracle` | 路由/鉴权矩阵、dev 端点响应、TTFT 采样 |
| SGLang 管理面 | 管理依赖 fail-open；profiler 的 `event_dir` 可写；ZMQ 反序列化 | `sglang-admin-failopen`、`sglang-omni-profiler-write`、`sglang-zmq-pickle-rce` | 端点响应、写入文件哈希、导出轨迹 |
| 训练框架控制面 | verl、AReaL、SkyRL、OpenRLHF 各自有“开发模式”和代码执行入口 | `verl-prime-code-exec`、`areal-setenv-engine-rce`、`skyrl-dev-pickle-rce`、`openrlhf-serve-rm` | 控制面转录、执行 marker、环境清单 |
| 模型仓库加载 | `trust_remote_code` 与未固定 revision 把仓库变成代码供应链 | `trust-remote-code-supply-chain`、`msswift-trust-remote-code` | 导入轨迹、revision 差异、签名状态 |
| 推理网关 | 网关持有上游 key、租户路由和缓存，鉴权失败会放大到所有模型 | `litellm-default-key-exfil`、`litellm-config-update-rce`、`aigateway-upstream-key-exfil` | 配置差异、key 作用域、缓存命中记录 |
| Agent 平台 | Dify、Open WebUI 的沙箱、默认 JWE key、跨租户快照是独立控制面 | `dify-local-sandbox-unauth-rce`、`dify-stub-token-forgery`、`open-webui-code-execute-rce` | 沙箱探测、伪造令牌、快照读取 |

### 第 3 层：组件 / Operator 层

| 检测点 | 为何训练推理集群独有 | 模块/模板键 | 证据产出 |
|---|---|---|---|
| Ray / LWS 控制面 | Dashboard 与 leader 端点在训练负载旁边直接接活 | `ray-dashboard-job`、`ray-control-plane`、`lws-leader-endpoint-audit` | 作业提交记录、Secret 差异 |
| GPU Operator / 驱动 | 驱动容器与 device plugin 在每个 GPU 节点上以高权限运行 | `gpu-operator-driver-audit`、`gpu-operator-driver-escape` | DaemonSet/挂载审计、容器逃逸路径 |
| DRA | 设备请求开始携带策略，包括 MIG profile | `gpu-dra-mig-policy` | ResourceClaim 策略快照 |
| CSI | 权重与 checkpoint 落在 Ceph、JuiceFS 等卷上 | `csi-node-plugin-escape`、`storage-protocol-csi` | 卷挂载图、节点插件权限 |
| BMC / Redfish | 节点管理是独立平面，凭据与 K8s 完全分离 | `bmc-ipmi-exposure`、`redfish-default-credentials`、`ipmi-cipher-zero-bypass` | 端点态势、凭据有效性、cipher 套件 |
| DPU / SmartNIC | 卸载把策略执行移到不受集群 RBAC 管理的硬件 | `dpu-ipu-offload`、`dpu-smartnic-surface` | 卸载清单、策略落点 |

### 第 4 层：网络 / fabric 层

| 检测点 | 为何训练推理集群独有 | 模块/模板键 | 证据产出 |
|---|---|---|---|
| NetworkPolicy 旁路 | hostNetwork、SR-IOV、macvlan 流量不经过常规策略钩子 | `multus-sriov-rdma-bypass`、`network-policy-coverage` | 接口清单、可达性证明 |
| CNI 双控制面 | 托管云把 VPC 路由与集群策略分成两套系统，天然漂移 | `cni-stack-capability`、`cni-aware-reachability-graph`、`vpc-cni-dual-control-plane-lateral` | 可达图、策略漂移清单 |
| IB SM / 分区 | 子网管理器是 K8s 之外的信任域 | `ib-sm-partition-audit`、`ib-subnet-manager-hijack`、`ib-rdma-collective-injection` | 分区表、成员证明 |
| RoCE PFC / ECN | 无损配置是全局的，一个坏队列能拖停整片 fabric | `roce-pfc-storm`、`fabric-telemetry-exposure` | PFC 计数器、队列遥测 |
| SHARP 聚合 | 聚合发生在交换机内，绕过主机策略 | `sharp-collective-config`、`sharp-in-network-poison`、`sharp-session-trust-audit` | 会话表、配置差异 |
| NCCL bootstrap | 集合通信 bootstrap 默认不认证 | `nccl-collective-join`、`nccl-straggler-injection`、`nccl-port-exhaustion` | 入组记录、时序偏斜 |

### 第 5 层：数据 / 权重层

| 检测点 | 为何训练推理集群独有 | 模块/模板键 | 证据产出 |
|---|---|---|---|
| checkpoint / 优化器分片 | 训练状态巨大、可写，并在加载时被信任 | `checkpoint-shard-poison`、`checkpoint-optimizer-state-poison`、`flat-network-admin-plane-weight-poison` | 分片差异、loader 轨迹 |
| 数据集管道 | webdataset、Arrow、pickle 解析与代码执行相邻 | `msswift-dataset-pickle-rce` | 管道配置、加载结果 |
| HF 缓存 | 一个租户写、另一个租户读，缓存是共享写面 | `cache-poison-persistence`、`shared-pvc-supply-chain-poison` | 写入路径、回读证明 |
| 权重存储 | 权重桶是云对象，权限由云 IAM 决定 | `skyrl-fetch-weights-traversal`、`sglang-weight-exfil`、`cloud-bucket-cross-tenant` | 对象 ACL、拉取转录 |
| 模型注册表 | 注册表是部署前最后一道信任门 | `model-registry-exposure`、`data-provenance-audit` | 暴露面、签名链 |
| KV / 前缀缓存 | 推理状态是数据，而且跨租户 | `prefix-cache-cross-tenant-leak`、`similarity-cache-false-hit`、`remote-kv-pool-isolation` | 缓存键作用域、命中样本 |

### 第 6 层：租户 / 隔离层

| 检测点 | 为何训练推理集群独有 | 模块/模板键 | 证据产出 |
|---|---|---|---|
| MIG / MPS 残留 | 分区不等于清零，显存与上下文可能存活 | `mig-profile-mismatch`、`mps-context-shared`、`gpu-tenant-residue` | 残留探针、profile 映射 |
| GPU 池化调度器 | HAMi、cGPU 在 K8s RBAC 之外做隔离决策 | `hami-scheduler-auth-gap`、`cgpu-isolation-audit`、`gpu-pool-scheduler-unauth` | 调度器 API 态势 |
| `cache_salt` | 每租户 salt 是缓存条目之间唯一的隔离物 | `cache-salt-policy-audit`、`approx-cache-cross-tenant-chain` | salt 配置、碰撞测试 |
| 路由指标泄露 | Router/EPP 指标暴露队列深度与缓存命中模式 | `router-cache-metrics-leak`、`gpu-metrics-tenant-leak` | 指标抓取、推断结果 |

### 第 7 层：供应链 / 身份层

| 检测点 | 为何训练推理集群独有 | 模块/模板键 | 证据产出 |
|---|---|---|---|
| 模型代码信任 | `trust_remote_code` 与自定义 modeling 文件在加载时执行 | `trust-remote-code-supply-chain`、`msswift-trust-remote-code` | 导入轨迹、文件哈希 |
| Revision 固定 | 同一 tag 可漂移，权重与代码不同源 | `model-revision-pinning`、`data-provenance-audit` | commit/revision 对照 |
| 签名与证明 | GPU CC、TEE、Sigstore 的信任链不统一 | `gpu-cc-attestation-chain`、`tee-attestation-policy`、`sigstore-keyless-verify` | 证明链、策略断言 |
| SBOM / AI-BOM | 推理镜像包含框架、CUDA、模型三层物料 | `ml-bom-coverage`、`image-sbom-provenance` | 物料清单、缺失项 |
| 云身份 | IRSA、Workload Identity、CAM 的 trust policy 常被放宽 | `cloud-irsa-trust-wildcard`、`imds-credential-reachability` | trust policy、IMDS 可达性 |
| 凭据暴露 | Pod 内 SA token、云凭据、Hugging Face token 并存 | `service-account-token-exposure`、`cloud-credential-in-pod` | 凭据位置、哈希、作用域 |

### 第 8 层：缓存安全层

| 检测点 | 为何训练推理集群独有 | 模块/模板键 | 证据产出 |
|---|---|---|---|
| 跨租户前缀缓存 | 前缀缓存按 token 复用，不按租户隔离 | `prefix-cache-cross-tenant-leak` | 缓存键、命中样本、租户边界 |
| 近似 / 语义缓存误命中 | 相似度阈值把不同请求合并 | `similarity-cache-false-hit`、`approx-cache-cross-tenant-chain` | 相似度分数、响应差异 |
| 逐出残留 | 逐出只释放索引，块可能仍可读 | `cache-eviction-residue` | 逐出前后读取结果 |
| 远程 KV 池 | KV 池独立于推理进程，鉴权常缺失 | `remote-kv-pool-isolation`、`pd-kv-poison` | 池端点、租户标签 |
| EPP 指标 / TTFT | 时序与队列指标可以反推其他租户的负载与缓存 | `cache-timing-sidechannel`、`router-cache-metrics-leak` | 时序样本、统计偏差 |

### 第 9 层：跨组合层

| 检测点 | 为何训练推理集群独有 | 模块/模板键 | 证据产出 |
|---|---|---|---|
| 插件鉴权 + 权重导出 | 单看路由或单看权重都不成立，组合才成立 | `vllm-plugin-auth-bypass` + `sglang-weight-exfil` | 组合链、两步证据锚 |
| IMEX + ComputeDomain + GPU 内存 | 跨节点内存共享越过进程与租户边界 | `imex-computedomain-gpu-memory-crossing` | 域成员、跨域访问 |
| 长上下文 + 前缀缓存 | 长窗口放大驻留，缓存复用放大泄露 | `long-context-cache-leak` | 驻留时间线、缓存命中 |
| GPU 租户 + 节点逃逸 | 残留与特权容器组合后从租户走到节点 | `gpu-tenant-residue-chain`、`gpu-network-operator-host-escape` | 残留样本、节点权限 |
| 网络旁路 + 控制面 | 多网卡绕过策略后直达 K8s 或 Ray 控制面 | `multus-sriov-rdma-bypass` + `ray-control-plane` | 可达路径、控制面响应 |
| 云身份 + 权重桶 | Pod 身份链到云角色，再链到权重对象 | `ssrf-sa-token-cloud-metadata`、`aws-role-weight-bucket` | 身份链、对象 ACL |

组合层只有一条计数规则：两个组件同时成立才算问题的，只报一次，报在组合上；不拆成两条低危重复项。

### 第 10 层：防护绕过与检测对抗

这一层是产品功能，不是附加演示。按目标架构，11 个 `defense-bypass-*` 模块全部走 Rust 探针模板执行，只使用良性 marker、只读探测或授权 scratch 内的写入，不携带恶意载荷、不做持久化、不关闭安全产品。迁移完成前，评估逻辑仍是 Python 参考实现，见第 8 节状态表。

| 检测点 | 为何训练推理集群独有 | 模块/模板键 | 证据产出 |
|---|---|---|---|
| HIDS agent/driver 指纹与规则盲区 | GPU 节点常同时装 Elkeid、AgentSmith 与容器扫描器，规则集与内核模块版本不一致 | `defense-bypass-elkeid`、`defense-bypass-agentsmith`、`defense-bypass-veinmind` | 部署态、driver 状态、良性 marker 是否命中、盲区清单 |
| 运行时策略降级 | Falco 无 driver、Tetragon 策略未挂载、KubeArmor 未覆盖命名空间时，界面仍显示“已部署” | `defense-bypass-falco`、`defense-bypass-tetragon`、`defense-bypass-kubearmor` | 降级证据、未覆盖工作负载、策略差异 |
| 准入策略豁免与顺序 | Kyverno/Gatekeeper 的豁免、Audit 模式、mutation 顺序和子资源缺口 | `defense-bypass-admission` | 豁免清单、Audit 命中、子资源提交结果 |
| 镜像扫描盲区 | 分层覆盖、改名工具、压缩样本、白名单样本名 | `defense-bypass-imagescan`、`defense-bypass-veinmind` | 分层检出率、改名/压缩样本结果 |
| 主机代理盲区 | Wazuh/Osquery agent 离线、规则集缺口、改名执行 | `defense-bypass-hostagent` | 在线状态、规则覆盖、执行可见性 |
| 推理面 WAF 变体 | ModSecurity/Coraza/雷池对编码、分块、Unicode、超长请求的归一化差异 | `defense-bypass-waf-inference` | 明文/变体请求的拦截差异 |
| 网络可视化旁路 | Hubble/Calico flows 对 hostNetwork、多网卡、短生命周期流的采样缺口 | `defense-bypass-netobserv` | 流可见性、采样窗口、盲区路径 |

逐项输出（11 个模块）：

| 产品 / 模块键 | 检测（deployed 态可见） | 盲区（动态验证重点） | 硬化建议 | 规则包反哺 |
|---|---|---|---|---|
| Elkeid HIDS / `defense-bypass-elkeid` | 敏感路径访问、受监控路径写入 | 白名单路径、工具改名、编码命令变体、ephemeral 容器 | 保留敏感路径/写入规则；白名单目录二次研判；改名执行启发式；补 ephemeral 事件宏 | Sigma（进程/文件）、Falco（路径/容器） |
| AgentSmith-HIDS / `defense-bypass-agentsmith` | 受监控路径写入 | 白名单路径、改名执行、良性 DNS 查询 | file-create kprobe 入规则链；execve 改名启发式；DNS hook 入规则 | Sigma（文件/进程/DNS） |
| veinmind 容器扫描 / `defense-bypass-veinmind` | 常规分层样本 | 深层覆盖、改名工具层、压缩样本、白名单样本名 | 全层解析；层内内容/哈希匹配；压缩解包递归；收窄排除清单 | Trivy/grype 配置、CI 扫描门 |
| Falco / `defense-bypass-falco` | 敏感路径访问、受监控路径写入 | 无 driver 降级、规则语法缺口、ephemeral 容器、改名执行 | 规则加载校验；ephemeral 宏；spawned_process 改名启发式；driver 健康检查 | Falco 规则、Sigma 转译 |
| Tetragon / eBPF / `defense-bypass-tetragon` | LSM 钩子路径、exec 事件 | 策略未挂载命名空间、hostNetwork、短生命周期进程 | TracingPolicy 命名空间全覆盖；hostNetwork 工作负载策略；exec 改名匹配 | Tetragon TracingPolicy、Falco |
| KubeArmor / `defense-bypass-kubearmor` | posture 已覆盖路径 | 未覆盖命名空间、hostNetwork、默认放行 | 默认兜底策略；未打 posture 注解视为 block；KubeArmorHostPolicy 覆盖 hostNetwork | KubeArmorPolicy、Kyverno 门 |
| Kyverno / Gatekeeper / `defense-bypass-admission` | 已 enforce 策略路径 | 豁免命名空间、Audit 模式、注解绕过、mutation 顺序、子资源缺口 | 豁免清单最小化；Audit 仅迁移期；清除绕过注解；mutate→validate 顺序审计；子资源策略 | Kyverno 策略、Gatekeeper ConstraintTemplate |
| Trivy / grype 镜像扫描 / `defense-bypass-imagescan` | 常规分层样本 | 深层覆盖、改名工具、白名单样本名、压缩样本 | 深层/被覆盖文件内容匹配；按内容/哈希识别改名；收窄排除；压缩递归 | Trivy/grype 配置、CI 门 |
| Wazuh / Osquery / `defense-bypass-hostagent` | 受监控路径写入 | 规则集覆盖缺口、agent 停用窗口、改名执行 | 监控目录覆盖 `/tmp`、`/dev/shm`；离线即告警；命令审计改名启发式 | Sigma、Wazuh 规则、Osquery 表 |
| ModSecurity / Coraza / 雷池 / `defense-bypass-waf-inference` | 明文良性请求 | 编码、分块、Unicode、超长请求变体 | URL/hex 解码后再匹配；反分块缓冲；Unicode 规范化；超长直接拒绝 | Suricata、CRS/WAF 规则 |
| Cilium Hubble / Calico flows / `defense-bypass-netobserv` | 常规 Pod 路径流 | hostNetwork、多网卡、短生命周期流 | hostNetwork 纳入采集；SR-IOV/RDMA 接口纳入；缩短采样窗口 | Hubble/Calico 采集配置、流验证用例 |

每个模块固定输出三类结果，缺一类即视为未完成：

1. **检测（detected）**：在 deployed/degraded/absent 三态下，哪些技术类别被现有规则看见。
2. **盲区（blind spots）**：哪些类别在动态验证中没有产生告警，原因是什么（driver 未加载、规则未覆盖、采样窗口过短、编码未归一化等）。
3. **硬化建议（hardening）**：可直接落地的规则、配置或策略修改；附产品、技术类别、状态和优先级。

规则包反哺关系：

| 盲区类型 | 反哺目标 | 产物 |
|---|---|---|
| 准入豁免、Audit、mutation 顺序、子资源 | Kyverno / Gatekeeper | `rules generate --pack admission` 生成策略与测试用例 |
| 进程、文件、DNS、改名执行 | Sigma（转 Falco/Wazuh/Elkeid） | `rules generate --pack runtime` 生成 Sigma 规则与字段映射 |
| 运行时 syscall、容器逃逸、敏感路径 | Falco / Tetragon | `rules generate --pack runtime` 生成 Falco 规则与 Tetragon TracingPolicy 建议 |
| 编码、分块、Unicode、超长请求 | Suricata / WAF | `rules generate --pack network` 生成 Suricata 规则与 WAF 归一化建议 |
| hostNetwork、多网卡、短流 | Hubble / Calico | 采集配置建议与流验证用例 |

防守方拿到的不是“你被绕过了”这句话，而是可复现的盲区、对应规则和回归用例。

## 5. 产品框架

```
授权与范围
   │
   ├─ Session：目标、时间窗、级别、证据目录
   │
   ├─ Probe：Rust 静态二进制，Pod 内唯一执行体
   │     ├─ 采集快照（身份/挂载/网络/SA/GPU）
   │     ├─ 执行模板（http/tcp/exec/fs/k8s/socks/spawn）
   │     └─ 投放子探针（父子树）
   │
   ├─ Evidence：任务结果 + 步骤归档 + manifest
   │
   └─ Report / Rules：双语报告 + 规则包 + 覆盖矩阵
```

控制端是 Python，但控制端不在目标 Pod 内执行任何逻辑。它做四件事：授权校验、模板选择与参数渲染、预算与超时、证据归档与报告。目标 Pod 内没有 Python、没有模块代码、没有 `run.py`。

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
- 一份覆盖矩阵：模板 × 层 × 部署画像 × 动态验证状态。
- 一份规则包：准入、运行时、网络三类，附重放结果（拦截/检出/漏过）。
- 一份限制清单：未覆盖的版本、需要特权的检测点、无法在 mock 靶场复现的行为。

## 8. 成熟度与状态

| 能力 | 状态 | 说明 |
|---|---|---|
| Rust 探针运行时（http/tcp/exec/fs/k8s/socks/spawn） | 主体已实现 | `probe/` 下 op、模板解释器、协议服务与 CLI 已落地；发布校验与边界行为收尾中 |
| 声明式模板注册表 | 已切换，收尾中 | 287 个模块目录中 286 个 `template.json` + 1 个 bootstrap；迁移窗口内仍有旧 `run.py`，发布前删除 |
| Pod 内零 Python | 已成立 | 探针不依赖 Python；bootstrap 只在控制端投放 Rust 二进制，不进入目标执行逻辑 |
| 10 层检测点 | 已定义 | 前 9 层沿用既有覆盖；第 10 层 11 个模块已实现评估逻辑 |
| 全量动态验证 | 已成立 | 286/286 模板在 Rust 探针上跑完两态，每态 3 次一致、0 失败（`c8d2f118…` / `1f0f57c`）；负控边界见 `docs/PROBE-COVERAGE.md` §6 |
| 报告 / 规则包 | 已成立 | 双语报告、SARIF/OCSF/VEX 导出、规则重放 |

## 9. English summary

InkBlade is a probe-centric testing product for ML clusters. The target-side runtime is a single static Rust binary; templates are data. The controller is Python but stays outside the target and never ships code into it. The product is organized around ten layers: architecture, framework, operator, fabric, data/weights, tenant isolation, supply chain/identity, cache, cross-component combinations, and defense bypass.

The tenth layer is a first-class product capability, not an add-on. Eleven `defense-bypass-*` modules measure whether Elkeid, AgentSmith, veinmind, Falco, Tetragon, KubeArmor, Kyverno/Gatekeeper, Trivy/grype, Wazuh/Osquery, ModSecurity/Coraza/SafeLine, and Hubble/Calico actually see benign, authorized activity. Each module returns detected techniques, blind spots, and hardening advice, and feeds Kyverno, Sigma, Falco, and Suricata rule packs.

覆盖率明细与生成式表格见 [`docs/PROBE-COVERAGE.md`](PROBE-COVERAGE.md)。

## 证据 / 限制

**证据**

- 模块目录：287 个；链定义：29 条；`defense-bypass-*` 模块：11 个。
- 第 10 层每个产品都有部署态/降级态/缺失态三态模型与 fixture 驱动的两态评估；评估逻辑在 `inkblade/core/defenseprobe.py`，模块入口在 `inkblade/modules/defense-bypass-*`。
- 探针 op 的代码锚：`probe/src/{http,tcp,exec,fsops,k8s,net,spawn}.rs`；协议帧在 `probe/src/protocol.rs`。
- 动态验证标准与当前完成度：`docs/DYNAMIC-VERIFICATION.md`。

**限制**

- 模板迁移已完成：287 个模块目录中 286 个有 `template.json`，1 个是 bootstrap；旧 `run.py` 已从工作树与 HEAD 全部删除。注册表强制模板，旧执行路径不再被加载。
- 11 个 defense-bypass 模块与其余 275 个模板一起在 Rust 探针上跑完两态（`runtime=rust`，每态 3 次一致）；其 detected/blindspots/hardening 来自模板输出的防护矩阵产物。
- fixed 态负控只对输入来自 mock 靶场的模板成立；两态共用 fixture 输入的模板只算执行验证，见 `docs/PROBE-COVERAGE.md` §6。
- 防护产品版本、规则集和内核配置差异很大；盲区结论只对被测版本和被测配置成立，不能外推为“该产品可被绕过”。
- 良性 marker 只能证明“这类行为是否可见”，不能证明“恶意行为一定不可见”；产品不提供恶意载荷、持久化或规避执法。
- 部分检测点需要特权 Pod、hostNetwork、GPU 设备或节点访问；没有对应部署面时，模板返回 `skipped`，不计入覆盖率分子。
