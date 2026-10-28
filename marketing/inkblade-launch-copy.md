# InkBlade 产品文案库

> **用途**：微信公众号与 X / Twitter 发布。  
> **范围**：功能、检测面、探针协议、代理协议、产物。  
> **基调**：专业、克制、只讲已实现能力，不写夸张承诺。  
> **更新时间**：2026-10-28

---

## 目录

1. [一句话定位](#一句话定位)
2. [核心卖点速览](#核心卖点速览)
3. [微信公众号长文](#微信公众号长文)
4. [微信公众号短文案](#微信公众号短文案)
5. [X / Twitter 发布线程](#x--twitter-发布线程)
6. [X / Twitter 单条 Hook](#x--twitter-单条-hook)
7. [发布检查清单](#发布检查清单)

---

## 一句话定位

> **InkBlade（墨刃零）是面向 LLM 训练/推理集群的授权安全测试平台。**  
> 它测试的不是模型会不会说错话，而是训练任务能否被污染、推理权重能否被拿走、低权限 Pod 能否横向、GPU 与网络 fabric 能否被滥用、云身份能否被接管。

英文版本：

> **InkBlade is an authorized security testing platform for LLM training and inference clusters.**  
> It tests the infrastructure underneath the model: Kubernetes, GPU operators, NCCL/RoCE fabric, Ray, vLLM/SGLang, model weights, KV cache and cloud identity.

---

## 核心卖点速览

| 维度 | InkBlade 能力 |
|---|---|
| **检测对象** | LLM 训练/推理基础设施，而不是通用 Web 或通用 K8s |
| **检测面** | 十层：架构、产品/框架、Operator、fabric、权重、租户、供应链、缓存、组合、防护绕过 |
| **目标侧执行体** | 静态 musl Rust 探针，运行在低权限 Pod 内 |
| **连接方向** | 探针主动回连控制端，目标 Pod 不开放监听端口 |
| **回连协议** | TLS、WSS、HTTPS 长轮询、QUIC、WebTransport（实验）、MASQUE CONNECT-UDP |
| **认证** | 控制端证书 SHA-256 pin + challenge-HMAC token |
| **ML 代理** | Triton/Ray gRPC、Ray GCS Redis、PyTorch TCPStore/Gloo、NCCL/UCX TCP 控制、ZMTP+CURVE、MASQUE UDP、loopback SOCKS5 |
| **产物** | 双语报告、修复报告、SARIF/OCSF/VEX、规则包、权限图、执行时间线、证据 manifest |
| **规模** | 286 模板、121 规则、29 链、184 条漏洞研究、68 个可运行 PoC |

---

# 微信公众号长文

## 标题

**InkBlade（墨刃零）：专为训练/推理集群设计的十层安全测试平台**

## 摘要

大模型安全讨论大多停在提示词和模型输出。  
但真正决定风险的是训练与推理所在的集群：Kubernetes、GPU Operator、NCCL/RoCE、Ray、vLLM/SGLang、共享权重卷、KV cache、云身份链路。

InkBlade 不是通用 K8s 扫描器，而是专门面向 **LLM 训练/推理基础设施** 的授权安全测试平台。

---

## 一、训练/推理集群为什么需要单独测

### 训练侧风险

训练集群的风险集中在作业控制、GPU 通信和权重链路：

- **作业与队列控制面**：Ray、LWS、Kueue、Volcano、多集群调度
- **GPU 与节点控制面**：GPU Operator、DRA、CSI、CNI、网络 Operator
- **集合通信与 fabric**：NCCL、RoCE、InfiniBand、SHARP、SR-IOV、IB Partition
- **模型与训练数据**：共享 PVC、checkpoint、optimizer 分片、权重桶、模型注册表
- **训练框架入口**：Megatron、DeepSpeed、verl、AReaL、SkyRL、slime
- **云身份链路**：IRSA、Pod Identity、IMDS、跨账户 AssumeRole

这些组件组合起来，决定了训练任务是否可能被污染、梯度是否可能被篡改、权重是否可能被导出。

### 推理侧风险

推理集群的风险集中在服务管理面、模型加载和缓存隔离：

- **推理服务管理面**：vLLM、SGLang、AReaL、OpenRLHF 的管理端点
- **插件与代码加载**：插件路由、远程代码加载、开发模式、权重导出路径
- **KV 与缓存隔离**：prefill/decode KV 通道、远程 KV 池、前缀缓存、跨租户命中
- **平台组件**：AI Gateway、模型注册表、向量库、配额与日志系统
- **GPU 租户隔离**：MIG、MPS、GPU 池化调度中的残留与隔离边界

推理侧一旦失守，影响不只是服务中断，还可能是权重外带、请求内容泄露或推理结果被操纵。

---

## 二、十层检测面

| 层 | 检测内容 |
|---|---|
| **1. 架构层** | rail 与多平面错配、prefill/decode KV 通道、IMEX/ComputeDomain、MoE/EP 集合通信、多集群信任 |
| **2. 产品/框架层** | vLLM、SGLang、AReaL、verl、DeepSpeed、Megatron、slime、AI Gateway 的管理面与插件面 |
| **3. 组件/Operator 层** | Ray、LWS、GPU Operator、DRA、CSI、CNI、BMC/Redfish 的特权与默认配置 |
| **4. 网络/fabric 层** | hostNetwork、SR-IOV、macvlan、双 CNI、IB Partition、RoCE PFC/ECN、SHARP、NCCL 端口与 DNS 发现 |
| **5. 数据/权重层** | checkpoint、optimizer 分片、数据集管线、Hugging Face cache、权重桶、模型注册表 |
| **6. 租户隔离层** | MIG/MPS 残留、GPU 池化调度、cache_salt、路由指标泄露 |
| **7. 供应链/身份层** | trust_remote_code、版本锁定、attestation、SBOM、IRSA、Workload Identity、IMDS |
| **8. 缓存安全层** | 跨租户前缀缓存、语义误命中、逐出残留、远程 KV 池、EPP 指标、TTFT 侧信道 |
| **9. 跨组合层** | 单独看是中危、组合后变高危的链路，例如“管理面无鉴权 + SA 权限 + 权重桶写入” |
| **10. 防护绕过层** | 验证哪些变体能绕过 HIDS、运行时 eBPF、准入、镜像扫描、WAF、网络可视化，并输出检测结果与盲区 |

---

## 三、探针：跑在目标 Pod 里的 Rust 执行体

InkBlade 的目标侧执行体是一个静态 musl Rust 探针。

### 默认环境假设

- 非 root
- 无 hostPath
- 无 privileged
- 无 kubeconfig
- 只允许出站连接

探针启动后主动回连控制端，不在目标 Pod 开监听端口。

### 回连协议

| 协议 | 说明 |
|---|---|
| **TLS** | 默认加密回连 |
| **WSS** | TLS + WebSocket，适合受限出口 |
| **HTTPS 长轮询** | 表现为普通 API 流量 |
| **QUIC** | UDP 443，低延迟传输 |
| **WebTransport** | HTTP/3 双向流，实验性 |
| **MASQUE CONNECT-UDP** | HTTP/3 UDP 代理，用于 UDP 辅助面 |

### 认证方式

- 控制端证书 SHA-256 pin
- challenge-HMAC token
- token 不写入日志和状态文件

### 探针能力

| 操作 | 能力 |
|---|---|
| `collect` | 主机、Pod、进程、网络、Kubernetes 上下文 |
| `exec` / `audit-exec` | 受预算和命令白名单约束的执行与审计 |
| `read-file` / `list-files` | 文件读取与目录枚举 |
| `upload` / `download` | 受授权控制的数据传输 |
| `dial` | TCP/UDP 探测与转发 |
| `spawn` | 投放子探针，保留 `probe_id` / `parent_id` |
| `beacon` | 状态与心跳 |
| `cleanup` | 子探针优先清理，避免遗留未回收 token |

子探针继承更严格的预算和白名单，并限制嵌套层数与并发子探针数量。

---

## 四、代理：为 ML 协议单独做的加密代理层

InkBlade 的代理不是通用 SOCKS 转发，而是面向训练/推理环境的服务协议代理。

| 协议 | 场景 |
|---|---|
| **gRPC over TLS** | Triton 8001 / Ray 8265，token 放 gRPC metadata |
| **Redis RESP over TLS** | Ray GCS 6379，客户端 AUTH 后转发 |
| **TCPStore/Gloo TLS relay** | PyTorch 29500，HMAC 握手后转发 |
| **NCCL/UCX TCP 控制 profile** | 50000–51000 等 bootstrap / 控制端口，只覆盖 TCP 控制流 |
| **ZMTP + CURVE** | SGLang / vLLM 常见 ZeroMQ 面，实验性 |
| **MASQUE CONNECT-UDP** | RoCE / UCX 的 UDP 辅助面 |
| **SOCKS5** | 仅 loopback，用于本地工具兼容 |

代理与控制通道统一使用证书 pin、HMAC token 和加密传输。  
NCCL/UCX 代理只处理 TCP 控制流，不冒充 RDMA 数据面。

---

## 五、输出物

InkBlade 输出的不是截图，而是可复核证据：

- 286 个检测模板
- 121 条检测规则
- 29 条攻击链
- 184 条漏洞研究记录
- 68 个可运行 PoC
- 中英双语渗透报告
- 修复报告
- SARIF / OCSF / VEX 导出
- 权限图、执行时间线、操作与文件访问台账
- SHA-256 证据 manifest
- 规则与攻击链覆盖矩阵

169 条研究记录中，47 条已完成动态复现并确认未公开，46 条可进入协调披露，去重后为 39 个独立利用原语。

---

## 六、一句话总结

> InkBlade 测的不是“模型会不会说错话”，而是：  
> **训练任务能不能被污染，推理权重能不能被拿走，低权限 Pod 能不能横向，GPU 与网络 fabric 能不能被滥用，云身份能不能被接管。**

**仓库**：`lupingQAQ/inkblade`  
**文档站**：`lupingqaq.github.io/inkblade`

InkBlade 仅用于获得书面授权的目标。

---

# 微信公众号短文案

> 大多数 AI 安全讨论停在提示词。  
> 但训练/推理集群真正的风险在下面：GPU Operator、NCCL/RoCE、Ray、vLLM/SGLang、共享 PVC、KV cache、云 IMDS。
>
> InkBlade 是面向 LLM 集群的授权安全测试平台：  
> Rust 探针运行在低权限 Pod 内，主动回连控制端；十层检测；覆盖 Triton gRPC、Ray Redis、PyTorch TCPStore、NCCL/UCX 控制、ZMTP、MASQUE 等 ML 协议代理。
>
> 286 模板 / 121 规则 / 29 链 / 184 条漏洞研究 / 68 个 PoC。  
> 仓库：`lupingQAQ/inkblade`  
> 仅限授权目标。

---

# X / Twitter 发布线程

```text
1/8

Most AI security starts at the prompt.
InkBlade starts underneath it: the training and inference clusters that run K8s, GPU operators, NCCL/RoCE fabric, Ray, vLLM and SGLang.

2/8

It is not a generic Kubernetes scanner.
It is an authorized security testing platform built for LLM training and inference infrastructure.

3/8

Ten detection layers:

- Architecture, PD/KV channels, IMEX, MoE/EP
- vLLM, SGLang, AReaL, verl, DeepSpeed, Megatron
- GPU Operator, DRA, CSI, CNI, Ray, LWS
- NCCL, RoCE, IB, SHARP, SR-IOV
- weights, checkpoints, PVCs, registries
- GPU tenancy, MIG/MPS, prefix cache
- IRSA, Workload Identity, IMDS
- cache and cross-tenant KV
- cross-combination chains
- defense-bypass outcomes

4/8

Training-side surfaces:

- Ray job and queue control planes
- GPU Operator and DRA privilege boundaries
- shared PVC, checkpoint and optimizer shards
- NCCL/RDMA bootstrap and fabric trust
- cloud identity chains from Pod to cross-account roles

5/8

Inference-side surfaces:

- vLLM / SGLang / AReaL admin endpoints
- plugin routes and remote-code loading
- prefill/decode KV channels
- prefix cache and remote KV pools
- AI gateway, model registry and vector DB exposure

6/8

The target-side executor is a static musl Rust probe inside a low-privilege Pod.

No root. No hostPath. No privileged. No kubeconfig. Outbound only.

Reverse transports:

- TLS
- WSS
- HTTPS long poll
- QUIC
- WebTransport (experimental)
- MASQUE CONNECT-UDP

Auth: certificate SHA-256 pin + challenge-HMAC token.

7/8

ML-native encrypted proxies:

- gRPC over TLS for Triton / Ray
- Redis RESP over TLS for Ray GCS
- TCPStore / Gloo TLS relay
- NCCL / UCX TCP control profiles
- ZMTP + CURVE for SGLang / vLLM (experimental)
- MASQUE for UDP auxiliary planes
- SOCKS5 only on loopback

8/8

286 templates. 121 rules. 29 chains. 184 vulnerability write-ups. 68 runnable PoCs.

Evidence-first output: SHA-256 manifests, bilingual reports, SARIF/OCSF/VEX, permission graph, execution timeline.

GitHub: https://github.com/lupingQAQ/inkblade
Docs: https://lupingqaq.github.io/inkblade/

Authorized testing only.
```

---

# X / Twitter 单条 Hook

## 版本 A：定位型

```text
Most AI security tools test the model.
InkBlade tests the cluster that trains and serves it: GPU operators, NCCL/RoCE, Ray, vLLM/SGLang, shared weights, KV cache, cloud identity.

Static Rust probe. Low-privilege Pod. Reverse encrypted channel. ML-native proxies.

https://github.com/lupingQAQ/inkblade
```

## 版本 B：风险型

```text
A low-privilege Pod should not become a path to model weights.

InkBlade tests that path with a static Rust probe and encrypted reverse channels: TLS / WSS / HTTPS / QUIC / WebTransport / MASQUE.

Proxies understand Triton gRPC, Ray GCS Redis, PyTorch TCPStore, NCCL/UCX control flow and ZMTP.

https://github.com/lupingQAQ/inkblade
```

## 版本 C：产物型

```text
Not screenshots. Evidence.

InkBlade outputs bilingual pentest reports, remediation reports, SARIF/OCSF/VEX, SHA-256 evidence manifests, permission graphs, operation timelines and replayable rule packs.

286 templates. 121 rules. 29 chains. 68 runnable PoCs.

https://github.com/lupingQAQ/inkblade
```

---

# 发布检查清单

## 公众号发布前

- [ ] 标题不超过 30 字
- [ ] 首段直接说明训练/推理集群风险
- [ ] 十层检测表完整展示
- [ ] 探针协议表完整展示
- [ ] ML 代理协议表完整展示
- [ ] 输出物清单完整
- [ ] 文末包含仓库与文档站
- [ ] 包含“仅限书面授权目标”
- [ ] 不出现未实现能力
- [ ] 不出现利用细节或真实目标信息

## X 发布前

- [ ] 线程共 8 条
- [ ] 第 1 条直接建立反差
- [ ] 第 3 条包含十层
- [ ] 第 6 条包含探针与回连协议
- [ ] 第 7 条包含 ML 代理协议
- [ ] 第 8 条包含规模、产物与链接
- [ ] 每条不超过 280 字符
- [ ] 包含 `#AIsecurity`、`#Kubernetes`、`#GPU`、`#LLM`
- [ ] 只声明已实现能力
- [ ] 包含 “Authorized testing only.”

---

## 底线表述

- 只写 **授权安全测试**
- 不写“免杀”“不可检测”“绕过所有安全产品”
- 不公开完整利用链
- 不展示未脱敏真实客户环境
- 实验性能力必须标注“实验性”
- NCCL/UCX 代理只描述 TCP 控制流，不冒充 RDMA 数据面
