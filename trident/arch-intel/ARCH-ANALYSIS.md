# 架构情报分析（ARCH-ANALYSIS）— 2026-10 公开基线

- 生成日期：2026-10-25（全部来源当日逐源核验，见 `coverage-matrix.json`）
- 权威门槛：`docs/design.md` 第 12.2 节
- 语料：`corpus/*.md` 共 35 篇（组织-系统命名），覆盖矩阵见 `coverage-matrix.json`，门槛校验器 `check.py`

---

## 1. 问题点汇总表：公开设计证据 ↔ 放大前提 ↔ 建议模块机器键

| # | 放大前提（设计基线 12.2） | 公开设计证据（来源条目） | 建议模块/链机器键（设计基线 5.2/6.3） |
|---|---|---|---|
| 1 | 集合通信无认证（平网直达即可入组） | NCCL 传输与 bootstrap 无鉴权语义（nccl-transports）；eRDMA 设备即 RDMA 通道（aliyun-ack-erdma）；IB 隔离仅靠 Partition/PKey（ib-partition-rdma）；HPN/Meta RoCE/MegaScale 全互通 fabric | `collective-communication-surface`、`nccl-collective-join`、`fabric-topology-isolation`、链「IB/RDMA 平面 → 集合通信注入」 |
| 2 | RDMA/IB 无内建认证与加密 | ib-kubernetes：SM/PKey 为唯一隔离；RoCE 变体无 PKey 等价物（回退 VLAN/安全组，常漏配）；Azure ND 每 GPU 独占 IB 且 VMSS 内自动组网（azure-nd-h100-infiniband） | `fabric-topology-isolation`、`multus-sriov-rdma-bypass`、`cni-aware-reachability-graph`（pod↔IB 维） |
| 3 | NetworkPolicy 旁路（SR-IOV/hostNetwork/独占 ENI） | Terway 官方明示：独占 ENI 节点池不支持 NetworkPolicy、Egress 策略无法约束 hostNetwork Pod/节点 IP（aliyun-terway）；CNI 规范本身不含策略（kubernetes-cni-spec）；SR-IOV VF/macvlan/IB 流量不受 NetworkPolicy 约束（multus-sriov-operator） | `multus-sriov-rdma-bypass`、`cni-stack-capability`、`network-policy-coverage`、链「VPC-CNI 双控制面错配 → 云内横向」 |
| 4 | 特权容器/驱动容器（operator 面） | Network Operator：OFED 驱动容器特权加载内核模块（nvidia-network-operator）；SR-IOV Operator 要求 pod-security enforce=privileged 命名空间（multus-sriov-operator）；GPU Manager 以 cluster-admin SA 运行（tencent-tke-gpu-manager）；KEP-4381 自认被攻陷 kubelet 插件≈节点 root（kubernetes-dra） | `gpu-network-operator-posture`、`privileged-workloads`、`privileged-gpu-pod-escape`、`runtime-socket-escape`、链「GPU 与网络 Operator → 宿主逃逸」 |
| 5 | 宽 RBAC / 集群级身份 | gpu-manager DaemonSet 绑 cluster-admin（tencent-tke-gpu-manager）；DRA ResourceClaim 创建权=跨命名空间抓敏感设备（kubernetes-dra、aws-eks-efa-dra）；Resource Injector 准入注入（multus-sriov-operator）；TKEStack 平台面=多集群枢纽（tencent-tkestack）；Singularity 全球调度身份（microsoft-singularity） | `rbac-mapping`、`overprivileged-sa-escalation`、`cloud-integration-fingerprint`、链「Ray Dashboard → 集群控制」 |
| 6 | 共享存储/共享 KV（偷换一体） | NFSv4 AUTH_SYS uid 可伪造（storage-protocol-csi）；RWX+HF 缓存目录（同上）；Mooncake 全局 KV 池与请求前缀复用（mooncake-kv-transfer）；llm-d 分层 KV 卸载落盘/对象存储（llm-d-nixl）；vGPU 显存共享（tencent-tke-gpu-manager） | `shared-volume-weight-copy`、`trust-remote-code-supply-chain`、`training-data-leak`、链「共享 PVC + 模型加载 → 供应链投毒」 |
| 7 | 多租户共享引擎/推理端点未鉴权 | DeepSeek 预填充-解码分离两池间 KV 传递无认证公开描述（deepseek-prefill-decode）；EPP/KV-cache 路由信息面（gateway-api-inference-extension）；llm-d 多租户流控在调度层而非传输层（llm-d-nixl） | `unlimited-query-distillation`、`inference-gateway-pd`、`lora-adapter-injection`、链「预填充-解码 KV 通道 → 推理操纵」 |
| 8 | 监控/管理面暴露 | MegaScale 深度可观测体系=拓扑与流量画像（bytedance-megascale）；观测面常与引擎同部署；EPP ext-proc 通道信任（gateway-api-inference-extension） | `observability-exposure`、`exposure-mapping`、`framework-port-matching` |
| 9 | SA token 与云凭据（元数据枢纽） | 各云条目共同证据：IRSA/Workload Identity/托管标识/RAM 角色/CAM/委托与节点池绑定（aws-eks-*、azure-aks-gpu、aliyun-terway、gcp-ai-on-gke、huawei-cce-turbo、tencent-tke-gpu-manager） | `metadata-egress`、`ssrf-imds-credential`、`multi-cloud-imds-credentials`、`cloud-role-overprivilege`、四条云侧权重桶链 |
| 10 | 混合互联放大平网 | CEN/TR 路由传播与跨账号互联（alibaba-cen-tr）；ExpressRoute Microsoft Peering 直达云 API（azure-expressroute）；PrivateLink 私网暴露语义（后端服务若自身无鉴权，私网=更大暴露）（alibaba-private-link） | `hybrid-cloud-egress-pivot`、`dns-service-discovery`、链「SSRF/SA Token → 云元数据」混合回旋段 |
| 11 | 拓扑即隔离但拓扑可被操控 | TPU OCS 动态重构拓扑、安全=重构正确性（google-tpu-oci）；ComputeDomain 域界正确性依赖驱动（nvidia-compute-domain-imex）；rail/双平面可被侦察推演（alibaba-hpn） | `fabric-topology-isolation`、`cni-aware-reachability-graph`、链「IMEX/ComputeDomain → 跨节点 GPU 内存越权」 |
| 12 | 调度/编排面（gang/抢占/队列） | Volcano 为 CCE 官方调度（huawei-cce-turbo）；Singularity 抢占迁移（microsoft-singularity）；gpu-admission 调度扩展（tencent-tke-gpu-manager）；gang 调度 DoS 面 | `scheduler-network-semantics`、`ray-control-plane` |
| 13 | 云托管化转移风险面 | EKS Auto Mode 驱动不可见但托管权限面扩大（aws-eks-auto-mode-accelerated）；托管集群 Trunk ENI 默认开启（aliyun-terway）；Autopilot/Turbo 全托管边界 | `cloud-integration-fingerprint`、`cloud-role-overprivilege` |
| 14 | 权重/数据面（checkpoint=权重） | 各云 StorageClass/OBS/OSS/GCS/Blob 权重桶 + 训练 checkpoint 桶；Singularity 迁移即 checkpoint 通道（microsoft-singularity） | `shared-volume-weight-copy`、`supply-chain-credential-theft`、四条云侧权重桶链 |

## 2. 横向架构思路（路径图·文字版）

主路径（网络七层模型贯穿）：

```
初始立足（推理端点/引擎管理面/共享卷/平台网关）
   │  ① 暴露面测绘 + 框架端口匹配（exposure-mapping / framework-port-matching）
   ▼
Pod→Pod 横向（CNI 层）
   ├─ NetworkPolicy 盲区：hostNetwork / SR-IOV VF / macvlan / IB / 独占 ENI（multus-sriov-rdma-bypass）
   ├─ VPC-native 双控制面错配：安全组 × K8s 策略两套语义（cni-stack-capability）
   ▼
网关与分离面（服务与网关层）
   ├─ EPP/failureMode=FailOpen → 旁路智能路由（inference-gateway-pd）
   ├─ 预填充池 →(NIXL/RDMA KV 明文通道)→ 解码池：注入/窃听 KV（collective-communication-surface）
   ▼
集合通信面（fabric 层）
   ├─ 探 TCPStore/rendezvous → NCCL 入组 → 梯度注入/参数旁听（nccl-collective-join）
   ├─ IB 可达且 default PKey 全通 → RDMA 直读写邻居（fabric-topology-isolation）
   └─ ComputeDomain/IMEX 划界错配 → 跨节点 GPU 内存越权（GB200 形态）
   ▼
存储数据面
   ├─ NFS AUTH_SYS 伪造 uid → 数据集/权重直读（storage-protocol-csi / shared-volume-weight-copy）
   ├─ RWX + HF 缓存 → 恶意权重/模型代码投放 → 加载即执行（trust-remote-code-supply-chain）
   ▼
云身份与凭据（云与混合边界层）
   ├─ 元数据（IMDSv2/托管标识/RAM/CAM/WIF）→ 节点/SA 云凭据（multi-cloud-imds-credentials）
   ├─ 权重桶链：IRSA/MI/RAM/CAM → S3/Blob/OSS/COS 权重读写投毒（cloud-role-overprivilege）
   ▼
混合回旋
   └─ CEN/ExpressRoute/PrivateLink 路由传播面 → IDC ↔ 多 VPC 回旋（hybrid-cloud-egress-pivot）
```

要点：
1. **“有 NetworkPolicy”≠“隔离有效”**——每条旁路（hostNetwork/SR-IOV/IB/独占 ENI/TCP fallback）都必须单独实证（可达性图五维：pod↔pod / pod↔宿主 / pod↔IB / pod↔元数据 / 跨集群）。
2. **新架构面优先**：预填充-解码 KV 通道（NIXL/llm-d）、ComputeDomain/IMEX、EPP FailOpen、DRA ResourceClaim 是 2026 检测面增量，均有公开设计证据支撑。
3. **云商共性问题**：六云一致出现「托管化转移风险面」——驱动/网络组件被托管收编，但节点角色与元数据语义不变，凭据链攻击仍是通用横向枢纽。
4. **规则转化**：旁路族建议出 per-CNI 规则包 + IB Partition/SM 补充建议 + hostNetwork 收敛清单（设计基线 10.1）。

## 3. 覆盖情况声明

- **门槛达成**（`check.py` 校验，逐源状态见 `coverage-matrix.json`）：
  - 自建与超大规模训练组网：**8 verified / ≥8 达标**（另 1 篇 verified-partial：xai-colossus，主站自实验网络不可达，经检索快照佐证，缺口显式记录）
  - 六云商各 ≥2：**全部达标**（AWS 2 / Azure 2 / 阿里 2 / 腾讯 2 / GCP 2 / 华为 2，均 verified）
  - 混合互联与边界：**3 / ≥3 达标**（CEN、ExpressRoute、PrivateLink，均 verified）
  - 网络架构专源：**11 / ≥8 达标**；必需 topic 9/9 全覆盖：CNI ✓、Multus/SR-IOV ✓、Network Operator ✓、DRA/ComputeDomain/IMEX ✓、Gateway API Inference Extension ✓、llm-d/NIXL ✓、NCCL ✓、IB/RoCE ✓、存储协议 ✓
- **核验方法**：websearch/webfetch/http fetch 逐源抓取（GitHub raw、arXiv 摘要与全文、SIGCOMM/USENIX 官方页、各云厂商帮助中心/学习站/产品页/官方开源仓），核验日期统一 2026-10-25；每篇 corpus 文件含来源 URL、核验状态、架构要素、问题点（前提↔模块机器键）、横向思路。
- **显式缺口与替代**：
  1. `cloud.google.com` 与 `research.google.com` 在本实验网络超时/拒连——GCP 条目改用 GoogleCloudPlatform 官方仓（ai-on-gke，已归档只读）与 Google 云 TPU 团队维护的 pytorch/xla 仓（官方弃用公告：2026-11-15 归档、迁移 TorchTPU）核验；
  2. `x.ai` 主站不可达——xai-colossus 记为 verified-partial（Bing 检索快照 + 中文科技媒体交叉佐证），不计入门槛；
  3. Calico raw README 当日抓取超时——cni-policy-calico-cilium 以 Cilium 官方文档直读为核验依据，Calico 语义待复验；
  4. 设计基线 12.1 首批清单中 NVIDIA SuperPOD RA、ACES、VeScale、Google Borg/Jupiter 原文、Anthropic 集群访谈等未在本轮独立成篇（非门槛项），由 HPN/GB200/TPU/Singularity 等同类已核验源覆盖其架构要素，后续批次补齐。
- **可回溯性**：本分析全部「问题点→模块」映射均标注来源条目 id；模块清单与组合签名库更新必须回溯到矩阵条目（设计基线 12.2 要求）。
