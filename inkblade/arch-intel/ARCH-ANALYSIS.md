# 架构情报分析（ARCH-ANALYSIS）— 2026-10 万卡语料推倒重收版

- 生成日期：2026-10-25（全部来源当日逐源核验，检索式与不可达清单见 `docs/RESEARCH-COVERAGE.md`）
- 语料：`corpus/{official-cn,official-en,paper}/` 共 **80 源**（中文官方 28 / 外文官方 39 / 论文 13；verified 75，其余 5 为 verified-partial 并显式标注不可达/快照原因）
- 门槛（`check.py` 全绿）：official-cn 28/≥12、official-en 39/≥12、万卡证据源 28/≥20、网络要素 8/8 全覆盖、本轮新增 32/≥30（official 占比 93.8%）
- 重收口径：**≥10k GPU/加速器实践 + 官方技术博客优先 + 中外并收**；每篇 corpus 文件含【万卡证据】（集群规模/部署数量原文摘录）与【网络要素】标注
- 并行批次：`batch=gen-26-fabric`（13 源）为 gen-26 fabric 面任务并入，保留其原始字段，不计入本任务新增门槛

---

## 1. 问题点汇总表：万卡官方证据 ↔ 放大前提 ↔ 模块机器键

> 机器键以 `trident/modules/` 现有目录为准；`fabric-*`/`nccl-*`/`roce-*` 等为 gen-26 fabric 面模块族（在跑，预留映射同步更新）。

| # | 放大前提（万卡官方证据） | 公开证据原文（来源条目） | 模块/链机器键 |
|---|---|---|---|
| 1 | **平网（flat/fat-tree 全互通）成万卡默认设计** | Microsoft Fairwater："single flat network...hundreds of thousands of GB200/GB300"（msft-fairwater-superfactory/wisconsin）；NVIDIA："Spectrum-X multiplane...flat, two-tier topology...128K GPUs"（nvidia-spectrum-x） | `cni-aware-reachability-graph`、`fabric-topology-isolation`、`network-policy-coverage` |
| 2 | **多平面/多轨 fabric 的平面间无隔离语义** | Spectrum-X multiplane 64x 单平面（nvidia-spectrum-x）；HPN 双平面/单层千卡两层万卡（alibaba-hpn、aliyun-lingjun）；星脉多轨（tencent-xingmai-2） | `fabric-topology-isolation`、`rail-mismatch-forcing`（gen-26 fabric 面） |
| 3 | **在网计算把聚合逻辑下沉交换机** | Quantum-X800 SHARP v4（gen-26 条目 nvidia-quantum-x800）；UEC 1.1 INC "offload compute to the network"（uec-spec）；Ultra Ethernet 批次 SHARP 条目 | `sharp-in-network-poison`（gen-26）、`collective-communication-surface` |
| 4 | **拥塞控制端网协同=协议层扰动面** | Meta 400G 弃 DCQCN、PFC-only+CTS 接收端准入（meta-roce-blog）；TiTa2.0 主动 CC 上网卡（tencent-xingmai-2）；UEC CSIG/PCM（uec-spec）；Fairwater packet spray/trimming（msft-fairwater-superfactory） | `roce-pfc-storm`（gen-26）、`fabric-topology-isolation`、`scheduler-network-semantics` |
| 5 | **集合通信无认证（万卡直达即可入组）** | Meta backend fabric 专为训练全域 RoCE（meta-roce-blog）；火山引擎"同一集群内 RDMA 互联互通、不同集群相互隔离"——集群内无租户身份（volcengine-hpc-rdma）；昆仑芯超节点柜间 IB/RoCE（kunlunxin-supernode） | `nccl-collective-join`、`nccl-port-exhaustion`（gen-26）、`nccl-straggler-injection`（gen-26）、链「IB/RDMA 平面 → 集合通信注入」 |
| 6 | **跨数据中心训练网=横向回旋新段** | Fairwater "dedicated AI WAN optical network...120,000 fiber miles"（msft-fairwater-superfactory）；Spectrum-XGS 跨楼宇/数百公里（nvidia-spectrum-x）；Meta Prometheus 跨栋+Twine/MAST 长距训练（meta-infra-evolution）；AWS Rainier EFA 跨 DC（aws-project-rainier） | `hybrid-cloud-egress-pivot`、`dns-service-discovery`、链「跨站 WAN → 远端 fabric 入组」（gen-26 预留） |
| 7 | **光交换/光互联重构可达性** | Google OCS 动态重构拓扑（google-tpu-oci、jupiter-evolving）；Ironwood ICI 9.6Tb/s 单域（google-ironwood）；Quantum-X CPO 共封装光（gen-26 条目） | `fabric-topology-isolation`、链「OCS/SDN 控制面 → 拓扑重配」（gen-26 预留） |
| 8 | **万卡自愈/调度自动化被劫持即大规模扰动** | 昇腾"秒级恢复、分钟级诊断/训练可用度98%"（huawei-ascend-10k-stability）；美团"自动故障恢复、月均日故障率降70%"（meituan-longcat-2）；星脉故障定位分钟级（tencent-xingmai-2）；Meta 中断率降 ~50x（llama3-herd） | `scheduler-network-semantics`、`driver-reset-trigger`（gen-26）、`checkpoint-io-storm`（gen-26） |
| 9 | **多租公共智算平台隔离在平台层而非 fabric** | 中国电信"息壤"万卡池公共多租（china-telecom-10k）；OCI Zettascale 云上交付 16,384 H100（oracle-zettascale）；MiniMax 租用算力样本（minimax-m1） | `network-policy-coverage`、`cloud-role-overprivilege`、`cloud-bucket-cross-tenant` |
| 10 | **超节点总线域替代以太=旁路族再扩容** | 华为"高速总线互联替代传统以太"16 万卡（huawei-ascend-cloud）；NVLink Fusion/GB200 NVL72 域（nvidia-gb200-nvl72、gen-26 nvidia-nvlink-fusion）；昆仑芯单柜全互联（kunlunxin-supernode） | `multus-sriov-rdma-bypass`、`privileged-gpu-pod-escape`、`gpu-device-cross-namespace` |
| 11 | **交换机 OS/NOS 开放化=控制面供应链** | Fairwater 明示 SONiC 为其交换机 OS（msft-fairwater-superfactory）；SONiC Foundation 多厂商 NOS（sonic-foundation）；SONiC 白盒安全（gen-26 sonic-whitebox-security） | `gpu-network-operator-posture`、`trust-remote-code-supply-chain`、链「白盒交换机指纹 → fabric 控制面」 |
| 12 | **UFM/fabric 管理器单点** | Quantum-X800 UFM 专用端口（gen-26 条目 nvidia-quantum-x800）；IB 子网管理器（ib-partition-rdma、gen-26 ib-subnet-manager-hijack） | `ib-subnet-manager-hijack`（gen-26）、`rbac-mapping`、`gpu-network-operator-posture` |
| 13 | **云凭据链仍是万卡租户/运营双方面共同枢纽** | AWS×Anthropic 专属容量+AWS 运营（aws-project-rainier）；OpenAI×NVIDIA 10GW（openai-nvidia-10gw）；Microsoft OpenAI 超算 10k GPU/400G（msft-openai-sc-2020） | `multi-cloud-imds-credentials`、`metadata-egress`、`ssrf-imds-credential`、`cloud-role-overprivilege` |
| 14 | **权重/checkpoint 双轨大通道** | Meta Tectonic+Hammerspace 双存储（meta-genai-infra）；Fairwater 存储专用楼+BlobFuse2（msft-fairwater-wisconsin）；vePFS RDMA 直访（volcengine-hpc-rdma） | `shared-volume-weight-copy`、`checkpoint-shard-poison`、`training-data-leak` |
| 15 | **观测面=拓扑与 rank 布局地图** | Meta desync debug/flight recorder（meta-genai-infra）；Minerva 全栈遥测（nvidia-spectrum-x）；昇腾分钟级定位（huawei-ascend-10k-stability） | `observability-exposure`、`exposure-mapping`、`gpu-metrics-tenant-leak` |
| 16 | **万卡规模常态化（宏观）** | 人民日报：全国已建成 42 个万卡级智算集群（people-daily-42-wanka，partial）；MegaScale 12,288/HPN 15K/Llama 3 24,576×2（paper 条目） | 全模块族量级依据（`exposure-mapping`） |

## 2. 横向架构思路（路径图·文字版，fabric 面为主线）

```
初始立足（推理端点/引擎管理面/共享卷/平台网关/云凭据）
   │  ① 暴露面测绘 + 框架端口匹配（exposure-mapping / framework-port-matching）
   ▼
Fabric 侦察段（gen-26 fabric 面 · 在跑）
   ├─ 拓扑指纹：平面数/rail 映射/超节点域边界（fabric-topology-isolation / rail-mismatch-forcing）
   ├─ 拥塞面画像：PFC/ECN/CC 代际（TiTa/DCQCN 弃用/CSIG）→ roce-pfc-storm
   └─ 交换机控制面：SONiC/UFM/IB SM 指纹 → gpu-network-operator-posture / ib-subnet-manager-hijack
   ▼
集合通信面（万卡 fabric 层）
   ├─ TCPStore/rendezvous → NCCL/TCCL 入组 → 梯度注入/参数旁听（nccl-collective-join）
   ├─ 在网计算段：SHARP/INC 聚合投毒（sharp-in-network-poison）
   └─ 慢节点/straggler：低速率拖垮万卡（nccl-straggler-injection）；自愈通道反向利用（scheduler-network-semantics）
   ▼
Pod→Pod / 云原生层（旁路族）
   ├─ NetworkPolicy 盲区：hostNetwork/SR-IOV/macvlan/IB/独占 ENI（multus-sriov-rdma-bypass）
   └─ VPC-native 双控制面错配（cni-stack-capability）
   ▼
跨站/混合回旋段
   ├─ AI WAN / XGS / Prometheus 跨栋：远端 fabric 段入组（hybrid-cloud-egress-pivot）
   └─ CEN/ExpressRoute/PrivateLink 路由传播（既有链）
   ▼
存储与权重面
   ├─ Tectonic/Hammerspace/vePFS-BlobFuse 双轨 → checkpoint 投毒（shared-volume-weight-copy / checkpoint-shard-poison）
   └─ RWX+HF 缓存 → 恶意模型投放（trust-remote-code-supply-chain）
   ▼
云身份枢纽
   └─ IMDS/托管标识/RAM/CAM → 权重桶链（multi-cloud-imds-credentials / cloud-role-overprivilege）
```

要点（重收后的更新）：
1. **平网与多平面是 2025-2026 万卡官方共识**（Fairwater/Spectrum-X/Meta 129k），"有 NetworkPolicy ≠ 隔离有效"升级为"平面间/跨站段默认全通"——可达性图必须新增 fabric 维与跨站维（gen-26 fabric 面承接）。
2. **在网计算（SHARP/INC）与端网协同 CC（CTS/TiTa/CSIG）成为协议层新攻击面**：不破密码即扰动/投毒万卡训练。
3. **万卡自愈自动化是双刃剑**：98% 可用度/秒级恢复依赖的探测-决策通道被劫持即成放大器（straggler/自愈投毒）。
4. **国内侧独有形态**：国产芯片万卡集群（昇腾 16 万卡/昆仑芯 3 万卡/美团五万卡/电信万卡池）+ 公共多租智算平台——平台层隔离与国产通信库（TCCL/HCCL 族）是差异化检测面。
5. **规则转化衔接**：fabric 面建议新增 Falco/Suricata 段（NCCL/TCCL 入组、SHARP 段、PFC 风暴）+ SONiC/白盒管理面收敛清单（对接规则转化引擎既有管线）。

## 3. 覆盖情况声明（重收门槛全绿）

- **门槛达成**（`check.py` 输出，2026-10-25）：
  - official-cn：**28 verified / ≥12 达标**（阿里云/腾讯云/华为云/百度智能云/火山引擎/中国电信/国资委/人民日报/美团/京东云×2/摩尔线程/昆仑芯/DeepSeek/MiniMax）
  - official-en：**39 verified / ≥12 达标**（Meta×3/Microsoft×3/OpenAI/AWS/Google/NVIDIA×2/UEC/SONiC Foundation + 云商与 OSS 官方文档 + gen-26 批次 8 源）
  - 万卡证据源：**28 / ≥20 达标**（每源 wanka_quote 原文摘录；规划口径与能力宣称如实排除）
  - 网络要素：**8/8 全覆盖**（rail 3 / multi-plane 8 / 在网计算 5 / 拥塞控制 13 / 光交换 2 / 多租 16 / 隔离 23 / 运维故障面 14）
  - 本轮新增：**32 / ≥30 达标**，official 占比 **93.8% / ≥70% 达标**
- **不可达与替代（显式记录）**：x.ai（ECONNREFUSED，xai-colossus 以检索快照佐证）；cloud.google.com（拒连，google-next26-80k 快照佐证）；oracle.com（403 WAF，快照佐证）；dl.acm.org（Cloudflare 403，jupiter-evolving 镜像/快照佐证）；paper.people.com.cn（未直读，快照佐证）；docs.volcengine.com/mthreads.com（JS 渲染，标题+快照佐证）。检索式与未找到项见 `docs/RESEARCH-COVERAGE.md`。
- **gen-26 并行批次**：13 源（UEC 生态/SHARP/Spectrum-X multiplane/NVLink Fusion/SONiC 白盒/Prometheus/Colossus 2/Ironwood OCS/MegaScale 推理/Trainium UltraServer 等）以 `batch=gen-26-fabric` 并入；`nvidia-quantum-x800` 撞名条目归 gen-26 批次（本任务同名新增源已让位）。fabric 面模块（`rail-mismatch-forcing`、`roce-pfc-storm`、`sharp-in-network-poison`、`ib-subnet-manager-hijack`、`nccl-straggler-injection`、`nccl-port-exhaustion`、`driver-reset-trigger`、`checkpoint-io-storm`、`_fabric-common.py`）为 gen-26 在跑交付，本分析的问题点→模块映射已按其机器键预留对齐。
- **可回溯性**：本分析全部「问题点→模块」映射均标注来源条目 id；模块清单与组合签名库更新必须回溯到矩阵条目（设计基线 12.2 要求）。
