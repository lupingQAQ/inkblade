# 开源 ML 集群测试工具全景（OSS-ML-CLUSTER-TOOLS）

> 生成：2026-10-26 · 机器可读数据：[docs/oss-ml-cluster-tools.json](oss-ml-cluster-tools.json)（34 条目 × 15 维）·
> 性能实测：[docs/OSS-BENCH.md](OSS-BENCH.md) + [reports/samples/oss-bench/](../reports/samples/oss-bench/)

## 1. 目的与方法

对训练/推理集群的五类开源测试工具做能力+性能对比，识别 Trident 平台的能力缺口：

1. **集群安全扫描/审计**（10 个）：kube-hunter、kube-bench、Kubescape、Trivy、KubeHound、kubeaudit、KubiScan、kdigger、Peirates、CDK
2. **模型/推理安全测试**（8 个）：ModelScan、Fickling、picklescan、garak、PyRIT、promptfoo、Giskard、DeepTeam
3. **网络 fabric/基础设施测试**（5 个）：nccl-tests、perftest、ibdiagnet、toxiproxy、sonobuoy
4. **扰动鲁棒/混沌工程**（6 个）：Chaos Mesh、Litmus、Chaos Toolkit、Pumba、tc/netem、DCGM diag
5. **训练框架测试套件**（3 个）：PyTorch distributed tests、Ray test suite、DeepSpeed tests

另以 **XBow / ARTEX** 两个自主渗透 agent 作参照（第六组，非测试工具）。

**来源核验口径**：全部 32 个工具经官方源逐一核验（GitHub REST API 2026-10-26 实查 stars/pushed_at/license/archived；非 GitHub 分发件（ibdiagnet、tc/netem、XBow）以官方文档/官网为源并注明）。勘误四则登记在案：

- `meta-llama/picklescan` 不存在（404），真实仓库 = `mmaitre314/picklescan`
- `NVIDIA/MFT` 与 `Mellanox/mft` 均 404：ibdiagnet 随 NVIDIA MFT 分发（官方手册 docs.nvidia.com v2.8），GitHub 遗留开源副本 `linux-rdma/infiniband-diags` 已于 2019 归档
- `gaia-app/pumba` 不存在（404），真实仓库 = `alexei-led/pumba`
- DeepSpeed 主仓已从 `microsoft/DeepSpeed` 迁至 `deepspeedai/DeepSpeed`（GitHub API 确认）

**克隆登记**（≤8 约束，本任务新增 8 个浅克隆，均已登记 `.slim/clonedeps/clonedeps.json`，只读零复用）：
`aquasecurity__trivy`(3a0164d) · `Shopify__toxiproxy`(49299d8) · `chaostoolkit__chaostoolkit`(2ff559b) ·
`chaos-mesh__chaos-mesh`(37f49f2) · `litmuschaos__litmus`(b957f31) · `NVIDIA__DCGM`(9fae286) ·
`NVIDIA__nccl-tests`(afd59ab) · `linux-rdma__perftest`(8f87844)。其余 15 工具沿用既有克隆（kube-hunter/kube-bench/Kubescape/KubeHound/kubeaudit/KubiScan/kdigger/CDK/garak/PyRIT/promptfoo/ModelScan/Fickling/picklescan/giskard）。

**判定标记**：✓ 完整能力 · ◐ 部分/间接 · ○ 不覆盖 · ? 官方材料无法判定（本版未使用）。每格判定只采信官方文档/实测，不臆断；逐条依据见 JSON 的 `dims` + `trident_overlap` 字段。

## 2. 五类 × 15 维能力矩阵

15 维：K8s 配置审计 / RBAC / 逃逸路径 / 网络 fabric 诊断 / GPU 硬件 / 驱动固件 BMC / 训练栈 / 推理引擎 / AI 网关 / 混沌注入 / 网络损伤 / GPU 诊断 / 性能压测 / 报告证据 / 编排集成。

### ①集群安全扫描/审计

| 工具 | K8s 配置审计 | RBAC/权限分析 | 容器/集群逃逸路径 | 网络 fabric 诊断 | GPU 硬件健康 | 驱动/固件/BMC | 训练栈测试 | 推理引擎测试 | AI 网关/LLM 应用测试 | 混沌/故障注入 | 网络损伤(latency/loss/partition) | GPU 诊断 | 性能压测 | 报告/证据输出 | 编排/自动化集成 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| [kube-hunter](https://github.com/aquasecurity/kube-hunter) | ◐ | ○ | ◐ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ✓ | ◐ |
| [kube-bench](https://github.com/aquasecurity/kube-bench) | ✓ | ◐ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ✓ | ✓ |
| [Kubescape](https://github.com/kubescape/kubescape) | ✓ | ✓ | ◐ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ✓ | ✓ |
| [Trivy](https://github.com/aquasecurity/trivy) | ✓ | ◐ | ◐ | ○ | ○ | ○ | ◐ | ◐ | ○ | ○ | ○ | ○ | ○ | ✓ | ✓ |
| [KubeHound](https://github.com/DataDog/KubeHound) | ◐ | ✓ | ✓ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ✓ | ◐ |
| [kubeaudit](https://github.com/Shopify/kubeaudit) | ✓ | ◐ | ◐ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ✓ | ◐ |
| [KubiScan](https://github.com/cyberark/KubiScan) | ◐ | ✓ | ◐ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ◐ | ○ |
| [kdigger](https://github.com/quarkslab/kdigger) | ◐ | ◐ | ◐ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ✓ | ○ |
| [Peirates](https://github.com/inguardians/peirates) | ◐ | ✓ | ✓ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ◐ | ○ |
| [CDK](https://github.com/cdk-team/CDK) | ◐ | ◐ | ✓ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ◐ | ○ |

### ②模型/推理安全测试

| 工具 | K8s 配置审计 | RBAC/权限分析 | 容器/集群逃逸路径 | 网络 fabric 诊断 | GPU 硬件健康 | 驱动/固件/BMC | 训练栈测试 | 推理引擎测试 | AI 网关/LLM 应用测试 | 混沌/故障注入 | 网络损伤(latency/loss/partition) | GPU 诊断 | 性能压测 | 报告/证据输出 | 编排/自动化集成 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| [ModelScan](https://github.com/protectai/modelscan) | ○ | ○ | ○ | ○ | ○ | ○ | ◐ | ✓ | ○ | ○ | ○ | ○ | ○ | ✓ | ◐ |
| [Fickling](https://github.com/trailofbits/fickling) | ○ | ○ | ○ | ○ | ○ | ○ | ◐ | ✓ | ○ | ○ | ○ | ○ | ○ | ◐ | ○ |
| [picklescan](https://github.com/mmaitre314/picklescan) | ○ | ○ | ○ | ○ | ○ | ○ | ◐ | ✓ | ○ | ○ | ○ | ○ | ○ | ◐ | ○ |
| [garak](https://github.com/NVIDIA/garak) | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ✓ | ✓ | ○ | ○ | ○ | ◐ | ✓ | ✓ |
| [PyRIT](https://github.com/microsoft/PyRIT) | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ✓ | ✓ | ○ | ○ | ○ | ○ | ✓ | ✓ |
| [promptfoo](https://github.com/promptfoo/promptfoo) | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ✓ | ✓ | ○ | ○ | ○ | ◐ | ✓ | ✓ |
| [Giskard](https://github.com/Giskard-AI/giskard) | ○ | ○ | ○ | ○ | ○ | ○ | ◐ | ✓ | ✓ | ○ | ○ | ○ | ○ | ✓ | ◐ |
| [DeepTeam](https://github.com/confident-ai/deepteam) | ○ | ○ | ○ | ○ | ○ | ○ | ○ | ✓ | ✓ | ○ | ○ | ○ | ○ | ◐ | ◐ |

### ③网络 fabric/基础设施测试

| 工具 | K8s 配置审计 | RBAC/权限分析 | 容器/集群逃逸路径 | 网络 fabric 诊断 | GPU 硬件健康 | 驱动/固件/BMC | 训练栈测试 | 推理引擎测试 | AI 网关/LLM 应用测试 | 混沌/故障注入 | 网络损伤(latency/loss/partition) | GPU 诊断 | 性能压测 | 报告/证据输出 | 编排/自动化集成 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| [nccl-tests](https://github.com/NVIDIA/nccl-tests) | ○ | ○ | ○ | ✓ | ◐ | ○ | ✓ | ◐ | ○ | ○ | ○ | ◐ | ✓ | ◐ | ◐ |
| [perftest (ib_write_bw/ib_read_lat...)](https://github.com/linux-rdma/perftest) | ○ | ○ | ○ | ✓ | ○ | ◐ | ◐ | ○ | ○ | ○ | ○ | ○ | ✓ | ◐ | ○ |
| [ibdiagnet (NVIDIA MFT)](https://docs.nvidia.com/ibdiagnet-infiniband-fabric-diagnostic-tool-user-manual-v2-8.pdf) | ○ | ○ | ○ | ✓ | ◐ | ✓ | ○ | ○ | ○ | ○ | ○ | ◐ | ◐ | ✓ | ◐ |
| [toxiproxy](https://github.com/Shopify/toxiproxy) | ○ | ○ | ○ | ◐ | ○ | ○ | ◐ | ◐ | ◐ | ✓ | ✓ | ○ | ○ | ◐ | ✓ |
| [sonobuoy](https://github.com/vmware-tanzu/sonobuoy) | ◐ | ○ | ○ | ◐ | ○ | ○ | ◐ | ○ | ○ | ◐ | ○ | ○ | ◐ | ✓ | ✓ |

### ④扰动鲁棒/混沌工程

| 工具 | K8s 配置审计 | RBAC/权限分析 | 容器/集群逃逸路径 | 网络 fabric 诊断 | GPU 硬件健康 | 驱动/固件/BMC | 训练栈测试 | 推理引擎测试 | AI 网关/LLM 应用测试 | 混沌/故障注入 | 网络损伤(latency/loss/partition) | GPU 诊断 | 性能压测 | 报告/证据输出 | 编排/自动化集成 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| [Chaos Mesh](https://github.com/chaos-mesh/chaos-mesh) | ○ | ○ | ○ | ◐ | ○ | ○ | ◐ | ◐ | ○ | ✓ | ✓ | ○ | ◐ | ◐ | ✓ |
| [LitmusChaos](https://github.com/litmuschaos/litmus) | ◐ | ○ | ○ | ○ | ○ | ○ | ◐ | ◐ | ○ | ✓ | ✓ | ○ | ◐ | ✓ | ✓ |
| [Chaos Toolkit](https://github.com/chaostoolkit/chaostoolkit) | ○ | ○ | ○ | ○ | ○ | ○ | ◐ | ◐ | ○ | ✓ | ◐ | ○ | ○ | ✓ | ✓ |
| [Pumba](https://github.com/alexei-led/pumba) | ○ | ○ | ○ | ◐ | ○ | ○ | ◐ | ◐ | ○ | ✓ | ✓ | ○ | ○ | ◐ | ◐ |
| [tc/netem (iproute2)](https://wiki.linuxfoundation.org/networking/iproute2) | ○ | ○ | ○ | ✓ | ○ | ○ | ◐ | ◐ | ○ | ◐ | ✓ | ○ | ◐ | ○ | ○ |
| [DCGM diag (dcgmi diag)](https://github.com/NVIDIA/DCGM) | ○ | ○ | ○ | ○ | ✓ | ✓ | ◐ | ◐ | ○ | ◐ | ○ | ✓ | ◐ | ✓ | ◐ |

### ⑤训练框架测试套件

| 工具 | K8s 配置审计 | RBAC/权限分析 | 容器/集群逃逸路径 | 网络 fabric 诊断 | GPU 硬件健康 | 驱动/固件/BMC | 训练栈测试 | 推理引擎测试 | AI 网关/LLM 应用测试 | 混沌/故障注入 | 网络损伤(latency/loss/partition) | GPU 诊断 | 性能压测 | 报告/证据输出 | 编排/自动化集成 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| [PyTorch distributed tests (test/distributed_*)](https://github.com/pytorch/pytorch/tree/main/test) | ○ | ○ | ○ | ◐ | ◐ | ○ | ✓ | ◐ | ○ | ◐ | ◐ | ◐ | ✓ | ◐ | ✓ |
| [Ray test suite (ray/test, ray/serve/test)](https://github.com/ray-project/ray) | ◐ | ○ | ○ | ○ | ◐ | ○ | ✓ | ✓ | ◐ | ◐ | ◐ | ◐ | ✓ | ◐ | ✓ |
| [DeepSpeed tests (tests/unit, tests/comm)](https://github.com/deepspeedai/DeepSpeed) | ○ | ○ | ○ | ◐ | ◐ | ○ | ✓ | ◐ | ○ | ◐ | ◐ | ◐ | ✓ | ◐ | ✓ |

### ⑥自主渗透 agent 参照

| 工具 | K8s 配置审计 | RBAC/权限分析 | 容器/集群逃逸路径 | 网络 fabric 诊断 | GPU 硬件健康 | 驱动/固件/BMC | 训练栈测试 | 推理引擎测试 | AI 网关/LLM 应用测试 | 混沌/故障注入 | 网络损伤(latency/loss/partition) | GPU 诊断 | 性能压测 | 报告/证据输出 | 编排/自动化集成 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| [XBow (参照)](https://xbow.com/) | ◐ | ✓ | ✓ | ◐ | ○ | ○ | ◐ | ◐ | ◐ | ○ | ○ | ○ | ○ | ✓ | ✓ |
| [ARTEX (参照)](https://github.com/RuoJi6/ARTEX) | ◐ | ◐ | ◐ | ○ | ○ | ○ | ◐ | ◐ | ◐ | ○ | ○ | ○ | ○ | ✓ | ✓ |

## 3. 逐工具速览（许可证 / 活跃度 / 本地可跑 / 与 Trident 重叠差异）

本地可跑口径：`yes`=本任务 bench 实测；`limited`=可安装但需要集群/硬件/交互环境；`no`=硬件缺失。活跃度=GitHub API 2026-10-26 实查。

### ①集群安全扫描/审计

| 工具 | 许可证 | 活跃度（stars/最近 push/状态） | 本地可跑 | 与 Trident 重叠·差异 |
|---|---|---|---|---|
| [kube-hunter](https://github.com/aquasecurity/kube-hunter) | Apache-2.0 | 5086 / 2024-03-19 / 维护停滞：README 声明不再积极开发并推荐迁移 Trivy | `yes` pip 安装；bench 中对本机 mock 端点实测 8 findings | trident/modules recon 族已有 kube-hunter 检查模块（29 检查映射）；CVE/VID 知识库重叠度高，但其主动利用能力弱于 Trident 权限链模块 |
| [kube-bench](https://github.com/aquasecurity/kube-bench) | Apache-2.0 | 8237 / 2026-10-19 / 活跃 | `limited` 仅 linux 二进制/容器；bench 在 QEMU TCG k3s guest 内 docker 实跑（自动选中 k3s-cis-1.9，中位 58.00s） | CIS 合规映射与 Trident 报告「合规映射」章节互补；Trident 无逐项 CIS 检查引擎，靠 findings→条款映射（trident/reports/compliance.py），对齐点=规则库差异 |
| [Kubescape](https://github.com/kubescape/kubescape) | Apache-2.0 | 11822 / 2026-10-25 / 活跃（CNCF 沙箱） | `yes` Windows 二进制可跑；本任务 bench 名单未含，未实测（避免与 kube-bench/Trivy 重复计费） | 框架扫描（NSA/CISA+CIS+ARMO 调olibrary）与 Trident recon 模块族同面；其 RBAC 可视化对应 trident privesc matrix 的输入面 |
| [Trivy](https://github.com/aquasecurity/trivy) | Apache-2.0 | 38715 / 2026-10-23 / 活跃 | `yes` Windows 二进制；bench 实测 fs（fixtures 86 misconfig+2 secret）与 k8s（live k3s 86 misconfig） | CVE 扫描/SBOM 与 trident supplychain.py（CycloneDX ML-BOM）互补；镜像/依赖 CVE 面 Trident 走版本矩阵+applicability，Trivy 走漏洞库——两条路线并行 |
| [KubeHound](https://github.com/DataDog/KubeHound) | Apache-2.0 | 1013 / 2026-10-21 / 活跃 | `limited` 需 K8s 采集 + MongoDB 后端；本机未部署（bench 未跑原因：无 mongo） | 25 条攻击边图数据库 vs Trident privesc graph（47 向量自动选路）——同为图路径思路，KubeHound 靠 Gremlin 查询、Trident 内嵌 DFS+BFS 纯 Python |
| [kubeaudit](https://github.com/Shopify/kubeaudit) | MIT | 1936 / 2024-08-21 / 已归档（2024-08） | `yes` 二进制可跑；bench 未含（归档项目） | 20+ 安全控制审计点已被 Trident recon/硬ening 规则（Kyverno/Gatekeeper 包）覆盖并超越（含 ML 面专属规则） |
| [KubiScan](https://github.com/cyberark/KubiScan) | GPL-3.0 | 1434 / 2025-05-25 / 低频维护 | `limited` 面向集群内 pod 运行（python）；需 kubeconfig/service account；bench 未跑（与 Trivy RBAC 面重叠） | risky RBAC 枚举（cluster-admin/通配/exec）与 trident privesc 模块族同覆盖；Trident 多了利用验证+回滚 |
| [kdigger](https://github.com/quarkslab/kdigger) | Apache-2.0 | 490 / 2025-11-07 / 低频维护 | `limited` 需在 pod 内跑 linux 二进制（bench 未跑：无受害 pod 执行环境；Trident 已有 20 bucket 模块映射） | pod 内态势感知 20 bucket 已映射进 Trident（agent-architecture 任务 21 新模块之一）；admission 六模板→Trident 规则包 |
| [Peirates](https://github.com/inguardians/peirates) | GPL-2.0 | 1487 / 2026-10-25 / 活跃 | `limited` 交互式 CLI，需在拿到 pod/凭据后使用；bench 未跑（交互式工具不适合自动化计时口径） | 37 个攻击原语（exec/pod-create/secret 读取/token 伪造）与 Trident 权限链+提权矩阵同面；Peirates 是人工交互式、Trident 是编排验证式 |
| [CDK](https://github.com/cdk-team/CDK) | Apache-2.0 | 4779 / 2026-05-01 / 低频维护 | `limited` linux 静态二进制，pod/容器内运行；bench 未跑（同 kdigger 原因） | 30 检测/13 利用分类已映射（Trident 21 新模块之一）；CDK 的容器逃逸 CVE 一键利用对应 Trident CVE arsenal 50 条的子集+版本闸门 |

### ②模型/推理安全测试

| 工具 | 许可证 | 活跃度（stars/最近 push/状态） | 本地可跑 | 与 Trident 重叠·差异 |
|---|---|---|---|---|
| [ModelScan](https://github.com/protectai/modelscan) | Apache-2.0 | 788 / 2026-09-28 / 活跃 | `yes` pip 安装；bench 实测 8/8 恶意检出 0 误报，0.26s/轮 | 权重反序列化面 Trident 有 pickle 链模块（fabric/kv/poison 系列）+供应链 verify-model；ModelScan 的多格式（pkl/pt/h5/safetensors）扫描器是 Trident 缺的独立扫描件 |
| [Fickling](https://github.com/trailofbits/fickling) | LGPL-3.0 | 675 / 2026-10-23 / 活跃 | `yes` pip；bench 实测 7/8 检出（torch zip 不支持）、1 误报（未知全局类保守判定）、逐文件 CLI | 同上（反序列化静态分析）；其反编译+注入能力（-i 注入）是研究向工具，Trident 不做注入只做检测 |
| [picklescan](https://github.com/mmaitre314/picklescan) | MIT | 429 / 2026-10-20 / 活跃 | `yes` pip；bench 实测 7/8 检出（漏 __import__）、0 误报、最快（0.17s） | HF 生态反病毒式扫描；作为 Trident verify-model 的可选外接引擎（当前未集成） |
| [garak](https://github.com/NVIDIA/garak) | Apache-2.0 | 9699 / 2026-10-23 / 活跃（NVIDIA 官方） | `yes` pip 安装；需要 generator 端点（OpenAI 兼容即可）；bench 未含（名单外，且探测轮次大、与 promptfoo 定位重叠） | LLM 探测器族（injection/leak/jailbreak）vs Trident aigateway 10 模块——garak 是模型行为面、Trident 是网关/基础设施面，互补 |
| [PyRIT](https://github.com/microsoft/PyRIT) | MIT | 4687 / 2026-10-25 / 活跃（MSRC 官方） | `yes` pip；需目标端点+（部分攻击）Azure OpenAI；bench 未含（名单外） | 多轮攻击编排（Crescendo/TAP）+ 评分器思想与 trident explorer（审批制自主探索）同型；PyRIT 面向模型红队、Trident 面向基础设施 |
| [promptfoo](https://github.com/promptfoo/promptfoo) | MIT | 26424 / 2026-10-26 / 非常活跃 | `yes` npm；bench 实测本地 echo provider 12/12 断言通过（热启 2.1s/轮） | 声明式矩阵评测+CI 是 Trident 报告评测缺的件；red-team 插件与 Trident aigateway 模块互补 |
| [Giskard](https://github.com/Giskard-AI/giskard) | Apache-2.0 | 5923 / 2026-10-25 / 活跃 | `yes` pip；扫描需 LLM API key（本机离线环境无外部 API，bench 未跑原因：目标不可达） | 质量+安全双面扫描器；其 scan() API 思路可与 Trident verify-effects 挂钩（未实施） |
| [DeepTeam](https://github.com/confident-ai/deepteam) | Apache-2.0 | 3050 / 2026-10-23 / 活跃 | `yes` pip；攻击生成需 LLM 端点（离线环境无外部 API，bench 未跑原因同 Giskard） |  deepeval 系红队（攻击库+漏洞分类）与 garak/PyRIT 同面；Trident 不做模型行为红队 |

### ③网络 fabric/基础设施测试

| 工具 | 许可证 | 活跃度（stars/最近 push/状态） | 本地可跑 | 与 Trident 重叠·差异 |
|---|---|---|---|---|
| [nccl-tests](https://github.com/NVIDIA/nccl-tests) | BSD-3-Clause | 1680 / 2026-10-05 / 活跃 | `no` 需 CUDA GPU + NCCL 库（本机无 NVIDIA GPU；QEMU guest 无 GPU 直通），bench 未跑原因：硬件缺失 | 集合通信带宽基线（algbw/busbw）+ -c 校验和是 Trident fabric 模块的对照基测；Trident 的 fabric_dos_sim 覆盖攻击面不覆盖性能基线 |
| [perftest (ib_write_bw/ib_read_lat...)](https://github.com/linux-rdma/perftest) | GPL-2.0 OR BSD-2-Clause（COPYING 双许可） | 1038 / 2026-10-21 / 活跃 | `no` 需 RDMA NIC（ibverbs）；本机无 RDMA 硬件，bench 未跑原因：硬件缺失 | RDMA 逐链路延迟/带宽矩阵=Trident rail/多平面 fabric-sim 的真实硬件对标（未达成项）；--validate 校验和思想与 Trident silent-corruption 检测同型 |
| [ibdiagnet (NVIDIA MFT)](https://docs.nvidia.com/ibdiagnet-infiniband-fabric-diagnostic-tool-user-manual-v2-8.pdf) | 随 NVIDIA MFT 分发（非 GitHub 源码仓库；遗留开源副本 linux-rdma/infiniband-diags GPL-2 已归档 2019） | N/A（非 GitHub 分发） / 手册 v2.8（docs.nvidia.com，2026 核验） / 活跃（NVIDIA 官方文档持续更新） | `no` 需 InfiniBand fabric；本机无 IB 交换机/HCA，bench 未跑原因：硬件缺失 | 全网 fabric 扫描+错误计数+链路质量报告是 Trident 最大的 fabric 诊断缺口（Trident 只有 fixture 级遥测读取）；NVIDIA/MFT 与 Mellanox/mft 两个 GitHub 名均 404，以官方手册为源 |
| [toxiproxy](https://github.com/Shopify/toxiproxy) | MIT | 12461 / 2026-10-20 / 活跃 | `yes` Windows 二进制；bench 实测 200ms 延迟 toxic 客户端实测 +228.5ms、timeout toxic 连接断开 | 网络损伤注入（latency/timeout/bandwidth/slow_connection）正是 Trident 扰动鲁棒缺口；与 trident explorer 的提案式注入天然对接（backlog 项） |
| [sonobuoy](https://github.com/vmware-tanzu/sonobuoy) | Apache-2.0 | 3049 / 2026-10-14 / 活跃（CNCF） | `limited` 单二进制可跑但需要目标集群执行插件；QEMU k3s 可跑 conformance 子集（bench 名单外未跑：非安全扫描口径） | 诊断数据聚合框架（插件化 AGENTS）+ e2e 套件装载与 Trident 连续化扫描（scheduler）互补；Trident 不做 conformance |

### ④扰动鲁棒/混沌工程

| 工具 | 许可证 | 活跃度（stars/最近 push/状态） | 本地可跑 | 与 Trident 重叠·差异 |
|---|---|---|---|---|
| [Chaos Mesh](https://github.com/chaos-mesh/chaos-mesh) | Apache-2.0 | 7950 / 2026-10-24 / 活跃（CNCF 毕业项目） | `limited` 需 K8s 集群部署 CRD+controller（QEMU k3s 理论可装但 TCG 太慢；bench 未跑原因：部署面大） | CRD 声明式故障实验（NetworkChaos/StressChaos/IOChaos/PodChaos/TimeChaos）覆盖 Trident 全部扰动缺口；workflow 串实验与 Trident 链编排同型但目标相反（韧性验证 vs 攻击验证） |
| [LitmusChaos](https://github.com/litmuschaos/litmus) | Apache-2.0 | 5730 / 2026-10-21 / 活跃（CNCF 孵化） | `limited` 需 K8s + portal（bench 未跑原因同 Chaos Mesh） | chaoshub 实验市场+调度+韧性探针（probe 前后验证）与 Trident「紫队验证」同一方法论；可作为 Trident 检测规则的验证执行器（backlog） |
| [Chaos Toolkit](https://github.com/chaostoolkit/chaostoolkit) | Apache-2.0 | 2034 / 2026-10-05 / 活跃 | `yes` pip 安装；bench 实测本地进程实验 2/2 检测到稳态破坏（journal 证据） | steady-state-hypothesis→method→journal 的证据结构与 Trident 三层证据库同型；python/process/http provider 可直接包装 Trident 模块作为混沌动作（backlog：robustness 套件） |
| [Pumba](https://github.com/alexei-led/pumba) | Apache-2.0 | 3179 / 2026-10-21 / 低频维护 | `limited` Go 二进制，对 docker 容器注入（本机无 docker 守护进程；bench 未跑原因：无容器运行时） | 容器级 stop/kill/pause + netem（延迟/丢包）；对 Trident 训练 Pod 扰动实验是最轻量的执行器之一（backlog 项） |
| [tc/netem (iproute2)](https://wiki.linuxfoundation.org/networking/iproute2) | GPL-2.0 (iproute2) | N/A（非 GitHub 分发） / 随 Linux 内核/iproute2 持续更新 / 内核自带标准件 | `limited` Linux 内核能力；Windows 宿主不可用（本机 WSL2 不可用），可在 QEMU guest/pod 内用（bench 未跑原因：需在目标 netns 内执行） | 延迟/丢包/重复/损坏/乱序+速率抖动是损伤注入的最底层原语；Chaos Mesh/Pumba 都封装它；Trident 若补网络损伤应以参数化 netem 配置生成为形态（不执行） |
| [DCGM diag (dcgmi diag)](https://github.com/NVIDIA/DCGM) | Apache-2.0 | 808 / 2026-10-21 / 活跃 | `no` 需 NVIDIA GPU + 驱动（本机无 GPU；bench 未跑原因：硬件缺失） | GPU 健康三级诊断（quick/medium/long：ECC/内存压力/NVLink/PCIe/fabric 一致性）是 Trident GPU 故障注入缺口的官方对标件；dcgmi diag -r 12 注入能力（memory error injection）可与 Trident GPU 模块联动 |

### ⑤训练框架测试套件

| 工具 | 许可证 | 活跃度（stars/最近 push/状态） | 本地可跑 | 与 Trident 重叠·差异 |
|---|---|---|---|---|
| [PyTorch distributed tests (test/distributed_*)](https://github.com/pytorch/pytorch/tree/main/test) | BSD-3-Clause + PATENTS（GitHub API license=NOASSERTION，以仓库 LICENSE/PATENTS 文件为准） | 105080 / 2026-10-26 / 非常活跃 | `limited` torch 已装（CPU）；distributed 套件需多进程/多 NIC/GPU 才有意义，单机 CPU 仅可跑子集（bench 未跑原因：无 GPU/多节点） | c10d/NCCL/Gloo 集合与容错测试（elastic agent 重启、rendezvous）是训练栈韧性的官方基线；Trident trainstack_sim 攻击面与其防御验证互补 |
| [Ray test suite (ray/test, ray/serve/test)](https://github.com/ray-project/ray) | Apache-2.0 | 44122 / 2026-10-26 / 非常活跃 | `limited` pip 装 ray 可跑单机子集；套件需 pytest 集群夹具与多 worker（bench 未跑原因：范围过大且非本任务口径） | Ray 控制面（8265）无鉴权等面已有 Trident 专用模块（ray-control-plane）；ray 自身 fault-tolerance 测试（GCS 重启/actor 故障）是韧性官方基线 |
| [DeepSpeed tests (tests/unit, tests/comm)](https://github.com/deepspeedai/DeepSpeed) | Apache-2.0 | 43273 / 2026-10-26 / 活跃 | `limited` pip 装 deepspeed 可跑 CPU 单卡子集；comm/NCCL 测试需多 GPU（bench 未跑原因：硬件缺失） | Megatron/DeepSpeed 配置面攻击（config 注入/优化器状态投毒）Trident 有专模块；DeepSpeed 通信组一致性测试是其防御侧对照 |

### ⑥自主渗透 agent 参照

| 工具 | 许可证 | 活跃度（stars/最近 push/状态） | 本地可跑 | 与 Trident 重叠·差异 |
|---|---|---|---|---|
| [XBow (参照)](https://xbow.com/) | 商业闭源 SaaS（无公开代码仓库；GitHub xbow-com/xbow 404 已核验） | N/A（非 GitHub 分发） / - / 商业运营（自主渗透赛道头部） | `no` 云端 SaaS；只能以公开材料对标（COMPETITIVE-MATRIX 已做功能对位） | 自主渗透 agent 商业标杆（漏洞→验证→报告闭环自主性）；Trident 以「提议-审批-确定性执行」差异化（REFLECTION-XBOW-ARTEX-KUBETRAIL.md 已对齐 8 项） |
| [ARTEX (参照)](https://github.com/RuoJi6/ARTEX) | AGPL-3.0（仅黑盒对标，零代码复用） | 656 / 2026-10-26 / 活跃（开源维护版） | `yes` QEMU guest docker 已实测（ARTEX-BENCH-RESULT.md：冷启 37.85s、空闲 RSS 169.8MiB、同靶场 13510ms vs Trident 105.6ms） | 多 agent 自主渗透开源对标（llmpool/审批/工作区）；Trident 已做 8/8 clean-room 功能族对齐 + 同靶场性能对比 |

## 4. 差距 backlog（S/M/L × 对应模块/功能键）

只登记不实施。编号 OSS-S*（小）/ OSS-M*（中）/ OSS-L*（大），对应模块/功能键为建议落点（与 COMPETITIVE-MATRIX 的 33 项 backlog 独立编号，无重复）。

| 编号 | 尺寸 | 缺口（类别） | 内容 | 对应模块/功能键 |
|---|---|---|---|---|
| OSS-S1 | S | ④ 网络损伤 | 网络损伤参数生成器：把 toxiproxy toxic/netem 参数（latency±jitter/loss/dup/corrupt/partition/timeout）物化为**只读配置工件**（toxic JSON + tc 命令行文本），供 explorer 审批式提案引用——平台不直接执行，输出给授权人工在目标 netns 内执行 | `trident/core/impairment.py`（新）；explorer 提案类型 `netem-preset` |
| OSS-S2 | S | ④ 混沌编排 | Chaos Toolkit 实验导出：把 Trident 链/检测规则探针转成 chaos experiment JSON（稳态=规则重放探针 + method=破坏动作占位），复用 journal 证据结构 | `trident/export.py::chaos_experiment` |
| OSS-S3 | S | ② 模型扫描 | 模型扫描器外接适配：modelscan/picklescan/fickling JSON 结果→Trident findings（供 `verify-model` 与供应链报告消费） | `trident/supplychain.py::modelscan_adapter` |
| OSS-S4 | S | ② LLM 评测 | promptfoo 配置导出：aigateway 10 模块的 case→promptfoo.yaml + 断言（本地 mock provider），CI 回归模型行为面 | `trident/export.py::promptfoo_config` |
| OSS-M1 | M | ④ 韧性闭环 | 检测规则→混沌验证：注入扰动后断言 Suricata/Falco 规则命中（紫队矩阵新增 robustness 列：损伤类型×规则检测态） | `trident/validate.py::robustness` |
| OSS-M2 | M | ④ GPU 诊断 | DCGM 诊断采集适配：dcgmi diag JSON/DCGM exporter 遥测只读解析→GPU 健康级 findings（ECC/Xid/NVLink/温度） | `trident/modules/gpu-diag-ingest` |
| OSS-M3 | M | ③ fabric 基线 | fabric 性能基线解析：nccl-tests（algbw/busbw）与 perftest（ib_write_bw/ib_read_lat）输出解析→rail 基线库，与 fabric-sim 期望值对比出偏差 findings | `trident/fabric_baseline.py` |
| OSS-M4 | M | ③ fabric 诊断 | fabric 遥测采集适配：ibdiagnet 报告/infiniband-diags 计数器（symbol error/port discard）+ SONiC 计数器→fabric findings（只读） | `trident/modules/fabric-diag-ingest` |
| OSS-M5 | M | ③ 诊断聚合 | sonobuoy 结果接入：sonobuoy 归档 tar→run evidence 归档（诊断插件结果作为证据链一层） | `trident/evidence.py::sonobuoy_ingest` |
| OSS-L1 | L | ④ 扰动鲁棒 | 扰动鲁棒编排套件（robustness profile）：网络损伤×GPU 故障×进程杀×IO 慢的组合场景库+验收判据+审批闸门（复用 backup/ROE 三闸门），一次跑出韧性评分 | `trident/objective.py::robustness-suite` |
| OSS-L2 | L | ④ GPU 故障注入 | GPU 故障注入面：Xid/ECC/MIG 错配/显存残留模拟扩展 + dcgmi diag -r 注入在真机联动（需真实 NVIDIA GPU，本机不可验证） | `trident/modules/gpu-fault-injection` |
| OSS-L3 | L | ④ 混沌编排 | K8s 混沌执行器对接：Chaos Mesh/Litmus CRD 生成器（NetworkChaos/StressChaos/PodChaos 实验物化+结果回收），需 live 集群 | `trident/chaos_crd.py` |

合计 **12 项（S 4 / M 5 / L 3）**。五类覆盖现状小结：

- **① 集群扫描**：Trident 已强（recon/privesc/CVE arsenal/规则转化），无新增 backlog；CIS 逐项引擎缺口以合规映射章节约束（非本任务新增）。
- **② 模型/推理**：Trident 做网关/基础设施面，模型行为面靠外接（OSS-S3/S4）。
- **③ fabric/基础设施**：Trident 只有 fixture 级遥测与仿真，**性能基线与全网诊断是最大缺口**（OSS-M3/M4/M5）。
- **④ 扰动鲁棒**：Tridian 目前仅有 fabric_dos_sim 攻击面仿真与 verify-effects，**无任何损伤注入/混沌编排能力**（OSS-S1/S2/M1/L1/L2/L3）——本全景最核心差距。
- **⑤ 训练框架测试**：官方套件即防御侧基线，Trident 以攻击面仿真互补；对齐项并入 OSS-M3（基线解析）。

## 5. 与既有对标文档的关系

- 竞品功能矩阵（自主渗透/K8s 攻防/运行时准入）：`COMPETITIVE-MATRIX.md`（23 工具×18 维，S13/M17/L3 backlog）
- 同靶场实测（ARTEX vs Trident）：`ARTEX-BENCH-RESULT.md`；企业就绪：`ENTERPRISE-READINESS.md`
- 本文新增的维度是**测试工具侧**（fabric 诊断/混沌/性能基线/训练栈），与竞品矩阵（攻击平台侧）互补不重叠。

## 6. 性能实测

见 [OSS-BENCH.md](OSS-BENCH.md)：10 项 bench（7 工具）同 fixture/同目标实测耗时/RSS/输出量/检出率/误报；跑不了的逐项写明原因（本节速览表 `local_runnable` 列即原因索引）。
