# NVIDIA Spectrum-X — AI 以太网平台（multiplane/128K GPU/性能隔离）

- 分类：official-en（外文官方源）
- 组织 / 系统：NVIDIA / Spectrum-X Ethernet（Spectrum-4/SN5600 + BlueField-3 SuperNIC；Spectrum-XGS 跨 DC）
- 源类型：vendor-docs（nvidia.com 官方平台页，2026-10-25 抓取）
- 核验日期：2026-10-25；核验状态：verified（webfetch nvidia.com 官方平台页直读，原句摘录）

## 来源
- https://www.nvidia.com/en-us/networking/spectrumx/

## 万卡证据（原文摘录）
- ✅ "NVIDIA Spectrum-X Ethernet makes the colossal NVIDIA Hopper 100,000-GPU system possible."（xAI Colossus 系统）
- ✅ "Spectrum-X Ethernet switches deliver high effective bandwidth and performance isolation for AI factories, scaling infrastructure to hundreds of thousands of GPUs."
- ✅ "Spectrum-X multiplane enables Ethernet to scale from thousands to hundreds of thousands of GPUs using a flat, two-tier topology." / "scales Spectrum-X Ethernet networks up to 128K GPUs in two tiers—64x more than single-plane networks."

## 网络要素
- multi-plane（多平面以太，平网两级拓扑到 128K GPU）
- isolation：performance isolation（性能隔离）为平台显式能力
- congestion-control："Spectrum-XGS Ethernet uses a topology-aware congestion control algorithm, precise latency management, and end-to-end telemetry to deliver 1.9x higher NCCL performance in cross-data center environments."
- SONiC 支持（开放 NOS：SONiC 与 Cumulus）；Minerva 遥测优化 AI 工厂良率
- 跨 DC：Spectrum-XGS 跨楼宇/数百公里统一 AI 超工厂

## 架构要素
- 组网：Spectrum-4 交换 + BlueField-3 SuperNIC 400G RoCE；RoCE 扩展（adaptive routing 族能力）
- 管理：端到端遥测（GPU/NVLink/SuperNIC/DPU/调度器）

## 安全问题点（放大前提 × 模块机器键）
- 多平面平网拓扑：平面数=可旁路通道数（平面间无隔离语义）→ `fabric-topology-isolation`
- BlueField SuperNIC/DPU 可编程面=高端侧攻击/防御双面 → `gpu-network-operator-posture`
- XGS 跨 DC 统一域：跨站可达性设计默认全通 → `hybrid-cloud-egress-pivot`

## 横向思路
- 识别平面数与 rail 映射（多平面指纹）→ 单平面内横向 → NCCL 入组；DPU 侧滥用（可编程转发）为高阶面
