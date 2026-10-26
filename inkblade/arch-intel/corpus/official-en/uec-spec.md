# Ultra Ethernet Consortium — UE Specification 1.0 / 1.1（官方规范）

- 分类：official-en（外文官方源）
- 组织 / 系统：Ultra Ethernet Consortium（Linux Foundation）/ UE Spec 1.0（2025-06-11）与 1.1（2026-10 更新）
- 源类型：official-repo/spec（ultraethernet.org 官方公告与规范）
- 核验日期：2026-10-25；核验状态：verified（webfetch ultraethernet.org 官方公告直读，原句摘录）

## 来源
- https://ultraethernet.org/ultra-ethernet-consortium-uec-launches-specification-1-0-transforming-ethernet-for-ai-and-hpc-at-scale/
- https://ultraethernet.org/ultra-ethernet-consortium-releases-specification-1-1-advancing-ai-and-hpc-networking/
- https://ultraethernet.org/specification-history/（1.0.2 2026-01-28：CMS 拥塞控制算法定正）

## 万卡证据（原文摘录）
- ⚠️ 规模目标口径（非部署）："End-to-End Scalability – From routing and provisioning to operations and testing, UEC scales to millions of endpoints."——如实标注为目标宣称

## 网络要素
- in-network-computing："In-Network Collectives that offload compute to the network"（1.1，INC，广播聚合最高 2x 加速）
- congestion-control："Congestion Signaling (CSIG) for congestion control and telemetry"+"Programmable Congestion Management (PCM)"；NSCC/RCCC 消费 CSIG 遥测（4/8 字节 L2 in-band tag）
- 面向 scale-up 的多优化；UE Transport 增强

## 架构要素
- 组网：完整以太通信栈（NIC/交换/光/缆多厂商互操作）；Modern RDMA for Ethernet and IP
- 演进：1.0（2025-06）→ 1.0.2（2026-01，拥塞算法定正）→ 1.1（2026-10）

## 安全问题点（放大前提 × 模块机器键）
- INC 在网聚合：与 SHARP 同族的在网计算攻击面（交换机内聚合）→ `collective-communication-surface`
- CSIG in-band 遥测可伪造：注入虚假拥塞信号扰动全部 CC 算法 → `fabric-topology-isolation`（性能攻击）
- 多厂商互操作=供应链面扩大 → `trust-remote-code-supply-chain`

## 横向思路
- UEC 落地后“标准以太+INC”环境：伪造 CSIG/INC 报文即协议层扰动面；规范条目作为 gen-26 fabric 面模块的威胁基线
