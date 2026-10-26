# SONiC — 开放网络操作系统（SONiC Foundation / Linux Foundation）

- 分类：official-en（外文官方源）
- 组织 / 系统：SONiC Foundation（Linux Foundation 项目；Microsoft 发起）/ SONiC NOS
- 源类型：official-repo（sonicfoundation.dev 官方站 + Azure 官方博文）
- 核验日期：2026-10-25；核验状态：verified（webfetch sonicfoundation.dev 与 azure.microsoft.com 官方页直读，原句摘录）

## 来源
- https://sonicfoundation.dev/
- https://azure.microsoft.com/en-us/blog/sonic-the-networking-switch-software-that-powers-the-microsoft-global-cloud/

## 万卡证据（原文摘录）
- ❌ NOS 项目无 ≥10k 部署计数（生产规模佐证："Experience has taught us that with hundreds of datacenters and tens of thousands of switches"——Azure 官方博文原句，交换机级而非 GPU 级）

## 网络要素
- ops-fault-surface："SONiC offers a full suite of network functionality, like BGP and RDMA, that has been production-hardened in the data centers of some of the largest cloud service providers."（官方原句）
- SAI 抽象（SAI 2015 开源）；容器化模块化组件；Microsoft AI 超工厂交换机 OS（见 Fairwater 条目 SONiC 原句）

## 架构要素
- 组网：多厂商交换机/ASIC 上的统一 NOS；白盒解耦
- 管理面：容器化组件 + SDN 统一控制

## 安全问题点（放大前提 × 模块机器键）
- 交换机 OS 开源供应链：SONiC/SAI 镜像投毒=全 fabric 控制面 → `gpu-network-operator-posture`、`trust-remote-code-supply-chain`
- RDMA/BGP 全套生产硬化但 NOS 本身凭据模型薄弱（社区版）→ `exposure-mapping`

## 横向思路
- 白盒交换机指纹（SONiC 版本/gNMI 端口）→ 交换机管理面横向（fabric 控制面拿拓扑/改路由）
