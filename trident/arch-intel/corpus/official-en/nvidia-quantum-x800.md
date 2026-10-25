# NVIDIA Quantum-X800 InfiniBand — 144×800G 与 SHARPv4

- 分类：official-en（外文官方源）
- 组织 / 系统：NVIDIA / Quantum-X800 InfiniBand 平台
- 核验日期：2026-10-25；核验状态：verified（nvidia.com 产品页直读，2026-10-25 更新）

## 来源
- https://www.nvidia.com/en-us/networking/products/infiniband/quantum-x800/
- https://nvidianews.nvidia.com/news/networking-switches-gpu-computing-ai

## 万卡证据（原文摘录）
- ➖（本源为规范/漏洞/机制证据，非万卡规模实证；wanka_evidence=false）

## 网络要素
- in-network-computing / congestion-control / isolation

## 架构要素
- 单交换机 144 端口 × 800 Gb/s；端到端 800G（对上代 2× 带宽、5× 吞吐、9× 在网计算）
- 硬件在网计算 SHARP v4；硬件自适应路由；基于遥测的拥塞控制与性能隔离
- ConnectX-8 SuperNIC 每 GPU 1.6 Tb/s；共封硅光版本面向数百万 GPU 与多站 AI 工厂
- UFM 管理端口 / 低功耗链路态 / 功耗画像等管理面能力

## 安全问题点（放大前提 × 模块机器键）
- SM/UFM 管理面单点：Partition/PKey 与会话配置可写即信任域可改 → `ib-subnet-manager-hijack`
- SHARPv4 在网聚合随每代扩大算法面：会话/贡献校验缺省依赖 NCCL 层身份 → `sharp-in-network-poison`
- 遥测拥塞控制：配置可写即集群级停摆调参面 → `roce-pfc-storm`

## 横向思路
- IB 面不受 NetworkPolicy 覆盖（见 ib-partition-advice）：SM/Partition 是唯一隔离手段，
  也是唯一攻击点 → `fabric-silent-corruption-chain` 第一步
