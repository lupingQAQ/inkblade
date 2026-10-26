# NVIDIA NVLink Fusion — 半定制 scale-up 域（NVLink 6 / Vera Rubin NVL72）

- 分类：official-en（外文官方源）
- 组织 / 系统：NVIDIA / NVLink Fusion（GB300 NVL72 → VR200 NVL72 谱系）
- 核验日期：2026-10-25；核验状态：verified（nvidia.com NVLink Fusion 页直读，2026-10-25 更新）

## 来源
- https://www.nvidia.com/en-us/data-center/nvlink-fusion/
- https://developer.nvidia.com/blog/nvidia-nvlink-the-scale-up-network-for-ai-factories/（2026-07-20）

## 万卡证据（原文摘录）
- ➖（本源为规范/漏洞/机制证据，非万卡规模实证；wanka_evidence=false）

## 网络要素
- in-network-computing

## 架构要素
- NVLink Fusion 开放半定制：超大规模厂商/自研 XPU/CPU 接入 NVIDIA rack 级（MGX）架构
- NVLink 6：72 XPU 全互联，每 XPU 3.6 TB/s；路线图域规模至 1152
- NVLink 6 + NVLink Switch：单 NVL72 域 260 TB/s；SHARP FP8 支持 4× 带宽效率
- Vera Rubin NVL72 与 XPU rack 共享机柜/网络/散热/供电/管理；Annapurna 为首个 NVHBM 伙伴
- 生态分四类伙伴（CPU/自研芯片/技术/光互联）+ MGX XPU 设计与内存供应

## 安全问题点（放大前提 × 模块机器键）
- scale-up 域把 72 GPU 变单一故障域：健康/Xid 面可写即整 rack 复位 → `driver-reset-trigger`
- 在网 SHARP FP8 进入 NVLink 交换：节点内 all-reduce 同样有会话篡改面 → `sharp-in-network-poison`
- 半定制成员（自研 ASIC）接入即异构信任：域成员准入若无证明即冒充面 → `nccl-collective-join`

## 横向思路
- 一次 Xid 注入 → NVL72 整域复位 → 大作业回滚到 checkpoint：低成本高破坏（`fabric-exhaustion-chain`）
