# Ultra Ethernet Consortium — UE Spec 1.1（2026-10-12）与 1.0.x 演进

- 分类：official-en（外文官方源）
- 组织 / 系统：Ultra Ethernet Consortium（UEC）/ Ultra Ethernet Specification
- 核验日期：2026-10-25；核验状态：verified（UEC 官网发布页 + 规范历史页直读）

## 来源
- https://ultraethernet.org/ultra-ethernet-consortium-releases-specification-1-1-advancing-ai-and-hpc-networking/
- https://ultraethernet.org/specification-history/
- https://ultraethernet.org/wp-content/uploads/sites/20/2026/01/UE-Specification-1.0.2-1.pdf

## 万卡证据（原文摘录）
- ➖（本源为规范/漏洞/机制证据，非万卡规模实证；wanka_evidence=false）

## 网络要素
- in-network-computing / congestion-control

## 架构要素
- 规范版本线：1.0（2025-06-11）→ 1.0.1（2025-09-05，RCCC 修正）→ 1.0.2（2026-01-28，CMS 拥塞控制修正）→ 1.0.3（2026-07-16）→ **1.1（2026-10-12，当前版）**
- 1.1 新增：scale-up 支持（UFH 统一转发头省 20B、Unified Local profile、write/read/atomic）；
  In-Network Collectives（INC，交换机在网 reduce，1GB 结果端点只发 1GB、约 2× 通信加速）；
  CSIG 4/8 字节 L2 遥测标签（瓶颈拥塞位置与幅度）；NSCC/RCCC 消费 CSIG；
  Programmable Congestion Management（PCM，可编程拥塞控制 API）
- 生态：OCP ESUN 1.0 已并入 UE v1.0 技术；UEC 与 OCP SUE-T / IEEE（CSIG 标准化）协作
- 1.0.x PDF 公开可下载（1.0.2 全文 2026-01-28）

## 安全问题点（放大前提 × 模块机器键）
- INC 把 all-reduce 语义推进交换机：会话/聚合树管理面成为新信任边界 → `sharp-in-network-poison`
- CSIG/PCM 可编程面：拥塞控制参数可编程即集群级 DoS 调参面 → `roce-pfc-storm`
- 规范安全为 optional（组密钥/加密气泡），落地缺省即无集合通信身份 → `nccl-collective-join`

## 横向思路
- 交换机侧在网 reduce 无作业身份 → 入组篡改梯度 → 训练静默损坏（`fabric-silent-corruption-chain`）
