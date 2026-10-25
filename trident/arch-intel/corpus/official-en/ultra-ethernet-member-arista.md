# Arista《Demystifying Ultra Ethernet》— UEC 成员视角白皮书

- 分类：official-en（外文官方源）
- 组织 / 系统：Aista Networks（UEC 创始成员）/ Etherlink 对 UET 的实现
- 核验日期：2026-10-25；核验状态：verified（Arista 官方博客直读，2026-10-16 更新）

## 来源
- https://blogs.arista.com/blog/demystifying-ultra-ethernet

## 万卡证据（原文摘录）
- ➖（本源为规范/漏洞/机制证据，非万卡规模实证；wanka_evidence=false）

## 网络要素
- congestion-control / isolation / multi-tenancy

## 架构要素
- UEC：100+ 成员公司、约 1000 参与者；UET（Ultra Ethernet Transport）把 RDMA 重塑为以太网原生应用
- 关键语义：>1M endpoint 扩展、原生乱序交付、逐包多路径（source-based packet spraying）、
  逐包丢包恢复、细粒度发送端/接收端拥塞控制（NSCC/RCCC）、语义级工作负载调优配置
- ULP：UET 实现 libfabric 2.0 API 的原生传输层，应用近零改造
- 安全：传统 RDMA 无原生安全；UET 把安全作为基础目标——**可选端到端加密与认证，
  基于组密钥方案（job/租户全体 XPUs 构成加密气泡 encrypted bubble）**，
  防跨租户数据注入与外带
- Arista Etherlink 自称 UET-ready

## 安全问题点（放大前提 × 模块机器键）
- 组密钥/加密为 optional：缺省部署无集合通信身份与机密性 → `nccl-collective-join`、`sharp-in-network-poison`
- 逐包 spray + 交换机在网计算：控制面（会话/路径编程）成为单点 → `roce-pfc-storm`
- libfabric 2.0 端点语义：rendezvous 端点枚举面扩大 → `nccl-port-exhaustion`

## 横向思路
- 「加密气泡」未启用即等价于明文 fabric：入组 + reduce 篡改 + 端口耗尽三连（fabric 两条链）
