# Microsoft — Inside the World's Most Powerful AI Datacenter（Fairwater Wisconsin）

- 分类：official-en（外文官方源）
- 组织 / 系统：Microsoft Azure / Fairwater Wisconsin AI 数据中心
- 源类型：engineering-blog（blogs.microsoft.com，2025-09-18，Scott Guthrie）
- 核验日期：2026-10-25；核验状态：verified（webfetch 官方博文全文直读，原句摘录）

## 来源
- https://blogs.microsoft.com/blog/2025/09/18/inside-the-worlds-most-powerful-ai-datacenter/

## 万卡证据（原文摘录）
- ✅ "this datacenter is built to work as one massive AI supercomputer using a single flat networking interconnecting hundreds of thousands of the latest NVIDIA GPUs."
- ✅ "This datacenter runs a single, massive cluster of interconnected NVIDIA GB200 servers and millions of compute cores and exabytes of storage."

## 网络要素
- 组网原句："Azure uses both InfiniBand and Ethernet fabrics that deliver 800 Gbps, in a full fat tree non-blocking architecture to ensure that every GPU can talk to every other GPU at full line rate without congestion."
- 拓扑：两层楼 3D 机架布局缩短线缆/时延；ToR→pod→DC 分层
- ops：闭环液冷（全球第二大水冷冻厂）、Blob 存储 2M+ TPS/BlobFuse2

## 架构要素
- 组网：GB200 rack（72 GPU NVLink 1.8TB/14TB 共享内存）+ IB/以太 800G fat-tree + AI WAN
- 隔离边界：单集群全互通（fat tree non-blocking 按设计）

## 安全问题点（放大前提 × 模块机器键）
- fat-tree 全线速互通+“无拥塞”设计=性能型攻击需走协议层而非链路层 → `collective-communication-surface`
- 存储/算力分离数据中心=checkpoint 大通道 → `shared-volume-weight-copy`
- IB+以太双栈并存双旁路 → `multus-sriov-rdma-bypass`

## 横向思路
- 混栈识别（IB GID vs 以太 RDMA）→ 双面入组验证；Blob/AI WAN 边界做数据外带路径
