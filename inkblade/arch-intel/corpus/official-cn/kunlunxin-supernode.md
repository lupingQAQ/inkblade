# 昆仑芯超节点 — 单柜 32/64 卡全互联，支持万卡以上智算集群构建

- 分类：official-cn（中文官方源）
- 组织 / 系统：Kunlunxin（昆仑科技）/ 昆仑芯超节点
- 源类型：newsroom（昆仑科技官网新闻）
- 核验日期：2026-10-25；核验状态：verified（webfetch 官网新闻直读，原句摘录）

## 来源
- https://www.kunlunxin.com/news/4541.html

## 万卡证据（原文摘录）
- ✅ “机柜间支持IB/RoCE通信，可实现跨柜高带宽、低延迟的数据传输，支持万卡以上规模的智算集群构建。”

## 网络要素
- IB/RoCE 机柜间通信（跨柜高带宽低时延）；单柜内卡间全互联（带宽提升高达8倍）

## 架构要素
- 组网：超高密度单柜 32/64 张加速卡；机柜间 IB/RoCE；冷板式液冷整柜 120kW
- 隔离边界：柜内/柜外两级互联域
- 通信：全互联通信带宽 +8 倍

## 安全问题点（放大前提 × 模块机器键）
- IB/RoCE 跨柜 fabric 无内建认证：柜间可达即可 RDMA → `fabric-topology-isolation`、`multus-sriov-rdma-bypass`
- 超节点密度放大单点投毒影响域 → `privileged-gpu-pod-escape`

## 横向思路
- 柜内立足 → IB/RoCE 跨柜直达邻居 rank → 入组/RDMA 窃听（同 IB 链路思路）
