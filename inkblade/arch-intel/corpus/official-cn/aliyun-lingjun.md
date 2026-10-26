# 阿里云灵骏智算集群 — 十万卡级 HPN 高性能网络

- 分类：official-cn（中文官方源）
- 组织 / 系统：Alibaba Cloud / 智能计算灵骏（PAI-Lingjun）
- 源类型：vendor-docs（官方产品页 + 帮助文档）
- 核验日期：2026-10-25；核验状态：verified（webfetch 官方产品页与帮助中心直读，原句摘录）

## 来源
- https://www.aliyun.com/product/lingjun
- https://help.aliyun.com/zh/intelligent-computing-lingjun/what-is-lingjun-intelligent-calculation-service

## 万卡证据（原文摘录）
- ✅ “灵骏支持十万卡级的高性能网络扩展能力，单任务可支持万卡规模扩展性”（灵骏简介，阿里云帮助中心）
- ✅ “灵骏采用高性能网络架构（HPN, High Performance Network）解决扩展性难题，单层网络可以实现千卡级扩展，两层网络可以实现万卡级扩展”（同上）

## 网络要素
- multi-plane：HPN 单层/两层网络分级扩展语义；rail-optimized（多级亲和性与拓扑感知调度）

## 架构要素
- 组网：HPN 单层千卡 / 两层万卡扩展；产品页称“训推融合的超大规模集群”
- 隔离边界：集群级多租户（Serverless/单租/混合云形态）
- 通信：万卡并行、分钟级故障自愈
- 管理面：运维管控 + 集群任务管理一体
- 云集成点：PAI 灵骏（公共云 Serverless）

## 安全问题点（放大前提 × 模块机器键）
- 万卡级 fabric 无租户级网络身份：HPN 平面内可达即通信面暴露 → `collective-communication-surface`
- 拓扑感知调度信息=拓扑泄露面：调度 API 可反推 rail/平面布局 → `observability-exposure`、`fabric-topology-isolation`
- 多租 Serverless 形态的租户隔离依赖平台策略而非 fabric 本身 → `network-policy-coverage`

## 横向思路
- 立足 PAI 控制面 → 查询集群拓扑/任务布局 → 定位万卡任务关键 rank → fabric 面预留（见 gen-26 fabric 平面模块族）
