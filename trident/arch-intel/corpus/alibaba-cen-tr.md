# 阿里云 CEN — 云企业网/转发路由器（混合互联）

- 分类：混合云互联与边界
- 组织 / 系统：Alibaba Cloud / Cloud Enterprise Network（CEN）+ Transit Router（TR）
- 核验日期：2026-10-25；核验状态：verified（阿里云帮助中心全文）

## 来源
- https://help.aliyun.com/zh/cen/product-overview/what-is-cen/

## 架构要素
- 组网：全球私网骨干；TR=地域级核心网元（每地域 1 个）；挂载 VPC/ECR/边界路由器 VBR/IPsec/CCN
- 隔离边界：TR 路由表关联转发实现互通/隔离策略；自定义路由策略可做安全域隔离、统一 DMZ、服务链
- 身份：云账号/跨账号授权（RAM）
- 存储：不直接（网络层）
- 通信：同地域线速、跨地域按带宽/QoS
- 管理面：CEN 控制台/OpenAPI
- 多租户：跨账号 VPC 互联（企业多账号架构）
- 云集成点：专线（VBR/ECR）+ VPN + PrivateLink（另条目）组合

## 安全问题点（放大前提 × 模块机器键）
- 私网互联放大平网：本地 IDC ↔ VPC 一旦打通，集群管理面直接暴露给内网任意位置 → `hybrid-cloud-egress-pivot`
- 路由学习/传播错配：错误关联=跨安全域可达 → `cni-aware-reachability-graph`（跨集群维）
- 跨地域通道：横向数据外带通道（egress 审计盲区）→ `metadata-egress`

## 横向思路
- 云内立足 → 探 CEN 边界 → 若路由传播过宽 → 直接触达客户 IDC 管理段 → 混合回旋（IDC→另一 VPC）
