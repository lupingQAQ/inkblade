# 腾讯云 TKEStack — 多集群多租户容器平台

- 分类：云商 K8s GPU/加速器集群（平台形态）
- 云商 / 系统：Tencent / TKEStack（开源 TKE 平台）
- 核验日期：2026-10-25；核验状态：verified（GitHub README）

## 来源
- https://raw.githubusercontent.com/tkestack/tke/master/README.md

## 架构要素
- 组网：Galaxy 网络插件（TKE 体系）；平台-业务-网关分层架构
- 隔离边界：team/user 多租户隔离（容器、构建、网络通信）；项目=跨集群资源容器
- 身份：统一授权（到 K8s 资源级）+ 身份提供者插件
- 存储：事件/日志持久化插件
- 通信：平台控制面 ↔ 成员集群 API
- 管理面：Web 控制台 + CLI 集中管多集群
- 多租户：一等公民（team 隔离）
- 云集成点：腾讯云 TKE 产品（VPC-CNI/超级节点）

## 安全问题点（放大前提 × 模块机器键）
- 平台控制面=多集群横向枢纽：平台凭据/网关漏洞即跨集群横向 → `rbac-mapping`、`cloud-integration-fingerprint`
- 租户网络隔离由平台声明：需实测 Galaxy/NetworkPolicy 真实覆盖 → `network-policy-coverage`
- 多集群 API 集中暴露：网关 0.0.0.0/弱鉴权即全量租户面 → `exposure-mapping`

## 横向思路
- 打点平台网关/控制台 → 拿租户 token → 跨集群提交 GPU 负载 → 节点面逃逸链
