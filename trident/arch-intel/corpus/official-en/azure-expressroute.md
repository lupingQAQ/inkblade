# Azure ExpressRoute — 混合专线边界

- 分类：混合云互联与边界
- 组织 / 系统：Microsoft Azure / ExpressRoute
- 核验日期：2026-10-25；核验状态：verified（Microsoft Learn 概览页）

## 来源
- https://learn.microsoft.com/en-us/azure/expressroute/expressroute-introduction

## 架构要素
- 组网：运营商专线连 Azure；Private Peering（VNet）、Microsoft Peering（公有服务）、Office 365 专用
- 隔离边界：物理专线+路由域分隔（对等隔离）；NSG/防火墙仍需自配
- 身份： ExpressRoute Circuit 归订阅（ARM 授权）
- 存储：经由 private endpoint 的存储流量
- 通信：BGP 会话（客户边缘↔微软边缘）
- 管理面：ARM/门户
- 多租户：多 VNet 挂载（premium 全局接入）
- 云集成点：与 VNet 对等/VPN 共存、Private Link 组合

## 安全问题点（放大前提 × 模块机器键）
- Microsoft Peering 范围过宽=内网直达云控制面 API：横向链缩短 → `hybrid-cloud-egress-pivot`
- 管理面（BGP/线路授权）错配：非预期边 disclosing → `cloud-integration-fingerprint`
- 借道 Azure 公有服务对等做匿名回旋（源=微软骨干）→ `metadata-egress`

## 横向思路
- IDC 立足 → private peering 进 VNet → AKS 管理段；反向：云内 → 经 ExpressRoute 回 IDC AD/文件服务器

---
## 万卡证据（2026-10-25 重收批注）
- ❌ 未达 ≥10k 口径：无 ≥10k 披露：专线文档
## 网络要素
- isolation
- 分类迁移：corpus 扁平目录 → corpus/official-en（外文官方源）
