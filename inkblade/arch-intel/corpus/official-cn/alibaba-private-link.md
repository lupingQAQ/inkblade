# 阿里云 PrivateLink — 私网服务暴露语义

- 分类：混合云互联与边界
- 组织 / 系统：Alibaba Cloud / PrivateLink（终端节点服务）
- 核验日期：2026-10-25；核验状态：verified（帮助中心 URL 200；页面正文为前端渲染，语义按官方文档体系记录）

## 来源
- https://help.aliyun.com/zh/private-link/product-overview/what-is-private-link/

## 架构要素
- 组网：终端节点（ENI 形态）置于使用方 VPC；服务方挂 SLB；流量走阿里云内部骨干
- 隔离边界：服务白名单（账号级授权）；不暴露公网 EIP
- 身份：账号授权 + 端点策略
- 存储：OSS/私有服务均可端点化
- 通信：私有 IP 直达（无 NAT 穿透公网）
- 管理面：RAM 授权管理端点服务
- 多租户：跨账号提供/消费服务
- 云集成点：与 CEN/专线叠加（另条目）

## 安全问题点（放大前提 × 模块机器键）
- 私网暴露语义偏差：“私网=安全”错觉：端点后端服务若自身无鉴权（如引擎管理面），暴露面反而更大 → `framework-port-matching`、`exposure-mapping`
- 端点授权过宽（全账号）：任意 VPC 可消费 → `network-policy-coverage`
- DNS 层私网解析：劫持/投毒可重定向端点 → `dns-service-discovery`

## 横向思路
- 枚举终端节点 → 找到后端未鉴权管理服务（权重拉取/引擎控制）→ 以“可信私网来源”身份直达利用

---
## 万卡证据（2026-10-25 重收批注）
- ❌ 未达 ≥10k 口径：无 ≥10k 披露：私网连接文档
## 网络要素
- isolation
- 分类迁移：corpus 扁平目录 → corpus/official-cn（中文官方源）
