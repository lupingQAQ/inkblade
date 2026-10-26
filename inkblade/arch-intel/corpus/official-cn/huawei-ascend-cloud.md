# 华为云昇腾云服务 — 最大 16 万卡集群 / 超节点总线互联

- 分类：official-cn（中文官方源）
- 组织 / 系统：Huawei Cloud / 昇腾云服务（CloudMatrix384 超节点底座）
- 源类型：vendor-docs（华为云官方产品页）
- 核验日期：2026-10-25；核验状态：verified（webfetch 官方产品页直读，原句摘录）

## 来源
- https://www.huaweicloud.com/product/modelarts/ascend-cloud.html

## 万卡证据（原文摘录）
- ✅ “支持最大支持16万卡集群，用高速总线互联替代传统以太，通信带宽提升15倍，通信时延降低10倍”
- ✅（同页另一口径）“支持最大超过10万卡集群……”

## 网络要素
- isolation：超节点域内高速总线替代传统以太（域内可达性模型改变）
- 多卡一专家分布式推理部署（超节点+大规模专家并行）

## 架构要素
- 组网：CloudMatrix384 超节点为算力底座；总线互联 scale-up 与 DCN 分离
- 隔离边界：超节点域 = 物理互联域
- 通信：EMS 跨节点共享 KV 缓存服务
- 管理面：ModelArts/ModelArts Studio 承载
- 云集成点：华为云 CANN/MindSpore 栈

## 安全问题点（放大前提 × 模块机器键）
- 总线互联替代以太：以太网侧防护/观测面（ACL/NetFlow）对总线域失效 → `fabric-topology-isolation`
- EMS 跨节点 KV 共享：KV 通道无租户认证公开描述 → `inference-gateway-pd`、`collective-communication-surface`
- 超节点推理“一卡一专家”：卡级故障即专家级投毒面 → `shared-volume-weight-copy`

## 横向思路
- 云内立足（CCE/元数据）→昇腾集群调度面→超节点域边界探测→KV/权重面；fabric 面预留（总线域可达性图）
