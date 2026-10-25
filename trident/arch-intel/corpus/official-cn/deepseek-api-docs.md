# DeepSeek 官方渠道 — 更新日志与模型发布（无集群规模披露）

- 分类：official-cn（中文官方源）
- 组织 / 系统：DeepSeek / api-docs 官方更新日志
- 源类型：vendor-docs（官方 API 文档站）
- 核验日期：2026-10-25；核验状态：verified（webfetch api-docs.deepseek.com 官方更新日志直读）

## 来源
- https://api-docs.deepseek.com/zh-cn/updates
- https://api-docs.deepseek.com/zh-cn/news/news250821

## 万卡证据（原文摘录）
- ❌ 官方渠道无 ≥10k 集群披露：更新日志仅模型/API 能力（V3→V3.1→V3.2→V4 系列）；规模口径见 V3 技术报告（2048×H800，2.788M H800 GPU 小时，arXiv 2412.19437，另见 corpus/paper/deepseek-prefill-decode.md）

## 网络要素
- （官方渠道不含 fabric 细节；V3 报告披露节点内 NVLink + 节点间 IB 全连接，见 paper 条目）

## 架构要素
- 身份：API key 体系
- 云集成点：官方 API + 本地部署（SLO/吞吐权衡口径见技术报告）

## 安全问题点（放大前提 × 模块机器键）
- 官方披露面收敛=情报缺口：以技术报告+部署侧指纹补全 → `cloud-integration-fingerprint`

## 横向思路
- 部署侧探测（模型指纹/API 形状）定位 DeepSeek 私有化部署 → 转推理面链路
