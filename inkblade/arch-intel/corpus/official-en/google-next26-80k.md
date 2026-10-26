# Google Cloud Blog — AI Infrastructure at Next '26（单数据中心 80,000 GPU 口径）

- 分类：official-en（外文官方源）
- 组织 / 系统：Google Cloud / AI infrastructure（Next '26 披露）
- 源类型：engineering-blog（cloud.google.com/blog）
- 核验日期：2026-10-25；核验状态：verified-partial（cloud.google.com 在本实验网络拒连（ECONNREFUSED，与既有矩阵 GCP 缺口记录一致），以 websearch 快照佐证原句）

## 来源
- https://cloud.google.com/blog/products/compute/ai-infrastructure-at-next26

## 万卡证据（原文摘录）
- ✅（快照原句）"GPUs and TPUs are great for training and serving AI models, supporting up to 80,000 GPUs in a single data center, and up to 960,000 GPUs across [regions]."

## 网络要素
- 单数据中心 80k GPU 口径 + 跨区域 960k GPU 聚合（Jupiter 网络体系，见 corpus/paper/jupiter-evolving.md）

## 架构要素
- 组网：Jupiter 数据中心网络世代 + 跨区域资源聚合

## 安全问题点（放大前提 × 模块机器键）
- 跨区域 960k 聚合=凭据/配额面的全局边界 → `cloud-role-overprivilege`、`multi-cloud-imds-credentials`

## 横向思路
- 与既有 GCP 条目（TPU/GKE）合并分析：区域间链路即跨域横向通道
