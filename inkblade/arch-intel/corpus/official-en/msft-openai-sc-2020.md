# Microsoft — 为 OpenAI 构建的超级计算机（10,000 GPU / 400G）

- 分类：official-en（外文官方源）
- 组织 / 系统：Microsoft（News）/ Azure OpenAI 专用超算
- 源类型：newsroom（news.microsoft.com 官方专题，2020-05）
- 核验日期：2026-10-25；核验状态：verified（webfetch 微软官方新闻直读，原句摘录）

## 来源
- https://news.microsoft.com/source/features/ai/openai-azure-supercomputer/

## 万卡证据（原文摘录）
- ✅ "The supercomputer developed for OpenAI is a single system with more than 285,000 CPU cores, 10,000 GPUs and 400 gigabits per second of network connectivity for each GPU server."

## 网络要素
- 400 Gbps per GPU server 网络口径（官方原句；早期口径未点名 IB/以太，仅称 high-bandwidth networks）

## 架构要素
- 组网：单系统 10k GPU、每 GPU 服务器 400G
- 云集成点：Azure 托管、专属构建；TOP500 前五口径

## 安全问题点（放大前提 × 模块机器键）
- 专属单租超算与云共享底座共存：云凭据链（托管标识）仍是边界 → `multi-cloud-imds-credentials`

## 横向思路
- 历史基线条目：万卡 400G/GPU-server 口径用于对标当下集群网络基线（≥400G/节点）
