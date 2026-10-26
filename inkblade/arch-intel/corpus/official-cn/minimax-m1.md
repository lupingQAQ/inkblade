# MiniMax-M1 — 512×H800 RL 训练官方披露（规模透明度样本）

- 分类：official-cn（中文官方源）
- 组织 / 系统：MiniMax / MiniMax-M1（含 M1 技术报告）
- 源类型：newsroom（minimax.io 官方新闻）
- 核验日期：2026-10-25；核验状态：verified（webfetch minimax.io 官方新闻直读，原句摘录）

## 来源
- https://www.minimax.io/news/minimaxm1
- https://arxiv.org/abs/2506.13585（技术报告）

## 万卡证据（原文摘录）
- ❌ 未达 ≥10k：“The entire reinforcement learning phase used only 512 H800s for three weeks, with a rental cost of just $534,700.”（官方原句——作为小规模高效口径样本收录）

## 网络要素
- Lightning Attention 混合注意力（计算通信比优化）

## 架构要素
- 通信：长上下文高效注意力降低通信压力
- 算力形态：租用算力（rental）——第三方万卡池的租户侧样本

## 安全问题点（放大前提 × 模块机器键）
- 租用算力=多租共享 fabric 上的高价值租户 → `network-policy-coverage`（跨租可达性）
- API 面为唯一官方边界 → `unlimited-query-distillation`

## 横向思路
- 若租用池 fabric 隔离失效，跨租侧信道/入组即为路径；此条目作为“云上大模型租户”威胁模型锚点
