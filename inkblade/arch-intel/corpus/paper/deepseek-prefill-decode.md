# DeepSeek V3 — 预填充-解码分离部署架构

- 分类：自建与超大规模训练组网（推理部署形态）
- 组织 / 系统：DeepSeek / DeepSeek-V3 Technical Report（arXiv 2412.19437）
- 核验日期：2026-10-25；核验状态：verified（arXiv 摘要 + HTML 全文“3.4 Inference and Deployment：3.4.1 Prefilling / 3.4.2 Decoding”确认分离部署）

## 来源
- https://arxiv.org/abs/2412.19437
- https://arxiv.org/html/2412.19437

## 架构要素
- 组网：预填充与解码两池 GPU 分离部署（不同节点负载特征）；MoE 全专家/all-to-all 通信
- 隔离边界：预填充池/解码池为信任域内两角色，未见跨池网络隔离
- 身份：服务层身份；节点间通信无独立认证
- 存储：权重/缓存多层（论文含存储优化章）
- 通信：节点间 all-to-all + KV 在预填充→解码间转移（跨池 KV 传递面）
- 管理面：引擎管理/调度服务
- 多租户：服务级多用户（API 层），节点层共享
- 云集成点：无（自建）

## 安全问题点（放大前提 × 模块机器键）
- KV/上下文跨池明文转移：预填充→解码通道可成为注入/窃听面 → `inference-gateway-pd`、`collective-communication-surface`
- 解码池管理端点（权重加载/更新）暴露=权重投毒直达 → `sglang-admin-failopen`、`slime-weight-pull-poison`
- 未鉴权推理端点=免费蒸馏 → `unlimited-query-distillation`

## 横向思路
- 打点推理入口 → 探测 EPP/网关与解码池端口 → 管理面 fail-open → 权重拉取投毒 / KV 通道操纵影响生成内容

---
## 万卡证据（2026-10-25 重收批注）
- ❌ 未达 ≥10k 口径：无 ≥10k 披露：V3 技术报告为 2048×H800（2.788M H800 GPU 小时）
## 网络要素
- （本源为控制面/组件语义类，不直接承载 8 项 fabric 要素）
- 分类迁移：corpus 扁平目录 → corpus/paper（论文/技术报告）
