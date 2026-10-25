# Microsoft Singularity — 全球级 AI 调度服务

- 分类：自建与超大规模训练组网（调度/管理面）
- 组织 / 系统：Microsoft / Singularity（arXiv 2202.07848）
- 核验日期：2026-10-25；核验状态：verified（arXiv API 检索）

## 来源
- https://arxiv.org/abs/2202.07848

## 架构要素
- 组网：全球数据中心 fabric；调度器感知位置把作业在节点/集群/数据中心/区域间迁移
- 隔离边界：作业级抢占与迁移；设备级可靠性（RAS）管控
- 身份：中心调度服务持有全局舰队控制权（高价值身份）
- 存储：checkpoint 随迁移透明恢复（作业状态外置）
- 通信：调度控制通道 + 训练数据/模型分发
- 管理面：workload-aware 调度器（可抢占/弹性）
- 多租户：多作业共池，抢占换利用率
- 云集成点：Azure 体系（ND 系列/GPU 舰队，另见 azure 条目）

## 安全问题点（放大前提 × 模块机器键）
- 中心调度权限=集群级横向枢纽：拿到调度面身份即可在任意节点起负载 → `rbac-mapping`、`overprivileged-sa-escalation`
- 迁移/checkpoint 通道：状态外置可被投毒（恢复即执行/污染）→ `verl-checkpoint-pickle`（同类 pickle 面）、`shared-volume-weight-copy`
- 抢占语义滥用：伪造抢占可对目标作业做 DoS → `scheduler-network-semantics`

## 横向思路
- 凭据/SSRF → 调度 API → 在目标租户相邻节点投放负载 → 设备直通/特权负载 → 节点横向

---
## 万卡证据（2026-10-25 重收批注）
- ❌ 未达 ≥10k 口径：无 ≥10k 披露：论文侧重调度抽象，未给集群规模数
## 网络要素
- （本源为控制面/组件语义类，不直接承载 8 项 fabric 要素）
- 分类迁移：corpus 扁平目录 → corpus/paper（论文/技术报告）
