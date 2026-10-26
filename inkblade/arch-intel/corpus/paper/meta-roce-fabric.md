# Meta RoCE Fabric — Meta 规模化 RoCE 训练网

- 分类：自建与超大规模训练组网
- 组织 / 系统：Meta / RoCE over Ethernet AI Training Fabric（SIGCOMM 2024 Experience Track）
- 核验日期：2026-10-25；核验状态：verified（SIGCOMM 2024 议程页：作者 Adithya Gangidi 等，Meta）

## 来源
- https://conferences.sigcomm.org/sigcomm/2024/program/（Experience Track 条目）

## 架构要素
- 组网：RoCEv2（不含 IP 路由复杂度的以太 RDMA）；独立 GPU backend 网络（与前端/存储网分离）；24K–32K GPU 级集群（工程界公开口径）
- 隔离边界：backend/前端双网物理分离；job 间隔离靠调度与网段划分
- 身份：fabric 无认证；可观测性（INT/遥测）用于运维而非准入
- 存储：独立存储网（Tectonic 体系另见其公开文）
- 通信：RoCEv2 + 自研拥塞控制（论文明确弃用 DCQCN，转向接收端/发送端协同）；大规模 PFC 语义谨慎使用
- 管理面：多轮路由迭代（ECMP → 感知拓扑的调度），fabric 管理集中化
- 多租户：训练任务级别共享，未见租户级网络身份
- 云集成点：无（自建）

## 安全问题点（放大前提 × 模块机器键）
- 集合通信无认证：RoCE 面可达即可注入/窃听候选路径 → `fabric-topology-isolation`、`nccl-collective-join`
- 拥塞控制/遥测面可被扰动：恶意流可挤压大象流调度（性能攻击面）→ `collective-communication-surface`
- backend 网独立性：一旦攻入 backend 网段，CNI/NetworkPolicy 等云原生控制面全部失效 → `cni-stack-capability`

## 横向思路
- 由前端业务立足点 → 找到通往 GPU backend 的路由/多网卡节点 → RoCE 直达训练 ranks → NCCL 入组或 KV/RDMA 窃听

---
## 万卡证据（2026-10-25 重收批注）
- ✅ 达标：同系统官方博客口径：AI networks interconnecting tens of thousands of GPUs；24k 级集群（engineering.fb.com 2024-03/08）
## 网络要素
- congestion-control、ops-fault-surface
- 分类迁移：corpus 扁平目录 → corpus/paper（论文/技术报告）
