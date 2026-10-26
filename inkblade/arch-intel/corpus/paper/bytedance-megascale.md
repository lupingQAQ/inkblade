# ByteDance MegaScale — 万卡级 LLM 训练系统

- 分类：自建与超大规模训练组网
- 组织 / 系统：ByteDance & 北大 / MegaScale（NSDI 2024）
- 核验日期：2026-10-25；核验状态：verified（USENIX 官方页面 + PDF）

## 来源
- https://www.usenix.org/conference/nsdi24/presentation/jiang-ziheng
- https://arxiv.org/abs/2402.15627

## 架构要素
- 组网：64×400Gbps 端口交换机构成 CLOS 拓扑，>10K GPU，上下行 1:1；每服务器 8×200G NIC，多网卡分流
- 隔离边界：集群为单一生产训练域；故障域按节点/Pod 划分
- 身份：训练守护进程（heartbeat/驱动器）体系，无网络身份
- 存储：数据加载与 checkpoint 体系（论文侧重算通重叠）
- 通信：all-to-all 拥塞调优、PFC 相关链路抖动治理；集合通信初始化从 O(n²) 优化到 <30s@10K GPU
- 管理面：驱动器 + 训练 daemon + 深度栈可观测（事件/流量画像）
- 多租户：多任务复用大集群
- 云集成点：火山引擎同类能力对外（另见其公开实践）

## 安全问题点（放大前提 × 模块机器键）
- 集合通信初始化（rendezvous）无认证：优化后的快速建链让"入组"同样快 → `collective-communication-surface`、`nccl-collective-join`
- 心跳/守护通道伪造：伪造心跳可触发错误节点摘除（调度面投毒）→ `scheduler-network-semantics`
- 拓扑感知并行=攻击者也可用：流量画像可反推并行布局与关键节点 → `observability-exposure`（监控面暴露）

## 横向思路
- 观测面拿拓扑图 → 定位 TP/PP 关键 rank → 精准摘除/拖慢（straggler 攻击）或入组污染梯度 → 权重面（共享 checkpoint 桶/卷）继续横向

---
## 万卡证据（2026-10-25 重收批注）
- ✅ 达标：论文口径：12,288 GPU 训练 175B 模型（NSDI'24 摘要）
## 网络要素
- congestion-control、ops-fault-surface
- 分类迁移：corpus 扁平目录 → corpus/paper（论文/技术报告）
