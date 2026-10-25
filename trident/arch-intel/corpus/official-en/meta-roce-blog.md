# Meta Engineering — RoCE Networks for Distributed AI Training at Scale

- 分类：official-en（外文官方源）
- 组织 / 系统：Meta Engineering / RoCEv2 backend fabric（SIGCOMM'24 论文官方博客版）
- 源类型：engineering-blog（engineering.fb.com）
- 核验日期：2026-10-25；核验状态：verified（webfetch 官方博文全文直读，原句摘录）

## 来源
- https://engineering.fb.com/2024/08/05/data-center-engineering/roce-network-distributed-ai-training-at-scale/
- https://engineering.fb.com/wp-content/uploads/2024/08/sigcomm24-final246.pdf（论文 PDF）

## 万卡证据（原文摘录）
- ✅ "AI networks play an important role in interconnecting tens of thousands of GPUs together, forming the foundational infrastructure for training, enabling large models with hundreds of billions of parameters such as LLAMA 3.1 405B."
- ✅ "a typical generative AI (GenAI) job may necessitate tight coordination of tens of thousands of GPUs over the course of several weeks."

## 网络要素
- 拓扑：FE/BE 双网分离；AI Zone 两级 Clos（RTSW 叶 + CTSW 脊，400G）+ ATSW 跨 Zone 聚合层
- 路由：ECMP → path-pinning → E-ECMP + QP scaling（AllReduce +40%）；跨 Zone 过订阅 + 调度器 minimum-cut
- congestion-control：400G 弃用 DCQCN，仅 PFC + 接收端准入（NCCL CTS clear-to-send）："We proceeded without DCQCN for our 400G deployments...over a year of experience with just PFC for flow control."
- ops-fault-surface：上链路故障→ECMP 重哈希冲突可拖慢整个作业（>30% 退化）等故障演化叙事

## 架构要素
- 组网：RoCEv2 over UDP；无损传输；深缓冲 CTSW
- 通信：NCCL 两段拷贝 + 通道缓冲；CTS 高优先级队列
- 管理面：路由多轮演进（生产四年经验）

## 安全问题点（放大前提 × 模块机器键）
- fabric 无认证：BE 网可达即可注入/旁听 → `collective-communication-surface`、`nccl-collective-join`
- CTS 接收端准入可被伪造 CTS 扰动（速率欺骗）→ 性能攻击面 `scheduler-network-semantics`
- ATSW 聚合层=跨 Zone 流量咽喉：拥塞放大点 → `fabric-topology-isolation`

## 横向思路
- 恶意接收端扣留/伪造 CTS → 拖慢目标 rank（straggler）；探测 RTSW/CTSW 拓扑反推 rank 布局；fabric 面预留
