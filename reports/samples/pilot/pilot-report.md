# Trident Pilot Report（试点只读报告）

> 生成时间：`2026-10-25T16:27:21Z` · 模式：**只读** · 写验证：**未授权**
>
> 边界：pilot 只生成清点/计划，不执行写操作；不代表生产容量、SLA 或合规认证。

## 1. 环境画像

- kubeconfig 文件：east.yaml, west.yaml
- context：2 · cluster：2 · 节点：12 · GPU 节点：6 · GPU：48
- 命名空间：14 · Pod：26 · Secret 元数据：8
- 云/平台：aws-eks, azure-aks

| context | provider | nodes | GPU | ns | pods | 特权 Pod | hostPath | 无 netpol ns |
|---|---|---:|---:|---:|---:|---:|---:|---|
| east-prod | aws-eks | 8 | 4 | 9 | 20 | 4 | 6 | ingress-nginx, kube-system, monitoring, security, tenant-b |
| west-prod | azure-aks | 4 | 2 | 5 | 6 | 1 | 2 | kube-system, monitoring, tenant-c |

## 2. 风险热图

| 类别 | 分数 | 等级 | 信号（截断） |
|---|---:|---|---|
| 身份与 RBAC | 96 | critical | 通配符角色：platform-operator；通配符角色：system:controller:node-controller；cluster-admin 非系统绑定：tenant-a-admin-binding → admin；通配符角色：platform-operator |
| 网络分区 | 100 | critical | 命名空间无默认拒绝 NetworkPolicy：ingress-nginx；命名空间无默认拒绝 NetworkPolicy：kube-system；命名空间无默认拒绝 NetworkPolicy：monitoring；命名空间无默认拒绝 NetworkPolicy：security |
| 工作负载逃逸面 | 100 | critical | 特权容器：kube-system/aws-node-9k2lp；hostPath 挂载：kube-system/aws-node-9k2lp → /var/run/docker.sock；hostPath 挂载：kube-system/aws-node-9k2lp → /var/lib/cni；特权容器：kube-system/ebs-csi-node-2x8v |
| 模型与数据面 | 68 | high | 权重/检查点 PVC：model-weights-pvc；权重/检查点 PVC：checkpoint-pvc；权重/检查点 PVC：model-weights-west |
| 检测与准入 | 100 | critical | Kyverno 未全部 Enforce（3/5 非强制）；Falco 规则未加载（3/8）；Kyverno 未全部 Enforce（2/3 非强制）；Falco 规则未加载（3/6） |
| 暴露面 | 74 | high | NodePort：ml-inference/vllm-router；LoadBalancer：ml-training/tensorboard；LoadBalancer：ml-training/mlflow；LoadBalancer：ingress-nginx/ingress-nginx-controller |
| 多租户隔离 | 60 | high | context=east-prod 租户命名空间 tenant-b 未被默认拒绝覆盖；context=west-prod 租户命名空间 tenant-c 未被默认拒绝覆盖 |

> 热图是只读启发式评分，不是漏洞定级；真实定级以模块证据与人工复核为准。

## 3. 只读发现（Top 20）

| 严重度 | 类别 | 发现 | 证据 |
|---|---|---|---|
| high | 工作负载逃逸面 | 特权容器：kube-system/aws-node-9k2lp | `context=east-prod pod=kube-system/aws-node-9k2lp privileged=true` |
| critical | 工作负载逃逸面 | hostPath 挂载：kube-system/aws-node-9k2lp → /var/run/docker.sock | `context=east-prod pod=kube-system/aws-node-9k2lp hostPath=/var/run/docker.sock` |
| medium | 工作负载逃逸面 | hostPath 挂载：kube-system/aws-node-9k2lp → /var/lib/cni | `context=east-prod pod=kube-system/aws-node-9k2lp hostPath=/var/lib/cni` |
| high | 工作负载逃逸面 | 特权容器：kube-system/ebs-csi-node-2x8v | `context=east-prod pod=kube-system/ebs-csi-node-2x8v privileged=true` |
| medium | 工作负载逃逸面 | hostPath 挂载：kube-system/ebs-csi-node-2x8v → /var/lib/kubelet | `context=east-prod pod=kube-system/ebs-csi-node-2x8v hostPath=/var/lib/kubelet` |
| medium | 工作负载逃逸面 | hostPath 挂载：kube-system/ebs-csi-node-2x8v → /dev | `context=east-prod pod=kube-system/ebs-csi-node-2x8v hostPath=/dev` |
| high | 工作负载逃逸面 | 特权容器：security/falco-jk2m9 | `context=east-prod pod=security/falco-jk2m9 privileged=true` |
| critical | 工作负载逃逸面 | hostPath 挂载：security/falco-jk2m9 → /proc | `context=east-prod pod=security/falco-jk2m9 hostPath=/proc` |
| critical | 工作负载逃逸面 | hostPath 挂载：security/falco-jk2m9 → /sys/kernel/debug | `context=east-prod pod=security/falco-jk2m9 hostPath=/sys/kernel/debug` |
| critical | 工作负载逃逸面 | hostPath 挂载：security/falco-jk2m9 → /var/run/docker.sock | `context=east-prod pod=security/falco-jk2m9 hostPath=/var/run/docker.sock` |
| critical | 工作负载逃逸面 | hostPath 挂载：monitoring/node-exporter-h4n2p → /proc | `context=east-prod pod=monitoring/node-exporter-h4n2p hostPath=/proc` |
| critical | 工作负载逃逸面 | hostPath 挂载：monitoring/node-exporter-h4n2p → /sys | `context=east-prod pod=monitoring/node-exporter-h4n2p hostPath=/sys` |
| medium | 工作负载逃逸面 | hostPath 挂载：monitoring/prometheus-0 → /var/lib/prometheus | `context=east-prod pod=monitoring/prometheus-0 hostPath=/var/lib/prometheus` |
| high | 工作负载逃逸面 | 特权容器：tenant-a/model-copy-job-8x2k | `context=east-prod pod=tenant-a/model-copy-job-8x2k privileged=true` |
| medium | 工作负载逃逸面 | hostPath 挂载：tenant-a/model-copy-job-8x2k → / | `context=east-prod pod=tenant-a/model-copy-job-8x2k hostPath=/` |
| critical | 身份与 RBAC | 通配符角色：platform-operator | `context=east-prod role=platform-operator` |
| critical | 身份与 RBAC | 通配符角色：system:controller:node-controller | `context=east-prod role=system:controller:node-controller` |
| critical | 身份与 RBAC | cluster-admin 非系统绑定：tenant-a-admin-binding → admin | `context=east-prod binding=tenant-a-admin-binding` |
| medium | 暴露面 | NodePort：ml-inference/vllm-router | `context=east-prod ports=8000` |
| high | 暴露面 | LoadBalancer：ml-training/tensorboard | `context=east-prod ports=6006` |

## 4. 建议测试计划

| 阶段 | 模式 | 窗口 | 时长 | 动作 | 退出标准 |
|---|---|---|---:|---|---|
| P0 只读清点与环境画像 | read-only | 任意时间（仅 kubectl get） | 20 | 多 context/cluster 合并；pods/services/netpol/RBAC/PVC/Secret 元数据清点；Kyverno/Falco/NetworkPolicy 生效状态读取 | 只读通过率 >= 95%；无写动作；环境画像与冲突清单完整 |
| P1 低影响验证 | read-only | 业务低峰；只读 API/快照分析 | 45 | 证据驱动链推荐（不执行）；误报/漏报基线（客户标注样本）；告警/SIEM 连通性干跑 | 误报率 <= 20%（Pilot 门槛）；漏报率 <= 10%；扫描窗口 <= 客户约定时长 |
| P2 受控写验证（条件执行）（未授权/已阻断） | write | 客户变更窗口内（建议业务低峰；训练作业暂停/排空后） | 60 | 仅生成计划；不执行任何写操作（P2 未授权） | 每个写动作有备份回执 + 回滚演练记录；回滚成功率 100%（失败即停止并升级）；写窗口内 P95 时延不超过客户阈值 |
| P3 复测、报告与签核 | read-only | 写验证后 24h 内 | 30 | 回归复测；pilot-report/证据 manifest 哈希；双签与保留策略登记 | 报告签核项 6/6；证据 manifest 校验通过；客户安全负责人签字 |

**推荐窗口**：客户变更窗口；避开训练/推理高峰；单次 <= 2h

**停止条件**：
- 客户 SOC/值班要求立即停止
- 出现非预期生产影响或 SLO 越界
- 授权/范围/时间窗任一失效
- 回滚失败或备份回执缺失

## 5. 回滚预案

1. 执行前导出目标命名空间资源 YAML + PVC/RBAC 元数据并计算 sha256
2. 每个写动作登记 backup_targets 与回滚命令（沿用 core/backup.py）
3. 异常时按步骤逆序回滚并校验资源哈希
4. 回滚后只读复测并记录回执

成功标准：回滚成功率 100%；失败项为 0；资源哈希一致

## 6. 审批清单（双签开关）

| 角色 | 必需 | 审批范围 | 签字 | 时间 |
|---|---|---|---|---|
| lead | 是 | 测试范围/窗口/停止条件 | ☐ | ____ |
| security-owner | 是 | 双签；数据敏感与变更窗口 | ☐ | ____ |
| platform-owner | 建议 | 集群/GPU 平台影响确认 | ☐ | ____ |
| data-owner | 建议 | 训练数据/模型权重接触确认 | ☐ | ____ |

> 双签：lead → 安全负责人；单签模式仅限只读/低风险试点，需在 ROE 中显式登记。

## 7. 量化门槛与签核

| 指标 | 目标 |
|---|---|
| read_only_pass_rate_target | >=95% |
| false_positive_rate_target | <=20% |
| false_negative_rate_target | <=10% |
| scan_window_target | <=客户约定窗口（默认 2h） |
| rollback_success_target | 100% |
| report_signoff_target | 6/6 |

报告签核项（6/6 方可交付）：
- [ ] 范围与授权一致
- [ ] 证据 manifest 校验通过
- [ ] 发现经人工复核
- [ ] 误报/漏报已复核
- [ ] 数据敏感与保留策略确认
- [ ] 回滚演练通过

---

本报告由 `trident pilot` 生成；默认只读。若需写验证，必须客户显式 `--allow-write` 并完成 lead→安全负责人双签与备份回执；禁止把本报告当作生产 SLA、合规认证或全量覆盖证明。
