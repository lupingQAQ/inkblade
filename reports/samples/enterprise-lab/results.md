# 企业真实感实验室结果（fixture 车道）

> 生成时间：`2026-10-25T16:16:41Z` · 来源：**fixture**（`lab/enterprise-fixtures`）
>
> 真实集群证据另列：单节点 k3s（QEMU TCG）只有结构性发现、无标注，**不计算 FP/FN**；本页数字不得外推到客户环境。

## 1. 口径

- FP / (TP + FP)：发现级误报占比
- FN / (TP + FN)：标注风险漏报率
- 只统计 critical, high, medium, low；info 不计入。

## 2. 三场景结果

| 场景 | 发现 | TP | FP | FN | FP 率 | FN 率 |
|---|---:|---:|---:|---:|---:|---:|
| platform-baseline-noise | 17 | 1 | 16 | 1 | 94.12% | 50.00% |
| rbac-intent-noise | 20 | 7 | 13 | 1 | 65.00% | 14.29% |
| audit-flood-noise | 3 | 3 | 0 | 2 | 0.00% | 40.00% |
| **合计** | 40 | 11 | 29 | 4 | **72.50%** | **28.57%** |

## 3. 逐场景说明

### 场景 1：平台组件基线噪声（privileged/hostPath/hostNetwork DaemonSet）

- 发现 17（TP 1 / FP 16 / FN 1）；标注风险 2 条。

### 场景 2：RBAC/NetworkPolicy 常规运维噪声（system wildcard / CI exec / 系统 NS）

- 发现 20（TP 7 / FP 13 / FN 1）；标注风险 7 条。

### 场景 3：审计事件洪水（340 良性 + 5 风险，2 未覆盖）

- 发现 3（TP 3 / FP 0 / FN 2）；标注风险 5 条。
- 调优（审计主体基线）：FP 180 → 0，降幅 100.0%；新增基线 `system:serviceaccount:ci:ci-runner, system:serviceaccount:security:scanner`。
- 调优后 TP 3 / FP 0 / FN 2；漏报风险仍为 2 条（未覆盖检测面）。

## 4. 防御生效状态

| 项 | 总数 | 生效/加载/覆盖 | 缺口 | 比率 |
|---|---:|---:|---:|---:|
| Kyverno 策略 | 8 | Enforce 3 | Audit 4 + Missing 1 | 37.5% |
| Falco 规则 | 14 | Loaded 8 | Missing 6 | 57.1% |
| NetworkPolicy 分区 | 14 NS | 默认拒绝 6 | 未覆盖 8 | 42.9% |

未覆盖命名空间（fixture）：east-prod/ingress-nginx, east-prod/kube-system, east-prod/monitoring, east-prod/security, east-prod/tenant-b, west-prod/kube-system, west-prod/monitoring, west-prod/tenant-c

## 5. 真实集群车道（与 fixture 分列）

- 来源：`reports/samples/real-cluster/recon-findings.json`
- 模块：6/6 ok；findings：16
- FP/FN：**不计算** — 真实集群单节点 k3s（QEMU TCG），只有结构性发现、无客户标注真值，故不计算 FP/FN；不得把 fixture 的 FP/FN 外推到该集群或客户环境。

## 6. 未达成与调优建议

- fixture 不等于客户集群：版本/CNI/CRD/准入/遥测差异未覆盖
- 审计场景只有 345 条事件，不等于客户日均百万级事件流
- 2 个风险（SA token 铸造、pods/portforward）当前检测器未覆盖 → 如实计 FN
- 真实集群车道无标注，不计算 FP/FN
- 调优建议 1：把 CI/扫描器/平台调度器纳入审计主体基线（本页已演示 FP 降幅，但需客户审批）。
- 调优建议 2：对云厂商 DaemonSet 建例外清单，按 image digest + namespace + SA 三元组，而不是按 finding 标题永久静默。
- 调优建议 3：pods/portforward、serviceaccounts/token 铸造、mutable image tag 需补检测器/准入，不能靠调基线“消灭”。

## 7. 复现

```bash
python lab/enterprise_lab.py
```

边界：fixture 非客户生产环境；版本/CNI/CRD/遥测差异、日均百万事件流、真实告警闭环均需 Pilot 在客户环境重测。
