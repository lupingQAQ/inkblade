# 企业真实感实验室结果（fixture 车道）

> 生成时间：`2026-10-26T05:48:26Z` · 来源：**fixture**（`lab/enterprise-fixtures`）
>
> 真实集群证据另列：单节点 k3s（QEMU TCG）只有结构性发现、无标注，**不计算 FP/FN**；本页数字不得外推到客户环境。

## 1. 口径

- FP / (TP + FP)：发现级误报占比
- FN / (TP + FN)：标注风险漏报率
- 只统计 critical, high, medium, low；info 不计入。

## 2. 三场景结果

| 场景 | 发现 | TP | FP | FN | FP 率 | FN 率 |
|---|---:|---:|---:|---:|---:|---:|
| platform-baseline-noise | 3 | 2 | 1 | 0 | 33.33% | 0.00% |
| rbac-intent-noise | 8 | 7 | 1 | 1 | 12.50% | 14.29% |
| audit-flood-noise | 5 | 5 | 0 | 0 | 0.00% | 0.00% |
| **合计** | 16 | 14 | 2 | 1 | **12.50%** | **7.14%** |

## 3. 调优前后（before → after）

### 3.1 同夹具实时复跑（推荐口径）

| 场景 | 发现 | TP | FP | FN | FP 率 | FN 率 |
|---|---:|---:|---:|---:|---:|---:|
| platform-baseline-noise 前 | 18 | 2 | 16 | 0 | 88.89% | 0.00% |
| platform-baseline-noise 后 | 3 | 2 | 1 | 0 | 33.33% | 0.00% |
| rbac-intent-noise 前 | 20 | 7 | 13 | 1 | 65.00% | 14.29% |
| rbac-intent-noise 后 | 8 | 7 | 1 | 1 | 12.50% | 14.29% |
| audit-flood-noise 前 | 123 | 3 | 120 | 2 | 97.56% | 40.00% |
| audit-flood-noise 后 | 5 | 5 | 0 | 0 | 0.00% | 0.00% |
| **合计 前（实时）** | 161 | 12 | 149 | 3 | **92.55%** | **21.43%** |
| **合计 后** | 16 | 14 | 2 | 1 | **12.50%** | **7.14%** |

### 3.2 历史快照（手填常量，仅追溯）

| 场景 | 发现 | TP | FP | FN | FP 率 | FN 率 |
|---|---:|---:|---:|---:|---:|---:|
| platform-baseline-noise 前 | 17 | 1 | 16 | 1 | 94.12% | 50.00% |
| platform-baseline-noise 后 | 3 | 2 | 1 | 0 | 33.33% | 0.00% |
| rbac-intent-noise 前 | 20 | 7 | 13 | 1 | 65.00% | 14.29% |
| rbac-intent-noise 后 | 8 | 7 | 1 | 1 | 12.50% | 14.29% |
| audit-flood-noise 前 | 3 | 3 | 0 | 2 | 0.00% | 40.00% |
| audit-flood-noise 后 | 5 | 5 | 0 | 0 | 0.00% | 0.00% |
| **合计 前（历史）** | 40 | 11 | 29 | 4 | **72.50%** | **28.57%** |
| **合计 后** | 16 | 14 | 2 | 1 | **12.50%** | **7.14%** |

> 前（实时）= 同一夹具、同一 ground-truth，关闭实体基线抑制并回退到补漏前检测器集合
> （`before_rerun`）——由当前代码实时重算，不是手填常量。
> 后 = `core/baseline.py` 实体基线 + 学习模式 + serviceaccounts/token、pods/portforward 检测器。

## 4. 逐场景说明

### 场景 1：平台组件基线噪声（privileged/hostPath/hostNetwork DaemonSet）

- 发现 3（TP 2 / FP 1 / FN 0）；标注风险 2 条。
- 基线抑制 15 条（platform-workload×13、subject-baseline×2），检测器输出不变，抑制逐条留痕（provenance 可审计）。

### 场景 2：RBAC/NetworkPolicy 常规运维噪声（system wildcard / CI exec / 系统 NS）

- 发现 8（TP 7 / FP 1 / FN 1）；标注风险 7 条。
- 基线抑制 12 条（controller-role-baseline×3、platform-namespace-baseline×6、subject-baseline×1、system-binding-baseline×2），检测器输出不变，抑制逐条留痕（provenance 可审计）。

### 场景 3：审计事件洪水（340 良性 + 5 风险）

- 发现 5（TP 5 / FP 0 / FN 0）；标注风险 5 条。
- 默认主体基线复跑（新检测器生效）：TP 5 / FP 120 / FN 0——FP 仍来自 CI exec 洪水（扫描器 403 按统一口径不入报）。
- 学习模式（仅前 340 条历史、不看标签）：习得 system:serviceaccount:ci:ci-runner（create pods/exec×120）；system:serviceaccount:monitoring:prometheus（get secrets×100）；system:serviceaccount:ml-training:platform-scheduler（create pods×60）。
- 学习-only 基线：TP 5 / FP 0 / FN 0——仅用前 340 条历史学习（时间切分、不看标签）：CI/监控/调度主体被习得；拒绝尝试（403）由检测器统一口径默认不入报 → 学习-only 也达到 0 FP，但产物仍须 lead 审批合并后才生效。

## 5. 防御生效状态

| 项 | 总数 | 生效/加载/覆盖 | 缺口 | 比率 |
|---|---:|---:|---:|---:|
| Kyverno 策略 | 8 | Enforce 3 | Audit 4 + Missing 1 | 37.5% |
| Falco 规则 | 14 | Loaded 8 | Missing 6 | 57.1% |
| NetworkPolicy 分区 | 14 NS | 默认拒绝 6 | 未覆盖 8 | 42.9% |

未覆盖命名空间（fixture）：east-prod/ingress-nginx, east-prod/kube-system, east-prod/monitoring, east-prod/security, east-prod/tenant-b, west-prod/kube-system, west-prod/monitoring, west-prod/tenant-c

## 6. 真实集群车道（与 fixture 分列）

- 来源：`reports/samples/real-cluster/recon-findings.json`
- 模块：6/6 ok；findings：16
- FP/FN：**不计算** — 真实集群单节点 k3s（QEMU TCG），只有结构性发现、无客户标注真值，故不计算 FP/FN；不得把 fixture 的 FP/FN 外推到该集群或客户环境。

## 7. 未达成与调优建议

- fixture 不等于客户集群：版本/CNI/CRD/准入/遥测差异未覆盖
- 审计场景只有 345 条事件，不等于客户日均百万级事件流
- 残余 FN：mutable image tag（本夹具无该形态证据，检测器已备、不造证据）；客户环境需以真实快照重测
- 残余 FP 逐条列出（各场景 tuning.after）：多为真实风险形态但无标注，不静默吞掉
- 真实集群车道无标注，不计算 FP/FN
- 调优路径 1（已落地）：CI/扫描器/控制器/系统绑定/平台命名空间/工作负载三元组实体基线（`inkblade/core/baseline.py`，抑制留痕可审计，客户环境需重审批）。
- 调优路径 2（已落地）：学习模式从历史事件流/run 生成 allowlist 候选（仅 2xx、高危形态永不学习、lead 审批后合并）。
- 调优路径 3（已落地）：补齐 serviceaccounts/token 与 pods/portforward 检测器 + Sigma×2（永不基线化）；mutable image tag 检测器已备（本夹具无证据，如实留 FN）。
- 抑制规则（时间窗/标签/注释）：`core/baseline.py::SuppressionRule`，客户维护窗与例外清单用，规则必须带 reason/created_by。

## 8. 复现

```bash
python lab/enterprise_lab.py
```

边界：fixture 非客户生产环境；版本/CNI/CRD/遥测差异、日均百万事件流、真实告警闭环均需 Pilot 在客户环境重测。
