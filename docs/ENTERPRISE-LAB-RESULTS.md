# 企业真实感实验室结果（2026-10-26）

> 两条车道严格分列：
> - **fixture 车道**：`lab/enterprise-fixtures` 的生产形态快照/清单 + `lab/enterprise_lab.py`
>   自动评测；有 ground-truth 标注，**计算 FP/FN**。
> - **真实集群车道**：`reports/samples/real-cluster/` 的单节点 k3s（QEMU TCG）；
>   只有结构性发现、**无客户标注真值，不计算 FP/FN**。
>
> 本页数字不得外推到客户环境；fixture 不是客户生产集群，也不是容量/SLA/合规证据。
> 机器可读结果：`reports/samples/enterprise-lab/results.json`（本文数字由该文件生成）。

## 1. 实验装置

| 项 | 内容 |
|---|---|
| 快照 | 2 个集群（east-prod / west-prod），14 个命名空间，混合平台/训练/推理/租户/CI 命名空间；GPU 节点 6 个、GPU 48 卡（fixture 容量）；20+ Pod；PVC/Secret 元数据；RBAC 通配符/系统绑定/租户绑定。 |
| 防御 | Kyverno 8 条策略（Enforce 3 / Audit 4 / Missing 1）；Falco 14 条规则（Loaded 8 / Missing 6）；NetworkPolicy 14 个命名空间（默认拒绝 6 / 未覆盖 8）。 |
| 审计 | 345 条事件：340 条良性（CI `pods/exec` ×120、扫描器 403 读 Secret ×60、监控读 Secret ×100、平台调度器挂权重 PVC 建 Pod ×60）+ 5 条风险（cluster-admin 绑定、tenant-b exec、权重 PVC patch、SA token 铸造、pods/portforward）。403 拒绝尝试按统一口径默认不入报；101 Switching Protocols 的 exec 会话视为成功会话。 |
| 检测器 | 真实模块：`escape-primitives`、`rbac-mapping`、`network-policy-coverage`、`exposure-mapping`、`observability-exposure`；审计：`core/auditlog.py` 八检测器（含 serviceaccounts/token、pods/portforward 两个补漏检测器）。 |
| 标注 | `ground-truth.json` 固化 benign/risk；实现不临时改标签。 |
| 口径 | FP 率 = FP / (TP + FP)；FN 率 = FN / (TP + FN)；只统计 critical/high/medium/low，info 不计。 |

**三类噪声场景**（任务要求至少 3 类）：

1. **平台组件基线噪声**：云厂商 CNI/CSI、node-exporter、prometheus、falco、ingress
   等 DaemonSet 的 privileged / hostPath / hostNetwork；
2. **RBAC/NetworkPolicy 常规运维噪声**：`system:controller` 通配符、平台 operator
   wildcard、CI `pods/exec`、系统命名空间未加默认拒绝；
3. **审计事件洪水**：340 条良性事件（CI exec、扫描器 403、监控读 Secret、平台调度器
   挂 PVC）与 5 条风险事件混合；调优前 2 条风险未被检测器覆盖（SA token、portforward），
   本轮已补，403 拒绝尝试按统一口径默认不入报。

## 2. 结果（fixture 车道）

### 2.1 同夹具 before → after（实时复跑）

> before = 关闭实体基线抑制 + 回退到补漏前检测器集合（`before_rerun`，当前代码实时重算，
> 不是手填常量）；after = `core/baseline.py` 实体基线 + 学习模式 +
> `serviceaccounts/token` / `pods/portforward` 检测器。

| 场景 | 发现 | TP | FP | FN | FP 率 | FN 率 |
|---|---:|---:|---:|---:|---:|---:|
| `platform-baseline-noise` before | 18 | 2 | 16 | 0 | 88.89% | 0.00% |
| `platform-baseline-noise` after | 3 | 2 | 1 | 0 | 33.33% | 0.00% |
| `rbac-intent-noise` before | 20 | 7 | 13 | 1 | 65.00% | 14.29% |
| `rbac-intent-noise` after | 8 | 7 | 1 | 1 | 12.50% | 14.29% |
| `audit-flood-noise` before | 123 | 3 | 120 | 2 | 97.56% | 40.00% |
| `audit-flood-noise` after | 5 | 5 | 0 | 0 | 0.00% | 0.00% |
| **合计 before（实时）** | 161 | 12 | 149 | 3 | **92.55%** | **21.43%** |
| **合计 after** | 16 | 14 | 2 | 1 | **12.50%** | **7.14%** |

目标 **FP ≤ 20% / FN ≤ 10%：达成**（合计口径）。残余如实保留、不静默：

- 残余 FP 2 条：`ml-training/ray-head-0` hostNetwork（真实风险形态但无标注）、
  `tenant-c` 读 Secret（真实能力但不在标注集）；合计 12.50%。
- 残余 FN 1 条：mutable image tag（检测器已备，夹具无该形态证据，不造证据）。
- 场景 1 单场景 FP 33.33%：18 条里只剩 1 条无标注 FP，样本小、比例失真；合计口径达标。

历史快照（上一版报告手填常量，保留追溯）：40 发现 / TP 11 / FP 29 / FN 4 →
FP **72.50%** / FN **28.57%**。

### 2.2 审计洪水调优（before → after）

| 指标 | 旧检测器 + 默认基线 | 补漏后默认基线 | 调优基线（实体默认清单） |
|---|---:|---:|---:|
| 发现数 | 123 | 125 | 5 |
| TP | 3 | 5 | 5 |
| FP | 120 | 120 | 0 |
| FN | 2 | 0 | 0 |
| FP 率 | 97.56% | 96.00% | 0.00% |
| FN 率 | 40.00% | 0.00% | 0.00% |

- 120 FP 全部来自 CI `pods/exec`（默认基线缺 CI 主体）；补漏检测器使 SA token 铸造与
  pods/portforward 从 FN 变 TP。
- 拒绝口径本轮统一收口：非 2xx 默认不入报（403 扫描器尝试不再计 FP），
  exec/attach/portforward 的 **101 Switching Protocols 视为成功会话**（不再误当拒绝）。
- 学习模式（仅前 340 条历史、不看标签、仅 2xx）习得 CI/监控/调度三个主体，
  学习-only 同样 0 FP / 0 FN；产物仍须 lead 审批 merge 才生效，且高危形态永不学习。

### 2.3 逐场景说明

- **平台基线**：before 18 条（16 FP）；after 3 条 = TP 2（tenant-a model-copy-job 特权挂载、
  Falco 未加载规则缺口）+ 1 条无标注 FP（ray-head hostNetwork）。7 类平台 DaemonSet
  噪声由 `(namespace, serviceAccount, image 前缀)` 三元组抑制 15 条，provenance 可审计。
- **RBAC/网络**：before 20 条（13 FP）；after 8 条 = TP 7（tenant-a cluster-admin、
  tenant-a-deployer 扩散、tenant-a 读 Secret、platform-scheduler 读 Secret、
  tenant-b/tenant-c 无隔离）+ 1 条无标注 FP（tenant-c 读 Secret）；FN 1 条为
  mutable image tag（当前模块不覆盖，如实计入）。
- **审计洪水**：before 123 条（120 FP）；after 5 条全 TP、0 FP、0 FN。
  CI exec / 监控读 Secret / 调度器挂 PVC 由主体基线抑制（留痕 120 条）；403 与
  SA token / portforward 按统一拒绝口径与补漏检测器处理。

## 3. 防御生效状态（fixture 声明，不是客户实测）

| 项 | 总数 | 生效/加载/覆盖 | 缺口 | 比率 |
|---|---:|---:|---:|---:|
| Kyverno 策略 | 8 | Enforce 3 | Audit 4 + Missing 1 | 37.5% |
| Falco 规则 | 14 | Loaded 8 | Missing 6 | 57.1% |
| NetworkPolicy 分区 | 14 NS | 默认拒绝 6 | 未覆盖 8 | 42.9% |

未覆盖命名空间（fixture）：`east-prod/ingress-nginx`、`east-prod/kube-system`、
`east-prod/monitoring`、`east-prod/security`、`east-prod/tenant-b`、
`west-prod/kube-system`、`west-prod/monitoring`、`west-prod/tenant-c`。

> 这些状态来自 `lab/enterprise-fixtures/manifests/` 与快照声明，**没有**在客户的
> EKS/AKS、Calico/Cilium、Kyverno/Falco 版本上实跑；Pilot 必须读取客户真实状态重测。

## 4. 真实集群车道（与 fixture 分列）

| 项 | 值 |
|---|---|
| 来源 | `reports/samples/real-cluster/recon-findings.json` |
| 环境 | 单节点 k3s `v1.36.5+k3s1`，QEMU TCG，2 GB 内存，无 HA |
| 模块 | 6/6 ok（exposure / network-policy / rbac / framework-port / escape / observability） |
| 发现 | 16 条（critical 11 / high 3 / medium 2） |
| FP/FN | **不计算 FP/FN**：无客户标注真值；只有结构性发现，不能当准确率 |

真实集群证明的是「真 apiserver/CNI/NetworkPolicy 数据面可跑通」，不是「误报漏报已调优」。
两者证据类型不同，禁止混写。

## 5. 未达成与后续

1. **fixture ≠ 客户集群**：K8s/CNI/CRD/Kyverno/Falco 版本、遥测字段、审计采样率均不同。
2. **事件量级**：345 条 ≠ 客户日均百万级；需在 Pilot 用客户审计流抽样/回放。
3. **漏报面**：本轮已补 serviceaccounts/token 与 pods/portforward 检测器；剩余 FN 为
   mutable image tag（夹具无该形态证据），已如实计入，不以造证据「消灭」。
4. **例外清单**：平台 DaemonSet 例外需客户审批与版本化，不能硬编码在规则里。
5. **真实规则生效**：Kyverno/Falco 的 Enforce/Loaded 状态必须在客户运行时读取，
   fixture 声明不算证据。
6. **调优轮次**：本目标只用了 1 轮（实体基线 + 学习 + 补漏 + 拒绝口径收口）；
   场景 1 单场景 FP 仍 33.33%（18 条中 1 条无标注），未用第二轮硬压到 0——
   那会让「无标注真实形态」被吞掉。

## 6. 复现

```bash
python lab/enterprise-fixtures/gen_fixtures.py   # 幂等再生成夹具
python lab/enterprise_lab.py                     # 输出 reports/samples/enterprise-lab/results.{json,md}
python -m unittest tests.test_enterprise_lab -v
```

边界：fixture 结果只用于本地可重复评测与调优方法验证；企业验收必须在客户环境按
`docs/ENTERPRISE-READINESS.md` 的 Pilot 门槛重测。
