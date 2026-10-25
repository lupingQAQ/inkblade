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
| 审计 | 345 条事件：340 条良性（CI `pods/exec` ×120、扫描器 403 读 Secret ×60、监控读 Secret ×100、平台调度器挂权重 PVC 建 Pod ×60）+ 5 条风险（cluster-admin 绑定、tenant-b exec、权重 PVC patch、SA token 铸造、pods/portforward）。 |
| 检测器 | 真实模块：`escape-primitives`、`rbac-mapping`、`network-policy-coverage`、`exposure-mapping`、`observability-exposure`；审计：`core/auditlog.py` 六检测器。 |
| 标注 | `ground-truth.json` 固化 benign/risk；实现不临时改标签。 |
| 口径 | FP 率 = FP / (TP + FP)；FN 率 = FN / (TP + FN)；只统计 critical/high/medium/low，info 不计。 |

**三类噪声场景**（任务要求至少 3 类）：

1. **平台组件基线噪声**：云厂商 CNI/CSI、node-exporter、prometheus、falco、ingress
   等 DaemonSet 的 privileged / hostPath / hostNetwork；
2. **RBAC/NetworkPolicy 常规运维噪声**：`system:controller` 通配符、平台 operator
   wildcard、CI `pods/exec`、系统命名空间未加默认拒绝；
3. **审计事件洪水**：340 条良性事件（CI exec、扫描器 403、监控读 Secret、平台调度器
   挂 PVC）与 5 条风险事件混合，其中 2 条为当前检测器未覆盖。

## 2. 结果（fixture 车道）

### 2.1 三场景 FP/FN

| 场景 | 发现数 | TP | FP | FN | FP 率 | FN 率 |
|---|---:|---:|---:|---:|---:|---:|
| `platform-baseline-noise` | 17 | 1 | 16 | 1 | 94.12% | 50.00% |
| `rbac-intent-noise` | 20 | 7 | 13 | 1 | 65.00% | 14.29% |
| `audit-flood-noise`（调优后） | 3 | 3 | 0 | 2 | 0.00% | 40.00% |
| **合计（按各场景调优后）** | 40 | 11 | 29 | 4 | **72.50%** | **28.57%** |

> 合计不是「产品准确率」，而是这组故意偏噪声的 fixture 上的结果；场景 1/2 没有做
> 客户例外清单调优，因此 FP 高。**不粉饰为低误报**。

### 2.2 审计洪水调优（before → after）

| 指标 | 默认基线 | 调优基线（+CI runner +安全扫描器） | 变化 |
|---|---:|---:|---:|
| 发现数 | 183 | 3 | -180 |
| TP | 3 | 3 | 0 |
| FP | 180 | 0 | **-100%** |
| FN | 2 | 2 | 0 |
| FP 率 | 98.36% | 0.00% | -98.36pp |
| FN 率 | 40.00% | 40.00% | 0 |

调优只解决「主体基线」这一类误报；**不解决漏报**。2 条未覆盖风险（SA token 铸造、
pods/portforward）在调优后仍然漏报，必须补检测器或准入，不能靠调基线「消灭」。

### 2.3 逐场景说明

- **平台基线**：`escape-primitives` 把 7 类平台 DaemonSet 的合法 privileged/hostPath/
  hostNetwork 报成 16 条 medium+（TP 只有 tenant-a 的 model-copy-job 1 条）。
  这证明「没有客户例外清单时，平台噪声会淹没真实租户风险」；例外清单需按
  `image digest + namespace + serviceAccount` 三元组审批，不能按标题永久静默。
- **RBAC/网络**：`system:controller`/`platform-operator` 通配符、CI pods/exec、
  kube-system/monitoring/security 无默认拒绝共 13 条 FP；真实风险 7 条（tenant-a
  cluster-admin、tenant-a-deployer、tenant-a 读 Secret、platform-scheduler 读 Secret、
  tenant-b/tenant-c 无隔离）中检测到 7 条，FN 1 条为 mutable image tag（当前模块不覆盖）。
- **审计洪水**：默认基线下 CI exec + 扫描器 403 造成 180 条 FP；调优后 0 FP。
  TP 3 条（cluster-admin 绑定、tenant-b exec、权重 PVC patch）；FN 2 条（SA token
  铸造、pods/portforward）。

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
3. **漏报面**：SA token 铸造、pods/portforward、mutable image tag 当前未覆盖，已如实计 FN。
4. **例外清单**：平台 DaemonSet 例外需客户审批与版本化，不能硬编码在规则里。
5. **真实规则生效**：Kyverno/Falco 的 Enforce/Loaded 状态必须在客户运行时读取，
   fixture 声明不算证据。

## 6. 复现

```bash
python lab/enterprise-fixtures/gen_fixtures.py   # 幂等再生成夹具
python lab/enterprise_lab.py                     # 输出 reports/samples/enterprise-lab/results.{json,md}
python -m unittest tests.test_enterprise_lab -v
```

边界：fixture 结果只用于本地可重复评测与调优方法验证；企业验收必须在客户环境按
`docs/ENTERPRISE-READINESS.md` 的 Pilot 门槛重测。
