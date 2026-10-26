# CIS Parity — Trident CIS 基准库 vs kube-bench

- 核对日期：2026-10-26
- kube-bench 基线：`aquasecurity/kube-bench@e278a5915a98`（2026-10-05），`cfg/cis-1.8/*.yaml`
- Trident 目录：`trident/cis/catalog.py`（`CATALOG` = 161 项）
- 判定引擎：`trident/cis/engine.py`（只读 fixture；缺证据 → `manual`）
- 超出项：`trident/cis/ml.py`（GPU Operator / vLLM / SGLang 部署基线 19 项，独立目录）
- 测试：`tests/test_cis_benchmark.py`（27 项）

## 1. kube-bench cis-1.8 官方条目数

`master.yaml` + `controlplane.yaml` + `etcd.yaml` + `node.yaml` + `policies.yaml` 合计 **130** 项；
其中 63 项 `scored=true`、40 项为 Manual（kube-bench `type: manual` 或全节 Manual）。

| Section | 官方条目 | 说明 |
|---|---:|---|
| 1.1 Control Plane Node Configuration Files | 21 | 文件权限/属主（4 项 scored=false） |
| 1.2 API Server | 30 | flag/准入插件/审计/加密（9 项 scored=false） |
| 1.3 Controller Manager | 7 | 1 项 scored=false |
| 1.4 Scheduler | 2 | — |
| 2 Etcd Node Configuration | 7 | 1 项 Manual（唯一 CA） |
| 3.1 Authentication and Authorization | 3 | 全 Manual |
| 3.2 Logging | 2 | 全 Manual（kube-bench 类型 auto/manual 各 1） |
| 4.1 Worker Node Configuration Files | 10 | 4 项 scored=false |
| 4.2 Kubelet | 13 | 8 项 scored=false |
| 5.1 RBAC and Service Accounts | 13 | 全 Manual |
| 5.2 Pod Security Standards | 13 | 全 Manual |
| 5.3 Network Policies and CNI | 2 | 全 Manual |
| 5.4 Secrets Management | 2 | 全 Manual |
| 5.5 Extensible Admission Control | 1 | 全 Manual |
| 5.7 General Policies | 4 | 全 Manual |
| **合计** | **130** | scored=63 / Manual=40 |

> 注：CIS v1.8 的 5.6（Managed Services）不在 kube-bench 自管 profile 中；本库同样不纳入
> 130 项口径，避免把托管服务条目混入自管集群评分。

## 2. Trident 覆盖（130/130）

| 口径 | 项数 | 说明 |
|---|---:|---|
| kube-bench cis-1.8 官方 | **130** | 逐条 ID 对齐（`OFFICIAL_IDS`），无缺项/无重复 |
| cis-1.9 前向兼容 | 1 | §4.3.1 kube-proxy metrics 绑定 localhost |
| CIS DIL v2.0 节点主机加固 | 25 | 内核参数/文件系统/auditd/SSH/文件权限 |
| k3s 自管面 | 5 | Secret 静态加密、etcd 快照、审计、Traefik dashboard、ServiceLB |
| **CIS catalog 合计** | **161** | `tier` 字段区分来源，矩阵按 section 汇总 |
| 超出项（ML 部署基线） | 19 | GPU Operator 6 / vLLM 5 / SGLang 4 / 部署 4，独立矩阵 |

- **Manual 项 42**：kube-bench 的 40 项 Manual + §2.7（唯一 CA）+ §1.2.12
  （PSP 已移除，kube-bench 标 auto 但无客观命令，本库改为 manual）。
- **判定类型**：flag / pair / plugin / file / owner / evidence / kubelet / manual；
  缺组件块、缺文件条目、缺 evidence 键一律 `manual`，**不臆造 pass/fail**。
- **计分**：仅 `scored=true` 且非 manual 的项进入分母；与 kube-bench 的 63 项计分口径一致。
- **fixture 驱动**：`lab/fixtures/cis/{compliant,vulnerable}-cluster.json`；模块
  `cis-benchmark-audit` 输出 `pass/fail/manual` 矩阵（summary JSON 的 `matrix` 字段）。

## 3. 超出项：GPU Operator / vLLM / SGLang

| 区域 | 项数 | 代表检查 |
|---|---:|---|
| GPU Operator | 6 | 版本固定、命名空间 PSA、DCGM exporter 暴露面、NFD/MIG 特权、validator |
| vLLM | 5 | api-key、`--trust-remote-code`、metrics 暴露、privileged、镜像 digest |
| SGLang | 4 | api-key、`--trust-remote-code`、metrics 暴露、hostNetwork |
| 部署面 | 4 | NetworkPolicy、runAsNonRoot、seccomp RuntimeDefault、敏感 hostPath |

这些项**不属于** CIS Kubernetes Benchmark，不进入 130 项 parity 统计；模块在 summary
中单独给出 `ml` 计数与 `ml_matrix`。缺失 `snapshot.ml` 时全部 `manual`。

## 4. 效果（fixture）

| fixture | pass | fail | manual | score | ML fail |
|---|---:|---:|---:|---:|---:|
| `compliant-cluster.json` | 119 | **0** | 42 | **1.0** | 0 |
| `vulnerable-cluster.json` | 46 | **73** | 42 | 0.415 | 15 |

关键检出（vulnerable）：`1.2.1` 匿名认证、`1.2.2` token-auth-file、`1.2.6` AlwaysAllow、
`1.2.15` NodeRestriction、`1.2.17` 审计日志缺失、`1.3.3` SA 凭据未分离、`2.2` etcd
无客户端证书、`4.2.1` kubelet 匿名认证、`4.2.4` 只读端口 10255、`4.3.1` kube-proxy
metrics 全网暴露、`DL-1.5.1` core dump、`K3S-1` 明文 Secret、`ML-VLLM-01` 无 api-key。
合规 fixture 中 42 项 Manual 保持 manual，不冒充 pass；自动化项 0 fail、score=1.0。

复现：

```
python -m unittest tests.test_cis_benchmark
```

## 5. 与 kube-bench 的差异与限制

1. **不执行 kube-bench**：本库是 fixture 判定器，用于 CI/报告矩阵；线上仍需 kube-bench
   采集（`--benchmark cis-1.8`）后转换为 snapshot。
2. **文件路径为 kubeadm 默认**（`/etc/kubernetes/manifests`、`/var/lib/kubelet`）；
   k3s/RKE 需在 snapshot 中替换路径或增加别名。
3. **1.2.12** 由 auto 改为 manual：PSP 在 1.25 移除，SecurityContextDeny 也不可用；
   保留条目但要求人工以 PSA/准入策略确认。
4. **1.2.30 / 4.2.12 强套件**：flag 为空时返回 manual（Go 默认套件随版本变化），
   避免对未显式配置的集群误报。
5. **主机/发行版项**参考 CIS DIL v2.0 与 k3s 文档，非 kube-bench K8s profile；已在 `tier`
   与矩阵中分离，不计入 130 项 parity。
6. **未覆盖**：托管控制面（EKS/GKE/AKS 的 5.6 Managed Services）、Windows 节点、
   审计策略内容逐条比对（3.2.2 保持 manual）。
