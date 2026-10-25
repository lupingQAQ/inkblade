# 企业真实感实验夹具（production-shaped fixture）

> **这是 fixture，不是客户生产集群。** 用于本地可重复地测误报/漏报与调优；
> 真实集群证据另见 `reports/samples/real-cluster/`（单节点 k3s/QEMU TCG，无标注，
> 因此不计算 FP/FN）。

## 内容

- `clusters/east-prod.json` / `west-prod.json`：混合命名空间（kube-system/security/
  monitoring/ml-training/ml-inference/tenant-a/tenant-b/tenant-c/ci/ingress-nginx）、
  NetworkPolicy 分区（含未隔离分区）、GPU 节点、PVC/Secret 元数据、RBAC 通配符与
  常规系统绑定、Kyverno/Falco 生效状态。
- `audit-noise.jsonl`：340 条良性审计事件（CI exec、扫描器 403、监控读 Secret、
  平台调度器挂载权重 PVC）+ 5 条标注风险（其中 2 条为当前检测器未覆盖）。
- `ground-truth.json`：逐条 benign/risk 标签（实现不得临时改标签）。
- `kubeconfigs/east.yaml` / `west.yaml`：仅含 `MOCK-*` token 的本地 kubeconfig，
  用于 CLI/多 context 合并演示；不是真实客户凭据。
- `manifests/`：Kyverno/Falco/NetworkPolicy/Namespace 生产形态清单（Kustomize 前置）。
- `gen_fixtures.py`：幂等再生成。

## 明确不声称

- 不声称这些清单已在客户的 EKS/AKS、Calico/Cilium、Kyverno/Falco 版本上实跑；
- 不声称 FP/FN 率可外推到客户环境；Pilot 必须用客户标注样本重测；
- 不把 fixture 结果写成「生产验证」。
