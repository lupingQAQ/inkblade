# Trident 紫队验证覆盖率矩阵（defense validation）

- 时间：2026-10-24T18:04:14Z；靶场：http://127.0.0.1:51558/（mode=vulnerable，仅 127.0.0.1）
- 摘要：链 18 条，覆盖 18，漏过 0；规则评估 56 项（拦截 18 / 检测 34 / 漏过 0）
- 判定口径：合成事件使用探测规格声明的业务端口（mock 基座端口随机分配）；匹配器：内置简化 sigma/falco/suricata 匹配器（selection/event_type/any_of 语义子集）

| 链 | 类别 | 探针重放 | 状态 |
|---|---|---|---|
| flat-network-admin-plane-weight-poison | 经典攻击链 | POST /pause → 200 复现；POST /pull_weights → 200 复现 | 拦截+检测 |
| ray-dashboard-cluster-takeover | 经典攻击链 | POST /api/jobs/ → 200 复现；fixture×1 | 拦截+检测 |
| nccl-gradient-injection | 经典攻击链 | fixture×2 | 拦截+检测 |
| shared-pvc-supply-chain-poison | 经典攻击链 | fixture×2 | 检测 |
| ssrf-sa-token-cloud-metadata | 经典攻击链 | GET /mock-imds/azure/metadata/instance?api-version=2021-02-01 → 200 复现；fixture×1 | 拦截+检测 |
| observability-pivot-precision-strike | 经典攻击链 | GET /__routes__ → 200 复现 | 拦截 |
| pickle-channel-unauth-execution | 经典攻击链 | POST /create_engine → 200 复现；fixture×1 | 拦截+检测 |
| aws-role-weight-bucket | 云侧权重桶链 | GET /mock-imds/aws/latest/meta-data/iam/security-credentials/role → 200 复现；fixture×1 | 检测 |
| azure-managed-identity-blob-weight | 云侧权重桶链 | GET /mock-imds/azure/metadata/instance?api-version=2021-02-01 → 200 复现；fixture×1 | 检测 |
| ali-ram-role-oss-weight | 云侧权重桶链 | GET /mock-imds/aliyun/latest/meta-data/ram/security-credentials/ → 200 复现；fixture×1 | 检测 |
| tencent-cam-role-cos-weight | 云侧权重桶链 | GET /mock-imds/tencent/latest/meta-data/cam/security-credentials/ → 200 复现；fixture×1 | 检测 |
| gpu-network-operator-host-escape | 网络利用链 | fixture×1 | 拦截+检测 |
| ib-rdma-collective-injection | 网络利用链 | fixture×2 | 拦截+检测 |
| imex-computedomain-gpu-memory-crossing | 网络利用链 | fixture×1 | 拦截+检测 |
| prefill-decode-kv-inference-manipulation | 网络利用链 | fixture×2 | 拦截+检测 |
| vpc-cni-dual-control-plane-lateral | 网络利用链 | fixture×1 | 拦截+检测 |
| agent-platform-zero-precondition-lateral | 零日链 | POST /v1/jobs/run → 200 复现；GET /mock-imds/aliyun/latest/meta-data/ram/security-credentials/ → 200 复现；fixture×1 | 拦截+检测 |
| agent-platform-cross-tenant-data-chain | 零日链 | POST /api/v1/bindings → 200 复现；fixture×1 | 检测 |

## 规则命中明细

### flat-network-admin-plane-weight-poison（拦截+检测）
- [拦截] alert-combo-signature（kyverno/gatekeeper）— 策略文件在包内齐备（默认 monitor，Enforce 后即拦截）
- [拦截] netpol-default-deny-partition（netpol）— 策略文件在包内齐备（默认 monitor，Enforce 后即拦截）
- [检测] falco-admin-plane-unauth-access（falco）— 事件命中: falco connect port=30000 parent=-
- [检测] falco-weight-file-abnormal-write（falco）— 事件命中: falco open_write port=- parent=-
- [检测] suricata-admin-endpoint-uri（suricata）— 事件命中: suricata 10.42.0.9:30000 uri=/pause

### ray-dashboard-cluster-takeover（拦截+检测）
- [拦截] deny-privileged-pod（kyverno/gatekeeper）— 策略文件在包内齐备（默认 monitor，Enforce 后即拦截）
- [拦截] alert-rolebinding-creation（kyverno/gatekeeper）— 策略文件在包内齐备（默认 monitor，Enforce 后即拦截）
- [拦截] netpol-default-deny-partition（netpol）— 策略文件在包内齐备（默认 monitor，Enforce 后即拦截）
- [检测] sigma-rolebinding-cluster-admin（sigma）— 事件命中: sigma create rolebinding
- [检测] sigma-ray-job-submit（sigma）— 事件命中: sigma create job
- [检测] falco-admin-plane-unauth-access（falco）— 事件命中: falco connect port=8265 parent=-

### nccl-gradient-injection（拦截+检测）
- [拦截] netpol-default-deny-partition（netpol）— 策略文件在包内齐备（默认 monitor，Enforce 后即拦截）
- [建议] rdma-sriov-ib-partition-advice（ib-advice）— 缓解建议文件在包内
- [检测] falco-nccl-abnormal-join（falco）— 事件命中: falco nccl_join port=29500 parent=-
- [检测] suricata-nccl-kv-ports（suricata）— 事件命中: suricata 10.42.0.9:29500 uri=-

### shared-pvc-supply-chain-poison（检测）
- [检测] falco-pickle-deserialize-call（falco）— 事件命中: falco deserialize port=- parent=-
- [检测] falco-weight-file-abnormal-write（falco）— 事件命中: falco open_write port=- parent=-

### ssrf-sa-token-cloud-metadata（拦截+检测）
- [拦截] deny-automount-serviceaccount-token（kyverno/gatekeeper）— 策略文件在包内齐备（默认 monitor，Enforce 后即拦截）
- [检测] sigma-secret-abnormal-read（sigma）— 事件命中: sigma get secret
- [检测] suricata-imds-egress（suricata）— 事件命中: suricata 169.254.169.254:80 uri=/mock-imds/azure/metadata/instance?api-version=2021-02-01

### observability-pivot-precision-strike（拦截）
- [拦截] netpol-default-deny-partition（netpol）— 策略文件在包内齐备（默认 monitor，Enforce 后即拦截）

### pickle-channel-unauth-execution（拦截+检测）
- [拦截] netpol-default-deny-partition（netpol）— 策略文件在包内齐备（默认 monitor，Enforce 后即拦截）
- [检测] falco-pickle-deserialize-call（falco）— 事件命中: falco deserialize port=- parent=-
- [检测] suricata-admin-endpoint-uri（suricata）— 事件命中: suricata 10.42.0.9:9000 uri=/create_engine

### aws-role-weight-bucket（检测）
- [检测] sigma-secret-abnormal-read（sigma）— 事件命中: sigma get secret
- [检测] suricata-imds-egress（suricata）— 事件命中: suricata 169.254.169.254:80 uri=/mock-imds/aws/latest/meta-data/iam/security-credentials/role

### azure-managed-identity-blob-weight（检测）
- [检测] sigma-secret-abnormal-read（sigma）— 事件命中: sigma get secret
- [检测] suricata-imds-egress（suricata）— 事件命中: suricata 169.254.169.254:80 uri=/mock-imds/azure/metadata/instance?api-version=2021-02-01

### ali-ram-role-oss-weight（检测）
- [检测] sigma-secret-abnormal-read（sigma）— 事件命中: sigma get secret
- [检测] suricata-imds-egress（suricata）— 事件命中: suricata 169.254.169.254:80 uri=/mock-imds/aliyun/latest/meta-data/ram/security-credentials/

### tencent-cam-role-cos-weight（检测）
- [检测] sigma-secret-abnormal-read（sigma）— 事件命中: sigma get secret
- [检测] suricata-imds-egress（suricata）— 事件命中: suricata 169.254.169.254:80 uri=/mock-imds/tencent/latest/meta-data/cam/security-credentials/

### gpu-network-operator-host-escape（拦截+检测）
- [拦截] deny-privileged-pod（kyverno/gatekeeper）— 策略文件在包内齐备（默认 monitor，Enforce 后即拦截）
- [拦截] deny-sensitive-hostpath（kyverno/gatekeeper）— 策略文件在包内齐备（默认 monitor，Enforce 后即拦截）
- [检测] sigma-privileged-pod-create（sigma）— 事件命中: sigma create pod

### ib-rdma-collective-injection（拦截+检测）
- [拦截] netpol-default-deny-partition（netpol）— 策略文件在包内齐备（默认 monitor，Enforce 后即拦截）
- [建议] rdma-sriov-ib-partition-advice（ib-advice）— 缓解建议文件在包内
- [检测] falco-nccl-abnormal-join（falco）— 事件命中: falco nccl_join port=29500 parent=-
- [检测] suricata-nccl-kv-ports（suricata）— 事件命中: suricata 10.42.0.9:29500 uri=-

### imex-computedomain-gpu-memory-crossing（拦截+检测）
- [拦截] deny-privileged-pod（kyverno/gatekeeper）— 策略文件在包内齐备（默认 monitor，Enforce 后即拦截）
- [建议] rdma-sriov-ib-partition-advice（ib-advice）— 缓解建议文件在包内
- [检测] sigma-privileged-pod-create（sigma）— 事件命中: sigma create pod

### prefill-decode-kv-inference-manipulation（拦截+检测）
- [拦截] netpol-default-deny-partition（netpol）— 策略文件在包内齐备（默认 monitor，Enforce 后即拦截）
- [建议] rdma-sriov-ib-partition-advice（ib-advice）— 缓解建议文件在包内
- [检测] falco-nccl-abnormal-join（falco）— 事件命中: falco nccl_join port=45678 parent=-
- [检测] suricata-nccl-kv-ports（suricata）— 事件命中: suricata 10.42.0.9:45678 uri=-

### vpc-cni-dual-control-plane-lateral（拦截+检测）
- [拦截] netpol-default-deny-partition（netpol）— 策略文件在包内齐备（默认 monitor，Enforce 后即拦截）
- [拦截] vpc-securitygroup-supplement（vpc-sg）— 策略文件在包内齐备（默认 monitor，Enforce 后即拦截）
- [检测] suricata-imds-egress（suricata）— 事件命中: suricata 169.254.169.254:80 uri=/latest/meta-data/iam/security-credentials/role

### agent-platform-zero-precondition-lateral（拦截+检测）
- [拦截] deny-automount-serviceaccount-token（kyverno/gatekeeper）— 策略文件在包内齐备（默认 monitor，Enforce 后即拦截）
- [拦截] netpol-default-deny-partition（netpol）— 策略文件在包内齐备（默认 monitor，Enforce 后即拦截）
- [检测] sigma-secret-abnormal-read（sigma）— 事件命中: sigma get secret
- [检测] suricata-imds-egress（suricata）— 事件命中: suricata 169.254.169.254:80 uri=/mock-imds/aliyun/latest/meta-data/ram/security-credentials/
- [检测] zeroday-agent-sandbox-unexpected-parent-exec（falco）— 事件命中: falco exec port=- parent=http-job-runner

### agent-platform-cross-tenant-data-chain（检测）
- [检测] sigma-secret-abnormal-read（sigma）— 事件命中: sigma get secret
- [检测] zeroday-agent-tenant-object-cross-read（sigma）— 事件命中: sigma create tenant-binding

## 知识闭环

- 漏过项 → 规则缺口 → 反哺规则库迭代；
- 拦截态 = 准入/隔离策略已在包内（默认 monitor，Enforce 后即拦截）；检测态 = 简化匹配器在重放事件上实际命中。
