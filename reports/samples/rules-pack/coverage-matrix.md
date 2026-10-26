# Trident 紫队验证覆盖率矩阵（defense validation）

- 时间：<timestamp>；靶场：http://127.0.0.1:<port>/（mode=vulnerable，仅 127.0.0.1）
- 摘要：链 28 条，覆盖 28，漏过 0；规则评估 98 项（拦截 21 / 检测 73 / 漏过 0）
- 判定口径：合成事件使用探测规格声明的业务端口（mock 基座端口随机分配）；匹配器：内置简化 sigma/falco/suricata 匹配器（selection/event_type/any_of 语义子集）

| 链 | 类别 | 探针重放 | 状态 |
|---|---|---|---|
| flat-network-admin-plane-weight-poison | 经典攻击链 | POST /pause → 200 复现；POST /pull_weights → 200 复现 | 拦截+检测 |
| ray-dashboard-cluster-takeover | 经典攻击链 | POST /api/jobs/ → 200 复现；fixture×4 | 拦截+检测 |
| nccl-gradient-injection | 经典攻击链 | fixture×2 | 拦截+检测 |
| shared-pvc-supply-chain-poison | 经典攻击链 | fixture×3 | 检测 |
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
| long-context-cache-leak | 网络利用链 | POST /v1/chat/completions → 200 复现 | 检测 |
| pd-kv-poison | 网络利用链 | fixture×2 | 检测 |
| vpc-cni-dual-control-plane-lateral | 网络利用链 | fixture×1 | 拦截+检测 |
| agent-platform-zero-precondition-lateral | 零日链 | POST /v1/jobs/run → 200 复现；GET /mock-imds/aliyun/latest/meta-data/ram/security-credentials/ → 200 复现；fixture×1 | 拦截+检测 |
| agent-platform-cross-tenant-data-chain | 零日链 | POST /api/v1/bindings → 200 复现；fixture×1 | 检测 |
| gpu-tenant-residue-chain | 网络利用链 | POST /gpu/allocate → 200 复现；POST /gpu/release → 200 复现；GET /gpu/residue?device=gpu-b-0&tenant=tenant-b → 200 复现；GET /gpu/metrics → 200 复现；fixture×3 | 检测 |
| cloud-cross-tenant-role-assume | 云侧权重桶链 | GET /cloud/identity?role=weight-reader → 200 复现；POST /cloud/identity/assume-role → 200 复现；GET /cloud/bucket/list?bucket=weights-b → 200 复现；fixture×1 | 检测 |
| ai-gateway-key-exfil | AI 网关链 | GET /health → 200 复现；POST /v1/chat/completions → 200 复现；GET /config → 200 复现；GET /models → 200 复现；POST /key/generate → 200 复现 | 检测 |
| fabric-silent-corruption-chain | 网络利用链 | POST /sharp/sessions → 200 复现；POST /sharp/reduce → 200 复现；POST /ib/sm/partition → 200 复现；fixture×2 | 检测 |
| fabric-exhaustion-chain | 网络利用链 | POST /nccl/bootstrap → 200 复现；POST /sched/gang → 200 复现；POST /checkpoint/io → 200 复现；POST /roce/pfc → 200 复现；fixture×2 | 检测 |
| cluster-takeover-objective | 经典攻击链 | fixture×10 | 拦截+检测 |
| approx-cache-cross-tenant-chain | 网络利用链 | GET /config → 200 复现；POST /approx/lookup → 200 复现 | 检测 |
| cache-sidechannel-chain | 网络利用链 | POST /v1/chat/completions → 200 复现；GET /router/metrics → 200 复现 | 检测 |

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
- [检测] sigma-sa-token-mint（sigma）— 事件命中: sigma create serviceaccounts
- [检测] sigma-pods-portforward-tunnel（sigma）— 事件命中: sigma create pods
- [检测] sigma-pods-exec-lateral（sigma）— 事件命中: sigma create pods
- [检测] falco-admin-plane-unauth-access（falco）— 事件命中: falco connect port=8265 parent=-

### nccl-gradient-injection（拦截+检测）
- [拦截] netpol-default-deny-partition（netpol）— 策略文件在包内齐备（默认 monitor，Enforce 后即拦截）
- [建议] rdma-sriov-ib-partition-advice（ib-advice）— 缓解建议文件在包内
- [检测] falco-nccl-abnormal-join（falco）— 事件命中: falco nccl_join port=29500 parent=-
- [检测] suricata-nccl-kv-ports（suricata）— 事件命中: suricata 10.42.0.9:29500 uri=-

### shared-pvc-supply-chain-poison（检测）
- [检测] sigma-weight-pvc-abnormal-write（sigma）— 事件命中: sigma patch persistentvolumeclaims
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

### long-context-cache-leak（检测）
- [检测] suricata-longctx-kv-endpoints（suricata）— 事件命中: suricata 10.42.0.9:8000 uri=/v1/chat/completions

### pd-kv-poison（检测）
- [检测] suricata-longctx-kv-endpoints（suricata）— 事件命中: suricata 10.42.0.9:45678 uri=/kv/transfer

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

### gpu-tenant-residue-chain（检测）
- [检测] sigma-gpu-pool-admin-unauth（sigma）— 事件命中: sigma allocate 
- [检测] falco-gpu-device-cross-namespace（falco）— 事件命中: falco mount port=- parent=-
- [检测] falco-mig-abnormal-reconfig（falco）— 事件命中: falco exec port=- parent=-
- [检测] suricata-gpu-cloud-tenant-uri（suricata）— 事件命中: suricata 10.42.0.9:8080 uri=/gpu/allocate

### cloud-cross-tenant-role-assume（检测）
- [检测] sigma-cloud-cross-account-assume（sigma）— 事件命中: sigma None 
- [检测] suricata-gpu-cloud-tenant-uri（suricata）— 事件命中: suricata 10.42.0.9:443 uri=/cloud/identity?role=weight-reader

### ai-gateway-key-exfil（检测）
- [检测] sigma-gateway-admin-api-no-auth（sigma）— 事件命中: sigma admin_api_call 
- [检测] sigma-gateway-default-master-key-use（sigma）— 事件命中: sigma authenticate 
- [检测] falco-gateway-upstream-config-read（falco）— 事件命中: falco config_read port=- parent=-
- [检测] suricata-ai-gateway-admin-uri（suricata）— 事件命中: suricata 10.42.0.9:4000 uri=/config

### fabric-silent-corruption-chain（检测）
- [检测] sigma-fabric-sharp-unauth-join（sigma）— 事件命中: sigma join 
- [检测] falco-fabric-collective-poison（falco）— 事件命中: falco collective_reduce port=8000 parent=-
- [检测] falco-fabric-control-plane-mutation（falco）— 事件命中: falco fabric_config_write port=8000 parent=-
- [检测] suricata-fabric-control-uri（suricata）— 事件命中: suricata 10.42.0.9:8000 uri=/sharp/sessions

### fabric-exhaustion-chain（检测）
- [检测] sigma-fabric-exhaustion-quota-miss（sigma）— 事件命中: sigma port_alloc 
- [检测] falco-fabric-control-plane-mutation（falco）— 事件命中: falco fabric_config_write port=8000 parent=-
- [检测] suricata-fabric-control-uri（suricata）— 事件命中: suricata 10.42.0.9:8000 uri=/nccl/bootstrap

### cluster-takeover-objective（拦截+检测）
- [拦截] deny-privileged-pod（kyverno/gatekeeper）— 策略文件在包内齐备（默认 monitor，Enforce 后即拦截）
- [拦截] alert-rolebinding-creation（kyverno/gatekeeper）— 策略文件在包内齐备（默认 monitor，Enforce 后即拦截）
- [拦截] netpol-default-deny-partition（netpol）— 策略文件在包内齐备（默认 monitor，Enforce 后即拦截）
- [检测] sigma-rolebinding-cluster-admin（sigma）— 事件命中: sigma create clusterrolebinding
- [检测] sigma-sa-token-mint（sigma）— 事件命中: sigma create serviceaccounts
- [检测] sigma-pods-portforward-tunnel（sigma）— 事件命中: sigma create pods
- [检测] sigma-pods-exec-lateral（sigma）— 事件命中: sigma create pods
- [检测] sigma-cluster-takeover-entry（sigma）— 事件命中: sigma list services
- [检测] sigma-cluster-token-harvest（sigma）— 事件命中: sigma create serviceaccounts
- [检测] sigma-cluster-rbac-takeover（sigma）— 事件命中: sigma create clusterrolebindings
- [检测] sigma-cluster-privileged-pod（sigma）— 事件命中: sigma create pods
- [检测] sigma-cluster-proof-actions（sigma）— 事件命中: sigma list secrets
- [检测] sigma-cluster-cleanup-trail（sigma）— 事件命中: sigma delete clusterrolebindings
- [检测] falco-node-root-marker-write（falco）— 事件命中: falco open_write port=- parent=-

### approx-cache-cross-tenant-chain（检测）
- [检测] sigma-cache-tenant-isolation-missing（sigma）— 事件命中: sigma None 
- [检测] suricata-cache-plane-uri（suricata）— 事件命中: suricata 10.42.0.11:8300 uri=/approx/lookup

### cache-sidechannel-chain（检测）
- [检测] sigma-cache-probing-burst（sigma）— 事件命中: sigma chat_completion 
- [检测] sigma-router-cache-metrics-leak（sigma）— 事件命中: sigma metrics_read 
- [检测] suricata-cache-plane-uri（suricata）— 事件命中: suricata 10.42.0.11:8300 uri=/router/metrics

## 知识闭环

- 漏过项 → 规则缺口 → 反哺规则库迭代；
- 拦截态 = 准入/隔离策略已在包内（默认 monitor，Enforce 后即拦截）；检测态 = 简化匹配器在重放事件上实际命中。
