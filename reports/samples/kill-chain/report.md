# 最高权限证明（真实 k3s 集群）/ Highest-Privilege Proof (real k3s cluster)

> 生成时间 / generated: `2026-10-25T17:18:41Z`；PROOF marker: `real-20261026-10`；backend: `kubectl` (real_cluster=True)

## 环境 / Environment

| 项 / Item | 值 / Value |
|---|---|
| cluster | `real k3s` |
| node | `k3s` |
| API | `<kubeconfig>` |
| QEMU | `QEMU TCG (documented in docs/REAL-CLUSTER-VERIFICATION.md)` |
| lab fixture | `lab\qemu-k3s\manifests\40-killchain-operator.yaml` |

> 说明 / Note：单节点 QEMU TCG k3s，非生产规模；硬件/交换机/带外阶段只做版本闸门与只读，不执行硬件写入。

# 最高权限证明报告（中英双语） / Highest-Privilege Proof Report (Bilingual)

- **PROOF marker**: `real-20261026-10`
- **run**: `objective-cluster-takeover-objective-20261026-011707-real-20261026-10`
- **backend**: `kubectl` (real_cluster=True)
- **generated_at**: `2026-10-25T17:18:22Z`
- **proof_sha256**: `1617a34f7061126bb94270f3745096c5f827962844fcdb187cf8261080ec2c94`

## 最高权限证明 / Highest-Privilege Proof

| 证明项 / Proof item | 结果 / Result | 证据 / Evidence |
|---|---|---|
| RBAC | `cluster-admin` | RoleBinding `inkblade-pwn-rb-real-20261026-10`；ClusterRoleBinding `inkblade-pwn-crb-real-20261026-10`；can-i all={'all': True, 'create_namespace': True, 'get_all_secrets': True} |
| 节点 root / Node root | verified=True | node=`k3s`；uid=`uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)`；path=`/root/INKBLADE-PROOF-real-20261026-10`；sha256=`29bc79c339ac9bd5abced0cf94ba160b471ce7bdd9534548872990534527a211` |
| 集群 secret 列举 / Cluster secret enumeration | count=2 | namespaces=['kube-system'] |
| 测试 namespace / Test namespace | created=True | `inkblade-proof-real-20261026-10` |
| 测试 ConfigMap / Test ConfigMap | read_back=True | `inkblade-proof-real-20261026-10/inkblade-proof` |

## 提权面 / Privesc surface

- 选路状态 / Selection status: `unavailable`
- 起始主体 / Principal: ``
- 选中路径 / Chosen path: `已是管理员/无需提权 / already admin`
- 选择依据 / Rationale: 
- 备选路径 / Alternates: 0 条 / path(s)

- 回退 / Fallback: `stage-3-rbac-escalation`

### 集群级动作清单 / Cluster-level action list

| # | stage | verb | resource | namespace | name | result | sha256 |
|---|---|---|---|---|---|---|---|
| 1 | stage-3-rbac-escalation | create | rolebinding | inkblade-killchain | inkblade-pwn-rb-real-20261026-10 | {"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"apiVersion\":\"rbac.authorization.k8s.io/v1\",\"kind\":\"RoleBinding\",\"metadata\":{\"annotations\":{},\"labels\":{\"inkblade.io/objective\":\"real-2026 | `d386e7574edcff4e` |
| 2 | stage-3-rbac-escalation | create | clusterrolebinding |  | inkblade-pwn-crb-real-20261026-10 | {"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"apiVersion\":\"rbac.authorization.k8s.io/v1\",\"kind\":\"ClusterRoleBinding\",\"metadata\":{\"annotations\":{},\"labels\":{\"inkblade.io/objective | `771a76e0d14406ea` |
| 3 | stage-4-privileged-pod | create | pod | inkblade-killchain | inkblade-pwn-pod-real-20261026-10 | {"apiVersion":"v1","kind":"Pod","metadata":{"annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"annotations\":{},\"labels\":{\"app\":\"inkblade-proof\",\"inkblade.io/objective\":\"real-20261026-10\"},\"name\":\"inkblade-pwn-pod-real | `e9c4549f7712e234` |
| 4 | stage-5-node-marker | exec | pods | inkblade-killchain | inkblade-pwn-pod-real-20261026-10 | {"op":"write-node-marker","path":"/root/INKBLADE-PROOF-real-20261026-10","sha256":"29bc79c339ac9bd5abced0cf94ba160b471ce7bdd9534548872990534527a211"} | `99feb7f5185fa314` |
| 5 | stage-6-cluster-proof | create | namespace |  | inkblade-proof-real-20261026-10 | {"apiVersion":"v1","kind":"Namespace","metadata":{"annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"apiVersion\":\"v1\",\"kind\":\"Namespace\",\"metadata\":{\"annotations\":{},\"labels\":{\"inkblade.io/objective\":\"real-20261026-10\"},\"name\":\"inkblade-proof-real-20261026-10\"}} | `76fbea290841cc9b` |
| 6 | stage-6-cluster-proof | create | configmap | inkblade-proof-real-20261026-10 | inkblade-proof | {"apiVersion":"v1","data":{"marker":"INKBLADE-PROOF-real-20261026-10","node":"k3s","objective":"cluster-takeover-objective","secret_count":"2"},"kind":"ConfigMap","metadata":{"annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"apiVersion\":\"v1\",\"data\":{\"marker\":\"INKBLADE-PROOF | `490e892b0069e877` |
| 7 | stage-7-cleanup | exec | pods | inkblade-killchain | inkblade-pwn-pod-real-20261026-10 | {"op":"remove-node-marker","path":"/root/INKBLADE-PROOF-real-20261026-10"} | `a84716713ffd3c66` |
| 8 | stage-7-cleanup | delete | configmap | inkblade-proof-real-20261026-10 | inkblade-proof | deleted | `1185f37d33b0f89e` |
| 9 | stage-7-cleanup | delete | namespace |  | inkblade-proof-real-20261026-10 | deleted | `1185f37d33b0f89e` |
| 10 | stage-7-cleanup | delete | clusterrolebinding |  | inkblade-pwn-crb-real-20261026-10 | deleted | `1185f37d33b0f89e` |
| 11 | stage-7-cleanup | delete | rolebinding | inkblade-killchain | inkblade-pwn-rb-real-20261026-10 | deleted | `1185f37d33b0f89e` |
| 12 | stage-7-cleanup | delete | pod | inkblade-killchain | inkblade-pwn-pod-real-20261026-10 | deleted | `1185f37d33b0f89e` |
| 13 | stage-7-cleanup | delete | clusterrolebinding |  | inkblade-operator-broad | deleted | `1185f37d33b0f89e` |
| 14 | stage-7-cleanup | delete | clusterrole |  | inkblade-operator-broad | deleted | `1185f37d33b0f89e` |
| 15 | stage-7-cleanup | delete | serviceaccount | inkblade-killchain | inkblade-operator | deleted | `1185f37d33b0f89e` |
| 16 | stage-7-cleanup | delete | namespace |  | inkblade-killchain | deleted | `1185f37d33b0f89e` |

### 已清理声明 / Cleanup / Cleanup / 已清理声明

- **verified**: `True`
- **residue**: `[]`
- **fixture_cleanup**: `True`

| 检查项 / Check | 结果 / Result | 观测 / Observed |
|---|---|---|
| node marker | PASS | absent |
| namespace inkblade-proof-real-20261026-10 absent | PASS | absent |
| clusterrolebinding inkblade-pwn-crb-real-20261026-10 absent | PASS | absent |
| rolebinding inkblade-pwn-rb-real-20261026-10 absent | PASS | absent |
| pod inkblade-pwn-pod-real-20261026-10 absent | PASS | absent |
| fixture-clusterrolebinding inkblade-operator-broad absent | PASS | absent |
| fixture-clusterrole inkblade-operator-broad absent | PASS | absent |
| fixture-namespace inkblade-killchain absent | PASS | absent |
| namespace set equals baseline | PASS | {'expected': ['default', 'kube-node-lease', 'kube-public', 'kube-system', 'inkblade-proof'], 'actual': ['default', 'kube-node-lease', 'kube-public', 'kube-system', 'inkblade-proof']} |
| secret name set equals baseline | PASS | {'expected_count': 2, 'actual_count': 2, 'delta': []} |
| no objective clusterrolebinding | PASS | [] |

**已清理**：测试 namespace、测试 ConfigMap、pwn RoleBinding/ClusterRoleBinding、特权 Pod 与节点 `/root` proof 文件均已删除，并在删除后按基线复核；本次运行未留下持久化对象。 / **Cleanup confirmed**: test namespace/ConfigMap, pwn RoleBinding/ClusterRoleBinding, privileged Pod and the node `/root` proof file were deleted and re-checked against the baseline; this run left no persistent objects.

### 阶段与证据哈希 / Stages and evidence hashes

| # | stage | status | artifact | sha256 |
|---|---|---|---|---|
| 1 | stage-1-entry | success | objective/stage-1-entry.json | `a3d42b1dbf65330b` |
| 2 | stage-2-credential | success | objective/stage-2-credential.json | `99df02d8d5b8253c` |
| 3 | stage-3-rbac-escalation | success | objective/stage-3-rbac-escalation.json | `57694216f88eac4a` |
| 4 | stage-4-privileged-pod | success | objective/stage-4-privileged-pod.json | `270d4c33f4b7189a` |
| 5 | stage-5-node-marker | success | objective/stage-5-node-marker.json | `ba7d35d238d7de7e` |
| 6 | stage-6-cluster-proof | success | objective/stage-6-cluster-proof.json | `53550568fdfae994` |
| 7 | stage-7-cleanup | success | objective/stage-7-cleanup.json | `3775120b8ad947e1` |

### 截图与哈希 / Screenshot and hashes

- screenshot: `proof.png` sha256=`624bdeba0b463d4f535741ee5b794a8ec27b9c4061aea078a67464e724bd7a49`
- stage artifacts: `{'stage-1-entry': 'a3d42b1dbf65330bc085c2d30d71ce3bea6aee9245c6b43c8a25402f53c88e84', 'stage-2-credential': '99df02d8d5b8253ce50b2cec941a1d4a6b2af62ca171df9321c1c8797499601f', 'stage-3-rbac-escalation': '57694216f88eac4a4238835628ecca3832895d835752f1220e94b13ac31be8e9', 'stage-4-privileged-pod': '270d4c33f4b7189add78cb2a8a895353b9ad841cb81c55fa522a6433b2c6ca95', 'stage-5-node-marker': 'ba7d35d238d7de7e200e9e32fd4baf479f1d3afe9e4f21e0ef184e614dd9c409', 'stage-6-cluster-proof': '53550568fdfae994bd7723d2adbeb9df079c3890e0f48777805b1a537ef9522d', 'stage-7-cleanup': '3775120b8ad947e12c952e3c61d36cb74cfae7ee7b2d4c9162ee916d4255ee81'}`
- actions_sha256: `17d1532aedee58b9ce74da84afad981c6a1d2b9320db7d7244bd1afbae3e0fbe`
- proof_sha256: `1617a34f7061126bb94270f3745096c5f827962844fcdb187cf8261080ec2c94`

### 边界与硬件闸门 / Boundaries and hardware gates

- 单节点 QEMU/TCG k3s（非生产规模；无 HA/多节点调度验证）
- 硬件/交换机/带外阶段仅版本闸门 + 只读，不执行硬件写入
- secret 仅列举名称，不读取 value；token 仅记录 sha256 前缀与尾 4 位
- `switch-fabric`: read-only-version-gate / max_action=只读 — 无物理交换机/带外管理访问；以版本矩阵与只读证据代替，不执行硬件写入
- `bmc-oob`: read-only-version-gate / max_action=只读 — 不触达 BMC/带外控制面；仅登记版本与暴露面证据

---
*本报告由 InkBlade objective 编排器生成；证据锚为 proof.json 与三层证据库。* / *Generated by the InkBlade objective orchestrator; evidence anchors are proof.json and the three-layer evidence store.*
