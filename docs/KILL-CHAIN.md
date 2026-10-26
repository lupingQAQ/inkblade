# 内网入口 → 集群最高权限：夺权链与 PROOF

> 状态：**真实 QEMU/TCG 单节点 k3s 全链跑通**（2026-10-26）。
> 链定义：`inkblade/chains/cluster-takeover-objective.json`；编排器：`inkblade/core/objective_chain.py`
> （通过 `inkblade/core/objective.py` 导出）；CLI：`inkblade objective cluster-takeover`。
> 真实 run：`real-20261026-10`；PROOF：`sha256:1617a34f7061126bb94270f3745096c5f827962844fcdb187cf8261080ec2c94`。
> 样张：`reports/samples/kill-chain/{proof.json,report.md,proof.png,transcript.jsonl}`。
> 清理：`cleanup.verified=true`、`residue=[]`、`fixture_namespace_absent=true`；节点 `/root` marker 已删除并 SSH 复核。

## 0. 结论摘要

| 证明项 | 结果 | 证据 |
|---|---|---|
| 真实集群 | k3s `v1.36.5+k3s1`，node `k3s` Ready，QEMU TCG 单节点 | `proof.json` stage 1、`reports/samples/kill-chain/transcript.jsonl` |
| 入口 | `inkblade-killchain/inkblade-entry-api` NodePort 30081 + 实验 port-forward，HTTP 200 | stage 1 evidence / transcript |
| 凭据 | ServiceAccount `inkblade-operator` TokenRequest，whoami 为该 SA | stage 2 evidence（token 仅 sha256 前缀/尾 4 位） |
| RBAC 提权 | RoleBinding + ClusterRoleBinding → `cluster-admin`；`auth can-i '*' '*' --all-namespaces` = yes | stage 3 evidence |
| 特权 Pod | `privileged=true`、`hostPID=true`、`hostPath=/` → Running | stage 4 evidence |
| 节点 root | 容器内 `uid=0(root)`；向节点 `/root/INKBLADE-PROOF-real-20261026-10` 写入并 sha256 回读一致 | stage 5 evidence |
| 集群级证明 | 列举 2 个 secret 名称；创建/回读测试 namespace + ConfigMap；复核节点 marker | stage 6 evidence |
| 清理 | 测试 namespace/ConfigMap、pwn 绑定、特权 Pod、节点 marker、脆弱 operator 夹具全部删除；namespace/secret 集合与基线一致 | stage 7 cleanup checks |
| 截图 | `reports/samples/kill-chain/proof.png`（终端 PROOF 捕获），sha256 `624bdeba0b463d4f535741ee5b794a8ec27b9c4061aea078a67464e724bd7a49` | `report.md` Screenshot 节 |

## 1. 七阶段：原语 × 证据 × 清理 × 边界

链定义中每个 stage 都有：`preconditions`（前置判定）、`backup_targets`（写前快照）、
`success_evidence`（成功证据）、`fallback`（失败回退）、`timeout_s`、`detection_rules`。
下表是执行口径与真实 run 的对应关系。

| # | 阶段 | 原语 | 前置判定 | 成功证据 | 备份/清理 | 失败回退 |
|---|---|---|---|---|---|---|
| 1 | `stage-1-entry` 入口 | 枚举 NodePort/Service 暴露面；识别训练/推理控制面；盘点 operator SA | `/readyz=ok`；至少一个 NodePort；SA 可读 | Service 清单、入口 HTTP 200、SA can-i 矩阵 | 无写；不删除任何既有服务 | HTTP 不可达 → 仅保留 API 层暴露证据，不进入凭据阶段 |
| 2 | `stage-2-credential` 凭据/SA | TokenRequest 取 bearer token；盘点 IRSA/默认 key 分支 | SA 存在；token whoami 匹配；token 可 create rolebindings/clusterrolebindings | token 指纹、whoami、can-i 矩阵、IRSA/默认 key 版本闸门声明 | 不落明文 token；运行结束删除临时 token kubeconfig | token 不可用 → 默认 SA token 只读盘点；仍失败则中止，不尝试默认口令 |
| 3 | `stage-3-rbac-escalation` RBAC | 用 operator token 创建 namespace RoleBinding + ClusterRoleBinding 指向 cluster-admin；复核集群级 can-i | token 有效；具备 RBAC 写；namespace 存在 | 两个绑定对象 JSON；`can-i '*' '*'` = yes；前后对比 | 写前快照两个绑定（预期 absent）；清理删除绑定 | 防提权拒绝 → 降级 namespace RoleBinding，明确标记“未达集群级”，不伪造 PROOF |
| 4 | `stage-4-privileged-pod` 特权 Pod | cluster-admin token 创建 privileged + hostPID + hostPath=/ Pod | cluster-admin 已验证；namespace 存在；节点 Ready | Pod JSON 字段回读、phase=Running、准入策略对照 | 写前快照 Pod（预期 absent）；清理删除 Pod | 准入拒绝/镜像不可拉 → 保留 RBAC 证据并降级，不宣称节点 root |
| 5 | `stage-5-node-marker` 节点 root | Pod 内 uid=0 向 `/host/root` 写唯一 marker，`sha256sum` 回读 | Pod Running；hostPath=/；uid=0 | `id`、`cat /host/etc/hostname`、marker 内容+sha256+回读一致 | node-file 快照（预期 absent）；清理 `rm -f` 后 `test ! -f` | 写入失败 → 删 Pod 并以逃逸原语证据降级，不伪造节点 root |
| 6 | `stage-6-cluster-proof` 集群级证明 | cluster-admin token 列举全集群 secret 名称；创建测试 namespace/ConfigMap 并回读；复核节点 marker | token 有效；marker 可读；可 cluster-scope create namespace | secret 名称清单；namespace created；ConfigMap read_back；marker sha256 | 写前快照 namespace/ConfigMap（预期 absent）；清理删除 | namespace 创建失败 → 以 secret 列举 + 节点 marker 作为集群级证据，并标记测试对象缺失 |
| 7 | `stage-7-cleanup` 清理 | 删除测试对象、pwn 绑定、特权 Pod、节点 marker、夹具；按基线比对 namespace/secret | 前序创建清单；快照可读；Pod 仍可删节点文件 | 全部 NotFound；marker absent；集合与基线一致；residue=[] | 逐对象快照 + 删除；输出 `objective-cleanup.json` | 清理失败 → 立即停止，输出残留清单并非零退出；不宣称已清理 |

### 1.1 真实 run 的阶段状态

| # | stage | 状态 | artifact sha256（前 16 位） |
|---|---|---|---|
| 1 | stage-1-entry | success | `a3d42b1dbf65330b` |
| 2 | stage-2-credential | success | `99df02d8d5b8253c` |
| 3 | stage-3-rbac-escalation | success | `57694216f88eac4a` |
| 4 | stage-4-privileged-pod | success | `270d4c33f4b7189a` |
| 5 | stage-5-node-marker | success | `ba7d35d238d7de7e` |
| 6 | stage-6-cluster-proof | success | `53550568fdfae994` |
| 7 | stage-7-cleanup | success | `3775120b8ad947e1` |

## 2. 编排器语义（三闸门 + 逐阶段）

`inkblade objective cluster-takeover --workspace ... --proof-marker ... [--dry-run] [--max-stage N]`

| 机制 | 实现 |
|---|---|
| 授权闸门 | `roe_status=complete`；`level` 必须为 `全影响演示`；时间窗有效；`session.can('execute')` |
| 范围闸门 | `--namespace` 必须在 consent `namespaces`；可选 `host` 必须在授权 CIDR |
| 备份闸门 | 每个 `writes=true` 阶段必须有 `backup_targets`；执行前逐目标快照并写入 `backups/` + `run.record_backup` |
| 紧急停止 | 每阶段前检查 `<ws>/abort.json`；命中即拒绝，不进入下一阶段 |
| 逐阶段确认 | 默认交互 `y/N`；展示阶段/原语/写面/备份数/成功证据/回退 |
| `--auto-approve` | **仅限** `level=全影响演示` 且 `role=lead`；否则退出码 91 |
| 阶段超时 | 每阶段 `timeout_s`（可用 `--stage-timeout` 覆盖）；超时进入失败回退并强制清理 |
| `--max-stage N` | 只执行到第 N 阶段，**随后强制执行 stage 7 清理**；PROOF 标记 `complete=false` |
| 证据三层 | 每阶段：`objective/<stage>.json` → `steps/<stage>.tar.gz`（归档+sha256）+ SQLite steps/findings/actions + `context.jsonl.gz` |
| 最终 PROOF | `objective-proof.json`：gates、7 阶段、highest_privilege、集群级动作清单、stage/actions 哈希、`proof_sha256`、cleanup 校验 |

退出码：`0` 全链成功且清理已验证（或 `--dry-run`）；`3` 阶段失败/清理未验证/部分链；`91` 三闸门拒绝。

## 3. 真实实验室（QEMU TCG + k3s）

### 3.1 夹具

`lab/qemu-k3s/manifests/40-killchain-operator.yaml`：

- Namespace `inkblade-killchain`；
- ServiceAccount `inkblade-operator`；
- ClusterRole `inkblade-operator-broad`：RBAC 组 `resources:["*"] verbs:["*"]`（含 bind/escalate），
  以及 secrets/pods/exec/namespaces/configmaps/nodes 的读写；
- ClusterRoleBinding 把上述 ClusterRole 绑到该 SA。

这是**故意脆弱**的实验夹具，代表“既有 operator 权限过宽”的真实姿态；不是生产清单。
`41-killchain-entry.yaml` 提供未鉴权的训练 API 入口（NodePort 30081 + 实验 port-forward）。

### 3.2 真实执行

```powershell
python lab/qemu-k3s/kill_chain_lab.py `
  --kubectl lab/qemu-k3s/kubectl.exe `
  --kubeconfig lab/qemu-k3s/out/k3s.yaml `
  --backend kubectl `
  --proof-marker real-20261026-10 `
  --out reports/samples/kill-chain
```

实测：7/7 阶段成功，75.8 s（TCG 下含 Pod 调度/命令执行）。关键输出：

```
token whoami -> system:serviceaccount:inkblade-killchain:inkblade-operator
auth can-i '*' '*' --all-namespaces -> yes
id -> uid=0(root) gid=0(root) groups=0(root)
sha256sum /host/root/INKBLADE-PROOF-real-20261026-10
  -> 29bc79c339ac9bd5abced0cf94ba160b471ce7bdd9534548872990534527a211
secrets -> 2 (kube-system/k3s-serving, kube-system/k3s.node-password.k3s)
```

### 3.3 清理与无残留

`stage-7-cleanup` 的 11 项检查全部 PASS：

- 节点 marker `test ! -f` 通过；
- 测试 namespace `inkblade-proof-real-20261026-10`、ConfigMap、pwn RoleBinding/ClusterRoleBinding、特权 Pod 均 NotFound；
- 夹具 CRB/ClusterRole/Namespace 已删除；
- namespace 集合与 baseline 一致（`default/kube-node-lease/kube-public/kube-system/inkblade-proof`）；
- secret 名称集合与 baseline 一致（2 个，delta=[]）；
- 无 objective ClusterRoleBinding 残留。

额外 SSH 复核：`ls /root/INKBLADE-PROOF-*` → `No such file or directory`。
**已清理声明**：本次真实 run 未留下持久化 K8s 对象或节点文件；临时 token kubeconfig 已在 run 收尾删除。

## 4. 检测规则（每阶段）

规则模板位于 `inkblade/rules/templates/{sigma,falco,admission}.json`，紫队重放计划位于
`probes.json`（`cluster-takeover-objective`，9 条审计/运行时事件 fixture）。

| # | 规则 | 引擎 | 阶段 | 紫队结果 |
|---|---|---|---|---|
| 1 | `sigma-cluster-takeover-entry` | Sigma | 1 入口 | 检测 |
| 2 | `sigma-cluster-token-harvest` | Sigma | 2 凭据 | 检测 |
| 3 | `sigma-cluster-rbac-takeover` | Sigma | 3 RBAC | 检测 |
| 4 | `alert-rolebinding-creation` | 准入（Kyverno/Gatekeeper） | 3 RBAC | 拦截（策略文件齐备，默认 monitor） |
| 5 | `sigma-cluster-privileged-pod` | Sigma | 4 特权 Pod | 检测 |
| 6 | `deny-privileged-pod` | 准入 | 4 特权 Pod | 拦截 |
| 7 | `falco-node-root-marker-write` | Falco | 5 节点 marker | 检测 |
| 8 | `sigma-cluster-proof-actions` | Sigma | 6 集群级证明 | 检测 |
| 9 | `sigma-cluster-cleanup-trail` | Sigma | 7 清理 | 检测 |
| 10 | `sigma-rolebinding-cluster-admin` | Sigma（既有） | 3 RBAC | 检测 |
| 11 | `sigma-pods-exec-lateral` | Sigma（既有） | 3/5 横向 | 检测 |
| 12 | `netpol-default-deny-partition` | 准入/隔离 | 入口/横向前置 | 拦截 |

紫队全量：**26 链 / 89 规则单元 / 0 漏过**；本链 12 条规则全部为「检测」或「拦截」。
重放命令：

```powershell
inkblade rules generate --chains-dir inkblade/chains --out reports/rules-pack
inkblade rules validate --pack reports/rules-pack
```

## 5. 边界（如实声明）

1. **非生产规模**：单节点 k3s、QEMU TCG 纯软件仿真，无 HA/多节点调度/真实 GPU。
2. **硬件/交换机/带外**：无物理交换机、InfiniBand、BMC/OOB 访问；仅以版本闸门 + 只读证据代替，
   不执行任何硬件写入（见链定义 `objective.hardware_gates`）。
3. **secret 仅名称**：stage 6 只列举 secret 名称，不读取 value；token 仅记录 sha256 前缀与尾 4 位。
4. **入口适配**：真实 NodePort 30081 未做 QEMU hostfwd，实验用 `kubectl port-forward` 作为宿主侧
   访问路径；这代表“入口可达”，不等价于生产 Ingress/负载均衡配置。
5. **脆弱 operator 是实验室夹具**：真实评估中应替换为客户既有 operator 的权限姿态，不能把夹具
   当成客户现状；`--cleanup-fixture` 仅用于实验室。
6. **fake-kubectl 降级**：VM 不可用时 `--backend fake` 可闭环编排/证据/清理逻辑，但 PROOF 明确
   `real_cluster=false`，不得作为真实集群结论。
7. **检测默认 monitor**：准入规则默认 Audit/dryrun，切换 Enforce 后才实际阻断；紫队“拦截”表示
   策略文件齐备，不是当前集群已启用。

## 6. 证据索引

| 文件 | 内容 |
|---|---|
| `reports/samples/kill-chain/proof.json` | 真实 PROOF：gates/7 阶段/最高权限/16 条集群动作/哈希/清理校验 |
| `reports/samples/kill-chain/report.md` | 中英双语 PROOF 报告（含最高权限证明、动作清单、截图哈希、已清理声明） |
| `reports/samples/kill-chain/proof.png` | 终端 PROOF 截图（sha256 见报告） |
| `reports/samples/kill-chain/transcript.jsonl` | kubectl 调用轨迹（token 已脱敏） |
| `reports/samples/kill-chain/lab-wrapper.json` | 夹具 teardown 与 wrapper 侧无残留复核 |
| `inkblade/chains/cluster-takeover-objective.json` | 七阶段链定义 |
| `inkblade/core/objective_chain.py` | 编排器实现（三闸门/确认/超时/证据/PROOF） |
| `lab/qemu-k3s/manifests/40-killchain-operator.yaml` | 脆弱 operator 夹具 |
| `lab/qemu-k3s/manifests/41-killchain-entry.yaml` | 未鉴权入口夹具 |
| `lab/qemu-k3s/kill_chain_lab.py` | 真实集群实验 runner |
| `tests/test_objective.py` | 三闸门/确认/超时/清理/PROOF 哈希测试 |
| `tests/test_kill_chain_artifacts.py` | 链/规则/文档/真实样张结构校验 |
