# Trident 提权验证（真集群 + fake-kubectl）

> 本文件由 `lab/privesc_verify.py` 生成；真集群部分为 QEMU TCG + Alpine + k3s。

## 1. 真集群 4 条路径

结果：**4/4 PASS**；清理残留：**[]**。

| 路径 | 主体 | before | after | 关键动作 |
|---|---|---|---|---|
| `escalate` | system:serviceaccount:privesc-lab:esc-sa | False | True | patch clusterrole esc-editable -> rules=* |
| `bind` | system:serviceaccount:privesc-lab:bind-sa | False | True | create clusterrolebinding privesc-bind-proof -> cluster-admin |
| `impersonate` | system:serviceaccount:privesc-lab:imp-sa | False | True | kubectl --as=privesc-superuser get nodes |
| `sa-token` | system:serviceaccount:privesc-lab:token-sa | False | True | create token privesc-admin -> 独立 kubeconfig |

四条路径分别验证：

1. **escalate**：`esc-sa` 已被绑定到 `esc-editable`，仅有 `escalate` + 该角色的 `update`；把 rules 改为 `*` 后既有绑定立即生效，`auth can-i '*' '*'` 由 no 变 yes。
2. **bind**：`bind-sa` 拥有 `bind cluster-admin` + `create clusterrolebindings`，创建指向自身的 CRB 后直接 cluster-admin。
3. **impersonate**：`imp-sa` 拥有 `impersonate users/privesc-superuser`；该 User 已绑定 cluster-admin，`--as` 后获得管理员视图。
4. **SA TokenRequest**：`token-sa` 仅有 `create serviceaccounts/token/privesc-admin`；为高权 SA 申请 token 后以独立 kubeconfig 访问，`auth can-i` 为 yes。

## 2. fake-kubectl 闭环（4 项）

结果：**4/4 PASS**。

| 原语 | 状态 | 关键证据 |
|---|---|---|
| `escalate` | PASS | subject=system:serviceaccount:lab:esc-sa, before_admin=False, after_admin=True, escalate_allowed=True |
| `bind` | PASS | subject=system:serviceaccount:lab:bind-sa, before_admin=False, after_admin=True, binding_created=True |
| `sa-token` | PASS | subject=system:serviceaccount:lab:token-sa, target_sa=privesc-admin, before_admin=False, token_issued=True |
| `webhook` | PASS | subject=system:serviceaccount:lab:webhook-sa, before_can_create_pods=False, webhook_written=True, failure_policy=Ignore |

fake-kubectl 覆盖 escalate、bind、SA token 与 **webhook 写入后提权**（fail-open mutating webhook 把所有 Pod 注入 privileged + hostPath /）；真集群的 webhook 路径未在本轮落地，原因与替代证据：

- 真集群 webhook 需要 apiserver 可达的 HTTPS 后端 + CA bundle，本轮以 fake-kubectl 闭环证明「写入 Webhook 配置 → Pod 被注入特权」的因果链；
- 真集群已用 escalate/bind/impersonate/token 四条独立路径证明 RBAC 接管；webhook 的写入权限面由 `admission-webhook-write` 模块与 Kyverno 检测规则覆盖。

## 3. 复现

```powershell
python lab/privesc_verify.py --kubectl lab/qemu-k3s/kubectl.exe --kubeconfig lab/qemu-k3s/out/k3s.yaml --out reports/samples/privesc
python -m unittest tests.test_privesc_real tests.test_privesc_modules -v
```

## 4. 边界

- QEMU TCG 单节点 k3s：真实 apiserver/RBAC/kubelet，但不是生产多节点/云托管控制面；
- 未验证云 IAM/IRSA/IMDS、GPU Operator driver、CNI/CSI 特权 DaemonSet（这些在矩阵与模块中以快照/检测规则覆盖，真集群验证需另建对应工作负载夹具）；
- 所有夹具在验证后删除；`--keep` 可保留复测，但不得用于生产。
