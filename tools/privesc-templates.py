# -*- coding: utf-8 -*-
"""Author the 15 shared-analyzer privilege-chain templates."""
from __future__ import annotations

import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULES = ROOT / "inkblade" / "modules"

ROLES = "concat(steps.snapshot.json.clusterroles, steps.snapshot.json.roles)"
PODS = "steps.snapshot.json.pods"
DAEMONSETS = "steps.snapshot.json.daemonsets"
SECRETS = "steps.snapshot.json.secrets"
CANI = "lower(str(steps.snapshot.json.cani))"


def roles_with(verbs: str, resources: str, field: str = ""):
    cond = (f"any(it.rules, contains(it.verbs, {verbs}) and "
            f"(contains(it.resources, {resources})" +
            (f" or {resources.replace(resources, resources)}" if False else "") + "))")
    return cond


def meta(key: str) -> dict:
    module = json.loads((MODULES / key / "module.json").read_text(encoding="utf-8"))
    return {"name": module["name"], "series": module["series"],
            "min_level": module["min_level"], "writes": bool(module["writes"]),
            "requires": list(module.get("requires") or []),
            "surfaces": [str(s) for s in (module.get("surfaces") or [])],
            "cves": list(module.get("verification_cves") or []), "fidelity": "equivalent"}


def base(key: str) -> dict:
    doc = {"schema": "inkblade-probe-template-v1", "key": key, "version": "1.0.0",
           "meta": meta(key),
           "inputs": {"fixture": {"from": "coalesce(params.fixture, params.snapshot)",
                                  "required": True}},
           "defaults": {"timeout_ms": 8000},
           "steps": [{"id": "snapshot", "op": "fs", "action": "read",
                      "path": "{{input.fixture}}", "json": True, "save": "snapshot"}],
           "checks": [{"id": "snapshot-readable", "when": "steps.snapshot.ok == true",
                       "fatal": True, "message": "snapshot is not readable JSON"}],
           "payloads": {"benign": {"marker": "INKBLADE-BENIGN"}},
           "limits": {"timeout_ms": 30000, "max_http_requests": 8}}
    if doc["meta"]["writes"]:
        doc["modes"] = {"probe_only": True, "backup_write": True, "requires_backup": True}
    return doc


def artifact(key: str, fields: dict) -> list[dict]:
    return [{"name": f"{key}-detection.json", "kind": "json", "fields": fields}]


def write(doc: dict) -> None:
    (MODULES / doc["key"] / "template.json").write_text(
        json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("wrote", doc["key"])


def demo(key: str, kind: str, content: str, title: str, mapping: str) -> dict:
    return {"id": "demo", "op": "fs", "action": "write", "write": True,
            "when": "params.mode == 'backup-write'", "path": "{{params.demo_target}}",
            "content": "# INKBLADE demo {{ctx.marker}} " + kind + "\n" + content,
            "save": "demo"}


def demo_finding(key: str, title: str, mapping: str) -> dict:
    return {"id": "demo-written", "when": "params.mode == 'backup-write'", "sev": "high",
            "title": title, "detail": "演示清单写入 {{params.demo_target}}（可回滚）",
            "evidence": "demo_target={{params.demo_target}}", "mapping": mapping}


def add(doc: dict, finding: dict, when: str, sev: str, title: str, detail: str,
        evidence: str, mapping: str, fix: str) -> None:
    doc["findings"].append({"id": finding, "when": when, "sev": sev, "title": title,
                            "detail": detail, "evidence": evidence, "mapping": mapping,
                            "fix": fix})


# ---------------------------------------------------------------- rbac-bind
key = "rbac-bind-verb"
d = base(key)
d["computed"] = {
    "roles": ROLES,
    "binders": "filter(computed.roles, any(it.rules, contains(it.verbs, 'bind') and "
               "(contains(it.resources, 'roles') or contains(it.resources, 'clusterroles'))))",
    "cani": "contains(" + CANI + ", 'bind') and contains(" + CANI + ", 'cluster-admin')",
}
d["findings"] = [
    {"id": "bind", "for_each": "computed.binders", "as": "role", "sev": "critical",
     "title": "bind 动词：{{role.name}}",
     "detail": "持有 bind 可把自身/任意主体绑定到高权角色（如 cluster-admin）；与 create rolebindings 组合即一步提权。rules={{str(role.rules)}}",
     "evidence": "role={{role.name}}",
     "mapping": "提权矩阵 rbac-bind-verb；KubeHound BIND 边",
     "fix": "仅允许 GitOps/break-glass 主体 bind cluster-admin；对 RoleBinding 创建做准入告警"},
    {"id": "cani", "when": "computed.cani and len(computed.binders) == 0", "sev": "high",
     "title": "can-i 矩阵显示 bind cluster-admin（自绑路径）",
     "detail": "该主体可直接创建指向 cluster-admin 的绑定；无需其他原语。",
     "evidence": "cani 含 bind cluster-admin", "fix": "移除 bind；改为受审批的 RoleBinding 请求流程"},
    {"id": "demo-written", "when": "params.mode == 'backup-write'", "sev": "high",
     "title": "bind 自绑演示已落盘（可回滚）",
     "detail": "演示 ClusterRoleBinding 清单写入 {{params.demo_target}}；真实集群中需 bind cluster-admin + create 绑定。",
     "evidence": "demo_target={{params.demo_target}}", "mapping": "rbac-bind-verb demo"},
]
d["steps"].append(demo(key, "bind",
                       "apiVersion: rbac.authorization.k8s.io/v1\n"
                       "kind: ClusterRoleBinding\nmetadata: {name: inkblade-bind-demo}\n"
                       "roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: cluster-admin}\n"
                       "subjects: [{kind: ServiceAccount, name: demo-sa, namespace: privesc-lab}]",
                       "rbac-bind-verb", "rbac-bind-verb demo"))
d["artifacts"] = artifact(key, {"binders": "map(computed.binders, it.name)",
                                 "cani": "computed.cani", "mode": "params.mode"})
write(d)

# ------------------------------------------------------------- impersonate
key = "impersonate-abuse"
d = base(key)
d["computed"] = {
    "roles": ROLES,
    "impersonators": "filter(computed.roles, any(it.rules, contains(it.verbs, 'impersonate') and "
                     "(contains(it.resources, 'users') or contains(it.resources, 'groups') or "
                     "contains(it.resources, 'serviceaccounts'))))",
    "cani": "contains(" + CANI + ", 'impersonate')",
}
d["findings"] = [
    {"id": "impersonate", "for_each": "computed.impersonators", "as": "role", "sev": "critical",
     "title": "impersonate 动词：{{role.name}}",
     "detail": "可冒充 User/Group/ServiceAccount；若目标绑定 cluster-admin 或 system:masters，则等价直接接管。rules={{str(role.rules)}}",
     "evidence": "role={{role.name}}", "mapping": "提权矩阵 rbac-impersonate；MITRE T1078",
     "fix": "禁止 impersonate 进入工作负载 SA；对 impersonatedUser 审计做实时告警"},
    {"id": "cani", "when": "computed.cani and len(computed.impersonators) == 0", "sev": "high",
     "title": "can-i 矩阵显示 impersonate 权限",
     "detail": "can-i 输出含 impersonate；需核对目标 users/groups 与是否存在 system:masters 绑定。",
     "evidence": "cani 含 impersonate", "fix": "按 resourceNames 收敛；禁止 groups=system:masters 的 impersonate"},
]
d["artifacts"] = artifact(key, {"impersonators": "map(computed.impersonators, it.name)",
                                 "cani": "computed.cani"})
write(d)

# -------------------------------------------------------------- sa-token
key = "sa-token-request"
d = base(key)
d["computed"] = {
    "roles": ROLES,
    "requesters": "filter(computed.roles, any(it.rules, contains(it.verbs, 'create') and "
                  "contains(it.resources, 'serviceaccounts/token')))",
    "projected": "filter(" + PODS + ", it.volumes != null)",
    "cani": "contains(" + CANI + ", 'serviceaccounts/token')",
}
d["findings"] = [
    {"id": "token", "for_each": "computed.requesters", "as": "role", "sev": "high",
     "title": "TokenRequest 权限：{{role.name}}",
     "detail": "可为高权 SA 申请短期 token；无需读取 Secret，即可借用其身份。rules={{str(role.rules)}}",
     "evidence": "role={{role.name}}", "mapping": "提权矩阵 rbac-sa-token-request；TokenRequest API",
     "fix": "限制 resourceNames；对 serviceaccounts/token 创建做主体白名单告警"},
    {"id": "cani", "when": "computed.cani and len(computed.requesters) == 0", "sev": "high",
     "title": "can-i 矩阵显示 create serviceaccounts/token",
     "detail": "TokenRequest 子资源可被直接调用；优先核对目标 SA 的角色绑定。",
     "evidence": "cani 含 serviceaccounts/token", "fix": "移除跨命名空间 token 创建；改用工作负载自身 SA"},
]
d["artifacts"] = artifact(key, {"requesters": "map(computed.requesters, it.name)",
                                 "cani": "computed.cani"})
write(d)

# -------------------------------------------------------------------- csr
key = "csr-approve"
d = base(key)
d["computed"] = {
    "roles": ROLES,
    "approvers": "filter(computed.roles, any(it.rules, (contains(it.resources, 'certificatesigningrequests/approval') or contains(it.resources, 'signers')) and contains(it.verbs, 'approve')))",
    "pending": "filter(steps.snapshot.json.certificatesigningrequests, it.status == 'Pending' and (contains(lower(str(it.subject.organization)), 'system:masters') or startswith(str(it.subject.commonName), 'system:admin')))",
}
d["findings"] = [
    {"id": "approve", "for_each": "computed.approvers", "as": "role", "sev": "critical",
     "title": "CSR 批准权限：{{role.name}}",
     "detail": "可批准/签发客户端证书；若 CSR subject 含 O=system:masters，则直接获得 cluster-admin。rules={{str(role.rules)}}",
     "evidence": "role={{role.name}}", "mapping": "提权矩阵 platform-cert-manager；K8s CSR API",
     "fix": "CSR 自动批准仅限 node serving；client cert 必须人工审批并校验 subject"},
    {"id": "pending", "for_each": "computed.pending", "as": "csr", "sev": "critical",
     "title": "待批准高权 CSR：{{csr.name}}",
     "detail": "subject={{str(csr.subject)}} signer={{csr.signerName}}；批准即签发 system:masters 客户端证书。",
     "evidence": "csr={{csr.name}} username={{csr.username}}",
     "mapping": "提权矩阵 platform-cert-manager；MITRE T1098",
     "fix": "拒绝 O=system:masters 的 CSR；启用 signerName 白名单与人工审批"},
]
d["artifacts"] = artifact(key, {"approvers": "map(computed.approvers, it.name)",
                                 "pending": "map(computed.pending, it.name)"})
write(d)

# --------------------------------------------------------- admission webhook
key = "admission-webhook-write"
d = base(key)
d["computed"] = {
    "webhooks": "concat(steps.snapshot.json.mutatingwebhookconfigurations, steps.snapshot.json.validatingwebhookconfigurations)",
    "risky": "filter(computed.webhooks, it.failurePolicy == 'Ignore' or startswith(str(it.clientConfig.url), 'http://') or it.namespaceSelector == null)",
    "apiservices": "filter(steps.snapshot.json.apiservices, it.insecureSkipTLSVerify == true or it.service == null)",
}
d["findings"] = [
    {"id": "risky", "for_each": "computed.risky", "as": "wh", "sev": "critical",
     "title": "fail-open/不安全准入 Webhook：{{wh.name}}",
     "detail": "failurePolicy={{wh.failurePolicy}} url={{wh.clientConfig.url}}；写入方可注入特权/窃取 AdmissionReview 中的 Secret。",
     "evidence": "webhook={{wh.name}}",
     "mapping": "提权矩阵 rbac-admission-webhook-write；K8s admission webhook",
     "fix": "failurePolicy=Fail、禁止 http URL、限定 namespaceSelector；webhook 配置变更需双人审批"},
    {"id": "demo-written", "when": "params.mode == 'backup-write'", "sev": "high",
     "title": "准入 Webhook 写入演示已落盘（可回滚）",
     "detail": "演示 MutatingWebhookConfiguration 写入 {{params.demo_target}}；fail-open + pod CREATE 覆盖可注入特权。",
     "evidence": "demo_target={{params.demo_target}}", "mapping": "admission-webhook-write demo"},
]
d["steps"].append(demo(key, "webhook",
                       "apiVersion: admissionregistration.k8s.io/v1\n"
                       "kind: MutatingWebhookConfiguration\nmetadata: {name: inkblade-webhook-demo}\n"
                       "webhooks: [{name: inject.inkblade.local, admissionReviewVersions: [v1], sideEffects: None, failurePolicy: Ignore}]",
                       "admission-webhook-write", "admission-webhook-write demo"))
d["artifacts"] = artifact(key, {"risky": "map(computed.risky, it.name)",
                                 "mode": "params.mode"})
write(d)

# ------------------------------------------------------------- apiservice
key = "apiservice-hijack"
d = base(key)
d["computed"] = {
    "risky": "filter(steps.snapshot.json.apiservices, it.insecureSkipTLSVerify == true or it.service == null)",
}
d["findings"] = [
    {"id": "apiservice", "for_each": "computed.risky", "as": "svc", "sev": "high",
     "title": "APIService 聚合层不安全：{{svc.name}}",
     "detail": "insecureSkipTLSVerify={{svc.insecureSkipTLSVerify}} service={{str(svc.service)}}；可劫持 API group、窃取 bearer token 或伪造对象。",
     "evidence": "apiservice={{svc.name}} group={{svc.group}}",
     "mapping": "提权矩阵 rbac-apiservice-hijack；K8s aggregation",
     "fix": "启用 TLS 校验、绑定 service；限制 apiservices 写权限到控制面组件"},
]
d["artifacts"] = artifact(key, {"risky": "map(computed.risky, it.name)"})
write(d)

# --------------------------------------------------------- crd conversion
key = "crd-conversion-webhook"
d = base(key)
d["computed"] = {
    "risky": "filter(steps.snapshot.json.customresourcedefinitions, it.conversion.strategy == 'Webhook' and not it.conversion.webhook.clientConfig.caBundle)",
}
d["findings"] = [
    {"id": "crd", "for_each": "computed.risky", "as": "crd", "sev": "high",
     "title": "CRD conversion webhook 缺 CA：{{crd.name}}",
     "detail": "conversion webhook 未配置 caBundle/不安全；可拦截/篡改所有 CR 版本转换，向 operator 注入恶意对象。",
     "evidence": "crd={{crd.name}} clientConfig={{str(crd.conversion.webhook.clientConfig)}}",
     "mapping": "提权矩阵 rbac-crd-conversion-webhook；K8s CRD versioning",
     "fix": "为 conversion webhook 配置受信 CA；限制 CRD 写权限；监控 conversion webhook 变更"},
]
d["artifacts"] = artifact(key, {"risky": "map(computed.risky, it.name)"})
write(d)

# --------------------------------------------------------------- kubelet
key = "kubelet-10250-exec"
d = base(key)
d["computed"] = {
    "nodes": "filter(steps.snapshot.json.nodes, it.kubelet.anonymousAuth == true or it.kubelet.authorizationMode == 'AlwaysAllow' or it.kubelet.readOnlyPort != null)",
    "kubelets": "filter(steps.snapshot.json.kubelets, it.anonymousAuth == true or it.authorizationMode == 'AlwaysAllow')",
}
d["findings"] = [
    {"id": "node", "for_each": "computed.nodes", "as": "node", "sev": "critical",
     "title": "kubelet 10250 认证/授权缺陷：{{node.name}}",
     "detail": "anonymousAuth={{node.kubelet.anonymousAuth}} authorizationMode={{node.kubelet.authorizationMode}} readOnlyPort={{node.kubelet.readOnlyPort}}；/exec、/run、/logs 可被未认证调用。",
     "evidence": "node={{node.name}} kubelet={{str(node.kubelet)}}",
     "mapping": "提权矩阵 node-kubelet-10250-exec / node-kubelet-10250-run",
     "fix": "anonymous-auth=false、authorization-mode=Webhook、关闭 readOnlyPort；10250 仅 apiserver 可达"},
    {"id": "kubelet", "for_each": "computed.kubelets", "as": "kl", "sev": "high",
     "title": "kubelet 暴露：{{kl.node}}",
     "detail": "port={{kl.port}} anonymousAuth={{kl.anonymousAuth}} authorizationMode={{kl.authorizationMode}}",
     "evidence": "kubelet={{str(kl)}}", "fix": "按节点收敛 kubelet 认证；NAT/安全组限制 10250 源"},
]
d["artifacts"] = artifact(key, {"nodes": "map(computed.nodes, it.name)",
                                 "kubelets": "map(computed.kubelets, it.node)"})
write(d)

# ------------------------------------------------------------------ etcd
key = "etcd-direct-access"
d = base(key)
d["computed"] = {
    "risky": "filter(steps.snapshot.json.etcd, it.tls != true or it.clientCertAuth != true)",
}
d["findings"] = [
    {"id": "etcd", "for_each": "computed.risky", "as": "etcd", "sev": "critical",
     "title": "etcd 直连风险：{{etcd.name}}",
     "detail": "endpoint={{etcd.endpoint}} tls={{etcd.tls}} clientCertAuth={{etcd.clientCertAuth}}；可读取全部 Secret/SA token 或写入 RBAC 对象。",
     "evidence": "etcd={{etcd.name}} endpoint={{etcd.endpoint}}",
     "mapping": "提权矩阵 node-etcd-direct；K8s etcd 运维",
     "fix": "启用 etcd mTLS 与客户端证书；2379/2380 仅控制面网段可达"},
]
d["artifacts"] = artifact(key, {"risky": "map(computed.risky, it.name)"})
write(d)

# --------------------------------------------------------- image pull secret
key = "image-pull-secret-theft"
d = base(key)
d["computed"] = {
    "docker": "filter(" + SECRETS + ", it.type == 'kubernetes.io/dockerconfigjson')",
    "pods": "filter(" + PODS + ", it.imagePullSecrets != null)",
}
d["findings"] = [
    {"id": "secret", "for_each": "computed.docker", "as": "sec", "sev": "high",
     "title": "imagePullSecret 可读：{{sec.name}}",
     "detail": "dockerconfigjson 含仓库凭据；可拉取私有镜像或向仓库推送恶意镜像，投毒 operator/DaemonSet。",
     "evidence": "secret={{sec.name}} type={{sec.type}}",
     "mapping": "提权矩阵 cred-image-pull-secret；MITRE T1525",
     "fix": "使用短时效 registry token/工作负载身份；限制 secrets 读权限到拉取组件"},
    {"id": "pod", "for_each": "computed.pods", "as": "pod", "sev": "medium",
     "title": "Pod 引用 imagePullSecret：{{pod.name}}",
     "detail": "imagePullSecrets={{str(pod.imagePullSecrets)}}；可被 exec/探针读取或滥用。",
     "evidence": "pod={{pod.name}}", "fix": "改用节点级/仓库联合身份；避免长期静态 dockerconfigjson"},
]
d["artifacts"] = artifact(key, {"secrets": "map(computed.docker, it.name)",
                                 "pods": "map(computed.pods, it.name)"})
write(d)

# ------------------------------------------------------------------ gitops
key = "gitops-secret-read"
d = base(key)
d["computed"] = {
    "deployments": "filter(steps.snapshot.json.deployments, (contains(lower(it.name), 'argocd') or contains(lower(it.name), 'flux')) and (it.clusterAdmin == true or it.secretRead == true or it.repoToken != null))",
    "secrets": "filter(" + SECRETS + ", contains(lower(it.name), 'argocd') or contains(lower(it.name), 'flux') or contains(lower(it.name), 'git'))",
}
d["findings"] = [
    {"id": "deployment", "for_each": "computed.deployments", "as": "dep", "sev": "high",
     "title": "GitOps 控制器高权：{{dep.name}}",
     "detail": "clusterAdmin={{dep.clusterAdmin}} secretRead={{dep.secretRead}} repoToken={{dep.repoToken != null}}；仓库写权限即可落地 cluster-admin 清单。",
     "evidence": "deployment={{dep.name}} sa={{dep.serviceAccount}}",
     "mapping": "提权矩阵 platform-argocd-flux；Argo CD/Flux 安全",
     "fix": "GitOps 控制器使用最小权限 + 项目级 AppProject；仓库写权限强制签名/审批"},
    {"id": "secret", "for_each": "computed.secrets", "as": "sec", "sev": "high",
     "title": "GitOps 凭据 Secret：{{sec.name}}",
     "detail": "keys={{str(sec.keys)}}；可被用于写仓库或伪造 sync 源。",
     "evidence": "secret={{sec.name}}", "fix": "使用短期 workload identity/部署密钥；限制 secret 读主体"},
]
d["artifacts"] = artifact(key, {"deployments": "map(computed.deployments, it.name)",
                                 "secrets": "map(computed.secrets, it.name)"})
write(d)

# ---------------------------------------------------------- gpu operator
key = "gpu-operator-driver-escape"
d = base(key)
d["computed"] = {
    "driver": "filter(" + DAEMONSETS + ", (contains(lower(it.name), 'driver') or contains(lower(str(it.image)), 'nvidia/driver')) and (it.privileged == true or contains(str(it.hostPath), '/dev') or contains(str(it.hostPath), '/run') or contains(str(it.hostPath), '/usr/lib64')))",
}
d["findings"] = [
    {"id": "driver", "for_each": "computed.driver", "as": "ds", "sev": "critical",
     "title": "GPU Operator driver 容器逃逸面：{{ds.name}}",
     "detail": "privileged={{ds.privileged}} hostPath={{str(ds.hostPath)}} image={{ds.image}}；driver 容器以节点 root 运行，替换镜像/注入命令即节点接管。",
     "evidence": "daemonset={{ds.name}} sa={{ds.serviceAccount}}",
     "mapping": "提权矩阵 platform-gpu-operator-driver；NVIDIA GPU Operator",
     "fix": "driver 容器按最小 hostPath/能力收敛；镜像签名+准入校验；daemonset 写权限仅平台管理员"},
]
d["artifacts"] = artifact(key, {"driver": "map(computed.driver, it.name)"})
write(d)

# --------------------------------------------------------------------- cni
key = "cni-plugin-exec"
d = base(key)
d["computed"] = {
    "cni": "filter(" + DAEMONSETS + ", (contains(lower(it.name), 'calico') or contains(lower(it.name), 'cilium') or contains(lower(it.name), 'cni') or contains(str(it.hostPath), '/opt/cni/bin')) and (it.privileged == true or contains(str(it.hostPath), '/opt/cni/bin')))",
}
d["findings"] = [
    {"id": "cni", "for_each": "computed.cni", "as": "ds", "sev": "critical",
     "title": "CNI 插件执行面：{{ds.name}}",
     "detail": "privileged={{ds.privileged}} hostPath={{str(ds.hostPath)}}；CNI 以节点 root 运行，替换二进制/注入 hook 可在所有节点执行。",
     "evidence": "daemonset={{ds.name}} sa={{ds.serviceAccount}}",
     "mapping": "提权矩阵 platform-cni-plugin；CNI 规范",
     "fix": "CNI 镜像签名+只读根；/opt/cni/bin 仅 kubelet 可写；daemonset 变更双人审批"},
]
d["artifacts"] = artifact(key, {"cni": "map(computed.cni, it.name)"})
write(d)

# --------------------------------------------------------------------- csi
key = "csi-node-plugin-escape"
d = base(key)
d["computed"] = {
    "csi": "filter(" + DAEMONSETS + ", (contains(lower(it.name), 'csi') or contains(lower(str(it.image)), 'nfsplugin')) and (it.privileged == true or contains(str(it.hostPath), '/var/lib/kubelet') or contains(str(it.hostPath), '/dev')))",
}
d["findings"] = [
    {"id": "csi", "for_each": "computed.csi", "as": "ds", "sev": "critical",
     "title": "CSI node plugin 逃逸面：{{ds.name}}",
     "detail": "privileged={{ds.privileged}} hostPath={{str(ds.hostPath)}}；插件可读写宿主 kubelet 目录/设备，篡改挂载流程或跨租户读取卷。",
     "evidence": "daemonset={{ds.name}} sa={{ds.serviceAccount}}",
     "mapping": "提权矩阵 platform-csi-node-plugin；CSI 规范",
     "fix": "CSI 插件按最小 hostPath 收敛；启用卷隔离/加密；插件镜像签名与准入校验"},
]
d["artifacts"] = artifact(key, {"csi": "map(computed.csi, it.name)"})
write(d)
