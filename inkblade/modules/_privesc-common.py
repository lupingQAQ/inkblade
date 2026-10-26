"""提权模块族共享库（仅标准库）。

约定：
- 输入：params.fixture = 快照 JSON 路径，缺省用 lab/fixtures/privesc/<default>；
- 输出：findings（sev/title/detail/evidence/mapping/fix）+ artifacts JSON；
- 写类模块仅在 params.mode=="backup-write" 且提供 demo_target 时写演示清单，
  真实变更仍由 runner 的 ROE/备份闸门约束；
- 所有判定基于只读快照，不在模块内直接调用集群 API。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

REPO = Path(__file__).resolve().parents[2]
FIXTURES = REPO / "lab" / "fixtures" / "privesc"

DEFAULT_FIXTURES = {
    "rbac-escalate-verb": "rbac.json",
    "rbac-bind-verb": "rbac.json",
    "impersonate-abuse": "rbac.json",
    "sa-token-request": "rbac.json",
    "csr-approve": "rbac.json",
    "admission-webhook-write": "admission.json",
    "apiservice-hijack": "admission.json",
    "crd-conversion-webhook": "admission.json",
    "kubelet-10250-exec": "node.json",
    "etcd-direct-access": "node.json",
    "image-pull-secret-theft": "credentials.json",
    "gitops-secret-read": "platform.json",
    "gpu-operator-driver-escape": "platform.json",
    "cni-plugin-exec": "platform.json",
    "csi-node-plugin-escape": "platform.json",
}

SEVS = ("critical", "high", "medium", "low", "info")


def load_fixture(params: dict, module_key: str) -> tuple[dict, str]:
    src = params.get("fixture")
    if not src:
        name = DEFAULT_FIXTURES.get(module_key, "rbac.json")
        path = FIXTURES / name
    else:
        path = Path(str(src))
    if not path.is_file():
        raise ValueError(f"提权夹具不存在: {path}")
    return json.loads(path.read_text(encoding="utf-8")), str(path)


def finding(sev: str, title: str, detail: str = "", evidence: str = "",
            mapping: str = "", fix: str = "", **extra) -> dict:
    if sev not in SEVS:
        sev = "info"
    item = {"sev": sev, "title": title, "detail": detail}
    if evidence:
        item["evidence"] = evidence
    if mapping:
        item["mapping"] = mapping
    if fix:
        item["fix"] = fix
    item.update(extra)
    return item


def _rules(node: dict) -> list[dict]:
    return list(node.get("rules") or [])


def role_entries(doc: dict) -> list[tuple[str, dict]]:
    out: list[tuple[str, dict]] = []
    for key, scope in (("clusterroles", "ClusterRole"), ("roles", "Role")):
        for role in doc.get(key, []) or []:
            if isinstance(role, dict):
                out.append((scope, role))
    return out


def has_verb(rule: dict, *verbs: str) -> bool:
    got = {str(v).lower() for v in rule.get("verbs", [])}
    return "*" in got or any(v.lower() in got for v in verbs)


def has_resource(rule: dict, *resources: str) -> bool:
    got = {str(r).lower() for r in rule.get("resources", [])}
    return "*" in got or any(r.lower() in got for r in resources)


def cani_text(doc: dict) -> str:
    return json.dumps(doc.get("cani", []), ensure_ascii=False).lower()


def _canary(ctx: dict, params: dict, filename: str, payload: str) -> Path:
    raw = params.get("demo_target")
    if not raw:
        raise ValueError("backup-write 演示需要 params.demo_target")
    target = Path(str(raw))
    if not target.exists():
        target.write_text("", encoding="utf-8")
    receipt = ctx["backup"].snapshot(f"{ctx['meta']['key']}-demo",
                                     [{"kind": "file", "path": str(target)}])
    if receipt is None:
        raise RuntimeError("backup-write 演示缺少快照回执")
    target.write_text(f"# INKBLADE demo {ctx['marker']} {filename}\n{payload}\n", encoding="utf-8")
    return target


# ---------------------------------------------------------------- analyzers

def analyze_escalate(doc: dict, params: dict) -> list[dict]:
    out: list[dict] = []
    for scope, role in role_entries(doc):
        for rule in _rules(role):
            if has_verb(rule, "escalate") and has_resource(rule, "roles", "clusterroles"):
                out.append(finding(
                    "critical", f"escalate 动词：{scope} {role.get('name', '?')}",
                    detail="持有 escalate 可将已绑定的角色改写为 *（无需重新绑定），等价获得该角色作用域的全权限。",
                    evidence=f"{scope}={role.get('name')} verbs={rule.get('verbs')} resources={rule.get('resources')}",
                    mapping="提权矩阵 rbac-escalate-verb；KubeHound ESCALATE_ROLE 边",
                    fix="禁止 escalate 进入日常角色；仅 break-glass 角色保留并强制审批/会话录制",
                ))
    text = cani_text(doc)
    if "escalate" in text:
        out.append(finding(
            "high", "can-i 矩阵显示 escalate 权限（复核绑定主体）",
            detail="can-i 输出含 escalate：需确认绑定主体与目标角色范围，避免 operator 默认角色扩散。",
            evidence="cani 含 escalate",
            fix="用 SubjectAccessReview 逐主体复核；收敛到 resourceNames 精确角色",
        ))
    return out


def analyze_bind(doc: dict, params: dict) -> list[dict]:
    out: list[dict] = []
    for scope, role in role_entries(doc):
        for rule in _rules(role):
            if has_verb(rule, "bind") and has_resource(rule, "roles", "clusterroles"):
                out.append(finding(
                    "critical", f"bind 动词：{scope} {role.get('name', '?')}",
                    detail="持有 bind 可把自身/任意主体绑定到高权角色（如 cluster-admin）；与 create rolebindings 组合即一步提权。",
                    evidence=f"{scope}={role.get('name')} resourceNames={rule.get('resourceNames')} verbs={rule.get('verbs')}",
                    mapping="提权矩阵 rbac-bind-verb；KubeHound BIND 边",
                    fix="仅允许 GitOps/break-glass 主体 bind cluster-admin；对 RoleBinding 创建做准入告警",
                ))
    text = cani_text(doc)
    if "bind" in text and "cluster-admin" in text:
        out.append(finding(
            "high", "can-i 矩阵显示 bind cluster-admin（自绑路径）",
            detail="该主体可直接创建指向 cluster-admin 的绑定；无需其他原语。",
            evidence="cani 含 bind cluster-admin",
            fix="移除 bind；改为受审批的 RoleBinding 请求流程",
        ))
    return out


def analyze_impersonate(doc: dict, params: dict) -> list[dict]:
    out: list[dict] = []
    for scope, role in role_entries(doc):
        for rule in _rules(role):
            if has_verb(rule, "impersonate") and has_resource(rule, "users", "groups", "serviceaccounts"):
                out.append(finding(
                    "critical", f"impersonate 动词：{scope} {role.get('name', '?')}",
                    detail="可冒充 User/Group/ServiceAccount；若目标绑定 cluster-admin 或 system:masters，则等价直接接管。",
                    evidence=f"{scope}={role.get('name')} resources={rule.get('resources')} resourceNames={rule.get('resourceNames')}",
                    mapping="提权矩阵 rbac-impersonate；MITRE T1078",
                    fix="禁止 impersonate 进入工作负载 SA；对 impersonatedUser 审计做实时告警",
                ))
    if "impersonate" in cani_text(doc):
        out.append(finding(
            "high", "can-i 矩阵显示 impersonate 权限",
            detail="can-i 输出含 impersonate；需核对目标 users/groups 与是否存在 system:masters 绑定。",
            evidence="cani 含 impersonate",
            fix="按 resourceNames 收敛；禁止 groups=system:masters 的 impersonate",
        ))
    return out


def analyze_sa_token(doc: dict, params: dict) -> list[dict]:
    out: list[dict] = []
    for scope, role in role_entries(doc):
        for rule in _rules(role):
            if has_verb(rule, "create") and has_resource(rule, "serviceaccounts/token"):
                out.append(finding(
                    "high", f"TokenRequest 权限：{scope} {role.get('name', '?')}",
                    detail="可为高权 SA 申请短期 token；无需读取 Secret，即可借用其身份。",
                    evidence=f"{scope}={role.get('name')} resourceNames={rule.get('resourceNames')}",
                    mapping="提权矩阵 rbac-sa-token-request；TokenRequest API",
                    fix="限制 resourceNames；对 serviceaccounts/token 创建做主体白名单告警",
                ))
    if "serviceaccounts/token" in cani_text(doc):
        out.append(finding(
            "high", "can-i 矩阵显示 create serviceaccounts/token",
            detail="TokenRequest 子资源可被直接调用；优先核对目标 SA 的角色绑定。",
            evidence="cani 含 serviceaccounts/token",
            fix="移除跨命名空间 token 创建；改用工作负载自身 SA",
        ))
    # projected token 过度授权（凭证夹具）
    for pod in doc.get("pods", []) or []:
        for vol in pod.get("volumes", []) or []:
            proj = vol.get("projected") or {}
            for src in proj.get("sources", []) or []:
                sat = src.get("serviceAccountToken")
                if sat:
                    out.append(finding(
                        "medium", f"projected SA token 过度授权：{pod.get('namespace')}/{pod.get('name')}",
                        detail=f"projected token audience={sat.get('audience')} expiration={sat.get('expirationSeconds')}s；"
                               "长有效期/宽 audience 便于外带。",
                        evidence=f"pod={pod.get('name')} projected={sat}",
                        mapping="提权矩阵 cred-projected-token",
                        fix="缩短 expiration（<=1h）、限定 audience；禁用跨信任域 audience",
                    ))
    return out


def analyze_csr(doc: dict, params: dict) -> list[dict]:
    out: list[dict] = []
    for scope, role in role_entries(doc):
        for rule in _rules(role):
            if has_resource(rule, "certificatesigningrequests/approval", "signers") and has_verb(
                    rule, "approve", "update", "*"):
                out.append(finding(
                    "critical", f"CSR 批准权限：{scope} {role.get('name', '?')}",
                    detail="可批准/签发客户端证书；若 CSR subject 含 O=system:masters，则直接获得 cluster-admin。",
                    evidence=f"{scope}={role.get('name')} verbs={rule.get('verbs')}",
                    mapping="提权矩阵 platform-cert-manager；K8s CSR API",
                    fix="CSR 自动批准仅限 node serving；client cert 必须人工审批并校验 subject",
                ))
    for csr in doc.get("certificatesigningrequests", []) or []:
        subject = csr.get("subject") or {}
        orgs = [str(x) for x in subject.get("organization", [])]
        if csr.get("status") == "Pending" and ("system:masters" in orgs or
                                               str(subject.get("commonName", "")).startswith("system:admin")):
            out.append(finding(
                "critical", f"待批准高权 CSR：{csr.get('name')}",
                detail=f"CSR subject={subject} signer={csr.get('signerName')}；批准即签发 system:masters 客户端证书。",
                evidence=f"csr={csr.get('name')} username={csr.get('username')} subject={subject}",
                mapping="提权矩阵 platform-cert-manager；MITRE T1098",
                fix="拒绝 O=system:masters 的 CSR；启用 signerName 白名单与人工审批",
            ))
    return out


def analyze_webhook_write(doc: dict, params: dict) -> list[dict]:
    out: list[dict] = []
    for key in ("mutatingwebhookconfigurations", "validatingwebhookconfigurations"):
        for wh in doc.get(key, []) or []:
            failure = str(wh.get("failurePolicy") or "")
            url = str((wh.get("clientConfig") or {}).get("url") or "")
            empty_selector = not wh.get("namespaceSelector")
            risky = failure == "Ignore" or url.startswith("http://") or empty_selector
            if risky:
                out.append(finding(
                    "critical", f"fail-open/不安全准入 Webhook：{wh.get('name')}",
                    detail=f"failurePolicy={failure} url={url or 'service'} emptySelector={empty_selector}；"
                           "写入方可注入特权/窃取 AdmissionReview 中的 Secret。",
                    evidence=f"{key}={wh.get('name')} rules={wh.get('rules')}",
                    mapping="提权矩阵 rbac-admission-webhook-write；K8s admission webhook",
                    fix="failurePolicy=Fail、禁止 http URL、限定 namespaceSelector；webhook 配置变更需双人审批",
                ))
    return out


def analyze_apiservice(doc: dict, params: dict) -> list[dict]:
    out: list[dict] = []
    for svc in doc.get("apiservices", []) or []:
        if svc.get("insecureSkipTLSVerify") or not svc.get("service"):
            out.append(finding(
                "high", f"APIService 聚合层不安全：{svc.get('name')}",
                detail=f"insecureSkipTLSVerify={svc.get('insecureSkipTLSVerify')} service={svc.get('service')}；"
                       "可劫持 API group、窃取 bearer token 或伪造对象。",
                evidence=f"apiservice={svc.get('name')} group={svc.get('group')}",
                mapping="提权矩阵 rbac-apiservice-hijack；K8s aggregation",
                fix="启用 TLS 校验、绑定 service；限制 apiservices 写权限到控制面组件",
            ))
    return out


def analyze_crd_conversion(doc: dict, params: dict) -> list[dict]:
    out: list[dict] = []
    for crd in doc.get("customresourcedefinitions", []) or []:
        conv = crd.get("conversion") or {}
        if str(conv.get("strategy")) != "Webhook":
            continue
        client = ((conv.get("webhook") or {}).get("clientConfig") or {})
        if not client.get("caBundle"):
            out.append(finding(
                "high", f"CRD conversion webhook 缺 CA：{crd.get('name')}",
                detail="conversion webhook 未配置 caBundle/不安全；可拦截/篡改所有 CR 版本转换，"
                       "向 operator 注入恶意对象或读取 CR 中的凭据引用。",
                evidence=f"crd={crd.get('name')} clientConfig={client}",
                mapping="提权矩阵 rbac-crd-conversion-webhook；K8s CRD versioning",
                fix="为 conversion webhook 配置受信 CA；限制 CRD 写权限；监控 conversion webhook 变更",
            ))
    return out


def analyze_kubelet(doc: dict, params: dict) -> list[dict]:
    out: list[dict] = []
    for node in doc.get("nodes", []) or []:
        kl = node.get("kubelet") or {}
        if kl.get("anonymousAuth") or str(kl.get("authorizationMode")) == "AlwaysAllow" or kl.get("readOnlyPort"):
            out.append(finding(
                "critical", f"kubelet 10250 认证/授权缺陷：{node.get('name')}",
                detail=f"anonymousAuth={kl.get('anonymousAuth')} authorizationMode={kl.get('authorizationMode')} "
                       f"readOnlyPort={kl.get('readOnlyPort')}；/exec、/run、/logs 可被未认证调用。",
                evidence=f"node={node.get('name')} kubelet={kl}",
                mapping="提权矩阵 node-kubelet-10250-exec / node-kubelet-10250-run",
                fix="anonymous-auth=false、authorization-mode=Webhook、关闭 readOnlyPort；10250 仅 apiserver 可达",
            ))
    for kl in doc.get("kubelets", []) or []:
        if kl.get("anonymousAuth") or str(kl.get("authorizationMode")) == "AlwaysAllow":
            out.append(finding(
                "high", f"kubelet 暴露：{kl.get('node')}",
                detail=f"port={kl.get('port')} anonymousAuth={kl.get('anonymousAuth')} "
                       f"authorizationMode={kl.get('authorizationMode')}",
                evidence=f"kubelet={kl}",
                fix="按节点收敛 kubelet 认证；NAT/安全组限制 10250 源",
            ))
    return out


def analyze_etcd(doc: dict, params: dict) -> list[dict]:
    out: list[dict] = []
    for etcd in doc.get("etcd", []) or []:
        if not etcd.get("tls") or not etcd.get("clientCertAuth"):
            out.append(finding(
                "critical", f"etcd 直连风险：{etcd.get('name')}",
                detail=f"endpoint={etcd.get('endpoint')} tls={etcd.get('tls')} "
                       f"clientCertAuth={etcd.get('clientCertAuth')}；可读取全部 Secret/SA token 或写入 RBAC 对象。",
                evidence=f"etcd={etcd.get('name')} endpoint={etcd.get('endpoint')}",
                mapping="提权矩阵 node-etcd-direct；K8s etcd 运维",
                fix="启用 etcd mTLS 与客户端证书；2379/2380 仅控制面网段可达",
            ))
    return out


def analyze_image_pull(doc: dict, params: dict) -> list[dict]:
    out: list[dict] = []
    for sec in doc.get("secrets", []) or []:
        if str(sec.get("type")) == "kubernetes.io/dockerconfigjson":
            out.append(finding(
                "high", f"imagePullSecret 可读：{sec.get('namespace')}/{sec.get('name')}",
                detail="dockerconfigjson 含仓库凭据；可拉取私有镜像或向仓库推送恶意镜像，投毒 operator/DaemonSet。",
                evidence=f"secret={sec.get('namespace')}/{sec.get('name')} type={sec.get('type')}",
                mapping="提权矩阵 cred-image-pull-secret；MITRE T1525",
                fix="使用短时效 registry token/工作负载身份；限制 secrets 读权限到拉取组件",
            ))
    for pod in doc.get("pods", []) or []:
        if pod.get("imagePullSecrets"):
            out.append(finding(
                "medium", f"Pod 引用 imagePullSecret：{pod.get('namespace')}/{pod.get('name')}",
                detail=f"imagePullSecrets={pod.get('imagePullSecrets')}；可被 exec/探针读取或滥用。",
                evidence=f"pod={pod.get('name')} imagePullSecrets={pod.get('imagePullSecrets')}",
                fix="改用节点级/仓库联合身份；避免长期静态 dockerconfigjson",
            ))
    return out


def analyze_gitops(doc: dict, params: dict) -> list[dict]:
    out: list[dict] = []
    for dep in doc.get("deployments", []) or []:
        name = str(dep.get("name", ""))
        if not any(k in name.lower() for k in ("argocd", "flux")):
            continue
        if dep.get("clusterAdmin") or dep.get("secretRead") or dep.get("repoToken"):
            out.append(finding(
                "high", f"GitOps 控制器高权：{dep.get('namespace')}/{name}",
                detail=f"clusterAdmin={dep.get('clusterAdmin')} secretRead={dep.get('secretRead')} "
                       f"repoToken={'yes' if dep.get('repoToken') else 'no'}；仓库写权限即可落地 cluster-admin 清单。",
                evidence=f"deployment={dep.get('namespace')}/{name} sa={dep.get('serviceAccount')}",
                mapping="提权矩阵 platform-argocd-flux；Argo CD/Flux 安全",
                fix="GitOps 控制器使用最小权限 + 项目级 AppProject；仓库写权限强制签名/审批",
            ))
    for sec in doc.get("secrets", []) or []:
        if any(k in str(sec.get("name", "")).lower() for k in ("argocd", "flux", "git")):
            out.append(finding(
                "high", f"GitOps 凭据 Secret：{sec.get('namespace')}/{sec.get('name')}",
                detail=f"keys={sec.get('keys')}；可被用于写仓库或伪造 sync 源。",
                evidence=f"secret={sec.get('name')}",
                fix="使用短期 workload identity/部署密钥；限制 secret 读主体",
            ))
    return out


def analyze_gpu_operator(doc: dict, params: dict) -> list[dict]:
    out: list[dict] = []
    for ds in doc.get("daemonsets", []) or []:
        image = str(ds.get("image", "")).lower()
        paths = [str(p) for p in ds.get("hostPath", [])]
        if "driver" in str(ds.get("name", "")).lower() or "nvidia/driver" in image:
            if ds.get("privileged") or any(p in ("/dev", "/run", "/usr/lib64") for p in paths):
                out.append(finding(
                    "critical", f"GPU Operator driver 容器逃逸面：{ds.get('namespace')}/{ds.get('name')}",
                    detail=f"privileged={ds.get('privileged')} hostPath={paths} image={ds.get('image')}；"
                           "driver 容器以节点 root 运行，替换镜像/注入命令即节点接管。",
                    evidence=f"daemonset={ds.get('name')} sa={ds.get('serviceAccount')}",
                    mapping="提权矩阵 platform-gpu-operator-driver；NVIDIA GPU Operator",
                    fix="driver 容器按最小 hostPath/能力收敛；镜像签名+准入校验；daemonset 写权限仅平台管理员",
                ))
    return out


def analyze_cni(doc: dict, params: dict) -> list[dict]:
    out: list[dict] = []
    for ds in doc.get("daemonsets", []) or []:
        name = str(ds.get("name", "")).lower()
        paths = [str(p) for p in ds.get("hostPath", [])]
        if any(k in name for k in ("calico", "cilium", "cni")) or "/opt/cni/bin" in paths:
            if ds.get("privileged") or "/opt/cni/bin" in paths:
                out.append(finding(
                    "critical", f"CNI 插件执行面：{ds.get('namespace')}/{ds.get('name')}",
                    detail=f"privileged={ds.get('privileged')} hostPath={paths}；CNI 以节点 root 运行，"
                           "替换二进制/注入 hook 可在所有节点执行。",
                    evidence=f"daemonset={ds.get('name')} sa={ds.get('serviceAccount')}",
                    mapping="提权矩阵 platform-cni-plugin；CNI 规范",
                    fix="CNI 镜像签名+只读根；/opt/cni/bin 仅 kubelet 可写；daemonset 变更双人审批",
                ))
    return out


def analyze_csi(doc: dict, params: dict) -> list[dict]:
    out: list[dict] = []
    for ds in doc.get("daemonsets", []) or []:
        name = str(ds.get("name", "")).lower()
        paths = [str(p) for p in ds.get("hostPath", [])]
        if "csi" in name or "nfsplugin" in str(ds.get("image", "")).lower():
            if ds.get("privileged") or "/var/lib/kubelet" in paths or "/dev" in paths:
                out.append(finding(
                    "critical", f"CSI node plugin 逃逸面：{ds.get('namespace')}/{ds.get('name')}",
                    detail=f"privileged={ds.get('privileged')} hostPath={paths}；插件可读写宿主 kubelet 目录/设备，"
                           "篡改挂载流程或跨租户读取卷。",
                    evidence=f"daemonset={ds.get('name')} sa={ds.get('serviceAccount')}",
                    mapping="提权矩阵 platform-csi-node-plugin；CSI 规范",
                    fix="CSI 插件按最小 hostPath 收敛；启用卷隔离/加密；插件镜像签名与准入校验",
                ))
    return out


ANALYZERS: dict[str, Callable[[dict, dict], list[dict]]] = {
    "rbac-escalate-verb": analyze_escalate,
    "rbac-bind-verb": analyze_bind,
    "impersonate-abuse": analyze_impersonate,
    "sa-token-request": analyze_sa_token,
    "csr-approve": analyze_csr,
    "admission-webhook-write": analyze_webhook_write,
    "apiservice-hijack": analyze_apiservice,
    "crd-conversion-webhook": analyze_crd_conversion,
    "kubelet-10250-exec": analyze_kubelet,
    "etcd-direct-access": analyze_etcd,
    "image-pull-secret-theft": analyze_image_pull,
    "gitops-secret-read": analyze_gitops,
    "gpu-operator-driver-escape": analyze_gpu_operator,
    "cni-plugin-exec": analyze_cni,
    "csi-node-plugin-escape": analyze_csi,
}


# ---------------------------------------------------------------- demos (写类，备份闸门)

def demo_escalate(ctx: dict, params: dict) -> list[dict]:
    payload = (
        "apiVersion: rbac.authorization.k8s.io/v1\n"
        "kind: ClusterRole\n"
        "metadata: {name: inkblade-escalated-demo}\n"
        "rules: [{apiGroups: ['*'], resources: ['*'], verbs: ['*']}]\n"
    )
    target = _canary(ctx, params, "escalate", payload)
    return [finding("high", "escalate 改写演示已落盘（可回滚）",
                    detail=f"演示 ClusterRole 清单写入 {target}；真实集群中由已绑定角色 escalate 后生效。",
                    evidence=f"demo_target={target}", mapping="rbac-escalate-verb demo")]


def demo_bind(ctx: dict, params: dict) -> list[dict]:
    payload = (
        "apiVersion: rbac.authorization.k8s.io/v1\n"
        "kind: ClusterRoleBinding\n"
        "metadata: {name: inkblade-bind-demo}\n"
        "roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: cluster-admin}\n"
        "subjects: [{kind: ServiceAccount, name: demo-sa, namespace: privesc-lab}]\n"
    )
    target = _canary(ctx, params, "bind", payload)
    return [finding("high", "bind 自绑演示已落盘（可回滚）",
                    detail=f"演示 ClusterRoleBinding 清单写入 {target}；真实集群中需 bind cluster-admin + create 绑定。",
                    evidence=f"demo_target={target}", mapping="rbac-bind-verb demo")]


def demo_webhook(ctx: dict, params: dict) -> list[dict]:
    payload = (
        "apiVersion: admissionregistration.k8s.io/v1\n"
        "kind: MutatingWebhookConfiguration\n"
        "metadata: {name: inkblade-webhook-demo}\n"
        "webhooks:\n"
        "  - name: inject.inkblade.local\n"
        "    admissionReviewVersions: [v1]\n"
        "    sideEffects: None\n"
        "    failurePolicy: Ignore\n"
        "    rules: [{apiGroups: [''], apiVersions: [v1], operations: [CREATE], resources: [pods]}]\n"
        "    clientConfig: {url: 'https://inkblade-webhook.privesc-lab.svc:443/mutate'}\n"
    )
    target = _canary(ctx, params, "webhook", payload)
    return [finding("high", "准入 Webhook 写入演示已落盘（可回滚）",
                    detail=f"演示 MutatingWebhookConfiguration 写入 {target}；fail-open + pod CREATE 覆盖可注入特权。",
                    evidence=f"demo_target={target}", mapping="admission-webhook-write demo")]


DEMOS = {
    "rbac-escalate-verb": demo_escalate,
    "rbac-bind-verb": demo_bind,
    "admission-webhook-write": demo_webhook,
}


# ---------------------------------------------------------------- runner

def run_detect(ctx: dict, params: dict, module_key: str, family: str) -> dict:
    doc, fixture = load_fixture(params, module_key)
    analyzer = ANALYZERS[module_key]
    findings = list(analyzer(doc, params))
    summary = f"{family}完成：{len(findings)} 条发现（夹具 {fixture}）"
    if params.get("mode") == "backup-write":
        demo = DEMOS.get(module_key)
        if demo is None:
            raise ValueError(f"{module_key} 不支持 backup-write 演示")
        extra = demo(ctx, params)
        findings += extra
        summary += "；已执行 backup-write 演示"
    art_dir = ctx["run"].dir / "artifacts"
    art_dir.mkdir(parents=True, exist_ok=True)
    art = art_dir / f"{module_key}-detection.json"
    art.write_text(json.dumps({
        "module": module_key,
        "fixture": fixture,
        "findings": findings,
        "marker": ctx["marker"],
        "summary": {
            "items": len(doc.get("items", [])),
            "roles": len(doc.get("clusterroles", []) or []) + len(doc.get("roles", []) or []),
            "pods": len(doc.get("pods", []) or []),
            "daemonsets": len(doc.get("daemonsets", []) or []),
        },
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"summary": summary, "findings": findings, "artifacts": [str(art)]}
