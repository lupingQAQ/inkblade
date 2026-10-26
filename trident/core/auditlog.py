# -*- coding: utf-8 -*-
"""core/auditlog.py — K8s API 审计轨迹分析引擎（who-did-what 追溯，侦察级只读）。

输入：
- 标准 K8s audit log JSON Lines（audit.k8s.io/v1 Event：verb/user/objectRef/requestObject/responseStatus/stageTimestamp）
- KubeTrail（github.com/ekkoo-z/KubeTrail）`dbus.json` 导出 Document（schemaVersion+facts+findings 形态，
  经 detect_kubetrail_export 识别 → adapt_kubetrail 适配为 Trident findings）

输出 finding 字段（除 sev/title/detail/evidence/mapping/fix 外）：
- subject 主体（user.username）
- verb    动词
- resource 资源（resource[/subresource] namespace/name）
- time    事件时间（stageTimestamp，缺省 requestReceivedTimestamp）
- chains  映射攻击链名（与 trident/chains/*.json 对齐）
- modules 关联模块键
- rule_keys 建议规则键（Sigma/Falco/Kyverno，与 trident/rules/templates 对齐）
- detector 检测器标识

误报口径（benign 零报）：
- 仅已完成动作（responseStatus.code 2xx）默认入报；403 已拒绝尝试默认不报（include_denied=True 时以 low 报）
- Secret 读：基线主体白名单（与 sigma-secret-abnormal-read not_in 一致）不报
- 挂载权重 PVC：平台调度器主体不报（baseline_subjects 可扩展）
- **永不基线化**：serviceaccounts/token 铸造与 pods/portforward 不吃主体白名单
  （任何主体铸造/隧道都留痕；core/baseline.NEVER_LEARN_PATTERNS 同步封死学习路径）
"""

from __future__ import annotations

import json
import re
from pathlib import Path

DEFAULT_BASELINE_SUBJECTS = (
    # 与 sigma-secret-abnormal-read not_in 白名单同源
    "system:serviceaccount:kube-system:generic-garbage-collector",
    "system:serviceaccount:monitoring:prometheus",
    # 权重 PVC 挂载/claim 写的基线主体（与 sigma-weight-pvc-abnormal-write not_in 同源）
    "system:serviceaccount:ml-training:platform-scheduler",
    "system:serviceaccount:kube-system:storage-operator",
)

# 权重/检查点类 PVC 名称特征（claim 级异常写 + 非 baseline 主体挂载）
WEIGHT_PVC_RE = re.compile(r"(weight|weights|model[-_]?weights|hf[-_]?cache|checkpoint|ckpt)", re.I)
# 敏感 hostPath 前缀（与 kyverno deny-sensitive-hostpath 同源）
SENSITIVE_HOSTPATH_PREFIXES = (
    "/var/run/docker.sock", "/var/run/containerd", "/var/run/crio",
    "/proc", "/sys", "/dev", "/etc/kubernetes",
)
RAY_NS_RE = re.compile(r"^ray[-_]", re.I)
RAY_JOB_NAME_RE = re.compile(r"^rayjob[-_]", re.I)

_RBAC_BINDING_RESOURCES = {"rolebinding", "rolebindings", "clusterrolebinding", "clusterrolebindings"}
_POD_RESOURCES = {"pod", "pods"}
_SA_RESOURCES = {"serviceaccount", "serviceaccounts"}
_SECRET_RESOURCES = {"secret", "secrets"}
_PVC_RESOURCES = {"persistentvolumeclaim", "persistentvolumeclaims"}
_READ_VERBS = {"get", "list", "watch"}
_WRITE_VERBS = {"create", "update", "patch", "delete"}


# ---------------------------------------------------------------- 解析

def parse_jsonl(text: str) -> list[dict]:
    """JSON Lines → 事件列表；空行与 # 注释行跳过；坏行静默跳过（审计流规模化容错）。"""
    events: list[dict] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            obj = json.loads(stripped)
        except ValueError:
            continue
        if isinstance(obj, dict):
            events.append(obj)
    return events


def load_events(source) -> list[dict]:
    """source：事件 list / dict 单事件 / JSON Lines 文件路径（str|Path）。"""
    if isinstance(source, dict):
        return [source]
    if isinstance(source, (list, tuple)):
        return [e for e in source if isinstance(e, dict)]
    path = Path(str(source))
    return parse_jsonl(path.read_text(encoding="utf-8"))


def subject_of(event: dict) -> str:
    user = event.get("user") or {}
    return str(user.get("username") or event.get("subject_sa") or "unknown")


def _resource_label(event: dict) -> str:
    ref = event.get("objectRef") or {}
    parts = [str(ref.get("resource") or "?")]
    if ref.get("subresource"):
        parts.append(str(ref["subresource"]))
    label = "/".join(parts)
    if ref.get("namespace"):
        label += f" {ref['namespace']}/{ref.get('name') or '?'}"
    elif ref.get("name"):
        label += f" {ref['name']}"
    return label


def _event_time(event: dict) -> str:
    return str(event.get("stageTimestamp") or event.get("requestReceivedTimestamp") or "")


def _succeeded(event: dict) -> bool:
    code = (event.get("responseStatus") or {}).get("code")
    if code is None:
        return True  # 合成事件无响应码按已完成处理
    return 200 <= int(code) < 300


def _verb(event: dict) -> str:
    return str(event.get("verb") or "").lower()


def _ref_resource(event: dict) -> str:
    return str((event.get("objectRef") or {}).get("resource") or "").lower()


def _finding(detector: str, sev: str, title: str, event: dict, *, detail: str,
             chains: list[str], modules: list[str], rule_keys: list[str], fix: str) -> dict:
    verb = _verb(event)
    resource = _resource_label(event)
    subject = subject_of(event)
    code = (event.get("responseStatus") or {}).get("code")
    return {
        "sev": sev,
        "title": title,
        "detail": detail,
        "subject": subject,
        "verb": verb,
        "resource": resource,
        "time": _event_time(event),
        "chains": chains,
        "modules": modules,
        "rule_keys": rule_keys,
        "detector": detector,
        "evidence": (f"auditID={event.get('auditID', '-')} user={subject} verb={verb} "
                     f"resource={resource} code={code if code is not None else '-'} "
                     f"sourceIPs={event.get('sourceIPs', '-')}"),
        "mapping": f"链 {'/'.join(chains)}；规则键 {' '.join(rule_keys)}",
        "fix": fix,
    }


# ---------------------------------------------------------------- 六类检测器（形态取自本仓库攻击链的 apiserver 投影）

def _role_ref_name(event: dict) -> str:
    for holder in (event.get("requestObject") or {}, event.get("objectRef") or {}):
        ref = holder.get("roleRef") or {}
        if ref.get("name"):
            return str(ref["name"])
    return ""


def _detect_rbac_clusteradmin_binding(event: dict, baseline: set[str]) -> dict | None:
    if _verb(event) != "create" or _ref_resource(event) not in _RBAC_BINDING_RESOURCES:
        return None
    if _role_ref_name(event) != "cluster-admin":
        return None
    denied = not _succeeded(event)
    hit = _finding(
        "rbac-clusteradmin-binding", "critical" if not denied else "low",
        ("审计轨迹：RoleBinding→cluster-admin 创建" + ("（已拒绝尝试）" if denied else "")),
        event,
        detail="主体把自身/他人绑定到 cluster-admin：权限链判定总入口，一步接管集群（含节点与密钥面）。",
        chains=["ray-dashboard-cluster-takeover"],
        modules=["overprivileged-sa-escalation"],
        rule_keys=["sigma-rolebinding-cluster-admin", "kyverno:alert-rolebinding-creation",
                   "gatekeeper:alert-rolebinding-creation"],
        fix="清点 cluster-admin 增量绑定主体；gitops/operator 常规绑定入主体白名单；绑定创建走准入告警/拦截",
    )
    hit["evidence"] += f" roleRef={_role_ref_name(event)}"
    return hit


def _pod_spec(event: dict) -> dict:
    obj = event.get("requestObject") or {}
    return obj.get("spec") if isinstance(obj.get("spec"), dict) else obj


def _containers(spec: dict) -> list[dict]:
    out = list(spec.get("containers") or []) + list(spec.get("initContainers") or [])
    return [c for c in out if isinstance(c, dict)]


def _detect_privileged_pod(event: dict, baseline: set[str]) -> dict | None:
    if _verb(event) != "create" or _ref_resource(event) not in _POD_RESOURCES:
        return None
    spec = _pod_spec(event)
    privileged = any((c.get("securityContext") or {}).get("privileged") is True or
                     c.get("privileged") is True for c in _containers(spec))
    if spec.get("privileged") is True:
        privileged = True
    host_flags = [flag for flag in ("hostPID", "hostIPC", "hostNetwork") if spec.get(flag) is True]
    host_paths = [v.get("hostPath", {}).get("path", "") for v in spec.get("volumes") or []
                  if isinstance(v, dict) and isinstance(v.get("hostPath"), dict)]
    sensitive = [p for p in host_paths
                 if any(str(p) == pre or str(p).startswith(pre.rstrip("/") + "/") or str(p) == "/"
                        for pre in SENSITIVE_HOSTPATH_PREFIXES)]
    if not (privileged or sensitive or host_flags):
        return None
    sev = "critical" if (privileged or sensitive) else "high"
    facets = []
    if privileged:
        facets.append("privileged")
    if sensitive:
        facets.append("hostPath:" + ",".join(sensitive))
    if host_flags:
        facets.append("+".join(host_flags))
    return _finding(
        "privileged-pod-create", sev,
        "审计轨迹：特权/宿主面 Pod 创建（" + "/".join(facets) + "）",
        event,
        detail="特权容器/hostPath 运行时 socket/宿主 namespace 共享 = 容器逃逸与节点接管原语。",
        chains=["gpu-network-operator-host-escape"],
        modules=["privileged-gpu-pod-escape", "runtime-socket-escape"],
        rule_keys=["sigma-privileged-pod-create", "kyverno:deny-privileged-pod",
                   "kyverno:deny-sensitive-hostpath"],
        fix="GPU operator 例外命名空间外禁止特权/hostPath；准入 Enforce 化 + 例外通道逐 DaemonSet 审计",
    )


def _detect_pods_exec(event: dict, baseline: set[str]) -> dict | None:
    ref = event.get("objectRef") or {}
    if _verb(event) != "create" or _ref_resource(event) not in _POD_RESOURCES:
        return None
    if str(ref.get("subresource") or "").lower() not in ("exec", "attach"):
        return None
    if subject_of(event) in baseline:
        return None
    return _finding(
        "pods-exec-session", "high", "审计轨迹：pods/exec 会话（非基线主体）",
        event,
        detail="进入容器即借用其能力与挂载凭据（GPU/特权/SA token）；横向与逃逸的通用支点。",
        chains=["ray-dashboard-cluster-takeover"],
        modules=["overprivileged-sa-escalation", "rbac-mapping"],
        rule_keys=["sigma-pods-exec-lateral"],
        fix="exec/attach 收敛到运维 break-glass 主体 + 会话录像与告警；异常主体直接 critical",
    )


def _detect_sa_token_mint(event: dict, baseline: set[str]) -> dict | None:
    """serviceaccounts/token 创建（TokenRequest 铸造）——**永不基线化**。

    铸造即获得该 SA 的长期凭据（忽略 baseline 主体白名单：任何主体铸造
    token 都应留痕；学习模式在 core/baseline.NEVER_LEARN_PATTERNS 同步封死）。
    """
    ref = event.get("objectRef") or {}
    if _verb(event) != "create" or _ref_resource(event) not in _SA_RESOURCES:
        return None
    if str(ref.get("subresource") or "").lower() != "token":
        return None
    denied = not _succeeded(event)
    return _finding(
        "sa-token-mint", "low" if denied else "high",
        "审计轨迹：ServiceAccount Token 铸造" + ("（已拒绝尝试）" if denied else ""),
        event,
        detail=("serviceaccounts/token 创建 = 为该 SA 铸造可带外使用的凭据"
                "（租户内自助铸造即权限面外泄；配合绑定即横向闭环）。"),
        chains=["ssrf-sa-token-cloud-metadata"],
        modules=["overprivileged-sa-escalation", "supply-chain-credential-theft"],
        rule_keys=["sigma-sa-token-mint"],
        fix="TokenRequest 收敛到控制器主体；租户 SA 禁止自助铸造；绑定 gkp/kyverno 准入告警",
    )


def _detect_pods_portforward(event: dict, baseline: set[str]) -> dict | None:
    """pods/portforward 隧道——**永不基线化**（隐蔽数据面/管理面外带通道）。"""
    ref = event.get("objectRef") or {}
    if _verb(event) != "create" or _ref_resource(event) not in _POD_RESOURCES:
        return None
    if str(ref.get("subresource") or "").lower() != "portforward":
        return None
    denied = not _succeeded(event)
    return _finding(
        "pods-portforward", "low" if denied else "high",
        "审计轨迹：pods/portforward 隧道" + ("（已拒绝尝试）" if denied else ""),
        event,
        detail=("portforward 把 Pod 端口经 apiserver 隧道外带：绕过 NetworkPolicy/入口审计，"
                "常用于隐蔽数据外传与管理面直达。"),
        chains=["ray-dashboard-cluster-takeover"],
        modules=["overprivileged-sa-escalation"],
        rule_keys=["sigma-pods-portforward-tunnel"],
        fix="portforward 收敛到平台调试主体并强制会话审计；租户命名空间直接准入拒绝",
    )


def _detect_secret_abnormal_read(event: dict, baseline: set[str]) -> dict | None:
    if _verb(event) not in _READ_VERBS or _ref_resource(event) not in _SECRET_RESOURCES:
        return None
    if subject_of(event) in baseline:
        return None
    return _finding(
        "secret-abnormal-read", "high", "审计轨迹：非基线主体读取 Secret",
        event,
        detail="Secret 读取可达 SA token/云凭据/模型仓库凭据：横向与云侧链起点（SSRF→IMDS、跨租户窃取）。",
        chains=["ssrf-sa-token-cloud-metadata", "agent-platform-zero-precondition-lateral",
                "agent-platform-cross-tenant-data-chain"],
        modules=["ssrf-imds-credential", "multi-cloud-imds-credentials", "metadata-egress",
                 "dify-snapshot-cross-tenant-theft", "training-data-leak"],
        rule_keys=["sigma-secret-abnormal-read"],
        fix="以 30 天 audit 基线提炼合法读 Secret 主体白名单；instance-role/云凭据类 Secret 单独加规则",
    )


def _is_ray_job_runtime_pod(event: dict) -> bool:
    ref = event.get("objectRef") or {}
    namespace = str(ref.get("namespace") or "")
    name = str(ref.get("name") or "")
    obj = event.get("requestObject") or {}
    labels = (obj.get("metadata") or {}).get("labels") or obj.get("labels") or {}
    ray_labels = any(str(k).startswith("ray.io/") for k in labels)
    head_submit = RAY_JOB_NAME_RE.match(name) or (ray_labels and
                                                  any("job" in str(v).lower() for v in labels.values()))
    return bool((RAY_NS_RE.match(namespace) or namespace == "ray-system") and head_submit)


def _detect_ray_job_runtime_pod(event: dict, baseline: set[str]) -> dict | None:
    if _verb(event) != "create" or _ref_resource(event) not in _POD_RESOURCES:
        return None
    if (event.get("objectRef") or {}).get("subresource"):
        return None  # exec/attach 由 pods-exec-session 处理
    if not _is_ray_job_runtime_pod(event):
        return None
    return _finding(
        "ray-job-runtime-pod", "high", "审计轨迹：Ray 作业 runtime Pod 落地（head SA 代理 8265 提交）",
        event,
        detail=("Ray dashboard 8265 无鉴权作业提交不经 apiserver 身份——在审计面上投影为 head SA 落 "
                "rayjob runtime Pod：任一可达 8265 者即以此主体执行任意 entrypoint。"),
        chains=["ray-dashboard-cluster-takeover"],
        modules=["ray-dashboard-job"],
        rule_keys=["sigma-ray-job-submit", "suricata:admin-endpoint-uri"],
        fix="8265 分区限源（NetworkPolicy/bastion）；提交主体白名单=平台调度器；其余来源 critical",
    )


def _mounted_pvc_names(event: dict) -> list[str]:
    spec = _pod_spec(event)
    names = []
    for vol in spec.get("volumes") or []:
        if isinstance(vol, dict) and isinstance(vol.get("persistentVolumeClaim"), dict):
            claim = vol["persistentVolumeClaim"].get("claimName")
            if claim:
                names.append(str(claim))
    return names


def _detect_weight_pvc_write(event: dict, baseline: set[str]) -> dict | None:
    verb = _verb(event)
    ref = event.get("objectRef") or {}
    # 形态 A：claim 级异常写（create/patch/update 权重类 PVC）
    if verb in _WRITE_VERBS and _ref_resource(event) in _PVC_RESOURCES:
        name = str(ref.get("name") or "")
        if WEIGHT_PVC_RE.search(name) and subject_of(event) not in baseline:
            return _finding(
                "weight-pvc-abnormal-write", "high", f"审计轨迹：权重 PVC claim 异常写（{name}）",
                event,
                detail="权重/检查点 PVC 的 claim 级变更（创建/扩容/改写）改变共享模型数据面：供应链投毒入口。",
                chains=["shared-pvc-supply-chain-poison"],
                modules=["shared-volume-weight-copy"],
                rule_keys=["sigma-weight-pvc-abnormal-write", "falco-weight-file-abnormal-write"],
                fix="权重 PVC claim 写收敛到存储运维主体；共享面改只读挂载或 per-租户 claim",
            )
    # 形态 B：非 baseline 主体创建挂载权重 PVC 的 Pod（写通道借位）
    if verb == "create" and _ref_resource(event) in _POD_RESOURCES and not ref.get("subresource"):
        claims = [c for c in _mounted_pvc_names(event) if WEIGHT_PVC_RE.search(c)]
        if claims and subject_of(event) not in baseline:
            return _finding(
                "weight-pvc-abnormal-write", "high",
                f"审计轨迹：非基线主体创建挂载权重 PVC 的 Pod（{'/'.join(claims)}）",
                event,
                detail="非平台调度主体把权重/检查点 PVC 挂进自定义 Pod = 权重异常写通道（运行时文件写由 Falco 覆盖）。",
                chains=["shared-pvc-supply-chain-poison"],
                modules=["shared-volume-weight-copy"],
                rule_keys=["sigma-weight-pvc-abnormal-write", "falco-weight-file-abnormal-write"],
                fix="权重 PVC 挂载收敛到平台调度器主体；eval/调试需求走只读副本 + 审批",
            )
    return None


_DETECTORS = (
    _detect_rbac_clusteradmin_binding,
    _detect_privileged_pod,
    _detect_pods_exec,
    _detect_sa_token_mint,
    _detect_pods_portforward,
    _detect_ray_job_runtime_pod,
    _detect_secret_abnormal_read,
    _detect_weight_pvc_write,
)


def analyze_events(events: list[dict], baseline_subjects=DEFAULT_BASELINE_SUBJECTS,
                   include_denied: bool = False) -> list[dict]:
    """事件流 → findings（who-did-what 追溯）。默认仅已完成动作；拒绝尝试可选拨出。"""
    baseline = set(baseline_subjects or DEFAULT_BASELINE_SUBJECTS)
    findings: list[dict] = []
    for event in events:
        if not isinstance(event, dict):
            continue
        for detector in _DETECTORS:
            hit = detector(event, baseline)
            if hit is None:
                continue
            if "已拒绝" in hit["title"] and not include_denied:
                break
            findings.append(hit)
            break  # 单事件单检测器（最严重面优先）
    return findings


# ---------------------------------------------------------------- KubeTrail 导出适配

_KUBETRAIL_CATEGORY_MAP = {
    "rbac": {
        "chains": ["ray-dashboard-cluster-takeover"],
        "modules": ["overprivileged-sa-escalation", "rbac-mapping"],
        "rule_keys": ["sigma-rolebinding-cluster-admin", "sigma-secret-abnormal-read"],
    },
    "escape": {
        "chains": ["gpu-network-operator-host-escape"],
        "modules": ["privileged-gpu-pod-escape", "runtime-socket-escape", "escape-primitives"],
        "rule_keys": ["sigma-privileged-pod-create", "kyverno:deny-privileged-pod",
                      "falco-weight-file-abnormal-write"],
    },
    "lpe": {
        "chains": ["gpu-network-operator-host-escape"],
        "modules": ["escape-primitives", "privileged-gpu-pod-escape"],
        "rule_keys": [],  # 主机内核面：K8s 准入/审计规则不覆盖，如实空列 + 建议见 fix
    },
}


def detect_kubetrail_export(doc) -> bool:
    """识别 KubeTrail dbus.json Document 形态（schemaVersion + facts 列表 + run/target）。"""
    return (isinstance(doc, dict) and isinstance(doc.get("facts"), list)
            and "schemaVersion" in doc and "run" in doc)


def adapt_kubetrail(doc: dict) -> list[dict]:
    """KubeTrail findings → Trident findings（severity 保序；类别映射链/规则键；主体取 target pod）。"""
    if not detect_kubetrail_export(doc):
        raise ValueError("不是 KubeTrail 导出 Document（缺 schemaVersion/facts/run）")
    target = doc.get("target") or {}
    subject = "kubetrail:" + "/".join(filter(None, [str(target.get("namespace") or ""),
                                                    str(target.get("podName") or target.get("hostname") or "unknown")]))
    run_info = doc.get("run") or {}
    happened_at = str(run_info.get("startedAt") or "")
    out: list[dict] = []
    for item in doc.get("findings") or []:
        category = str(item.get("category") or "").lower()
        mapped = _KUBETRAIL_CATEGORY_MAP.get(category, {"chains": [], "modules": [], "rule_keys": []})
        sev = str(item.get("severity") or "info").lower()
        if sev not in ("critical", "high", "medium", "low", "info"):
            sev = "info"
        rule_keys = list(mapped["rule_keys"])
        fix = "按 KubeTrail 建议复核；Trident 权限链/逃逸模块复测收敛"
        if not rule_keys:
            fix = "主机内核 LPE 面：K8s 准入/审计规则不覆盖，建议节点层（内核补丁/seccomp/BPF 监控）治理"
        out.append({
            "sev": sev,
            "title": f"[KubeTrail] {item.get('title', 'untitled')}",
            "detail": str(item.get("description") or ""),
            "subject": subject,
            "verb": "collect",
            "resource": f"kubetrail-fact:{item.get('evidence', '-')}",
            "time": happened_at,
            "chains": list(mapped["chains"]),
            "modules": list(mapped["modules"]),
            "rule_keys": rule_keys,
            "detector": f"kubetrail-{category or 'generic'}",
            "evidence": (f"source=kubetrail category={category} confidence={item.get('confidence', '-')} "
                         f"fact={item.get('evidence', '-')} target={subject}"),
            "mapping": f"链 {'/'.join(mapped['chains']) or '-'}；规则键 {' '.join(rule_keys) or '（无，见 fix）'}",
            "fix": fix,
            "kubetrail_category": category or "generic",
        })
    return out


# ---------------------------------------------------------------- 汇总入口

def analyze(auditlog=None, baseline_subjects=DEFAULT_BASELINE_SUBJECTS,
            kubetrail_export=None, include_denied: bool = False) -> dict:
    """统一入口：auditlog（路径/事件列表）+ 可选 KubeTrail 导出 → findings + 统计。"""
    events: list[dict] = []
    skipped = 0
    if auditlog is not None:
        if isinstance(auditlog, (str, Path)) and Path(str(auditlog)).is_file():
            events = load_events(auditlog)
        elif isinstance(auditlog, (list, tuple)):
            events = [e for e in auditlog if isinstance(e, dict)]
            skipped = len(auditlog) - len(events)
        else:
            raise ValueError("auditlog 需为 JSON Lines 文件路径或事件列表")
    findings = analyze_events(events, baseline_subjects=baseline_subjects,
                              include_denied=include_denied)
    kt_findings: list[dict] = []
    if kubetrail_export is not None:
        doc = kubetrail_export
        if isinstance(kubetrail_export, (str, Path)):
            doc = json.loads(Path(str(kubetrail_export)).read_text(encoding="utf-8"))
        kt_findings = adapt_kubetrail(doc)
    return {
        "events": events,
        "findings": findings + kt_findings,
        "stats": {
            "events": len(events),
            "skipped": skipped,
            "audit_findings": len(findings),
            "kubetrail_findings": len(kt_findings),
        },
    }
