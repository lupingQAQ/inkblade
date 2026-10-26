"""kubiscan-risky — risky 实体反查 + 逐 Pod Secret 挂载盘点 + token dump 面。"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_surface_common", _PARENT / "_surface-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

finding, run_surface = _C.finding, _C.run_surface
section, pods, pod_id, automount_token = _C.section, _C.pods, _C.pod_id, _C.automount_token
subjects_with, wildcard_subjects = _C.subjects_with, _C.wildcard_subjects

DANGEROUS = (
    ("get", "secrets", "critical", "读取 Secret"),
    ("list", "secrets", "critical", "枚举 Secret"),
    ("create", "pods/exec", "high", "Pod exec"),
    ("impersonate", "users", "critical", "冒充用户"),
    ("create", "clusterrolebindings", "critical", "创建集群绑定"),
)


def analyze(snapshot: dict, params: dict) -> list[dict]:
    out: list[dict] = []
    for subject in wildcard_subjects(snapshot):
        out.append(finding(
            "critical", f"risky 主体（通配符）：{subject}",
            "allowed 含 *，等价集群管理员（KubiScan risky subjects 口径）。",
            evidence=f"subject={subject} wildcard=true",
            mapping_text="KubiScan risky roles/subjects（CM-36）",
            fix="去通配符；按动词/资源最小化", subject=subject,
        ))
    for binding in section(snapshot, "clusterrolebindings"):
        if str(binding.get("role", "")).lower() in ("cluster-admin", "admin"):
            for subject in binding.get("subjects") or []:
                if str(subject).startswith("system:"):
                    continue
                out.append(finding(
                    "critical", f"risky 主体（cluster-admin 绑定）：{subject}",
                    f"通过 {binding.get('name')} 获得最高权限。",
                    evidence=f"binding={binding.get('name')} subject={subject}",
                    mapping_text="KubiScan static risky roles（CM-36）",
                    fix="收敛 cluster-admin 绑定", subject=str(subject),
                ))
    for verb, resource, sev, desc in DANGEROUS:
        for subject in subjects_with(snapshot, verb, resource):
            out.append(finding(
                sev, f"risky 主体（{desc}）：{subject}",
                f"can-i {verb} {resource} = true。",
                evidence=f"subject={subject} verb={verb} resource={resource}",
                mapping_text="KubiScan risky entities（CM-36）",
                fix="按主体收敛 RBAC", subject=subject,
            ))

    for pod in pods(snapshot):
        pid = pod_id(pod)
        secret_vols = [v.get("name") for v in pod.get("volumes") or [] if (v.get("secret") or {})]
        env_secrets = []
        for container in pod.get("containers") or []:
            for env in container.get("env") or []:
                ref = (env.get("valueFrom") or {}).get("secretKeyRef") or {}
                if ref.get("name"):
                    env_secrets.append(f"{env.get('name')}←{ref['name']}")
        if secret_vols or env_secrets or automount_token(pod):
            out.append(finding(
                "high" if (secret_vols or env_secrets) else "medium",
                f"Secret 挂载盘点：{pid}（volume={len(secret_vols)} env={len(env_secrets)} "
                f"token={automount_token(pod)}）",
                "逐 Pod Secret 挂载面：volume/env/token 均可被容器内进程读取。",
                evidence=f"pod={pid} volumes={secret_vols} env={env_secrets} automount={automount_token(pod)}",
                mapping_text="KubiScan pods-secrets-volume/-env（CM-36）",
                fix="按需挂载 + 短期凭据 + 只读根文件系统", pod=pid,
            ))

    dump = [pod_id(p) for p in pods(snapshot) if automount_token(p)]
    if dump and (subjects_with(snapshot, "get", "pods") or subjects_with(snapshot, "create", "pods/exec")):
        out.append(finding(
            "critical", f"Token dump 面：{len(dump)} 个 automount Pod × Pod 读取/exec 权限",
            "可进入/读取 Pod 取得 SA token（KubiScan -dt 的盘点等价）。",
            evidence=f"pods={dump[:3]}",
            mapping_text="KubiScan --dump-tokens（CM-36 盘点等价）",
            fix="禁用 automount；exec 收敛；bound token",
        ))
    return out


def extra(snapshot: dict, findings: list[dict]) -> dict:
    subjects = {f.get("subject") for f in findings if f.get("subject")}
    return {"risky_subjects": len(subjects), "findings": len(findings),
            "pods_inventoried": len(pods(snapshot))}


def run(ctx: dict, params: dict) -> dict:
    return run_surface(ctx, params, analyze, family="KubiScan risky 实体", extra=extra)
