"""reverse-rbac-lookup — 身份反查（谁有权做 X），kubectl-can-i 的反向等价（CM-36）。"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_surface_common", _PARENT / "_surface-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

finding, run_surface = _C.finding, _C.run_surface
section, allows = _C.section, _C.allows

QUERIES = (
    ("get", "secrets", "critical", "读取 Secret（token/权重桶/仓库凭据）"),
    ("list", "secrets", "critical", "枚举全部 Secret"),
    ("create", "pods/exec", "critical", "在任意 Pod 内执行命令"),
    ("create", "pods", "high", "创建 Pod（可挂载任意 SA/特权模板）"),
    ("create", "rolebindings", "critical", "创建 RoleBinding（权限提升）"),
    ("create", "clusterrolebindings", "critical", "创建 ClusterRoleBinding（集群提权）"),
    ("impersonate", "users", "critical", "冒充任意用户/组"),
    ("get", "nodes/proxy", "high", "通过 nodes/proxy 访问 kubelet"),
    ("create", "tokenreviews", "medium", "TokenReview（凭据校验面）"),
    ("create", "selfsubjectaccessreviews", "low", "权限自省（信息面）"),
)


def lookup(snapshot: dict, verb: str, resource: str) -> list[str]:
    """返回有权执行 verb+resource 的主体（去重排序）。"""
    out = []
    for entry in section(snapshot, "cani"):
        if allows(entry, verb, resource):
            out.append(str(entry.get("subject", "?")))
    return sorted(set(out))


def analyze(snapshot: dict, params: dict) -> list[dict]:
    out = []
    for verb, resource, sev, desc in QUERIES:
        subjects = lookup(snapshot, verb, resource)
        if not subjects:
            continue
        out.append(finding(
            sev, f"谁可以 {verb} {resource}：{len(subjects)} 个主体",
            f"{desc}；主体：{', '.join(subjects[:6])}"
            + (f"（+{len(subjects) - 6}）" if len(subjects) > 6 else ""),
            evidence=f"verb={verb} resource={resource} subjects={subjects}",
            mapping_text="Peirates kubectl-can-i 反向查询（CM-36）",
            fix="按主体收敛 RBAC；高风险动词限 break-glass + 审计",
            verb=verb, resource=resource, subjects=subjects,
        ))
        for subject in subjects:
            if subject.startswith("system:") or subject == "system:masters":
                continue
            out.append(finding(
                "high" if sev == "critical" else "medium",
                f"非系统主体持有高风险权限：{subject} → {verb} {resource}",
                "普通用户/SA 直接持有高风险动词，优先复核绑定来源。",
                evidence=f"subject={subject} verb={verb} resource={resource}",
                mapping_text="Peirates kubectl-can-i / KubiScan risky subjects",
                fix="复核 RoleBinding 来源；必要时降权",
                subject=subject, verb=verb, resource=resource,
            ))
    return out


def extra(snapshot: dict, findings: list[dict]) -> dict:
    return {"queries": len(QUERIES),
            "with_subjects": len({(f.get("verb"), f.get("resource")) for f in findings
                                  if f.get("verb") and f.get("resource")})}


def run(ctx: dict, params: dict) -> dict:
    return run_surface(ctx, params, analyze, family="RBAC 身份反查", extra=extra)
