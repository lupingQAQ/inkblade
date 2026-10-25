"""kdigger-admission — admission 六模板 dry-run 结果判定（不创建对象）。

输入：集群侧已执行的 dry-run 结果（params.snapshot 的 ``admission.dry_run``），或
``params.dry_run`` 直传。六个模板：privileged / priv-escalation / hostnetwork /
hostpath / runasroot / hostpid。只读消费结果，**本模块不发起任何 dry-run 请求**。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_surface_common", _PARENT / "_surface-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

finding, run_surface = _C.finding, _C.run_surface

TEMPLATES = ("privileged", "priv-escalation", "hostnetwork", "hostpath", "runasroot", "hostpid")
SEV = {"privileged": "critical", "priv-escalation": "critical", "hostpath": "critical",
       "hostpid": "high", "hostnetwork": "high", "runasroot": "medium"}
HINTS = {
    "privileged": "privileged=true 可获得宿主设备与内核面",
    "priv-escalation": "allowPrivilegeEscalation=true 可借 setuid/文件能力提权",
    "hostnetwork": "hostNetwork 绕过 CNI/NetworkPolicy",
    "hostpath": "hostPath 挂载宿主文件系统",
    "runasroot": "runAsUser=0 以 root 运行",
    "hostpid": "hostPID 可见宿主进程",
}


def analyze(snapshot: dict, params: dict) -> list[dict]:
    admission = snapshot.get("admission") or {}
    results = params.get("dry_run") or admission.get("dry_run") or []
    if not results and not admission:
        return []
    by_template = {str(r.get("template")): r for r in results if isinstance(r, dict)}
    out: list[dict] = []

    if admission.get("pod_security_enforced") is False:
        out.append(finding(
            "high", "PSA/准入策略未强制（六模板 dry-run 前置条件）",
            "命名空间未启用 restricted 基线，特权模板大概率放行。",
            evidence="pod_security_enforced=false",
            mapping_text="kdigger Admission（CM-24）+ KubeTrail admission_dryrun",
            fix="启用 PSA restricted / Kyverno 拒绝特权字段",
        ))

    for template in TEMPLATES:
        record = by_template.get(template)
        if record is None:
            out.append(finding(
                "medium", f"admission dry-run 缺失模板：{template}",
                "未提供该模板的 dry-run 结果，无法确认准入边界（建议补测）。",
                evidence=f"template={template} missing",
                mapping_text="kdigger Admission 六模板（CM-24）",
                fix="在授权窗口内执行 server-side dry-run 并回填结果",
                template=template, allowed=None,
            ))
            continue
        allowed = bool(record.get("allowed"))
        if allowed:
            out.append(finding(
                SEV[template], f"admission dry-run 放行：{template}",
                f"{HINTS[template]}；reason={record.get('reason', '')}",
                evidence=f"template={template} allowed=true reason={record.get('reason', '')}",
                mapping_text="kdigger Admission 六模板（CM-24）",
                fix="准入拒绝该模板；必要时走审批例外",
                template=template, allowed=True,
            ))
        else:
            out.append(finding(
                "info", f"admission dry-run 拒绝：{template}",
                f"准入已拦截（reason={record.get('reason', '')}）。",
                evidence=f"template={template} allowed=false",
                mapping_text="kdigger Admission 六模板（CM-24）",
                fix="保持策略并纳入回归",
                template=template, allowed=False,
            ))
    return out


def extra(snapshot: dict, findings: list[dict]) -> dict:
    admission = snapshot.get("admission") or {}
    results = admission.get("dry_run") or []
    allowed = [f.get("template") for f in findings if f.get("allowed") is True]
    denied = [f.get("template") for f in findings if f.get("allowed") is False]
    return {"templates": len(TEMPLATES), "results": len(results),
            "allowed": allowed, "denied": denied,
            "pod_security_enforced": admission.get("pod_security_enforced")}


def run(ctx: dict, params: dict) -> dict:
    return run_surface(ctx, params, analyze, family="kdigger admission 探测", extra=extra)
