# -*- coding: utf-8 -*-
"""Slurm Prolog/Epilog 生命周期执行审计（只读）。"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_slurm_common", _PARENT / "_slurm-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "slurm-prolog-epilog-audit"
_UNTRUSTED = ("/home/", "/tmp/", "/var/tmp/", "/dev/shm/", "/srv/images/")


def run(ctx: dict, params: dict) -> dict:
    snap = _C.load_snapshot(params)
    doc = _C.json_file(snap, "prolog-epilog.json", default={})
    conf = _C.conf(snap, "slurm.conf")
    scripts = doc.get("scripts") if isinstance(doc.get("scripts"), dict) else {}
    findings: list[dict] = []

    flags = str(doc.get("PrologFlags") or _C.get(conf, "PrologFlags") or "").lower()
    if "contain" not in flags:
        findings.append(_C.finding(
            "high", "PrologFlags 未启用 Contain（作业可逃出 cgroup）",
            {"PrologFlags": flags or "<missing>"},
            evidence=f"PrologFlags={flags or '<missing>'}",
            mapping="作业生命周期 cgroup 约束",
            fix="PrologFlags=Alloc,Contain",
        ))
    if not doc.get("PrologSlurmctld") and not doc.get("EpilogSlurmctld"):
        findings.append(_C.finding(
            "medium", "未配置控制器侧 PrologSlurmctld/EpilogSlurmctld",
            {"PrologSlurmctld": doc.get("PrologSlurmctld"),
             "EpilogSlurmctld": doc.get("EpilogSlurmctld")},
            evidence="controller-side prolog/epilog missing",
            mapping="调度侧生命周期钩子",
            fix="关键审计/配额动作放控制器侧钩子，并保护脚本路径",
        ))
    for label, key in (("Prolog", "Prolog"), ("Epilog", "Epilog"),
                       ("PrologSlurmctld", "PrologSlurmctld"),
                       ("EpilogSlurmctld", "EpilogSlurmctld")):
        path = str(doc.get(key) or _C.get(conf, key) or "")
        if not path:
            continue
        meta = scripts.get(path) or _C.meta(snap, Path(path).name, path)
        mode = _C.parse_mode(meta.get("mode"))
        owner = str(meta.get("owner") or "")
        issues = []
        if path.lower().startswith(_UNTRUSTED):
            issues.append("user-writable-location")
        if mode is not None and mode & 0o022:
            issues.append("group-or-world-writable")
        if owner and owner not in ("root", "slurm"):
            issues.append(f"owner={owner}")
        if meta.get("signed") is False:
            issues.append("unsigned")
        if not meta:
            issues.append("missing-metadata")
        if issues:
            findings.append(_C.finding(
                "high", f"{label} 脚本不可信：{path}",
                {"path": path, "meta": meta, "issues": issues},
                evidence=f"{label}={path} issues={','.join(issues)}",
                mapping="slurmd root 执行面",
                fix="脚本 root:root 0755、签名、放 /etc/slurm；禁止共享存储路径",
            ))
    if bool(doc.get("root_exec")) and any(
            str((scripts.get(k) or {}).get("signed")).lower() == "false"
            for k in (doc.get("Prolog"), doc.get("Epilog")) if k in scripts):
        findings.append(_C.finding(
            "critical", "root 执行的 prolog/epilog 未签名",
            {"Prolog": doc.get("Prolog"), "Epilog": doc.get("Epilog")},
            evidence="root_exec=true and signed=false",
            mapping="计算节点 root 持久化",
            fix="签名校验 + 只读挂载 + IMA/完整性监控",
        ))

    extra = {
        "prolog_flags": flags or "missing",
        "scripts": len(scripts),
        "contain": "contain" in flags,
        "finding_count": len(findings),
    }
    return _C.result(ctx, KEY, "Slurm Prolog/Epilog 生命周期执行审计", findings, extra=extra,
                     source=str(params.get("snapshot") or "<inline snapshot>"))
