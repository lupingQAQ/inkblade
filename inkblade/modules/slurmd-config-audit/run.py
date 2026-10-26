# -*- coding: utf-8 -*-
"""slurmd 节点守护进程配置审计（只读）。"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_slurm_common", _PARENT / "_slurm-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "slurmd-config-audit"


def run(ctx: dict, params: dict) -> dict:
    snap = _C.load_snapshot(params)
    conf = _C.conf(snap, "slurm.conf")
    prolog_doc = _C.json_file(snap, "prolog-epilog.json", default={})
    script_meta = prolog_doc.get("scripts") if isinstance(prolog_doc.get("scripts"), dict) else {}
    findings: list[dict] = []

    slurmd_user = _C.get(conf, "SlurmdUser")
    task_plugin = _C.get(conf, "TaskPlugin").lower()
    proctrack = _C.get(conf, "ProctrackType").lower()
    spool = _C.get(conf, "SlurmdSpoolDir")
    slurmd_params = _C.get(conf, "SlurmdParameters").lower()
    health = _C.get(conf, "HealthCheckProgram")
    prolog = _C.get(conf, "Prolog")
    epilog = _C.get(conf, "Epilog")
    acct_gather = _C.get(conf, "JobAcctGatherType").lower()
    mpi = _C.get(conf, "MpiDefault").lower()
    return_to_service = _C.as_int(_C.get(conf, "ReturnToService"), 0)

    if slurmd_user in ("", "root"):
        findings.append(_C.finding(
            "high", "SlurmdUser 为 root 或未设置",
            {"SlurmdUser": slurmd_user or "<missing>"},
            evidence=f"SlurmdUser={slurmd_user or '<missing>'}",
            mapping="slurmd 最小权限",
            fix="设置 SlurmdUser=slurm；计算节点不跑 root slurmd",
        ))
    if "task/cgroup" not in task_plugin:
        findings.append(_C.finding(
            "high", "节点未启用 task/cgroup",
            {"TaskPlugin": task_plugin or "<missing>"},
            evidence=f"TaskPlugin={task_plugin or '<missing>'}",
            mapping="Slurm TaskPlugin / 节点隔离",
            fix="TaskPlugin=task/cgroup,task/affinity",
        ))
    if "cgroup" not in proctrack:
        findings.append(_C.finding(
            "medium", "节点未使用 cgroup 追踪进程",
            {"ProctrackType": proctrack or "<missing>"},
            evidence=f"ProctrackType={proctrack or '<missing>'}",
            mapping="Slurm ProctrackType",
            fix="ProctrackType=proctrack/cgroup",
        ))
    spool_meta = _C.meta(snap, spool or "SlurmdSpoolDir")
    if spool and not spool_meta:
        findings.append(_C.finding(
            "medium", "SlurmdSpoolDir 权限未能验证",
            {"SlurmdSpoolDir": spool},
            evidence=f"SlurmdSpoolDir={spool} metadata missing",
            mapping="slurmd spool 完整性",
            fix="导出 spool 目录 mode/owner 后复测；确认为 slurm:slurm 0750",
        ))
    elif spool and _C.group_or_world_writable(spool_meta.get("mode")):
        findings.append(_C.finding(
            "high", "SlurmdSpoolDir 可被非 Slurm 用户写入",
            {"SlurmdSpoolDir": spool, "meta": spool_meta},
            evidence=f"SlurmdSpoolDir={spool} mode={spool_meta.get('mode')}",
            mapping="slurmd spool 完整性",
            fix="spool 目录归 slurm:slurm，权限 0750；禁止共享存储挂载",
        ))
    if "config_overrides" in slurmd_params:
        findings.append(_C.finding(
            "high", "SlurmdParameters 允许 config_overrides",
            {"SlurmdParameters": _C.get(conf, "SlurmdParameters")},
            evidence="SlurmdParameters contains config_overrides",
            mapping="Slurm 节点配置覆盖 / 绕过 slurmctld",
            fix="移除 config_overrides；节点配置由 slurmctld 统一下发",
        ))
    if health:
        meta = _C.meta(snap, health)
        if not meta or _C.world_writable(meta.get("mode")) or str(meta.get("owner")) not in ("root", "slurm"):
            findings.append(_C.finding(
                "high", "HealthCheckProgram 可写或非 root 属主",
                {"program": health, "meta": meta},
                evidence=f"HealthCheckProgram={health} meta={meta or '<missing>'}",
                mapping="节点健康检查执行面",
                fix="健康检查脚本 root:root 0755，纳入签名/完整性校验",
            ))
    for label, script in (("Prolog", prolog), ("Epilog", epilog)):
        if not script:
            continue
        meta = _C.meta(snap, script) or script_meta.get(script) or {}
        if not meta:
            findings.append(_C.finding(
                "medium", f"{label} 脚本权限未能验证",
                {"path": script},
                evidence=f"{label}={script} metadata missing",
                mapping="Slurm 作业生命周期 root 执行",
                fix=f"导出 {label} mode/owner/签名后复测；要求 root:root 0755 且签名",
            ))
        elif _C.world_writable(meta.get("mode")) or str(meta.get("owner")) not in ("root", "slurm") \
                or meta.get("signed") is False:
            findings.append(_C.finding(
                "high", f"{label} 脚本可写或非特权属主",
                {"path": script, "meta": meta},
                evidence=f"{label}={script} meta={meta}",
                mapping="Slurm 作业生命周期 root 执行",
                fix=f"{label} root:root 0755 且签名；禁止用户目录/共享存储路径",
            ))
    if "cgroup" not in acct_gather or "none" in acct_gather:
        findings.append(_C.finding(
            "medium", "JobAcctGatherType 未使用 cgroup",
            {"JobAcctGatherType": acct_gather or "<missing>"},
            evidence=f"JobAcctGatherType={acct_gather or '<missing>'}",
            mapping="作业资源记账",
            fix="JobAcctGatherType=jobacct_gather/cgroup",
        ))
    if mpi in ("", "none"):
        findings.append(_C.finding(
            "medium", "MpiDefault=none（PMIx 认证/拓扑信息缺失）",
            {"MpiDefault": mpi or "<missing>"},
            evidence=f"MpiDefault={mpi or '<missing>'}",
            mapping="Slurm PMIx / 作业步骤认证",
            fix="设置 MpiDefault=pmix，并保持 PMIx 与 Slurm 版本匹配",
        ))
    if return_to_service > 1:
        findings.append(_C.finding(
            "low", "ReturnToService 允许节点在健康检查失败后多次自动返池",
            {"ReturnToService": return_to_service},
            evidence=f"ReturnToService={return_to_service}",
            mapping="Slurm 节点健康状态机",
            fix="设置 ReturnToService=0 或 1；带病节点需人工确认后恢复",
        ))

    extra = {
        "slurmd_user": slurmd_user or "missing",
        "task_plugin": task_plugin or "missing",
        "proctrack": proctrack or "missing",
        "spool_dir": spool or "missing",
        "health_check": health or "",
        "mpi_default": mpi or "missing",
        "return_to_service": return_to_service,
        "finding_count": len(findings),
    }
    return _C.result(ctx, KEY, "slurmd 节点守护进程配置审计", findings, extra=extra,
                     source=str(params.get("snapshot") or "<inline snapshot>"))
