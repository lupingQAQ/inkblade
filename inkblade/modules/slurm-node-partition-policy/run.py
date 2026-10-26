# -*- coding: utf-8 -*-
"""Slurm 节点 drain/分区/QOS 配额审计（只读 sinfo/scontrol 导出）。"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_slurm_common", _PARENT / "_slurm-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "slurm-node-partition-policy"
_WILDCARD = ("", "ALL", "*", "ALLOWALL")


def run(ctx: dict, params: dict) -> dict:
    snap = _C.load_snapshot(params)
    nodes = _C.node_list(snap)
    partitions = _C.partition_list(snap)
    qos_doc = _C.json_file(snap, "qos.json", default={"qos": []})
    qoses = qos_doc.get("qos") if isinstance(qos_doc, dict) else qos_doc
    qoses = [q for q in (qoses or []) if isinstance(q, dict)]
    findings: list[dict] = []
    now = params.get("now")

    sick = [n for n in nodes if str(n.get("state") or "").upper() in ("DRAIN", "DOWN", "DRAINED", "FAIL")]
    stale = []
    for node in sick:
        resume = node.get("resume_after")
        age = _C.age_days(node.get("drain_since") or node.get("mtime"), now=now)
        if not resume:
            stale.append(node)
        elif age is not None and age > 30:
            stale.append(node)
    if sick:
        findings.append(_C.finding(
            "high" if any(not n.get("resume_after") for n in sick) else "medium",
            "存在 DRAIN/DOWN 节点仍留在可调度分区",
            {"nodes": [{"name": n.get("name"), "state": n.get("state"),
                        "reason": n.get("reason"), "resume_after": n.get("resume_after"),
                        "partition": n.get("partition")} for n in sick[:20]],
             "stale": len(stale)},
            evidence=f"drain_nodes={[n.get('name') for n in sick]} stale={[n.get('name') for n in stale]}",
            mapping="Slurm 节点健康状态 / 带病返池",
            fix="核验 drain 原因；修复后 scontrol update NodeName=... State=RESUME；长期故障节点移出分区",
        ))

    open_parts = []
    for part in partitions:
        groups = str(part.get("allow_groups") or part.get("AllowGroups") or "").upper()
        accounts = str(part.get("allow_accounts") or part.get("AllowAccounts") or "").upper()
        if groups in _WILDCARD or accounts in _WILDCARD:
            open_parts.append({"name": part.get("name"), "allow_groups": groups,
                               "allow_accounts": accounts})
    if open_parts:
        findings.append(_C.finding(
            "high", "分区允许全用户/全账户访问",
            {"partitions": open_parts[:20]},
            evidence=f"open_partitions={[p['name'] for p in open_parts]}",
            mapping="Slurm 分区准入 / 租户隔离",
            fix="AllowGroups/AllowAccounts 指向业务组；默认分区最小化",
        ))
    unlimited_parts = []
    for part in partitions:
        max_nodes = str(part.get("max_nodes") or part.get("MaxNodes") or "").upper()
        max_time = str(part.get("max_time") or part.get("MaxTime") or "").upper()
        over = str(part.get("over_subscribe") or part.get("OverSubscribe") or "").upper()
        if _C.is_unlimited(max_nodes) or _C.is_unlimited(max_time) or over in ("FORCE", "YES"):
            unlimited_parts.append({"name": part.get("name"), "max_nodes": max_nodes,
                                    "max_time": max_time, "over_subscribe": over})
    if unlimited_parts:
        findings.append(_C.finding(
            "medium", "分区存在无限节点/无限时长或强制超分",
            {"partitions": unlimited_parts[:20]},
            evidence=f"unlimited_partitions={[p['name'] for p in unlimited_parts]}",
            mapping="Slurm 配额与公平性",
            fix="设置 MaxNodes/MaxTime；OverSubscribe=NO（除显式测试分区）",
        ))
    default_open = [p for p in partitions
                    if str(p.get("default") or p.get("Default") or "").upper() == "YES"
                    and str(p.get("allow_groups") or p.get("AllowGroups") or "").upper() in _WILDCARD]
    if default_open:
        findings.append(_C.finding(
            "high", "默认分区对所有用户开放",
            {"partitions": [p.get("name") for p in default_open]},
            evidence=f"default_open={[p.get('name') for p in default_open]}",
            mapping="默认配额边界",
            fix="默认分区指向受限 CPU 分区；GPU 分区需显式申请",
        ))
    unlimited_qos = []
    for qos in qoses:
        grp = str(qos.get("grp_tres") or qos.get("GrpTRES") or "").upper()
        per_user = str(qos.get("max_tres_per_user") or qos.get("MaxTRESPerUser") or "").upper()
        max_jobs = str(qos.get("max_jobs_per_user") or qos.get("MaxJobsPerUser") or "").upper()
        flags = [str(f) for f in (qos.get("flags") or qos.get("Flags") or [])]
        if _C.is_unlimited(grp) and _C.is_unlimited(per_user) and _C.is_unlimited(max_jobs):
            unlimited_qos.append({"name": qos.get("name"), "grp_tres": grp,
                                  "max_tres_per_user": per_user, "max_jobs_per_user": max_jobs,
                                  "deny_on_limit": any("denyonlimit" in f.lower() for f in flags)})
    if unlimited_qos:
        findings.append(_C.finding(
            "high", "QOS 未设置任何 TRES/作业上限",
            {"qos": unlimited_qos[:20]},
            evidence=f"unlimited_qos={[q.get('name') for q in unlimited_qos]}",
            mapping="QOS 配额 / 资源耗尽",
            fix="为每个 QOS 设置 GrpTRES/MaxTRESPerUser/MaxJobsPerUser；启用 DenyOnLimit",
        ))
    no_deny = [q for q in qoses
               if not any("denyonlimit" in str(f).lower()
                          for f in (q.get("flags") or q.get("Flags") or []))]
    if qoses and no_deny:
        findings.append(_C.finding(
            "medium", "QOS 未启用 DenyOnLimit（超限行为不确定）",
            {"qos": [q.get("name") for q in no_deny][:20]},
            evidence=f"qos_without_deny={[q.get('name') for q in no_deny]}",
            mapping="QOS 超限执行",
            fix="QOS Flags=DenyOnLimit",
        ))
    idle_with_alloc = [n for n in nodes
                       if str(n.get("state") or "").upper() == "IDLE" and n.get("alloc_tres")]
    if idle_with_alloc:
        findings.append(_C.finding(
            "low", "IDLE 节点仍带 alloc_tres（状态导出可能过期）",
            {"nodes": [n.get("name") for n in idle_with_alloc][:20]},
            evidence=f"idle_with_alloc={[n.get('name') for n in idle_with_alloc]}",
            mapping="调度状态一致性",
            fix="重新导出 scontrol show node -j；核对 slurmctld 与 sinfo 缓存",
        ))

    extra = {
        "nodes": len(nodes),
        "drain_nodes": len(sick),
        "partitions": len(partitions),
        "open_partitions": len(open_parts),
        "qos": len(qoses),
        "unlimited_qos": len(unlimited_qos),
        "finding_count": len(findings),
    }
    return _C.result(ctx, KEY, "Slurm 节点/分区/QOS 配额审计", findings, extra=extra,
                     source=str(params.get("snapshot") or "<inline snapshot>"))
