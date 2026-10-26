# -*- coding: utf-8 -*-
"""gang/EPP 调度滥用 — 占位 job 拖垮队列（pending > capacity）。

rounds × POST /sched/gang {placeholders, hold} → pending_gpus > capacity、
clogged=true → high；fixed 姿态 401/429（令牌 + 配额）。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_fabric_common", _PARENT / "_fabric-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

KEY = "gang-scheduler-abuse"
WRITES = False


def run(ctx: dict, params: dict) -> dict:
    target = _COMMON.target_of(params)
    if not target:
        return _COMMON.no_target()
    marker = _COMMON.marker_of(ctx, params)
    gang_size = max(1, _COMMON.int_of(params.get("gang_size"), 8))
    rounds = max(1, min(10, _COMMON.int_of(params.get("rounds"), 5)))
    headers = _COMMON.headers_for(params)
    t = _COMMON.Trace(ctx, KEY)
    findings: list[dict] = []
    detail: dict = {"route": "/sched/gang", "gang_size": gang_size, "rounds": rounds,
                    "marker": marker}

    statuses: list[int] = []
    pending = 0
    clogged = False
    for i in range(rounds):
        call = t.call("POST", f"{target}/sched/gang", {
            "job_id": f"placeholder-{marker[:16]}-{i}",
            "gang_size": gang_size, "placeholders": gang_size, "hold": True,
        }, headers)
        statuses.append(_COMMON.int_of(call.get("status")))
        body = _COMMON.resp(call)
        pending = _COMMON.int_of(body.get("pending_gpus"), pending)
        clogged = bool(body.get("clogged")) or clogged
    after = _COMMON.metrics(t, target)
    gang_after = (after.get("gang") or {})
    detail.update({
        "gang_statuses": statuses,
        "pending_gpus": _COMMON.int_of(gang_after.get("pending_gpus"), pending),
        "capacity": _COMMON.int_of(gang_after.get("capacity")),
        "queue_length": _COMMON.int_of(gang_after.get("queue_length")),
        "placeholder_jobs": _COMMON.int_of(gang_after.get("placeholder_jobs")),
        "clogged": bool(gang_after.get("clogged")) or clogged,
    })
    if any(s == 200 for s in statuses) and detail["clogged"] \
            and detail["pending_gpus"] > detail["capacity"] > 0:
        findings.append(_COMMON.finding(
            "high", "占位 gang 作业拖垮调度队列（后续训练作业全部阻塞）", detail))
    else:
        findings.append(_COMMON.finding(
            "info", "gang 配额/鉴权生效或队列未阻塞（滥用未成立）", detail))

    artifact = t.dump()
    _COMMON.write_artifact(ctx, f"{KEY}.json", detail)
    return {"summary": (f"rounds={rounds} pending={detail['pending_gpus']}"
                        f" capacity={detail['capacity']} clogged={detail['clogged']}"),
            "artifacts": [str(artifact)], "findings": findings}
