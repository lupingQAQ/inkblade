# -*- coding: utf-8 -*-
"""NCCL bootstrap 端口耗尽 — rendezvous 端口池被占满后诚实作业被拒。

有界分配循环（≤ max_allocs）：POST /nccl/bootstrap 直到 ports_remaining==0，
随后以 honest 作业重试 → 503 exhausted → high。
fixed 姿态：401/429（按作业上限），诚实拒绝证据不成立。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_fabric_common", _PARENT / "_fabric-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

KEY = "nccl-port-exhaustion"
WRITES = False


def run(ctx: dict, params: dict) -> dict:
    target = _COMMON.target_of(params)
    if not target:
        return _COMMON.no_target()
    marker = _COMMON.marker_of(ctx, params)
    job = str(params.get("job") or "inkblade-probe")
    max_allocs = max(1, min(60, _COMMON.int_of(params.get("max_allocs"), 30)))
    headers = _COMMON.headers_for(params)
    t = _COMMON.Trace(ctx, KEY)
    findings: list[dict] = []
    detail: dict = {"route": "/nccl/bootstrap", "job": job,
                    "max_allocs": max_allocs, "marker": marker}

    alloc_statuses: list[int] = []
    remaining = None
    for _ in range(max_allocs):
        call = t.call("POST", f"{target}/nccl/bootstrap",
                      {"job": job, "ranks": 2}, headers)
        alloc_statuses.append(_COMMON.int_of(call.get("status")))
        remaining = _COMMON.int_of(_COMMON.resp(call).get("ports_remaining"), remaining or 0)
        if remaining is not None and remaining <= 0 or call.get("status") != 200:
            break
    victim = t.call("POST", f"{target}/nccl/bootstrap",
                    {"job": "victim-honest-job", "ranks": 1, "honest": True}, headers)
    victim_resp = _COMMON.resp(victim)
    detail.update({
        "alloc_statuses": alloc_statuses,
        "alloc_calls": len(alloc_statuses),
        "ports_remaining": remaining,
        "victim_status": victim.get("status"),
        "victim_refused": bool(victim_resp.get("error") == "bootstrap_ports_exhausted"),
        "exhausted_refusals": _COMMON.int_of(victim_resp.get("exhausted_refusals")),
    })
    if detail["victim_refused"] and (remaining or 0) <= 0:
        findings.append(_COMMON.finding(
            "high", "bootstrap 端口池可被单作业占满（后续训练作业 rendezvous 被拒）", detail))
    else:
        findings.append(_COMMON.finding(
            "info", "端口耗尽未成立（上限/鉴权拦截）", detail))

    artifact = t.dump()
    _COMMON.write_artifact(ctx, f"{KEY}.json", detail)
    return {"summary": (f"allocs={len(alloc_statuses)} remaining={remaining}"
                        f" victim={victim.get('status')}"),
            "artifacts": [str(artifact)], "findings": findings}
