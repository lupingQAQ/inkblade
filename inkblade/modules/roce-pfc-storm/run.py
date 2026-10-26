# -*- coding: utf-8 -*-
"""RoCE PFC 暂停风暴 — PFC 配置面可写即暂停风暴（计数器度量）。

probe-only：GET /roce/pfc 读配置与暂停帧计数。
backup-write：POST storm 档 × rounds → pfc_pause_frames 计数暴增（≥ 50000）→ high。
fixed 姿态：写面 401；storm 档被拒。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_fabric_common", _PARENT / "_fabric-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

KEY = "roce-pfc-storm"
WRITES = True
STORM_THRESHOLD = 50000


def run(ctx: dict, params: dict) -> dict:
    target = _COMMON.target_of(params)
    if not target:
        return _COMMON.no_target()
    marker = _COMMON.marker_of(ctx, params)
    mode, note = _COMMON.resolve_mode(params, WRITES)
    rounds = max(1, min(10, _COMMON.int_of(params.get("rounds"), 3)))
    t = _COMMON.Trace(ctx, KEY)
    findings: list[dict] = []
    detail: dict = {"route": "/roce/pfc", "mode": mode, "rounds": rounds,
                    "marker": marker}

    before = t.call("GET", f"{target}/roce/pfc")
    before_pause = _COMMON.int_of(_COMMON.resp(before).get("pfc_pause_frames"))
    detail.update({"read_status": before.get("status"),
                   "pfc_pause_frames_before": before_pause,
                   "storm_active_before": bool(_COMMON.resp(before).get("pfc", {}).get("storm"))})

    if mode == "backup-write":
        statuses: list[int] = []
        for _ in range(rounds):
            call = t.call("POST", f"{target}/roce/pfc", {
                "mode": "storm", "interfaces": ["all"],
            })
            statuses.append(_COMMON.int_of(call.get("status")))
        after = t.call("GET", f"{target}/roce/pfc")
        after_resp = _COMMON.resp(after)
        after_pause = _COMMON.int_of(after_resp.get("pfc_pause_frames"))
        ecn_marks = _COMMON.int_of(after_resp.get("ecn_marks"))
        detail.update({
            "storm_statuses": statuses,
            "pfc_pause_frames_after": after_pause,
            "pfc_pause_frames_delta": after_pause - before_pause,
            "ecn_marks": ecn_marks,
            "storm_active": bool(after_resp.get("pfc", {}).get("storm")),
            "interfaces": after_resp.get("pfc", {}).get("interfaces") or [],
        })
        if any(s == 200 for s in statuses) and after_pause - before_pause >= STORM_THRESHOLD:
            findings.append(_COMMON.finding(
                "high", f"PFC 配置面可写引发暂停风暴（Δ暂停帧 ≥ {STORM_THRESHOLD}）", detail))
        else:
            findings.append(_COMMON.finding(
                "info", "PFC 风暴档被拒绝或计数未达阈值（风暴未成立）", detail))
    else:
        if _COMMON.is_ok(before):
            findings.append(_COMMON.finding(
                "info", "PFC/ECN 配置与计数读回（probe-only，不触碰写面）", detail))
        else:
            findings.append(_COMMON.finding(
                "info", "PFC 配置面不可读（探测不成立）", detail))

    artifact = t.dump()
    _COMMON.write_artifact(ctx, f"{KEY}.json", detail)
    summary = (f"mode={mode} pause_delta={detail.get('pfc_pause_frames_delta', 0)}"
               f" read={detail.get('read_status')}")
    if note:
        summary += f"；{note}"
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
