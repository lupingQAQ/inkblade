# -*- coding: utf-8 -*-
"""rail 错配强制 — 破坏 rail-optimized 局部性（跨 rail 流计数度量）。

probe-only：GET /nccl/rail 读回 rail 绑定图。
backup-write：POST /nccl/rail {force_rail} → rail 图被改写、cross_rail_flows ≥ 1、
步时劣化 → high；fixed 姿态写面 401。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_fabric_common", _PARENT / "_fabric-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

KEY = "rail-mismatch-forcing"
WRITES = True


def run(ctx: dict, params: dict) -> dict:
    target = _COMMON.target_of(params)
    if not target:
        return _COMMON.no_target()
    marker = _COMMON.marker_of(ctx, params)
    mode, note = _COMMON.resolve_mode(params, WRITES)
    rank = str(params.get("rank") or "rank-7")
    force_rail = str(params.get("force_rail") or "rail-0")
    headers = _COMMON.headers_for(params)
    t = _COMMON.Trace(ctx, KEY)
    findings: list[dict] = []
    detail: dict = {"route": "/nccl/rail", "mode": mode, "rank": rank,
                    "force_rail": force_rail, "marker": marker}

    before = t.call("GET", f"{target}/nccl/rail", headers=headers)
    before_resp = _COMMON.resp(before)
    original_rail = str((before_resp.get("rail_map") or {}).get(rank) or "")
    detail.update({
        "read_status": before.get("status"),
        "original_rail": original_rail,
        "cross_rail_flows_before": _COMMON.int_of(before_resp.get("cross_rail_flows")),
    })

    if mode == "backup-write":
        force = t.call("POST", f"{target}/nccl/rail", {
            "rank": rank, "force_rail": force_rail,
        })
        after = t.call("GET", f"{target}/nccl/rail", headers=headers)
        after_resp = _COMMON.resp(after)
        step = t.call("POST", f"{target}/train/step", {"steps": 1})
        detail.update({
            "force_status": force.get("status"),
            "readback_status": after.get("status"),
            "forced_rail": str((after_resp.get("rail_map") or {}).get(rank) or ""),
            "mismatch": bool(_COMMON.resp(force).get("mismatch")),
            "cross_rail_flows": _COMMON.int_of(after_resp.get("cross_rail_flows")),
            "step_ms": _COMMON.float_of(_COMMON.resp(step).get("step_ms")),
        })
        if (_COMMON.is_ok(force) and detail["mismatch"]
                and detail["cross_rail_flows"] >= 1
                and detail["forced_rail"] == force_rail != original_rail):
            findings.append(_COMMON.finding(
                "high", "rail 绑定可被强制错配（跨 rail 流破坏局部性并劣化步时）", detail))
        else:
            findings.append(_COMMON.finding(
                "info", "rail 强制被拒绝或未产生跨 rail 流（错配未成立）", detail))
    else:
        if _COMMON.is_ok(before):
            findings.append(_COMMON.finding(
                "info", "rail 绑定图读回（probe-only，不触碰写面）", detail))
        else:
            findings.append(_COMMON.finding(
                "info", "rail 图端点不可达（探测不成立）", detail))

    artifact = t.dump()
    _COMMON.write_artifact(ctx, f"{KEY}.json", detail)
    summary = (f"mode={mode} rail={original_rail}"
               f"→{detail.get('forced_rail') or original_rail}")
    if note:
        summary += f"；{note}"
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
