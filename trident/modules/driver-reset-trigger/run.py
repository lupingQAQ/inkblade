# -*- coding: utf-8 -*-
"""Xid/驱动复位触发 — GPU 健康写面可注入 Xid（复位计数度量）。

probe-only：GET /gpu/health 设备健康读回。
backup-write：POST /gpu/health {xid_code: 79} → driver_resets ≥ 1、
healthy=false → high（NVL72 大故障域下单次复位即中断整 rack 训练）。
fixed 姿态：写面 401。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_fabric_common", _PARENT / "_fabric-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

KEY = "driver-reset-trigger"
WRITES = True


def run(ctx: dict, params: dict) -> dict:
    target = _COMMON.target_of(params)
    if not target:
        return _COMMON.no_target()
    marker = _COMMON.marker_of(ctx, params)
    mode, note = _COMMON.resolve_mode(params, WRITES)
    gpu = str(params.get("gpu") or "gpu-0")
    xid_code = _COMMON.int_of(params.get("xid_code"), 79)
    t = _COMMON.Trace(ctx, KEY)
    findings: list[dict] = []
    detail: dict = {"route": "/gpu/health", "mode": mode, "gpu": gpu,
                    "xid_code": xid_code, "marker": marker}

    health = t.call("GET", f"{target}/gpu/health")
    health_resp = _COMMON.resp(health)
    detail.update({
        "read_status": health.get("status"),
        "driver_resets_before": _COMMON.int_of(health_resp.get("driver_resets")),
        "xid_events_before": _COMMON.int_of(health_resp.get("xid_events")),
        "healthy_before": bool(((health_resp.get("devices") or {}).get(gpu) or {})
                               .get("healthy", True)),
    })

    if mode == "backup-write":
        inject = t.call("POST", f"{target}/gpu/health", {
            "gpu": gpu, "xid_code": xid_code,
        })
        after = t.call("GET", f"{target}/gpu/health")
        after_resp = _COMMON.resp(after)
        device = ((after_resp.get("devices") or {}).get(gpu) or {})
        detail.update({
            "inject_status": inject.get("status"),
            "readback_status": after.get("status"),
            "reset_triggered": bool(_COMMON.resp(inject).get("reset_triggered")),
            "driver_resets_after": _COMMON.int_of(after_resp.get("driver_resets")),
            "xid_events_after": _COMMON.int_of(after_resp.get("xid_events")),
            "healthy_after": bool(device.get("healthy", True)),
            "xid_seen": xid_code in (device.get("xid") or []),
        })
        if (_COMMON.is_ok(inject) and detail["reset_triggered"]
                and detail["driver_resets_after"] - detail["driver_resets_before"] >= 1
                and detail["healthy_after"] is False):
            findings.append(_COMMON.finding(
                "high", "GPU 健康面可写注入 Xid 触发驱动复位（rack 级训练中断原语）", detail))
        else:
            findings.append(_COMMON.finding(
                "info", "Xid 注入被拒绝或未触发复位（复位未成立）", detail))
    else:
        if _COMMON.is_ok(health):
            findings.append(_COMMON.finding(
                "info", "GPU 健康读回（probe-only，不触碰写面）", detail))
        else:
            findings.append(_COMMON.finding(
                "info", "GPU 健康端点不可达（探测不成立）", detail))

    artifact = t.dump()
    _COMMON.write_artifact(ctx, f"{KEY}.json", detail)
    summary = (f"mode={mode} resets={detail.get('driver_resets_before')}"
               f"→{detail.get('driver_resets_after')}")
    if note:
        summary += f"；{note}"
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
