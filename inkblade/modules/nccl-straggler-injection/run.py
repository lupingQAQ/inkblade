# -*- coding: utf-8 -*-
"""NCCL 慢 rank 注入 — straggler 拖垮同步 all-reduce 步时。

probe-only：POST /train/step 基线步时。
backup-write：POST /nccl/rank 注入 straggler_ms → POST /train/step →
步时较基线 ≥ 2× → high（goodput 静默劣化）。
fixed 姿态：rank 写面 401；>500ms 注入 400。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_fabric_common", _PARENT / "_fabric-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

KEY = "nccl-straggler-injection"
WRITES = True


def run(ctx: dict, params: dict) -> dict:
    target = _COMMON.target_of(params)
    if not target:
        return _COMMON.no_target()
    marker = _COMMON.marker_of(ctx, params)
    mode, note = _COMMON.resolve_mode(params, WRITES)
    rank = str(params.get("rank") or "rank-7")
    straggler_ms = max(1, _COMMON.int_of(params.get("straggler_ms"), 5000))
    t = _COMMON.Trace(ctx, KEY)
    findings: list[dict] = []
    detail: dict = {"route": "/nccl/rank,/train/step", "mode": mode, "rank": rank,
                    "straggler_ms": straggler_ms, "marker": marker}

    baseline = t.call("POST", f"{target}/train/step", {"steps": 1})
    baseline_ms = _COMMON.float_of(_COMMON.resp(baseline).get("step_ms"))
    detail.update({"baseline_status": baseline.get("status"),
                   "baseline_step_ms": baseline_ms})

    if mode == "backup-write":
        inject = t.call("POST", f"{target}/nccl/rank", {
            "rank": rank, "straggler_ms": straggler_ms,
        })
        slowed = t.call("POST", f"{target}/train/step", {"steps": 1})
        slowed_ms = _COMMON.float_of(_COMMON.resp(slowed).get("step_ms"))
        ratio = (slowed_ms / baseline_ms) if baseline_ms > 0 else 0.0
        detail.update({
            "inject_status": inject.get("status"),
            "slowdown_status": slowed.get("status"),
            "slowed_step_ms": slowed_ms,
            "step_time_ratio": round(ratio, 3),
            "worst_straggler_ms": _COMMON.int_of(_COMMON.resp(inject).get("worst_straggler_ms")),
        })
        if _COMMON.is_ok(inject) and _COMMON.is_ok(slowed) and ratio >= 2.0:
            findings.append(_COMMON.finding(
                "high", f"慢 rank 注入使训练步时劣化 {ratio:.1f}×（goodput 静默下降）", detail))
        else:
            findings.append(_COMMON.finding(
                "info", "慢 rank 注入被拒绝或步时未显著劣化", detail))
    else:
        if _COMMON.is_ok(baseline):
            findings.append(_COMMON.finding(
                "info", "训练步时基线（probe-only，不触碰 rank 写面）", detail))
        else:
            findings.append(_COMMON.finding(
                "info", "训练步计时端点不可达（探测不成立）", detail))

    artifact = t.dump()
    _COMMON.write_artifact(ctx, f"{KEY}.json", detail)
    summary = (f"mode={mode} baseline={baseline_ms}ms"
               f" slowed={detail.get('slowed_step_ms')}ms")
    if note:
        summary += f"；{note}"
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
