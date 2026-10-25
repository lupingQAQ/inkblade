# -*- coding: utf-8 -*-
"""训练静默损坏 — Byzantine 梯度/损失篡改面（loss 静默发散，无告警）。

probe-only：GET /train/loss 基线轨迹。
backup-write：GET 基线 → POST /train/gradient {mode:byzantine, scale} →
GET 轨迹 → loss 增长 ≥ 2× 且 silent=true、corruption_events ≥ 1 → high。
fixed 姿态：梯度写面 401 / peer 校验 400。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_fabric_common", _PARENT / "_fabric-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

KEY = "training-silent-corruption"
WRITES = True


def _last_loss(entry) -> float:
    history = (_COMMON.resp(entry).get("loss_history") or [])
    return _COMMON.float_of(history[-1]) if history else 0.0


def run(ctx: dict, params: dict) -> dict:
    target = _COMMON.target_of(params)
    if not target:
        return _COMMON.no_target()
    marker = _COMMON.marker_of(ctx, params)
    mode, note = _COMMON.resolve_mode(params, WRITES)
    scale = _COMMON.float_of(params.get("scale"), 3.0) or 3.0
    t = _COMMON.Trace(ctx, KEY)
    findings: list[dict] = []
    detail: dict = {"route": "/train/gradient,/train/loss", "mode": mode,
                    "scale": scale, "marker": marker}

    baseline = t.call("GET", f"{target}/train/loss")
    baseline_loss = _last_loss(baseline)
    detail.update({"baseline_status": baseline.get("status"),
                   "loss_before": baseline_loss})

    if mode == "backup-write":
        tamper = t.call("POST", f"{target}/train/gradient", {
            "mode": "byzantine", "scale": scale,
        })
        after = t.call("GET", f"{target}/train/loss")
        after_loss = _last_loss(after)
        ratio = (after_loss / baseline_loss) if baseline_loss > 0 else 0.0
        detail.update({
            "tamper_status": tamper.get("status"),
            "readback_status": after.get("status"),
            "loss_after": after_loss,
            "loss_ratio": round(ratio, 3),
            "silent": bool(_COMMON.resp(tamper).get("silent")),
            "corruption_events": _COMMON.int_of(_COMMON.resp(tamper).get("corruption_events")),
            "server_loss_after": _COMMON.float_of(_COMMON.resp(tamper).get("loss_after")),
        })
        if (_COMMON.is_ok(tamper) and baseline_loss > 0 and after_loss >= 2 * baseline_loss
                and detail["silent"] and detail["corruption_events"] >= 1):
            findings.append(_COMMON.finding(
                "high", f"Byzantine 梯度使 loss 静默发散 {ratio:.1f}×（训练无效且无告警）", detail))
        else:
            findings.append(_COMMON.finding(
                "info", "梯度篡改被拒绝或 loss 未显著发散（损坏未成立）", detail))
    else:
        if _COMMON.is_ok(baseline):
            findings.append(_COMMON.finding(
                "info", "loss 轨迹基线（probe-only，不触碰梯度写面）", detail))
        else:
            findings.append(_COMMON.finding(
                "info", "loss 轨迹端点不可达（探测不成立）", detail))

    artifact = t.dump()
    _COMMON.write_artifact(ctx, f"{KEY}.json", detail)
    summary = f"mode={mode} loss_before={baseline_loss} loss_after={detail.get('loss_after')}"
    if note:
        summary += f"；{note}"
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
