# -*- coding: utf-8 -*-
"""KV/激活 OOM 炸弹 — 超长上下文无 max 生效（OOM 计数度量）。

POST /train/context {context_tokens: 巨量, declared: 小} → 200 接受 +
kv_bytes 超容量 + oom_events ≥ 1 + silent → high；
fixed 姿态超限 400（max_context_enforced）。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_fabric_common", _PARENT / "_fabric-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

KEY = "kv-oom-bomb"
WRITES = False


def run(ctx: dict, params: dict) -> dict:
    target = _COMMON.target_of(params)
    if not target:
        return _COMMON.no_target()
    marker = _COMMON.marker_of(ctx, params)
    context_tokens = max(1, _COMMON.int_of(params.get("context_tokens"), 4000000))
    declared = max(1, _COMMON.int_of(params.get("declared_context_tokens"), 8192))
    t = _COMMON.Trace(ctx, KEY)
    findings: list[dict] = []
    detail: dict = {"route": "/train/context", "context_tokens": context_tokens,
                    "declared_context_tokens": declared, "marker": marker}

    bomb = t.call("POST", f"{target}/train/context", {
        "context_tokens": context_tokens, "declared_context_tokens": declared,
    })
    body = _COMMON.resp(bomb)
    detail.update({
        "http_status": bomb.get("status"),
        "accepted": bool(body.get("accepted")),
        "oom": bool(body.get("oom")),
        "oom_events": _COMMON.int_of(body.get("oom_events")),
        "kv_bytes": _COMMON.int_of(body.get("kv_bytes")),
        "capacity_bytes": _COMMON.int_of(body.get("capacity_bytes")),
        "silent": bool(body.get("silent")),
    })
    if _COMMON.is_ok(bomb) and detail["accepted"] and detail["oom"] \
            and detail["kv_bytes"] > detail["capacity_bytes"] > 0:
        findings.append(_COMMON.finding(
            "high", "超长上下文无 max 生效（单请求 KV/激活 OOM 炸弹）", detail))
    else:
        findings.append(_COMMON.finding(
            "info", "上下文上限生效或 OOM 未触发（炸弹未成立）", detail))

    artifact = t.dump()
    _COMMON.write_artifact(ctx, f"{KEY}.json", detail)
    return {"summary": (f"status={bomb.get('status')} accepted={detail['accepted']}"
                        f" oom={detail['oom']} kv={detail['kv_bytes']}"),
            "artifacts": [str(artifact)], "findings": findings}
