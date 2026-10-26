# -*- coding: utf-8 -*-
"""Model watermark / backdoor service audit (read-only; quarantined)."""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_emerging_common", _PARENT / "_emerging-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "model-watermark-backdoor-audit"


def run(ctx: dict, params: dict) -> dict:
    doc = _C.collection(params)
    state = _C.surface_state(ctx.get("meta") or {}, params, doc)
    if state.get("status") != "deployed":
        return _C.not_deployed(ctx, KEY, state)

    findings: list[dict] = []
    service = _C.endpoint_hit(doc, "watermark")
    if service:
        findings.append(_C.finding(
            "medium", "模型水印/验收服务未授权可达",
            {"endpoint": service.get("url"), "status": service.get("status")},
            evidence="watermark endpoint returned 2xx"))
    meta = params.get("model_metadata") or {}
    trigger = meta.get("trigger") or meta.get("backdoor") or meta.get("watermark_trigger")
    if trigger:
        findings.append(_C.finding(
            "high", "模型元数据包含触发器/后门标记",
            {"model": meta.get("model") or meta.get("name"), "trigger": trigger,
             "target_label": meta.get("target_label")},
            evidence="model_metadata.trigger present"))

    return _C.result(ctx, KEY, state, findings,
                     f"watermark_service={'open' if service else 'absent'} "
                     f"trigger={bool(trigger)} findings={len(findings)}",
                     {"model_metadata": meta})
