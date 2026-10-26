# -*- coding: utf-8 -*-
"""Federated-learning control-plane audit (read-only; quarantined by default)."""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_emerging_common", _PARENT / "_emerging-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "federated-learning-audit"


def run(ctx: dict, params: dict) -> dict:
    doc = _C.collection(params)
    state = _C.surface_state(ctx.get("meta") or {}, params, doc)
    if state.get("status") != "deployed":
        return _C.not_deployed(ctx, KEY, state)

    findings: list[dict] = []
    controllers = [o for o in _C.objects(doc)
                   if any(x in str(o.get("name", "")).lower() for x in ("nvflare", "flower", "fate"))]
    round_api = _C.endpoint_hit(doc, "/fl") or _C.endpoint_hit(doc, "round")
    if round_api:
        findings.append(_C.finding(
            "high", "联邦学习轮次 API 未授权可达，可提交恶意更新",
            {"endpoint": round_api.get("url"), "status": round_api.get("status")},
            evidence="FL round endpoint returned 2xx"))
    unauth_join = params.get("participant_registration") == "open"
    if unauth_join:
        findings.append(_C.finding(
            "high", "联邦学习参与方注册开放，攻击者可加入训练轮次",
            {"controllers": [o.get("name") for o in controllers]},
            evidence="params participant_registration=open"))

    return _C.result(ctx, KEY, state, findings,
                     f"controllers={len(controllers)} round_api={'open' if round_api else 'absent'} "
                     f"findings={len(findings)}",
                     {"controllers": [o.get("name") for o in controllers]})
