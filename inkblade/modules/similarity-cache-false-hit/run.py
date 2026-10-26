# -*- coding: utf-8 -*-
"""similarity-cache-false-hit — 近似/语义缓存误命中（相似度阈值内读回他租户内容）。

检测口径：
1) GET /config 读近似缓存相似度阈值（不可读时按 0.85）；
2) 正对照：本租户条目文本 lookup → 命中（检索链路健康）；
3) 攻击：注入与受害租户缓存文本高相似的良性前缀（单 token 变异）→ lookup；
4) vulnerable：命中且 matched.tenant 为他租户、响应含其 benign 标记 → high
   （近似缓存跨租户误命中 → 数据泄露）；fixed：仅本租户检索，miss → info。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_cache_common", _PARENT / "_cache-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

KEY = "similarity-cache-false-hit"
WRITES = False

# 靶场预置受害条目的先验（攻击者对受害语料风格的已知部分）；单 token 变体保持高相似
DEFAULT_VICTIM_PROBE = (
    "tenant-b quarterly revenue guidance for fiscal 2026 total pipeline "
    "equals 42.8M USD with eighteen percent growth"
)
DEFAULT_CONTROL_PROBE = (
    "tenant-a infrastructure capacity plan for fiscal 2026 total gpu "
    "nodes equals 512 units"
)


def run(ctx: dict, params: dict) -> dict:
    target = _COMMON.target_of(params)
    if not target:
        return _COMMON.no_target()
    tenant = _COMMON.tenant_of(params)
    victim_tenant = _COMMON.victim_tenant_of(params)
    probe_text = str(params.get("victim_probe_text") or DEFAULT_VICTIM_PROBE)
    control_text = str(params.get("control_probe_text") or DEFAULT_CONTROL_PROBE)
    marker_needle = str(params.get("marker_needle") or "INKBLADE-BENIGN-APPROX-VICTIM")

    t = _COMMON.Trace(ctx, KEY)
    config = t.call("GET", f"{target}/config", headers=_COMMON.headers_for(params))
    threshold = _COMMON.float_of(
        (_COMMON.resp(config).get("approx_cache") or {}).get("similarity_threshold"), 0.85)

    control = t.call("POST", f"{target}/approx/lookup", {"text": control_text},
                     _COMMON.headers_for(params))
    attack = t.call("POST", f"{target}/approx/lookup", {"text": probe_text},
                    _COMMON.headers_for(params))
    control_payload = _COMMON.resp(control)
    attack_payload = _COMMON.resp(attack)
    matched = attack_payload.get("matched") or {}
    matched_tenant = str(matched.get("tenant") or "")
    response_text = str(matched.get("response") or "")
    cross_tenant_hit = bool(
        _COMMON.is_ok(attack) and attack_payload.get("hit")
        and matched_tenant and matched_tenant not in (tenant, ""))

    detail = {
        "route": "/approx/lookup",
        "http_status": attack.get("status"),
        "threshold": threshold,
        "best_similarity": attack_payload.get("best_similarity"),
        "requester_tenant": tenant,
        "entry_tenant": matched_tenant,
        "cross_tenant_hit": cross_tenant_hit,
        "victim_marker_present": marker_needle in response_text,
        "response_excerpt": response_text[:96],
        "control_hit": bool(control_payload.get("hit")),
        "control_status": control.get("status"),
        "scope": attack_payload.get("scope"),
        "probe_technique": "注入高相似良性前缀（单 token 数值变异）触发阈值内检索",
    }
    findings: list[dict] = []
    if cross_tenant_hit:
        findings.append(_COMMON.finding(
            "high",
            f"近似缓存误命中：{tenant} 以相似度 {attack_payload.get('best_similarity')} "
            f"读回 {matched_tenant} 缓存响应（跨租户数据泄露）",
            detail))
    else:
        findings.append(_COMMON.finding(
            "info", "近似缓存检索按租户隔离（他租户条目 miss 或正对照失败）", detail))

    artifact = t.dump()
    _COMMON.write_artifact(ctx, "similarity-cache-false-hit.json", detail)
    summary = (f"attack={attack.get('status')} hit={attack_payload.get('hit')} "
               f"entry_tenant={matched_tenant or '-'} "
               f"sim={attack_payload.get('best_similarity')}")
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
