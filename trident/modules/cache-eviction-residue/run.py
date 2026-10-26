# -*- coding: utf-8 -*-
"""cache-eviction-residue — LRU 逐出后跨租户残留读。

检测口径：
1) GET /router/metrics 记录逐出计数基线；
2) 以唯一前缀洪泛（cache priming，无写面）越过池容量 → 逐出计数增长；
3) GET /cache/residue?prefix=<受害前缀>：
   vulnerable：残留层保留且跨租户可读（tenant=受害租户、preview 含 benign 标记）→ high；
   fixed：逐出即 zeroize → 404 → info。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
from urllib.parse import quote

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_cache_common", _PARENT / "_cache-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

KEY = "cache-eviction-residue"
WRITES = False
DEFAULT_FLOOD = 160
DEFAULT_VICTIM_PREFIX = (
    "tenant-b residue corpus marker TRIDENT-BENIGN-RESIDUE-VICTIM "
    "quarterly close data pack appendix"
)


def run(ctx: dict, params: dict) -> dict:
    target = _COMMON.target_of(params)
    if not target:
        return _COMMON.no_target()
    marker = _COMMON.marker_of(ctx, params)
    tenant = _COMMON.tenant_of(params)
    flood = max(1, _COMMON.int_of(params.get("flood_count"), DEFAULT_FLOOD))
    victim_prefix = str(params.get("victim_prefix") or DEFAULT_VICTIM_PREFIX)
    marker_needle = str(params.get("marker_needle") or "TRIDENT-BENIGN-RESIDUE-VICTIM")

    t = _COMMON.Trace(ctx, KEY)
    headers = _COMMON.headers_for(params)
    before = t.call("GET", f"{target}/router/metrics", headers=headers)
    evictions_before = _COMMON.int_of(
        ((_COMMON.resp(before).get("pool") or {}).get("evictions_total")))
    for i in range(flood):
        t.call("POST", f"{target}/v1/chat/completions", {
            "prompt_prefix": f"evict-flood-{marker}-{i:04d} unique corpus pressure",
            "prefix_tokens": 2048, "max_tokens": 1,
        }, headers)
    after = t.call("GET", f"{target}/router/metrics", headers=headers)
    evictions_after = _COMMON.int_of(
        ((_COMMON.resp(after).get("pool") or {}).get("evictions_total")))
    evictions_delta = max(0, evictions_after - evictions_before)

    residue = t.call(
        "GET", f"{target}/cache/residue?prefix={quote(victim_prefix, safe='')}",
        headers=headers)
    residue_payload = _COMMON.resp(residue)
    residue_tenant = str(residue_payload.get("tenant") or "")
    preview = str(residue_payload.get("prefix_preview") or "")
    cross_tenant_residue = bool(
        _COMMON.is_ok(residue) and residue_payload.get("found")
        and residue_tenant and residue_tenant != tenant)

    detail = {
        "route_residue": "/cache/residue",
        "route_metrics": "/router/metrics",
        "flood_count": flood,
        "evictions_before": evictions_before,
        "evictions_after": evictions_after,
        "evictions_delta": evictions_delta,
        "residue_status": residue.get("status"),
        "residue_found": bool(residue_payload.get("found")),
        "residue_tenant": residue_tenant,
        "requester_tenant": tenant,
        "marker_present": marker_needle in preview,
        "prefix_preview": preview,
        "cross_tenant_residue": cross_tenant_residue,
    }
    findings: list[dict] = []
    if evictions_delta >= 1 and cross_tenant_residue and detail["marker_present"]:
        detail["http_status"] = residue.get("status")
        findings.append(_COMMON.finding(
            "high",
            f"LRU 逐出后残留跨租户可读：{tenant} 读到 {residue_tenant} 被逐出前缀"
            "（逐出未 zeroize，KV 残留层泄露）",
            detail))
    elif evictions_delta >= 1:
        detail["http_status"] = residue.get("status")
        findings.append(_COMMON.finding(
            "info", "逐出已发生但残留层已 zeroize/不可读（跨租户残留未成立）", detail))
    else:
        detail["http_status"] = residue.get("status")
        findings.append(_COMMON.finding(
            "info", "洪泛未触发逐出（容量过大或计数不可读），残留面未验证", detail))

    artifact = t.dump()
    _COMMON.write_artifact(ctx, "cache-eviction-residue.json", detail)
    summary = (f"evictions={evictions_before}->{evictions_after} "
               f"residue={residue.get('status')} tenant={residue_tenant or '-'}")
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
