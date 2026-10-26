# -*- coding: utf-8 -*-
"""router-cache-metrics-leak — EPP 路由器缓存指标按租户泄露（缓存状态侧信道）。

检测口径：
GET /router/metrics（仅携带本租户头，无管理凭据）：
- vulnerable：200 且 per_tenant 含他租户（KV 利用率/命中率/独立前缀数/前缀样本）
  → 他租户缓存状态可观测（缓存行为侧信道，辅助前缀字典提取）→ high；
- fixed：无身份 401 或租户头仅本租户视图（无他租户键）→ info。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_cache_common", _PARENT / "_cache-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

KEY = "router-cache-metrics-leak"
WRITES = False


def run(ctx: dict, params: dict) -> dict:
    target = _COMMON.target_of(params)
    if not target:
        return _COMMON.no_target()
    tenant = _COMMON.tenant_of(params)
    victim_tenant = _COMMON.victim_tenant_of(params)

    t = _COMMON.Trace(ctx, KEY)
    metrics = t.call("GET", f"{target}/router/metrics",
                     headers=_COMMON.headers_for(params))
    payload = _COMMON.resp(metrics)
    per_tenant = payload.get("per_tenant") or {}
    victim_view = per_tenant.get(victim_tenant) if isinstance(per_tenant, dict) else None
    visible_tenants = sorted(per_tenant) if isinstance(per_tenant, dict) else []
    cross_tenant_visible = bool(
        _COMMON.is_ok(metrics) and victim_view is not None)

    detail = {
        "route": "/router/metrics",
        "http_status": metrics.get("status"),
        "requester_tenant": tenant,
        "aggregated_scope": payload.get("aggregated", {}).get("scope"),
        "visible_tenants": visible_tenants,
        "victim_tenant": victim_tenant,
        "cross_tenant_visible": cross_tenant_visible,
        "victim_metrics": victim_view,
        "pool": payload.get("pool"),
        "note": "按租户命中率/独立前缀数/前缀样本直接泄露他租户缓存行为（成员推断辅助通道）",
    }
    findings: list[dict] = []
    if cross_tenant_visible:
        findings.append(_COMMON.finding(
            "high",
            f"路由器缓存指标按租户泄露：{tenant} 无管理凭据可读 {victim_tenant} 的"
            " KV 利用率/命中率/前缀样本（缓存状态侧信道）",
            detail))
    else:
        findings.append(_COMMON.finding(
            "info",
            "路由器缓存指标已收敛（无身份 401 或仅本租户聚合视图）", detail))

    artifact = t.dump()
    _COMMON.write_artifact(ctx, "router-cache-metrics-leak.json", detail)
    summary = (f"status={metrics.get('status')} scope={detail['aggregated_scope']} "
               f"visible={','.join(visible_tenants) or '-'}")
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
