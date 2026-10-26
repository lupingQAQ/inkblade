# -*- coding: utf-8 -*-
"""PD 分离 KV 通道未鉴权 — prefill/decode 之间的 KV 传输通道无身份校验。

检测口径（真实 HTTP 差分）：
- GET /metrics：读取 kv_cache_usage / queue_depth / prefill_pool / decode_pool；
- POST /kv/transfer op=read（只读握手）：vulnerable 200（found 状态无关），fixed 401。
两者同时 200 → 通道对任意租户开放（high）。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_longctx_common", _PARENT / "_longctx-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

KEY = "prefill-decode-kv-channel-unauth"
WRITES = False


def run(ctx: dict, params: dict) -> dict:
    target = _COMMON.target_of(params)
    if not target:
        return _COMMON.no_target()
    block_id = str(params.get("block_id") or "pd-handshake")
    tenant = _COMMON.tenant_of(params)
    t = _COMMON.Trace(ctx, KEY)
    metrics = t.call("GET", f"{target}/metrics", headers=_COMMON.headers_for(params))
    read = t.call("POST", f"{target}/kv/transfer", {
        "op": "read",
        "block_id": block_id,
        "source_tenant": tenant,
        "dest_tenant": "tenant-b",
        "layer": 0,
    }, _COMMON.headers_for(params))

    metrics_payload = _COMMON.resp(metrics)
    detail = {
        "route": "/kv/transfer",
        "transport": "kv-transfer",
        "block_id": block_id,
        "source_tenant": tenant,
        "dest_tenant": "tenant-b",
        "metrics_status": metrics.get("status"),
        "read_status": read.get("status"),
        "read_found": bool(_COMMON.resp(read).get("found")),
        "kv_cache_usage": metrics_payload.get("kv_cache_usage"),
        "queue_depth": metrics_payload.get("queue_depth"),
        "prefill_pool": metrics_payload.get("prefill_pool"),
        "decode_pool": metrics_payload.get("decode_pool"),
    }
    findings: list[dict] = []
    if _COMMON.is_ok(read):
        findings.append(_COMMON.finding(
            "high", "PD 分离 KV 通道无鉴权：跨租户读握手放行", detail))
    else:
        findings.append(_COMMON.finding(
            "info", "PD KV 通道需要鉴权（读握手被拒绝）", detail))

    artifact = t.dump()
    _COMMON.write_artifact(ctx, "prefill-decode-kv-channel-unauth.json", detail)
    summary = f"metrics={metrics.get('status')} kv_read={read.get('status')}"
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
