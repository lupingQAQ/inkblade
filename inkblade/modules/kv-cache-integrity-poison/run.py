# -*- coding: utf-8 -*-
"""KV cache 完整性污染 — PD KV 通道未鉴权写入并读回（benign marker）。

probe-only：POST /kv/transfer op=read 判定通道可未鉴权读（只读，无副作用）。
backup-write：写入带 run marker 的良性 KV 块，再独立 GET 读回，
value/sha256 一致才判定 high；写面走 runner backup_targets 闸门。
fixed 姿态：401（缺管理密钥），跨租户写 403。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
from urllib.parse import quote

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_longctx_common", _PARENT / "_longctx-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

KEY = "kv-cache-integrity-poison"
WRITES = True


def run(ctx: dict, params: dict) -> dict:
    target = _COMMON.target_of(params)
    if not target:
        return _COMMON.no_target()
    marker = _COMMON.marker_of(ctx, params)
    mode, note = _COMMON.resolve_mode(params, WRITES)
    block_id = str(params.get("block_id") or f"kv-block-{marker}")
    tenant = _COMMON.tenant_of(params)
    t = _COMMON.Trace(ctx, KEY)
    metrics = t.call("GET", f"{target}/metrics", headers=_COMMON.headers_for(params))
    findings: list[dict] = []
    detail = {
        "route": "/kv/transfer",
        "mode": mode,
        "block_id": block_id,
        "metrics_status": metrics.get("status"),
        "kv_cache_usage": _COMMON.resp(metrics).get("kv_cache_usage"),
        "source_tenant": tenant,
        "dest_tenant": "tenant-b",
    }

    if mode == "backup-write":
        payload = str(params.get("payload") or (
            '{"marker": "' + marker + '", "benign": true, "integrity": "inkblade-lab-poison", '
            '"layer": 3, "service": "pd-kv-channel"}'
        ))
        write = t.call("POST", f"{target}/kv/transfer", {
            "op": "write",
            "block_id": block_id,
            "value": payload,
            "source_tenant": tenant,
            "dest_tenant": "tenant-b",
            "layer": _COMMON.int_of(params.get("layer"), 3),
        }, _COMMON.headers_for(params))
        read = t.call("GET", f"{target}/kv/transfer?block_id={quote(block_id, safe='')}",
                      headers=_COMMON.headers_for(params))
        readback = _COMMON.resp(read)
        readback_value = readback.get("value")
        expected_sha = _COMMON.sha256_text(payload)
        matches = bool(_COMMON.is_ok(read) and readback.get("found")
                       and readback_value == payload
                       and readback.get("sha256") == expected_sha)
        detail.update({
            "write_status": write.get("status"),
            "readback_status": read.get("status"),
            "readback_found": bool(readback.get("found")),
            "readback_sha256": readback.get("sha256", ""),
            "expected_sha256": expected_sha,
            "readback_matches": matches,
            "bytes": len(payload.encode("utf-8")),
            "marker": marker,
        })
        if _COMMON.is_ok(write) and matches:
            findings.append(_COMMON.finding(
                "high", "KV cache 未鉴权写入并读回（跨租户完整性污染）", detail))
        else:
            findings.append(_COMMON.finding(
                "info", "KV 通道写面被拒绝或读回不一致（完整性污染未成立）", detail))
    else:
        read = t.call("POST", f"{target}/kv/transfer", {
            "op": "read",
            "block_id": block_id,
            "source_tenant": tenant,
        }, _COMMON.headers_for(params))
        detail.update({
            "read_status": read.get("status"),
            "found": bool(_COMMON.resp(read).get("found")),
        })
        if _COMMON.is_ok(read):
            findings.append(_COMMON.finding(
                "high", "PD KV 通道未鉴权可读（KV cache 完整性面暴露）", detail))
        else:
            findings.append(_COMMON.finding(
                "info", "KV 通道读面被拒绝（需管理密钥）", detail))

    artifact = t.dump()
    _COMMON.write_artifact(ctx, "kv-cache-integrity-poison.json", detail)
    summary = f"mode={mode} read={detail.get('read_status', detail.get('readback_status'))}"
    if note:
        summary += f"；{note}"
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
