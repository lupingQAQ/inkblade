# -*- coding: utf-8 -*-
"""checkpoint 分片投毒 — 训练检查点分片写面无鉴权，可改写分片并读回。

probe-only：GET /checkpoint/shards/<id> 仅读回指纹（不写）。
backup-write：POST 分片（benign marker payload）→ GET 读回 → 内容/sha256 一致 → high。
写面走 runner backup_targets 闸门（file 快照可精确回滚）。
fixed 姿态：写面 401；读回仍允许。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
from urllib.parse import quote

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_longctx_common", _PARENT / "_longctx-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

KEY = "checkpoint-shard-poison"
WRITES = True


def run(ctx: dict, params: dict) -> dict:
    target = _COMMON.target_of(params)
    if not target:
        return _COMMON.no_target()
    marker = _COMMON.marker_of(ctx, params)
    mode, note = _COMMON.resolve_mode(params, WRITES)
    shard_id = str(params.get("shard_id") or f"shard-{marker}")
    t = _COMMON.Trace(ctx, KEY)
    findings: list[dict] = []
    detail = {
        "route": "/checkpoint/shards",
        "mode": mode,
        "shard_id": shard_id,
        "marker": marker,
    }

    if mode == "backup-write":
        payload = str(params.get("payload") or (
            '{"marker": "' + marker + '", "poisoned": true, "benign": true, '
            '"source": "trident-lab", "shard": "' + shard_id + '"}'
        ) + "\n")
        write = t.call("POST", f"{target}/checkpoint/shards", {
            "shard_id": shard_id,
            "payload": payload,
        }, _COMMON.headers_for(params))
        read = t.call("GET", f"{target}/checkpoint/shards/{quote(shard_id, safe='')}",
                      headers=_COMMON.headers_for(params))
        readback = read.get("response")
        readback_text = read.get("response_text")
        if not isinstance(readback_text, str):
            readback_text = readback if isinstance(readback, str) else ""
        expected_sha = _COMMON.sha256_text(payload)
        readback_sha = _COMMON.sha256_text(readback_text) if readback_text else ""
        matches = bool(_COMMON.is_ok(read) and readback_text == payload
                       and readback_sha == expected_sha)
        detail.update({
            "write_status": write.get("status"),
            "readback_status": read.get("status"),
            "expected_sha256": expected_sha,
            "readback_sha256": readback_sha,
            "server_sha256": _COMMON.resp(write).get("sha256", ""),
            "readback_matches": matches,
            "bytes": len(payload.encode("utf-8")),
        })
        if _COMMON.is_ok(write) and matches:
            findings.append(_COMMON.finding(
                "high", "checkpoint 分片未鉴权写入并读回（训练污染原语）", detail))
        else:
            findings.append(_COMMON.finding(
                "info", "checkpoint 分片写面被拒绝或读回不一致（投毒未成立）", detail))
    else:
        read = t.call("GET", f"{target}/checkpoint/shards/{quote(shard_id, safe='')}",
                      headers=_COMMON.headers_for(params))
        body = read.get("response")
        detail.update({
            "read_status": read.get("status"),
            "readback_sha256": _COMMON.sha256_text(body) if isinstance(body, str) else "",
            "readback_bytes": len(body.encode("utf-8")) if isinstance(body, str) else 0,
        })
        findings.append(_COMMON.finding(
            "info", "checkpoint 分片读回指纹（probe-only，不触碰写面）", detail))

    artifact = t.dump()
    _COMMON.write_artifact(ctx, "checkpoint-shard-poison.json", detail)
    summary = f"mode={mode} shard={shard_id} read={detail.get('readback_status', detail.get('read_status'))}"
    if note:
        summary += f"；{note}"
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
