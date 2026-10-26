# -*- coding: utf-8 -*-
"""checkpoint optimizer state 投毒 — 分片可写 + benign marker 读回 + sha256 一致。

probe-only：GET /ckpt/optimizer/<shard> 仅读回指纹（404 视为无基线）。
backup-write：先读基线，POST 带 benign marker 的 optimizer state（step/exp_avg/exp_avg_sq
标记 + poisoned=false 语义位），再读回；写入 200 且读回文本/sha256 与提交一致 → high。
写面走 runner backup_targets 闸门（file 快照可精确回滚）。
fixed：写面 401 → info；读回仍允许。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
from urllib.parse import quote

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_trainstack_common", _PARENT / "_trainstack-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

KEY = "checkpoint-optimizer-state-poison"
WRITES = True


def run(ctx: dict, params: dict) -> dict:
    target = _COMMON.target_of(params)
    if not target:
        return _COMMON.no_target()
    marker = _COMMON.marker_of(ctx, params)
    mode, note = _COMMON.resolve_mode(params, WRITES)
    shard_id = str(params.get("shard_id") or "ckpt-optim-0001")
    t = _COMMON.Trace(ctx, KEY)
    findings: list[dict] = []
    detail = {"route": "/ckpt/optimizer", "mode": mode, "shard_id": shard_id,
              "marker": marker}

    prior = t.call("GET", f"{target}/ckpt/optimizer/{quote(shard_id, safe='')}",
                   headers=_COMMON.headers_for(params))
    prior_payload = _COMMON.resp(prior)
    detail.update({
        "prior_status": prior.get("status"),
        "prior_sha256": prior_payload.get("sha256", ""),
        "prior_optimizer_state": bool(prior_payload.get("optimizer_state")),
    })

    if mode == "backup-write":
        payload = str(params.get("payload") or (
            '{"marker": "' + marker + '", "benign": true, "optimizer_state": true, '
            '"step": 4242, "exp_avg": [0.0, 0.0], "exp_avg_sq": [0.0, 0.0], '
            '"source": "inkblade-lab"}\n'))
        write = t.call("POST", f"{target}/ckpt/optimizer",
                       {"shard_id": shard_id, "payload": payload},
                       _COMMON.headers_for(params))
        read = t.call("GET", f"{target}/ckpt/optimizer/{quote(shard_id, safe='')}",
                      headers=_COMMON.headers_for(params))
        readback = _COMMON.resp(read)
        readback_text = readback.get("payload")
        if not isinstance(readback_text, str):
            readback_text = read.get("response_text") if isinstance(read.get("response_text"), str) else ""
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
            "changed_from_prior": bool(detail["prior_sha256"]) and readback_sha != detail["prior_sha256"],
            "bytes": len(payload.encode("utf-8")),
            "optimizer_state": bool(readback.get("optimizer_state")),
        })
        if _COMMON.is_ok(write) and matches:
            findings.append(_COMMON.finding(
                "high",
                "optimizer state 分片未鉴权写入并读回：训练恢复可被污染（step/动量可改写）",
                detail))
        else:
            findings.append(_COMMON.finding(
                "info", "optimizer state 写面被拒绝或读回不一致（投毒未成立）", detail))
    else:
        detail.update({
            "readback_status": prior.get("status"),
            "readback_sha256": prior_payload.get("sha256", ""),
            "bytes": _COMMON.int_of(prior_payload.get("bytes")),
        })
        findings.append(_COMMON.finding(
            "info", "optimizer state 读回指纹（probe-only，不触碰写面）", detail))

    artifact = t.dump()
    _COMMON.write_artifact(ctx, f"{KEY}.json", detail)
    summary = (f"mode={mode} shard={shard_id} "
               f"write={detail.get('write_status', 'skipped')} prior={detail['prior_status']}")
    if note:
        summary += f"；{note}"
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
