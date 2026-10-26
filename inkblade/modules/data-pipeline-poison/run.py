# -*- coding: utf-8 -*-
"""数据管线投毒 — webdataset/Arrow/parquet 分片追加篡改与采样器检出。

probe-only：GET /data/manifest + GET /data/sampler（读基线顺序与逐分片 sha256）。
backup-write：POST /data/shard 追加样本（重复 id + 未知 id + benign marker），再取
sampler：tamper_detected=true、expected/actual sha256 不一致、duplicate/unknown id
增加、采样顺序变化 → high。
fixed：分片写面 401 → info；sampler 仍可读且 tamper_detected=false。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_trainstack_common", _PARENT / "_trainstack-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

KEY = "data-pipeline-poison"
WRITES = True
DEFAULT_SHARD = "shard-0001"


def _sampler(t, target: str, params: dict, epoch: int = 1):
    return t.call("GET", f"{target}/data/sampler?epoch={epoch}",
                  headers=_COMMON.headers_for(params))


def run(ctx: dict, params: dict) -> dict:
    target = _COMMON.target_of(params)
    if not target:
        return _COMMON.no_target()
    marker = _COMMON.marker_of(ctx, params)
    mode, note = _COMMON.resolve_mode(params, WRITES)
    shard_id = str(params.get("shard_id") or DEFAULT_SHARD)
    t = _COMMON.Trace(ctx, KEY)
    findings: list[dict] = []
    detail = {"route": "/data/manifest,/data/sampler,/data/shard", "mode": mode,
              "shard_id": shard_id, "marker": marker}

    manifest_entry = t.call("GET", f"{target}/data/manifest",
                            headers=_COMMON.headers_for(params))
    baseline_entry = _sampler(t, target, params)
    manifest = _COMMON.resp(manifest_entry)
    baseline = _COMMON.resp(baseline_entry)
    shards = [s for s in (manifest.get("shards") or []) if isinstance(s, dict)]
    detail.update({
        "manifest_status": manifest_entry.get("status"),
        "sampler_status": baseline_entry.get("status"),
        "shard_count": len(shards),
        "baseline_samples": _COMMON.int_of(baseline.get("samples_total")),
        "baseline_order": baseline.get("order") or [],
        "baseline_expected_sha256": baseline.get("expected_sha256", ""),
    })

    if mode == "backup-write":
        payload = str(params.get("payload") or (
            '{"id": "s-0001", "text": "' + marker + '-DUP"}\n'
            '{"id": "s-0001", "text": "' + marker + '-DUP"}\n'
            '{"id": "s-9999", "text": "' + marker + '-EXTRA"}\n'))
        write = t.call("POST", f"{target}/data/shard",
                       {"shard_id": shard_id, "payload": payload},
                       _COMMON.headers_for(params))
        after_entry = _sampler(t, target, params)
        after = _COMMON.resp(after_entry)
        detail.update({
            "write_status": write.get("status"),
            "appended": _COMMON.int_of(_COMMON.resp(write).get("appended")),
            "after_sampler_status": after_entry.get("status"),
            "expected_sha256": after.get("expected_sha256", ""),
            "actual_sha256": after.get("actual_sha256", ""),
            "tamper_detected": bool(after.get("tamper_detected")),
            "duplicate_ids": _COMMON.int_of(after.get("duplicate_ids")),
            "unknown_ids": _COMMON.int_of(after.get("unknown_ids")),
            "order_changed": bool(after.get("order_changed")),
            "samples_total": _COMMON.int_of(after.get("samples_total")),
            "tampered_shards": after.get("tampered_shards") or [],
        })
        detected = (detail["tamper_detected"] and detail["expected_sha256"] != detail["actual_sha256"]
                    and (detail["duplicate_ids"] >= 1 or detail["unknown_ids"] >= 1))
        if _COMMON.is_ok(write) and detected:
            findings.append(_COMMON.finding(
                "high",
                "训练数据分片未鉴权追加篡改：重复/未知样本进入采样且与 manifest sha256 不符（可检出）",
                detail))
        else:
            findings.append(_COMMON.finding(
                "info", "数据分片写面被拒绝或采样器未检出偏差（篡改未成立）", detail))
    else:
        detail.update({
            "tamper_detected": bool(baseline.get("tamper_detected")),
            "duplicate_ids": _COMMON.int_of(baseline.get("duplicate_ids")),
            "unknown_ids": _COMMON.int_of(baseline.get("unknown_ids")),
            "samples_total": _COMMON.int_of(baseline.get("samples_total")),
        })
        findings.append(_COMMON.finding(
            "info", "数据清单与采样顺序指纹（probe-only，不触碰写面）", detail))

    artifact = t.dump()
    _COMMON.write_artifact(ctx, f"{KEY}.json", detail)
    summary = (f"mode={mode} shard={shard_id} manifest={detail['manifest_status']} "
               f"tamper={detail.get('tamper_detected')}")
    if note:
        summary += f"；{note}"
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
