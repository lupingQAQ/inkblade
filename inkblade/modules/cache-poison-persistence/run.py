# -*- coding: utf-8 -*-
"""cache-poison-persistence — 毒化 KV 块存续（逐出策略绕过）。

probe-only：只读探池读面（GET 受害块）——vulnerable 200 found 即远程 KV 池读面
未隔离（毒化存续的前置条件），fixed 403。

backup-write（走 runner backup_targets 闸门）：
1) POST /kvpool/blocks 写入带 run marker 的良性 KV 块并申请 pinned 逐出策略；
2) 唯一前缀洪泛制造逐出压力（/router/metrics 逐出计数增长为证）；
3) GET 独立读回：vulnerable pinned 生效且逐出压力下块仍存续（sha256 一致）→ high
   （毒化块持久驻留/逐出策略绕过）；fixed pinned 仅管理密钥可设（普通租户降级 lru），
   洪泛后块被逐出 404 → info。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
from urllib.parse import quote

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_cache_common", _PARENT / "_cache-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

KEY = "cache-poison-persistence"
WRITES = True
DEFAULT_FLOOD = 160


def run(ctx: dict, params: dict) -> dict:
    target = _COMMON.target_of(params)
    if not target:
        return _COMMON.no_target()
    marker = _COMMON.marker_of(ctx, params)
    mode, note = _COMMON.resolve_mode(params, WRITES)
    tenant = _COMMON.tenant_of(params)
    flood = max(1, _COMMON.int_of(params.get("flood_count"), DEFAULT_FLOOD))
    victim_block = str(params.get("victim_block") or "tenant-b/ctx/seed-001")

    t = _COMMON.Trace(ctx, KEY)
    headers = _COMMON.headers_for(params)
    findings: list[dict] = []
    detail: dict = {
        "route": "/kvpool/blocks",
        "mode": mode,
        "tenant": tenant,
    }

    if mode == "backup-write":
        block_id = str(params.get("block_id") or f"poison-{marker}")
        payload_value = str(params.get("payload") or (
            '{"marker": "' + marker + '", "benign": true, "class": "trident-lab-poison", '
            '"surface": "remote-kv-pool", "policy": "pinned"}'
        ))
        write = t.call("POST", f"{target}/kvpool/blocks", {
            "block_id": block_id,
            "namespace": str(params.get("namespace") or tenant),
            "value": payload_value,
            "eviction_policy": "pinned",
        }, headers)
        write_payload = _COMMON.resp(write)
        expected_sha = _COMMON.sha256_text(payload_value)
        pinned_applied = bool(write_payload.get("pinned"))

        before = t.call("GET", f"{target}/router/metrics", headers=headers)
        evictions_before = _COMMON.int_of(
            ((_COMMON.resp(before).get("pool") or {}).get("evictions_total")))
        for i in range(flood):
            t.call("POST", f"{target}/v1/chat/completions", {
                "prompt_prefix": f"poison-flood-{marker}-{i:04d} unique corpus pressure",
                "prefix_tokens": 2048, "max_tokens": 1,
            }, headers)
        after = t.call("GET", f"{target}/router/metrics", headers=headers)
        evictions_after = _COMMON.int_of(
            ((_COMMON.resp(after).get("pool") or {}).get("evictions_total")))
        evictions_delta = max(0, evictions_after - evictions_before)

        readback = t.call("GET", f"{target}/kvpool/blocks/{quote(block_id, safe='')}",
                          headers=headers)
        readback_payload = _COMMON.resp(readback)
        readback_matches = bool(
            _COMMON.is_ok(readback) and readback_payload.get("found")
            and readback_payload.get("sha256") == expected_sha)
        survived = bool(readback_payload.get("found")) and pinned_applied

        detail.update({
            "block_id": block_id,
            "write_status": write.get("status"),
            "pinned_applied": pinned_applied,
            "pinning_denied": bool(write_payload.get("pinning_denied")),
            "write_sha256": expected_sha,
            "flood_count": flood,
            "evictions_before": evictions_before,
            "evictions_after": evictions_after,
            "evictions_delta": evictions_delta,
            "readback_status": readback.get("status"),
            "readback_found": bool(readback_payload.get("found")),
            "readback_matches": readback_matches,
            "survived_eviction_pressure": survived,
            "marker": marker,
        })
        if (_COMMON.is_ok(write) and pinned_applied and evictions_delta >= 1
                and readback_matches and survived):
            findings.append(_COMMON.finding(
                "high",
                "毒化 KV 块逐出策略绕过：pinned 生效且逐出压力下持久存续"
                "（跨租户缓存完整性污染驻留）",
                detail))
        else:
            findings.append(_COMMON.finding(
                "info", "毒化块未持久存续（pinning 被拒或洪泛后被逐出），存续不成立", detail))
    else:
        probe = t.call("GET", f"{target}/kvpool/blocks/{quote(victim_block, safe='')}",
                       headers=headers)
        probe_payload = _COMMON.resp(probe)
        detail.update({
            "probe_block": victim_block,
            "probe_status": probe.get("status"),
            "probe_found": bool(probe_payload.get("found")),
            "block_tenant": probe_payload.get("tenant"),
        })
        if _COMMON.is_ok(probe) and probe_payload.get("found"):
            findings.append(_COMMON.finding(
                "high", "远程 KV 池读面未隔离（毒化存续前置条件成立，写面未触碰）", detail))
        else:
            findings.append(_COMMON.finding(
                "info", "远程 KV 池读面按租户隔离（读探针被拒）", detail))

    artifact = t.dump()
    _COMMON.write_artifact(ctx, "cache-poison-persistence.json", detail)
    summary = f"mode={mode}"
    if mode == "backup-write":
        summary += (f" write={detail['write_status']} pinned={detail['pinned_applied']} "
                    f"evictions=+{detail['evictions_delta']} "
                    f"readback={detail['readback_status']}")
    else:
        summary += f" probe={detail['probe_status']}"
    if note:
        summary += f"；{note}"
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
