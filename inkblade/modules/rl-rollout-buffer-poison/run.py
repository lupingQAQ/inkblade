# -*- coding: utf-8 -*-
"""RL 轨迹/回放缓冲投毒 — 跨租户写入与读回。

probe-only：GET /rl/buffer/stats（缓冲共享性与租户视图）。
backup-write：tenant-a 先写本租户轨迹，再以 tenant-b 身份写入带 benign marker 的轨迹
（服务端标记 cross_tenant=true），最后读回该轨迹；共享缓冲 + 跨租户写成功 + marker
读回 → high。fixed：跨租户写/读 403 → info。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
from urllib.parse import urlencode

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_trainstack_common", _PARENT / "_trainstack-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

KEY = "rl-rollout-buffer-poison"
WRITES = True


def run(ctx: dict, params: dict) -> dict:
    target = _COMMON.target_of(params)
    if not target:
        return _COMMON.no_target()
    marker = _COMMON.marker_of(ctx, params)
    mode, note = _COMMON.resolve_mode(params, WRITES)
    tenant = _COMMON.tenant_of(params)
    victim = _COMMON.victim_tenant_of(params)
    t = _COMMON.Trace(ctx, KEY)
    findings: list[dict] = []
    detail = {"route": "/rl/rollout,/rl/buffer/stats", "mode": mode,
              "tenant": tenant, "victim_tenant": victim, "marker": marker}

    stats_entry = t.call("GET", f"{target}/rl/buffer/stats",
                         headers=_COMMON.headers_for(params))
    stats = _COMMON.resp(stats_entry)
    detail.update({
        "stats_status": stats_entry.get("status"),
        "shared_buffer": bool(stats.get("shared_buffer")),
        "buffer_trajectories": _COMMON.int_of(stats.get("trajectories")),
        "buffer_tenants": stats.get("tenants") or [],
    })

    if mode == "backup-write":
        own_id = f"traj-{marker}-own"
        own = t.call("POST", f"{target}/rl/rollout", {
            "tenant": tenant, "trajectory_id": own_id,
            "samples": [{"prompt": "trident-lab", "response": "benign", "reward": 0.1}],
        }, _COMMON.headers_for(params))
        victim_id = f"traj-{marker}-victim"
        victim_write = t.call("POST", f"{target}/rl/rollout", {
            "tenant": victim, "trajectory_id": victim_id,
            "samples": [{"prompt": "trident-lab", "response": marker, "reward": 1.0}],
        }, _COMMON.headers_for(params))
        readback = t.call(
            "GET", f"{target}/rl/rollout?" + urlencode({"tenant": victim,
                                                        "trajectory_id": victim_id}),
            headers={_COMMON.TENANT_HEADER: victim})
        trajectory = _COMMON.resp(readback).get("trajectory") or {}
        samples = trajectory.get("samples") or []
        responses = [str((s or {}).get("response", "")) for s in samples
                     if isinstance(s, dict)]
        detail.update({
            "own_write_status": own.get("status"),
            "victim_write_status": victim_write.get("status"),
            "cross_tenant": bool(_COMMON.resp(victim_write).get("cross_tenant")),
            "victim_sha256": _COMMON.resp(victim_write).get("sha256", ""),
            "readback_status": readback.get("status"),
            "readback_trajectory_id": trajectory.get("trajectory_id", ""),
            "readback_sha256": trajectory.get("sha256", ""),
            "marker_present": marker in responses,
            "samples_readback": len(responses),
        })
        exploited = (_COMMON.is_ok(victim_write) and detail["cross_tenant"]
                     and _COMMON.is_ok(readback) and detail["marker_present"]
                     and detail["shared_buffer"])
        if exploited:
            findings.append(_COMMON.finding(
                "high",
                "RL 回放缓冲跨租户投毒：tenant-a 改写 tenant-b 轨迹并读回（共享缓冲无隔离）",
                detail))
        else:
            findings.append(_COMMON.finding(
                "info", "回放缓冲写面被拒绝或未形成跨租户读写（投毒未成立）", detail))
    else:
        detail.update({"own_write_status": "skipped", "victim_write_status": "skipped",
                       "readback_status": "skipped"})
        findings.append(_COMMON.finding(
            "info", "回放缓冲统计指纹（probe-only，不触碰写面）", detail))

    artifact = t.dump()
    _COMMON.write_artifact(ctx, f"{KEY}.json", detail)
    summary = (f"mode={mode} stats={detail['stats_status']} shared={detail['shared_buffer']} "
               f"victim_write={detail.get('victim_write_status')}")
    if note:
        summary += f"；{note}"
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
