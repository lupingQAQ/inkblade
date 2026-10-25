# -*- coding: utf-8 -*-
"""IB Subnet Manager Partition 劫持 — SM 成员面可写即信任域可改。

probe-only：GET /ib/sm/partition 枚举 partition 成员。
backup-write：POST 增加带 run marker 的 benign 成员 → GET 读回包含该成员 →
/metrics.ib.membership_changes 增长 → high。
fixed 姿态：读写面 401（无管理密钥）。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_fabric_common", _PARENT / "_fabric-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

KEY = "ib-subnet-manager-hijack"
WRITES = True


def run(ctx: dict, params: dict) -> dict:
    target = _COMMON.target_of(params)
    if not target:
        return _COMMON.no_target()
    marker = _COMMON.marker_of(ctx, params)
    mode, note = _COMMON.resolve_mode(params, WRITES)
    pkey = str(params.get("pkey") or "0x8001")
    t = _COMMON.Trace(ctx, KEY)
    findings: list[dict] = []
    detail: dict = {"route": "/ib/sm/partition", "mode": mode, "pkey": pkey,
                    "marker": marker}

    listing = t.call("GET", f"{target}/ib/sm/partition")
    partitions = _COMMON.resp(listing).get("partitions") or {}
    detail.update({
        "list_status": listing.get("status"),
        "partition_count": len(partitions) if isinstance(partitions, dict) else 0,
        "target_partition_exists": pkey in partitions if isinstance(partitions, dict) else False,
    })

    if mode == "backup-write":
        member = f"guid-trident-{marker[:24]}"
        before = _COMMON.metrics(t, target)
        write = t.call("POST", f"{target}/ib/sm/partition", {
            "pkey": pkey, "add_members": [member],
        })
        readback = t.call("GET", f"{target}/ib/sm/partition")
        after = _COMMON.metrics(t, target)
        members = (((_COMMON.resp(readback).get("partitions") or {}).get(pkey) or {})
                   .get("members") or [])
        changes_delta = _COMMON.counter_delta(before, after, ("ib", "membership_changes"))
        detail.update({
            "write_status": write.get("status"),
            "readback_status": readback.get("status"),
            "injected_member": member,
            "member_in_partition": member in members,
            "membership_changes_delta": changes_delta,
            "member_count": len(members),
        })
        if _COMMON.is_ok(write) and member in members and changes_delta >= 1:
            findings.append(_COMMON.finding(
                "high", "IB SM Partition 成员无鉴权改写（通信信任域重定义）", detail))
        else:
            findings.append(_COMMON.finding(
                "info", "IB SM Partition 改写被拒绝或读回不一致（劫持未成立）", detail))
    else:
        if _COMMON.is_ok(listing) and isinstance(partitions, dict) and partitions:
            findings.append(_COMMON.finding(
                "high", "IB SM Partition 成员清单无鉴权枚举（拓扑/信任域测绘面）", detail))
        else:
            findings.append(_COMMON.finding(
                "info", "IB SM Partition 枚举被拒绝（探测不成立）", detail))

    artifact = t.dump()
    _COMMON.write_artifact(ctx, f"{KEY}.json", detail)
    summary = f"mode={mode} list={detail.get('list_status')} write={detail.get('write_status')}"
    if note:
        summary += f"；{note}"
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
