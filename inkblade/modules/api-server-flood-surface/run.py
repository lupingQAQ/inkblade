# -*- coding: utf-8 -*-
"""apiserver/IMDS 请求洪 — 控制面配额缺失（计数器度量）。

rounds × POST /apiserver/request{count} + imds_rounds × /imds/request →
requests/imds 总数无界增长且 quota_enforced=false → high；
fixed 姿态超配额 429（quota_enforced=true）。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_fabric_common", _PARENT / "_fabric-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

KEY = "api-server-flood-surface"
WRITES = False
FLOOD_THRESHOLD = 500


def run(ctx: dict, params: dict) -> dict:
    target = _COMMON.target_of(params)
    if not target:
        return _COMMON.no_target()
    marker = _COMMON.marker_of(ctx, params)
    count = max(1, _COMMON.int_of(params.get("count"), 250))
    rounds = max(1, min(10, _COMMON.int_of(params.get("rounds"), 4)))
    imds_rounds = max(0, min(10, _COMMON.int_of(params.get("imds_rounds"), 2)))
    t = _COMMON.Trace(ctx, KEY)
    findings: list[dict] = []
    detail: dict = {"routes": "/apiserver/request,/imds/request", "count": count,
                    "rounds": rounds, "imds_rounds": imds_rounds, "marker": marker}

    before = _COMMON.metrics(t, target)
    api_statuses: list[int] = []
    for _ in range(rounds):
        call = t.call("POST", f"{target}/apiserver/request", {"count": count})
        api_statuses.append(_COMMON.int_of(call.get("status")))
    imds_statuses: list[int] = []
    for _ in range(imds_rounds):
        call = t.call("POST", f"{target}/imds/request", {"count": count})
        imds_statuses.append(_COMMON.int_of(call.get("status")))
    after = _COMMON.metrics(t, target)
    api_after = (after.get("api") or {})
    detail.update({
        "api_statuses": api_statuses,
        "imds_statuses": imds_statuses,
        "requests_delta": _COMMON.counter_delta(before, after, ("api", "requests_total")),
        "imds_requests_delta": _COMMON.counter_delta(before, after, ("api", "imds_requests_total")),
        "quota_enforced": bool(api_after.get("quota_enforced")),
        "throttled": _COMMON.int_of(api_after.get("throttled")),
    })
    total_flood = detail["requests_delta"] + detail["imds_requests_delta"]
    if any(s == 200 for s in api_statuses) and total_flood >= FLOOD_THRESHOLD \
            and not detail["quota_enforced"]:
        findings.append(_COMMON.finding(
            "high", f"控制面/元数据请求洪无配额（Δ请求 ≥ {FLOOD_THRESHOLD}）", detail))
    else:
        findings.append(_COMMON.finding(
            "info", "请求配额生效或计数未达阈值（洪泛未成立）", detail))

    artifact = t.dump()
    _COMMON.write_artifact(ctx, f"{KEY}.json", detail)
    return {"summary": (f"api_delta={detail['requests_delta']} imds_delta={detail['imds_requests_delta']}"
                        f" quota={detail['quota_enforced']}"),
            "artifacts": [str(artifact)], "findings": findings}
