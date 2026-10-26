# -*- coding: utf-8 -*-
"""checkpoint I/O 风暴 — 限速缺失时少量并发 burst 推高 I/O 计数（不真写盘）。

rounds × {bytes_mb, burst} POST /checkpoint/io → io_bytes/io_queue 增长且
rate_limited=false → high；fixed 姿态 401/429（限速生效）。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_fabric_common", _PARENT / "_fabric-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

KEY = "checkpoint-io-storm"
WRITES = False
IO_BYTES_THRESHOLD_MB = 40960  # 40 GiB 等价 I/O 洪峰


def run(ctx: dict, params: dict) -> dict:
    target = _COMMON.target_of(params)
    if not target:
        return _COMMON.no_target()
    marker = _COMMON.marker_of(ctx, params)
    bytes_mb = max(1, _COMMON.int_of(params.get("bytes_mb"), 4096))
    burst = max(1, _COMMON.int_of(params.get("burst"), 4))
    rounds = max(1, min(10, _COMMON.int_of(params.get("rounds"), 5)))
    headers = _COMMON.headers_for(params)
    t = _COMMON.Trace(ctx, KEY)
    findings: list[dict] = []
    detail: dict = {"route": "/checkpoint/io", "bytes_mb": bytes_mb, "burst": burst,
                    "rounds": rounds, "marker": marker}

    before = _COMMON.metrics(t, target)
    before_mb = _COMMON.int_of((before.get("checkpoint_io") or {}).get("io_bytes_mb"))
    statuses: list[int] = []
    last_io_mb = before_mb
    io_queue = 0
    for _ in range(rounds):
        call = t.call("POST", f"{target}/checkpoint/io", {
            "bytes_mb": bytes_mb, "burst": burst,
        }, headers)
        statuses.append(_COMMON.int_of(call.get("status")))
        body = _COMMON.resp(call)
        last_io_mb = _COMMON.int_of(body.get("io_bytes_mb"), last_io_mb)
        io_queue = _COMMON.int_of(body.get("io_queue"), io_queue)
    after = _COMMON.metrics(t, target)
    after_io = (after.get("checkpoint_io") or {})
    detail.update({
        "io_statuses": statuses,
        "io_bytes_mb_delta": _COMMON.int_of(after_io.get("io_bytes_mb"), last_io_mb) - before_mb,
        "io_queue": _COMMON.int_of(after_io.get("io_queue"), io_queue),
        "rate_limited": bool(after_io.get("rate_limited")),
        "throttled": _COMMON.int_of(after_io.get("throttled")),
    })
    if any(s == 200 for s in statuses) and detail["io_bytes_mb_delta"] >= IO_BYTES_THRESHOLD_MB \
            and not detail["rate_limited"]:
        findings.append(_COMMON.finding(
            "high", "checkpoint I/O 面无限速（少量请求即 fabric 级 I/O 洪峰）", detail))
    else:
        findings.append(_COMMON.finding(
            "info", "I/O 限速/鉴权生效或计数未达阈值（风暴未成立）", detail))

    artifact = t.dump()
    _COMMON.write_artifact(ctx, f"{KEY}.json", detail)
    return {"summary": (f"rounds={rounds} io_delta_mb={detail['io_bytes_mb_delta']}"
                        f" queue={detail['io_queue']} limited={detail['rate_limited']}"),
            "artifacts": [str(artifact)], "findings": findings}
