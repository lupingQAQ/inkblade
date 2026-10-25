# -*- coding: utf-8 -*-
"""SHARP 在网聚合投毒 — 会话面无鉴权入组 + 篡改 all-reduce 结果（静默损坏）。

probe-only：POST /sharp/sessions 入组（200 即无鉴权入组成立）。
backup-write：入组 → 基线 reduce（诚实贡献）→ 篡改 reduce（tamper_factor）→
结果差分 + /metrics.sharp.tampered_reduces 增长 → high。
fixed 姿态：入组 401（无令牌）；篡改被拒（401/400）。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_fabric_common", _PARENT / "_fabric-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

KEY = "sharp-in-network-poison"
WRITES = True
CONTRIBS = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]


def run(ctx: dict, params: dict) -> dict:
    target = _COMMON.target_of(params)
    if not target:
        return _COMMON.no_target()
    marker = _COMMON.marker_of(ctx, params)
    mode, note = _COMMON.resolve_mode(params, WRITES)
    session_id = str(params.get("session_id") or "train-job-alpha")
    headers = _COMMON.headers_for(params)
    t = _COMMON.Trace(ctx, KEY)
    findings: list[dict] = []
    detail: dict = {"route": "/sharp/sessions,/sharp/reduce", "mode": mode,
                    "session_id": session_id, "marker": marker}

    join = t.call("POST", f"{target}/sharp/sessions", {
        "op": "join", "session_id": session_id, "rank": f"trident-{marker[:24]}",
    }, headers)
    join_resp = _COMMON.resp(join)
    detail.update({
        "join_status": join.get("status"),
        "joined": bool(join_resp.get("joined")),
        "member_count": _COMMON.int_of(join_resp.get("member_count")),
    })

    if mode == "backup-write":
        before = _COMMON.metrics(t, target)
        baseline = t.call("POST", f"{target}/sharp/reduce", {
            "session_id": session_id, "contributions": CONTRIBS,
        }, headers)
        tampered = t.call("POST", f"{target}/sharp/reduce", {
            "session_id": session_id, "contributions": CONTRIBS, "tamper_factor": 3.0,
        }, headers)
        after = _COMMON.metrics(t, target)
        baseline_result = _COMMON.float_of(_COMMON.resp(baseline).get("result"))
        tampered_result = _COMMON.float_of(_COMMON.resp(tampered).get("result"))
        expected = float(sum(CONTRIBS))
        tampered_delta = _COMMON.counter_delta(before, after, ("sharp", "tampered_reduces"))
        detail.update({
            "baseline_status": baseline.get("status"),
            "tamper_status": tampered.get("status"),
            "expected_result": expected,
            "baseline_result": baseline_result,
            "tampered_result": tampered_result,
            "results_differ": tampered_result != baseline_result,
            "silent": bool(_COMMON.resp(tampered).get("silent")),
            "tampered_reduces_delta": tampered_delta,
        })
        if (_COMMON.is_ok(join) and _COMMON.is_ok(baseline) and _COMMON.is_ok(tampered)
                and tampered_result != baseline_result
                and baseline_result == expected and tampered_delta >= 1):
            findings.append(_COMMON.finding(
                "high", "SHARP 在网 all-reduce 结果被入组主体篡改（训练静默损坏原语）", detail))
        elif _COMMON.is_ok(join):
            findings.append(_COMMON.finding(
                "info", "SHARP 会话入组成立但篡改未获差分（防护或语义不符）", detail))
        else:
            findings.append(_COMMON.finding(
                "info", "SHARP 会话入组被拒绝（篡改未成立）", detail))
    else:
        if _COMMON.is_ok(join) and join_resp.get("joined"):
            findings.append(_COMMON.finding(
                "high", "SHARP 在网聚合会话无鉴权入组（跨作业集合通信域可入）", detail))
        else:
            findings.append(_COMMON.finding(
                "info", "SHARP 会话入组被拒绝（探测不成立）", detail))

    artifact = t.dump()
    _COMMON.write_artifact(ctx, f"{KEY}.json", detail)
    summary = f"mode={mode} join={detail.get('join_status')}"
    if mode == "backup-write":
        summary += (f" baseline={detail.get('baseline_result')}"
                    f" tampered={detail.get('tampered_result')}")
    if note:
        summary += f"；{note}"
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
