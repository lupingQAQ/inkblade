# -*- coding: utf-8 -*-
"""torchrun 弹性训练面 — etcd rendezvous 无鉴权/无 TLS/动态成员注入。

只读：GET /train/elastic → rdzv_backend / rdzv_endpoint / etcd_auth / tls /
dynamic_membership / members / c10d_port。
判定：etcd 后端 + auth=none + tls=false + 成员列表可见 + 动态成员开启 → high
（可插入恶意 rank / 投毒 world_size）；fixed 姿态 401 → info。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_trainstack_common", _PARENT / "_trainstack-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

KEY = "torchrun-elastic-surface"
WRITES = False


def run(ctx: dict, params: dict) -> dict:
    target = _COMMON.target_of(params)
    if not target:
        return _COMMON.no_target()
    t = _COMMON.Trace(ctx, KEY)
    entry = t.call("GET", f"{target}/train/elastic", headers=_COMMON.headers_for(params))
    payload = _COMMON.resp(entry)
    members = [str(m) for m in (payload.get("members") or [])]
    detail = {
        "route": "/train/elastic",
        "http_status": entry.get("status"),
        "rdzv_backend": payload.get("rdzv_backend", ""),
        "rdzv_endpoint": payload.get("rdzv_endpoint", ""),
        "etcd_auth": payload.get("etcd_auth", ""),
        "tls": bool(payload.get("tls")),
        "dynamic_membership": bool(payload.get("dynamic_membership")),
        "standalone": bool(payload.get("standalone")),
        "c10d_port": _COMMON.int_of(payload.get("c10d_port")),
        "member_count": len(members),
        "members": members,
        "injection_surface": "etcd 无鉴权 + 动态成员 → 可注册伪 rank/改写 rendezvous 视图",
    }
    exposed = (_COMMON.is_ok(entry) and detail["rdzv_backend"] == "etcd"
               and str(detail["etcd_auth"]).lower() in ("", "none")
               and not detail["tls"] and detail["dynamic_membership"]
               and detail["member_count"] >= 2)
    findings: list[dict] = []
    if exposed:
        findings.append(_COMMON.finding(
            "high",
            "torchrun 弹性 rendezvous 无鉴权：etcd 明文 + 动态成员可注入伪 rank",
            detail))
    else:
        findings.append(_COMMON.finding(
            "info", "弹性 rendezvous 被拒绝或已加固（401 / auth / mTLS / 固定成员）", detail))

    artifact = t.dump()
    _COMMON.write_artifact(ctx, f"{KEY}.json", detail)
    summary = (f"status={entry.get('status')} backend={detail['rdzv_backend']} "
               f"auth={detail['etcd_auth']} tls={detail['tls']} members={detail['member_count']}")
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
