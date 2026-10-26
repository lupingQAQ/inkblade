# -*- coding: utf-8 -*-
"""联邦学习聚合面（只读侦察）。

GET /fl/round：
- 更新未签名/未验证 → high；
- 未启用安全聚合 → high；
- 未启用差分隐私/拜占庭过滤 → medium；
- 更新范数异常 → medium。

只读：不参与轮次、不上传更新、不修改聚合器。
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_infra2026_common", _PARENT / "_infra2026-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "federated-learning-surface"


def run(ctx: dict, params: dict) -> dict:
    target = str(params.get("target") or "").rstrip("/")
    if not target:
        return _C.no_target()
    t = _C.Trace(ctx, KEY)
    entry = t.get(f"{target}/fl/round")
    doc = _C.resp(entry)
    updates = [u for u in _C.as_list(doc.get("updates")) if isinstance(u, dict)]
    dp = doc.get("dp") or {}
    findings: list[dict] = []

    unverified = [u for u in updates
                  if not bool(u.get("verified")) or not bool(u.get("signed"))]
    secure = bool(doc.get("secure_aggregation"))
    dp_on = bool(dp.get("enabled"))
    byzantine = bool(doc.get("byzantine_filter"))
    norms = [float(u.get("norm") or 0.0) for u in updates]
    outlier = [u for u in updates
               if float(u.get("norm") or 0.0) > 100.0
               or float(u.get("norm") or 0.0) <= 0.0]

    if unverified:
        findings.append(_C.finding(
            "high", "联邦更新未签名或未验证",
            {"detected": True,
             "updates": [{"client": u.get("client"), "verified": u.get("verified"),
                          "signed": u.get("signed"), "norm": u.get("norm")}
                         for u in unverified]},
            evidence=f"unverified_updates={len(unverified)}",
            mapping="联邦学习客户端更新 / 签名与证明",
            fix="要求客户端更新签名并验证；未验证更新拒绝进入聚合",
        ))
    if not secure:
        findings.append(_C.finding(
            "high", "未启用安全聚合",
            {"detected": True, "secure_aggregation": secure,
             "updates": len(updates)},
            evidence="secure_aggregation=false",
            mapping="Secure Aggregation / 联邦聚合隐私",
            fix="启用安全聚合，服务端不可见单客户端更新",
        ))
    if not dp_on or not byzantine:
        findings.append(_C.finding(
            "medium", "未启用差分隐私或拜占庭过滤",
            {"detected": True, "dp_enabled": dp_on, "epsilon": dp.get("epsilon"),
             "byzantine_filter": byzantine},
            evidence=f"dp={dp_on} byzantine_filter={byzantine}",
            mapping="DP-SGD / 拜占庭鲁棒聚合",
            fix="启用差分隐私预算与拜占庭过滤（Krum/median）",
        ))
    if outlier:
        findings.append(_C.finding(
            "medium", "联邦更新范数异常",
            {"detected": True,
             "updates": [{"client": u.get("client"), "norm": u.get("norm")}
                         for u in outlier], "max_norm": max(norms or [0.0])},
            evidence=f"outlier_updates={[u.get('client') for u in outlier]}",
            mapping="模型投毒 / 梯度范数异常",
            fix="设置范数裁剪与异常检测；隔离异常客户端并复核",
        ))

    extra = {
        "round": doc.get("round"),
        "aggregator": doc.get("aggregator"),
        "clients": doc.get("clients"),
        "updates": len(updates),
        "unverified_updates": len(unverified),
        "secure_aggregation": secure,
        "dp_enabled": dp_on,
        "byzantine_filter": byzantine,
        "status": entry.get("status"),
    }
    summary = _C.summary_json("联邦学习聚合面", findings, extra=extra, source=target)
    artifact = _C.write_artifact(ctx, f"{KEY}.json", {
        "summary": json.loads(summary), "federated": doc, "findings": findings,
    })
    trace = t.dump()
    artifacts = ([str(trace)] if trace else []) + artifact
    return {"summary": summary, "artifacts": artifacts, "findings": findings}
