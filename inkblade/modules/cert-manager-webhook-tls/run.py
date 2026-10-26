# -*- coding: utf-8 -*-
"""cert-manager Webhook TLS 面（主动探测，只读）。

GET /webhook/tls：
- 证书已过期 → high；
- SAN 与 Service 名不匹配 → high；
- CA bundle 不匹配或 insecureSkipVerify → medium；
- 未启用证书轮换 → medium。

只读：不签发/轮换证书，不修改 webhook 配置。
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_infra2026_common", _PARENT / "_infra2026-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "cert-manager-webhook-tls"


def run(ctx: dict, params: dict) -> dict:
    target = str(params.get("target") or "").rstrip("/")
    if not target:
        return _C.no_target()
    t = _C.Trace(ctx, KEY)
    entry = t.get(f"{target}/webhook/tls")
    doc = _C.resp(entry)
    findings: list[dict] = []

    not_after = str(doc.get("not_after") or "")
    now = str(doc.get("now") or "")
    is_expired = _C.expired(not_after, now or None)
    left = _C.days_left(not_after, now or None)
    san = [str(x) for x in _C.as_list(doc.get("san"))]
    expected = [str(x) for x in _C.as_list(doc.get("expected_san"))]
    san_match = bool(expected) and all(name in san for name in expected)
    ca_match = bool(doc.get("ca_bundle_matches"))
    skip_verify = bool(doc.get("insecure_skip_verify"))
    rotator = bool(doc.get("cert_rotator"))

    if is_expired or (left is not None and left < 14):
        findings.append(_C.finding(
            "high", "Webhook 证书已过期",
            {"detected": True, "not_after": not_after, "now": now,
             "days_left": left, "secret": doc.get("secret")},
            evidence=f"not_after={not_after} now={now} days_left={left}",
            mapping="cert-manager Certificate / admission webhook TLS",
            fix="立即轮换 webhook 证书；设置 renewBefore 并告警到期",
        ))
    if expected and not san_match:
        findings.append(_C.finding(
            "high", "Webhook 证书 SAN 与 Service 不匹配",
            {"detected": True, "san": san, "expected_san": expected},
            evidence=f"san={san} expected={expected}",
            mapping="x509 SAN / Kubernetes Service DNS",
            fix="重新签发包含 <service>.<namespace>.svc 的证书；拒绝不匹配 SAN",
        ))
    if not ca_match or skip_verify:
        findings.append(_C.finding(
            "medium", "Webhook CA bundle 不匹配或跳过校验",
            {"detected": True, "ca_bundle_matches": ca_match,
             "insecure_skip_verify": skip_verify},
            evidence=f"ca_bundle_matches={ca_match} insecure_skip_verify={skip_verify}",
            mapping="APIServer caBundle / TLS 校验",
            fix="同步 caBundle 到 cert-manager CA；关闭 insecureSkipVerify",
        ))
    if not rotator:
        findings.append(_C.finding(
            "medium", "Webhook 证书未启用自动轮换",
            {"detected": True, "cert_rotator": rotator},
            evidence="cert_rotator=false",
            mapping="cert-manager 轮换 / 证书生命周期",
            fix="启用 cert-manager 轮换并监控 Certificate Ready/expiry",
        ))

    extra = {
        "expired": is_expired,
        "days_left": left,
        "san_match": san_match,
        "ca_bundle_matches": ca_match,
        "insecure_skip_verify": skip_verify,
        "cert_rotator": rotator,
        "not_after": not_after,
        "status": entry.get("status"),
    }
    summary = _C.summary_json("cert-manager Webhook TLS", findings, extra=extra,
                              source=target)
    artifact = _C.write_artifact(ctx, f"{KEY}.json", {
        "summary": json.loads(summary), "tls": doc, "findings": findings,
    })
    trace = t.dump()
    artifacts = ([str(trace)] if trace else []) + artifact
    return {"summary": summary, "artifacts": artifacts, "findings": findings}
