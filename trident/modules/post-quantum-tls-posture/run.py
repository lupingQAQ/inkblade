# -*- coding: utf-8 -*-
"""后量子 TLS 姿态面（主动探测，只读）。

GET /tls/posture：
- TLS1.2/RSA 密钥交换 → high；
- 无 X25519MLKEM768 混合组 → high；
- 证书/签名非后量子或存在 HNDL 暴露 → medium。

只读：仅读取 TLS 配置快照，不发起握手降级或修改端点。
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_infra2026_common", _PARENT / "_infra2026-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "post-quantum-tls-posture"
PQ_GROUP = "X25519MLKEM768"


def run(ctx: dict, params: dict) -> dict:
    target = str(params.get("target") or "").rstrip("/")
    if not target:
        return _C.no_target()
    t = _C.Trace(ctx, KEY)
    entry = t.get(f"{target}/tls/posture")
    doc = _C.resp(entry)
    findings: list[dict] = []

    min_version = str(doc.get("min_version") or "")
    key_exchange = str(doc.get("key_exchange") or "")
    hybrid = str(doc.get("hybrid_group") or "")
    cert = doc.get("cert") or {}
    signature = str(doc.get("signature_alg") or "")
    hndl = bool(doc.get("hndl_exposed")) or not bool(doc.get("hndl_safe"))

    if min_version != "TLS1.3" or key_exchange in ("rsa", ""):
        findings.append(_C.finding(
            "high", "TLS 使用 RSA 密钥交换或低于 TLS 1.3",
            {"detected": True, "min_version": min_version, "key_exchange": key_exchange,
             "cipher_suites": doc.get("cipher_suites")},
            evidence=f"min_version={min_version} key_exchange={key_exchange}",
            mapping="TLS 1.3 / RFC 8446 / 密钥交换",
            fix="最低 TLS1.3；禁用静态 RSA 密钥交换，仅保留前向保密套件",
        ))
    if hybrid != PQ_GROUP:
        findings.append(_C.finding(
            "high", "未配置混合后量子密钥交换",
            {"detected": True, "hybrid_group": hybrid, "expected": PQ_GROUP},
            evidence=f"hybrid_group={hybrid or 'none'}",
            mapping="X25519MLKEM768 / hybrid key exchange",
            fix="启用 X25519MLKEM768（或等价 hybrid）并优先协商",
        ))
    cert_alg = str(cert.get("alg") or "")
    if not cert_alg.startswith("ML-") and "ML-DSA" not in signature:
        findings.append(_C.finding(
            "medium", "证书或签名算法非后量子",
            {"detected": True, "cert_alg": cert_alg, "cert_bits": cert.get("bits"),
             "signature_alg": signature},
            evidence=f"cert={cert_alg} signature={signature}",
            mapping="ML-DSA / SLH-DSA 证书与签名迁移",
            fix="规划 ML-DSA/SLH-DSA 证书链；双证书期并行验证",
        ))
    if hndl:
        findings.append(_C.finding(
            "medium", "存在 harvest-now-decrypt-later 暴露",
            {"detected": True, "hndl_exposed": hndl, "min_version": min_version,
             "hybrid_group": hybrid},
            evidence="hndl_exposed=true",
            mapping="HNDL / 长期机密性",
            fix="对长期敏感数据优先启用 PQ hybrid；缩短密钥/数据生命周期",
        ))

    extra = {
        "min_version": min_version,
        "key_exchange": key_exchange,
        "hybrid_group": hybrid,
        "cert_alg": cert_alg,
        "hndl_exposed": hndl,
        "status": entry.get("status"),
    }
    summary = _C.summary_json("后量子 TLS 姿态", findings, extra=extra, source=target)
    artifact = _C.write_artifact(ctx, f"{KEY}.json", {
        "summary": json.loads(summary), "tls": doc, "findings": findings,
    })
    trace = t.dump()
    artifacts = ([str(trace)] if trace else []) + artifact
    return {"summary": summary, "artifacts": artifacts, "findings": findings}
