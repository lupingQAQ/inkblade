# -*- coding: utf-8 -*-
"""Post-quantum TLS audit (read-only; quarantined by default)."""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_emerging_common", _PARENT / "_emerging-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "post-quantum-tls-audit"
_PQ = ("x25519mlkem768", "x25519kyber768", "mlkem", "kyber")


def run(ctx: dict, params: dict) -> dict:
    doc = _C.collection(params)
    state = _C.surface_state(ctx.get("meta") or {}, params, doc)
    if state.get("status") != "deployed":
        return _C.not_deployed(ctx, KEY, state)

    findings: list[dict] = []
    tls_eps = [e for e in _C.endpoints(doc) if e.get("tls")]
    weak = []
    for ep in tls_eps:
        groups = [str(g).lower() for g in (ep.get("tls") or {}).get("groups") or []]
        offered = " ".join(groups)
        if not any(p in offered for p in _PQ):
            weak.append({"url": ep.get("url"), "tls_version": (ep.get("tls") or {}).get("version"),
                         "cipher": (ep.get("tls") or {}).get("cipher"), "groups": groups})
    if weak:
        findings.append(_C.finding(
            "medium", "TLS 端点未提供混合后量子密钥交换组",
            {"endpoints": weak, "expected_any": list(_PQ)},
            evidence="TLS metadata has no ML-KEM/Kyber group"))
    legacy = [e.get("url") for e in tls_eps
              if str((e.get("tls") or {}).get("version", "")).upper() in ("TLSV1", "TLSV1.1")]
    if legacy:
        findings.append(_C.finding(
            "high", "TLS 端点仍启用 TLS 1.0/1.1",
            {"endpoints": legacy}, evidence="tls.version legacy"))

    return _C.result(ctx, KEY, state, findings,
                     f"tls_endpoints={len(tls_eps)} non_pq={len(weak)} findings={len(findings)}",
                     {"tls_endpoints": [e.get("url") for e in tls_eps]})
