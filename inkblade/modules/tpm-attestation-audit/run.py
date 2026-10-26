# -*- coding: utf-8 -*-
"""TPM / measured-boot attestation audit (read-only)."""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_emerging_common", _PARENT / "_emerging-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "tpm-attestation-audit"


def run(ctx: dict, params: dict) -> dict:
    doc = _C.collection(params)
    state = _C.surface_state(ctx.get("meta") or {}, params, doc)
    if state.get("status") != "deployed":
        return _C.not_deployed(ctx, KEY, state)

    findings: list[dict] = []
    tpms = _C.hardware(doc, "tpm")
    attest = params.get("attestation") or {}
    if tpms and attest.get("enabled") is False:
        findings.append(_C.finding(
            "high", "节点存在 TPM 但证明链被显式关闭",
            {"tpm": [t.get("id") for t in tpms], "attestation": attest},
            evidence="params attestation.enabled=false"))
    missing_ek = [t.get("id") for t in tpms if not (t.get("ek_sha256") or t.get("ek"))
                  and not any(str(f.get("path", "")).lower().find("ek") >= 0 for f in _C.files(doc))]
    if tpms and missing_ek:
        findings.append(_C.finding(
            "medium", "TPM 存在但缺少 EK/AK 或 PCR 基线证据",
            {"tpm": missing_ek[:50]}, evidence="no ek_sha256 / PCR baseline in export"))
    if tpms and not attest:
        findings.append(_C.finding(
            "info", "TPM 已采集但未提供 measured-boot 策略，证明链未验证",
            {"tpm": [t.get("id") for t in tpms][:50]},
            evidence="params attestation missing"))

    return _C.result(ctx, KEY, state, findings,
                     f"tpm={len(tpms)} attestation={bool(attest)} findings={len(findings)}",
                     {"tpm": [t.get("id") for t in tpms][:50]})
