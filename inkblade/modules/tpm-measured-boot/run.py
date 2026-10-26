# -*- coding: utf-8 -*-
"""TPM 测量启动与证明面（只读侦察）。

GET /tpm/eventlog：
- Secure Boot/Measured Boot 未启用 → high；
- PCR 测量值不匹配 → high；
- SHA-1 PCR bank 或证明密钥未保护 → medium。

只读：不扩展 PCR、不重置 TPM、不写 NVRAM。
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_infra2026_common", _PARENT / "_infra2026-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "tpm-measured-boot"


def run(ctx: dict, params: dict) -> dict:
    target = str(params.get("target") or "").rstrip("/")
    if not target:
        return _C.no_target()
    t = _C.Trace(ctx, KEY)
    entry = t.get(f"{target}/tpm/eventlog")
    doc = _C.resp(entry)
    findings: list[dict] = []

    secure = bool(doc.get("secure_boot"))
    measured = bool(doc.get("measured_boot"))
    mismatches = [str(x) for x in _C.as_list(doc.get("pcr_mismatches"))]
    bank = str(doc.get("pcr_bank") or "")
    verified = bool(doc.get("eventlog_verified"))
    key_protected = bool(doc.get("attestation_key_protected"))

    if not secure or not measured:
        findings.append(_C.finding(
            "high", "Secure Boot/Measured Boot 未启用",
            {"detected": True, "secure_boot": secure, "measured_boot": measured,
             "tpm_version": doc.get("tpm_version")},
            evidence=f"secure_boot={secure} measured_boot={measured}",
            mapping="UEFI Secure Boot / TCG measured boot",
            fix="启用 Secure Boot 与 measured boot；将 PCR 纳入远程证明策略",
        ))
    if mismatches or not verified:
        findings.append(_C.finding(
            "high", "TPM PCR 测量值不匹配",
            {"detected": True, "pcr_mismatches": mismatches,
             "eventlog_verified": verified},
            evidence=f"pcr_mismatches={mismatches} verified={verified}",
            mapping="TPM PCR / eventlog replay / remote attestation",
            fix="比对 golden PCR 基线；事件日志重放校验失败即拒绝启动证明",
        ))
    if bank.lower() != "sha256" or not key_protected:
        findings.append(_C.finding(
            "medium", "TPM 使用 SHA-1 PCR bank 或证明密钥未保护",
            {"detected": True, "pcr_bank": bank,
             "attestation_key_protected": key_protected},
            evidence=f"pcr_bank={bank} key_protected={key_protected}",
            mapping="TPM 2.0 PCR bank / AK 保护",
            fix="使用 SHA-256 bank；AK 绑定 TPM 并设置迁移限制",
        ))

    extra = {
        "tpm_version": doc.get("tpm_version"),
        "secure_boot": secure,
        "measured_boot": measured,
        "pcr_bank": bank,
        "pcr_mismatches": len(mismatches),
        "eventlog_verified": verified,
        "status": entry.get("status"),
    }
    summary = _C.summary_json("TPM 测量启动面", findings, extra=extra, source=target)
    artifact = _C.write_artifact(ctx, f"{KEY}.json", {
        "summary": json.loads(summary), "tpm": doc, "findings": findings,
    })
    trace = t.dump()
    artifacts = ([str(trace)] if trace else []) + artifact
    return {"summary": summary, "artifacts": artifacts, "findings": findings}
