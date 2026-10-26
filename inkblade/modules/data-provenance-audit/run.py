# -*- coding: utf-8 -*-
"""数据/制品来源证明审计面（主动探测，只读）。

GET /provenance/attestation：
- 证明签名无效 → high；
- 缺少 SBOM 或 materials → high；
- SLSA 等级不足或未接入 Rekor → medium；
- 来源漂移 → medium。

只读：不签名、不上传 Rekor、不修改制品。
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_infra2026_common", _PARENT / "_infra2026-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "data-provenance-audit"


def run(ctx: dict, params: dict) -> dict:
    target = str(params.get("target") or "").rstrip("/")
    if not target:
        return _C.no_target()
    t = _C.Trace(ctx, KEY)
    entry = t.get(f"{target}/provenance/attestation")
    doc = _C.resp(entry)
    att = doc.get("attestation") or {}
    sbom = doc.get("sbom") or {}
    findings: list[dict] = []

    signature_valid = bool(att.get("signature_valid"))
    materials = _C.as_list(att.get("materials"))
    sbom_present = bool(sbom.get("present"))
    slsa = _C.as_int(att.get("slsa_level"))
    in_toto = bool(att.get("in_toto"))
    rekor = bool(att.get("rekor"))
    drift = bool(doc.get("drift"))

    if not signature_valid:
        findings.append(_C.finding(
            "high", "制品证明签名无效",
            {"detected": True, "signature_valid": signature_valid,
             "builder": att.get("builder"), "artifact": doc.get("artifact")},
            evidence=f"signature_valid={signature_valid} builder={att.get('builder')}",
            mapping="Sigstore/cosign / in-toto attestation",
            fix="重新生成并签名证明；准入拒绝签名无效制品",
        ))
    if not sbom_present or not materials:
        findings.append(_C.finding(
            "high", "缺少 SBOM 或来源材料",
            {"detected": True, "sbom_present": sbom_present,
             "materials": len(materials), "builder": att.get("builder")},
            evidence=f"sbom={sbom_present} materials={len(materials)}",
            mapping="SBOM / in-toto materials / 供应链可追溯",
            fix="构建时生成 SBOM 与 materials；与制品 digest 绑定",
        ))
    if slsa < 3 or not rekor or not in_toto:
        findings.append(_C.finding(
            "medium", "SLSA 等级不足或未接入 Rekor",
            {"detected": True, "slsa_level": slsa, "in_toto": in_toto, "rekor": rekor},
            evidence=f"slsa={slsa} in_toto={in_toto} rekor={rekor}",
            mapping="SLSA v1 / in-toto / Rekor 透明日志",
            fix="提升到 SLSA L3；in-toto 证明入 Rekor 并校验 inclusion proof",
        ))
    if drift:
        findings.append(_C.finding(
            "medium", "制品来源漂移",
            {"detected": True, "drift": drift, "artifact": doc.get("artifact")},
            evidence="drift=true",
            mapping="制品 digest 漂移 / 运行时完整性",
            fix="运行时校验 digest 与证明一致；发现漂移即隔离并重新部署",
        ))

    extra = {
        "artifact": doc.get("artifact"),
        "signature_valid": signature_valid,
        "sbom_present": sbom_present,
        "materials": len(materials),
        "slsa_level": slsa,
        "in_toto": in_toto,
        "rekor": rekor,
        "drift": drift,
        "status": entry.get("status"),
    }
    summary = _C.summary_json("来源证明审计面", findings, extra=extra, source=target)
    artifact = _C.write_artifact(ctx, f"{KEY}.json", {
        "summary": json.loads(summary), "provenance": doc, "findings": findings,
    })
    trace = t.dump()
    artifacts = ([str(trace)] if trace else []) + artifact
    return {"summary": summary, "artifacts": artifacts, "findings": findings}
