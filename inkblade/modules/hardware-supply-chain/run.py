# -*- coding: utf-8 -*-
"""固件签名/哈希清单核验（fixture 驱动，只读）。

输入：
- params.manifest = 固件清单 JSON 路径或 dict（components[].file/sha256/signed_by/vendor）；
- params.blobs_dir = 实际固件目录（缺省为 manifest 所在目录）；
- params.key_file / params.hmac_key = fixture HMAC 密钥（可选；生产应换厂商非对称签名）。

核验：
- 清单 HMAC 签名（fixture 口径）；签名无效 → high；
- 每个组件实际 sha256 与清单不一致 → high（tampered_components）；
- 组件缺失 → high；路径越界 / 哈希格式无效 / 缺签名者 / 供应商不一致 → medium。

只读：不刷新固件、不写设备；不把 HMAC fixture 冒充厂商 PKI。
"""
from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import re
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_hardware_common", _PARENT / "_hardware-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "hardware-supply-chain"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def canonical_manifest(manifest: dict) -> str:
    payload = {k: v for k, v in manifest.items() if k != "signature"}
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sign_manifest(manifest: dict, key: str) -> str:
    return hmac.new(key.encode("utf-8"), canonical_manifest(manifest).encode("utf-8"),
                    hashlib.sha256).hexdigest()


def _load_inputs(params: dict) -> tuple[dict, Path, str]:
    raw = params.get("manifest")
    if raw is None:
        raise ValueError("缺少 params.manifest（固件清单 JSON）")
    if isinstance(raw, dict):
        manifest = raw
        base = Path(params.get("blobs_dir") or ".")
    else:
        path = Path(str(raw))
        manifest = json.loads(path.read_text(encoding="utf-8"))
        base = Path(params.get("blobs_dir") or path.parent)
    key = str(params.get("hmac_key") or "")
    if params.get("key_file"):
        key = _C.read_text_file(params["key_file"])
    return manifest, base, key


def run(ctx: dict, params: dict) -> dict:
    manifest, base, key = _load_inputs(params)
    components = [c for c in manifest.get("components") or [] if isinstance(c, dict)]
    findings: list[dict] = []
    base_resolved = base.resolve()

    signature_status = "unchecked"
    signature_checked = bool(key)
    if key:
        expected_sig = sign_manifest(manifest, key)
        actual_sig = str(manifest.get("signature") or "")
        valid = hmac.compare_digest(expected_sig, actual_sig)
        signature_status = "valid" if valid else "invalid"
        if not valid:
            findings.append(_C.finding(
                "high", "固件清单签名无效",
                {"detected": True, "signature_status": "invalid",
                 "key_id": (manifest.get("signing") or {}).get("key_id", ""),
                 "expected_sha256": expected_sig, "actual_sha256": actual_sig},
                evidence="manifest HMAC signature mismatch",
                mapping="固件清单签名（fixture HMAC；生产用厂商非对称签名）",
                fix="拒绝该固件清单；从厂商可信渠道重取并核对公钥指纹/签名链",
            ))

    tampered: list[dict] = []
    missing: list[str] = []
    unsigned: list[str] = []
    vendor_mismatch: list[dict] = []
    invalid_hashes: list[str] = []
    path_escape: list[str] = []
    for comp in components:
        name = str(comp.get("name") or comp.get("file") or "?")
        rel = str(comp.get("file") or "")
        expected = str(comp.get("sha256") or "").lower()
        if not _HEX64.match(expected):
            invalid_hashes.append(name)
        if not comp.get("signed_by"):
            unsigned.append(name)
        if comp.get("vendor") and manifest.get("vendor") and comp.get("vendor") != manifest.get("vendor"):
            vendor_mismatch.append({"name": name, "component_vendor": comp.get("vendor"),
                                    "manifest_vendor": manifest.get("vendor")})
        if not rel:
            missing.append(name)
            continue
        candidate = (base / rel).resolve()
        try:
            candidate.relative_to(base_resolved)
        except ValueError:
            path_escape.append(name)
            continue
        if not candidate.is_file():
            missing.append(name)
            continue
        actual = _C.sha256_file(candidate)
        if actual != expected:
            tampered.append({"name": name, "file": rel, "expected_sha256": expected,
                             "actual_sha256": actual})
        comp["actual_sha256"] = actual
        comp["verified"] = actual == expected

    if tampered:
        first = tampered[0]
        findings.append(_C.finding(
            "high", "固件哈希不匹配",
            {"detected": True, "tampered_components": [t["name"] for t in tampered],
             "expected_sha256": first["expected_sha256"],
             "actual_sha256": first["actual_sha256"],
             "tampered": tampered},
            evidence=f"sha256 mismatch: {[t['name'] for t in tampered]}",
            mapping="固件完整性（供应链篡改/损坏）",
            fix="拒绝该固件；从厂商可信渠道重取，核对签名与哈希后再进入变更窗口",
        ))
    if missing:
        findings.append(_C.finding(
            "high", "固件组件缺失",
            {"detected": True, "missing_components": missing},
            fix="补齐清单中的固件或从清单移除；不得跳过缺失项",
        ))
    if path_escape:
        findings.append(_C.finding(
            "high", "固件清单路径越界",
            {"detected": True, "components": path_escape},
            fix="清单 file 必须是 blobs_dir 内相对路径；拒绝绝对路径/.. 越界",
        ))
    if invalid_hashes:
        findings.append(_C.finding(
            "medium", "固件哈希格式无效",
            {"detected": True, "components": invalid_hashes},
            fix="清单 sha256 必须是 64 位十六进制；修正生成流水线",
        ))
    if unsigned:
        findings.append(_C.finding(
            "medium", "固件组件缺少签名者",
            {"detected": True, "components": unsigned},
            fix="每个组件必须有厂商签名/签名者标识，纳入 provenance",
        ))
    if vendor_mismatch:
        findings.append(_C.finding(
            "medium", "固件供应商与清单不一致",
            {"detected": True, "mismatches": vendor_mismatch},
            fix="核对组件来源与厂商授权；拒绝未知供应商固件",
        ))

    verified = len([c for c in components if c.get("verified") is True])
    extra = {
        "schema": manifest.get("schema", ""),
        "vendor": manifest.get("vendor", ""),
        "components": len(components),
        "verified": verified,
        "tampered": len(tampered),
        "missing": len(missing),
        "signature_status": signature_status,
        "signature_checked": signature_checked,
        "tampered_components": [t["name"] for t in tampered],
        "missing_components": missing,
        "unsigned_components": unsigned,
        "vendor_mismatches": [m["name"] for m in vendor_mismatch],
        "invalid_hashes": invalid_hashes,
        "key_id": (manifest.get("signing") or {}).get("key_id", ""),
    }
    source = params.get("manifest") if isinstance(params.get("manifest"), str) else "<inline fixture>"
    summary = _C.summary_json("固件供应链核验", findings, extra=extra, source=source)
    artifact = _C.write_artifact(ctx, f"{KEY}.json", {
        "summary": json.loads(summary), "components": components, "findings": findings,
    })
    return {"summary": summary, "artifacts": artifact, "findings": findings}
