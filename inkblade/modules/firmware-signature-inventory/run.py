# -*- coding: utf-8 -*-
"""固件签名清单核验（厂商 X.509 链 + 分离签名，非 HMAC 占位）。

输入（params.manifest）：
```
{
  "vendor": "NVIDIA",
  "trust_root_pem": "-----BEGIN CERTIFICATE-----…",   # pinned root
  "revoked_serials": [4660],
  "components": [
    {"name": "gpu-vbios", "kind": "firmware", "file": "vbios.bin",
     "sha256": "…", "signature_b64": "…", "chain_pem": "leaf PEM",
     "algorithm": "ecdsa-sha256", "serial": 4097, "vendor": "NVIDIA",
     "version": "96.00.89.00.01"},
    {"name": "cpu-microcode", "kind": "microcode", "content_b64": "…",
     "signature_b64": "…", "chain_pem": "leaf PEM", "sha256": "…",
     "version": "0x2", "min_version": "0x2e"}
  ]
}
```

核验：
- 组件实际 sha256 与清单一致；
- 分离签名用 leaf 公钥做真实非对称验签（RSA PKCS#1 v1.5 / ECDSA raw r||s）；
- leaf→root 链签名/有效期/CA 位，root 必须是显式 pinned；
- 弱算法（SHA-1/MD5）、未签名、缺信任根、证书吊销 serial；
- microcode 组件按厂商安全基线比较 revision。

边界：只读取客户导出/离线清单；不刷新固件、不写设备。与
``hardware-supply-chain`` 的 HMAC fixture 不同，本模块不接受共享密钥占位。
"""
from __future__ import annotations

import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

_REPO = Path(__file__).resolve().parents[3]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_chip_common", _PARENT / "_chip-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

from trident.tee._asn1 import DerError  # noqa: E402
from trident.tee.keys import (ALG_ECDSA_SHA256, ALG_ECDSA_SHA384, ALG_RSA_SHA256,  # noqa: E402
                              PublicKey)
from trident.tee.x509 import (load_certificates_pem, parse_certificate,  # noqa: E402
                              verify_chain)

KEY = "firmware-signature-inventory"
_ALGS = {
    "rsa-sha256": ALG_RSA_SHA256,
    "rsasha256": ALG_RSA_SHA256,
    "sha256withrsaencryption": ALG_RSA_SHA256,
    "rsa-pkcs1-sha256": ALG_RSA_SHA256,
    "ecdsa-sha256": ALG_ECDSA_SHA256,
    "ecdsasha256": ALG_ECDSA_SHA256,
    "ecdsa-sha384": ALG_ECDSA_SHA384,
    "ecdsasha384": ALG_ECDSA_SHA384,
}


def _alg(value) -> str:
    key = str(value or "ecdsa-sha256").lower().replace("_", "-").replace(" ", "")
    return _ALGS.get(key, _ALGS.get(key.replace("-", ""), ""))


def _read_pem(value, base: Path) -> tuple[str, str]:
    text = str(value or "")
    if not text:
        return "", ""
    path = Path(text)
    if "\n" not in text and path.is_file():
        return path.read_text(encoding="utf-8"), str(path)
    if "\n" not in text and (base / text).is_file():
        candidate = base / text
        return candidate.read_text(encoding="utf-8"), str(candidate)
    return text, "<inline pem>"


def _content(comp: dict, base: Path) -> tuple[bytes, str]:
    if comp.get("content_b64"):
        return _C.b64decode_any(comp["content_b64"]), "<content_b64>"
    rel = str(comp.get("file") or "")
    if not rel:
        return b"", ""
    path = (base / rel).resolve()
    try:
        path.relative_to(base.resolve())
    except ValueError:
        return b"", f"path-escape:{rel}"
    if not path.is_file():
        return b"", rel
    return path.read_bytes(), rel


def _signature(comp: dict, base: Path) -> bytes:
    if comp.get("signature_b64"):
        return _C.b64decode_any(comp["signature_b64"])
    if comp.get("signature_file"):
        return Path(str(comp["signature_file"])).read_bytes()
    value = comp.get("signature")
    if isinstance(value, str) and value:
        if "\n" not in value and (base / value).is_file():
            return (base / value).read_bytes()
        try:
            return _C.b64decode_any(value)
        except ValueError:
            return b""
    return b""


def _chain(comp: dict, base: Path, manifest: dict):
    chain_pem, chain_src = _read_pem(comp.get("chain_pem") or comp.get("chain_file"), base)
    root_pem, root_src = _read_pem(
        comp.get("trust_root_pem") or manifest.get("trust_root_pem")
        or manifest.get("trust_root_file"), base)
    chain = []
    if chain_pem:
        try:
            chain = load_certificates_pem(chain_pem)
        except (DerError, ValueError):
            chain = []
    root = None
    if root_pem:
        try:
            root = load_certificates_pem(root_pem)[-1]
        except (DerError, ValueError):
            root = None
    if root is None and chain and chain[-1].is_ca and chain[-1].verify_self_signed():
        root = chain.pop()
    return chain, root, chain_src, root_src


def _sig_ok(chain: list, public_key_pem: str, alg: str, content: bytes, sig: bytes) -> bool:
    key = None
    if chain:
        key = chain[0].public_key
    elif public_key_pem:
        try:
            key = PublicKey.from_pem(public_key_pem)
        except (DerError, ValueError):
            key = None
    if key is None or not sig or not content:
        return False
    alg_oid = _alg(alg)
    if not alg_oid:
        return False
    return bool(key.verify(alg_oid, content, sig))


def run(ctx: dict, params: dict) -> dict:
    manifest, base, source = _C.load_manifest(params)
    components = [c for c in manifest.get("components") or [] if isinstance(c, dict)]
    now = datetime.fromtimestamp(_C.now_ts(params), tz=timezone.utc)
    revoked = {_C.int_of(x, -1) for x in manifest.get("revoked_serials") or []}
    findings: list[dict] = []

    verified = 0
    missing: list[str] = []
    hash_mismatch: list[dict] = []
    invalid_signature: list[str] = []
    expired: list[str] = []
    unsigned: list[str] = []
    weak_algo: list[str] = []
    revoked_hits: list[str] = []
    microcode_stale: list[dict] = []
    chain_errors: dict[str, list[str]] = {}
    trust_root_pinned = False
    root_cn = ""

    for comp in components:
        name = str(comp.get("name") or comp.get("file") or "?")
        content, content_ref = _content(comp, base)
        if not content:
            missing.append(name)
            continue
        expected = _C.norm_hex(comp.get("sha256") or "")
        actual = _C.sha256_hex(content)
        hash_ok = bool(expected) and actual == expected
        if expected and not hash_ok:
            hash_mismatch.append({"name": name, "expected": expected, "actual": actual,
                                  "file": content_ref})

        chain, root, chain_src, root_src = _chain(comp, base, manifest)
        if root is not None and root.is_ca:
            trust_root_pinned = trust_root_pinned or bool(root_src and root_src != "<inline pem>")
            trust_root_pinned = trust_root_pinned or bool(
                comp.get("trust_root_pem") or manifest.get("trust_root_pem")
                or comp.get("trust_root_file") or manifest.get("trust_root_file"))
            root_cn = root.subject_cn or root_cn
            errors = verify_chain(chain, root, now=now)
        else:
            errors = ["未提供 pinned 信任锚"]
            for cert in chain:
                if not cert.is_valid_at(now):
                    errors.append(
                        f"{cert.subject_cn or '<leaf>'}: 证书不在有效期内"
                        f"（{cert.not_before:%Y-%m-%d}~{cert.not_after:%Y-%m-%d}）")
        if errors:
            chain_errors[name] = errors
            if any("不在有效期" in e for e in errors):
                expired.append(name)

        algorithm = str(comp.get("algorithm") or "ecdsa-sha256")
        if any(x in algorithm.lower() for x in ("sha1", "md5")):
            weak_algo.append(name)
        signature = _signature(comp, base)
        public_key_pem, _ = _read_pem(comp.get("public_key_pem"), base)
        sig_ok = _sig_ok(chain, public_key_pem, algorithm, content, signature) if signature else False
        if not signature:
            unsigned.append(name)
        elif not sig_ok:
            invalid_signature.append(name)

        serial = _C.int_of(comp.get("serial"), -1)
        if serial >= 0 and serial in revoked:
            revoked_hits.append(name)
        if comp.get("vendor") and manifest.get("vendor") and comp.get("vendor") != manifest.get("vendor"):
            findings.append(_C.finding(
                "medium", "固件组件供应商与清单不一致",
                {"detected": True, "component": name, "vendor": comp.get("vendor"),
                 "manifest_vendor": manifest.get("vendor")},
                fix="核对厂商授权/来源；拒绝未知供应商组件",
            ))

        if comp.get("kind") == "microcode":
            current = comp.get("version") or comp.get("revision")
            minimum = comp.get("min_version") or comp.get("min_revision")
            if minimum is None:
                findings.append(_C.finding(
                    "medium", "微码组件缺少厂商安全基线",
                    {"detected": True, "component": name, "version": current},
                    fix="按厂商微码更新指南登记最低 revision",
                ))
            elif _C.int_of(current, -1) < _C.int_of(minimum, -1):
                microcode_stale.append({"name": name, "version": current,
                                        "min_version": minimum})
                findings.append(_C.finding(
                    "high", "CPU 微码版本低于安全基线",
                    {"detected": True, "component": name, "version": current,
                     "min_version": minimum},
                    evidence=f"{name}: {current} < {minimum}",
                    mapping="Intel/AMD microcode revision guidance",
                    fix="在变更窗口升级 BIOS/微码；升级后核对 revision 与侧信道缓解",
                ))

        if (hash_ok and sig_ok and not errors and name not in weak_algo
                and name not in revoked_hits):
            verified += 1

    if hash_mismatch:
        first = hash_mismatch[0]
        findings.append(_C.finding(
            "high", "固件哈希不匹配",
            {"detected": True, "components": [x["name"] for x in hash_mismatch],
             "mismatches": hash_mismatch,
             "expected_sha256": first["expected"], "actual_sha256": first["actual"]},
            evidence=f"sha256 mismatch: {[x['name'] for x in hash_mismatch]}",
            mapping="NIST SP 800-193 firmware integrity",
            fix="拒绝该固件；从厂商可信渠道重取并核对签名/哈希",
        ))
    if invalid_signature:
        findings.append(_C.finding(
            "high", "固件签名无效",
            {"detected": True, "components": invalid_signature,
             "invalid_components": invalid_signature,
             "chain_errors": {k: chain_errors.get(k, []) for k in invalid_signature}},
            evidence=f"asymmetric verify failed: {invalid_signature}",
            mapping="Vendor X.509 chain + detached signature (RSA/ECDSA)",
            fix="拒绝该固件；核对厂商证书链/公钥指纹与签名工具",
        ))
    if expired:
        findings.append(_C.finding(
            "high", "固件签名证书链无效/过期",
            {"detected": True, "components": expired,
             "errors": {k: chain_errors.get(k, []) for k in expired}},
            evidence=f"expired/invalid chain: {expired}",
            mapping="X.509 validity / vendor PKI",
            fix="使用有效期内证书重签；轮换证书并更新 pinned 根",
        ))
    if not trust_root_pinned:
        findings.append(_C.finding(
            "high", "固件信任根未固定",
            {"detected": True, "trust_root": root_cn,
             "components": [str(c.get("name") or "?") for c in components]},
            fix="把厂商根证书/公钥指纹固定到设备或审计策略；拒绝动态信任任意根",
        ))
    if weak_algo:
        findings.append(_C.finding(
            "high", "固件使用弱签名算法",
            {"detected": True, "components": weak_algo},
            fix="迁移到 SHA-256+ RSA/ECDSA/Ed25519；撤销 SHA-1 签名",
        ))
    if unsigned:
        findings.append(_C.finding(
            "high", "固件组件未签名",
            {"detected": True, "components": unsigned},
            fix="要求每个组件有厂商分离签名/签名者标识",
        ))
    if revoked_hits:
        findings.append(_C.finding(
            "high", "固件证书已吊销",
            {"detected": True, "components": revoked_hits,
             "revoked_serials": sorted(revoked)},
            fix="拒绝已吊销证书签发的固件；轮换签名密钥",
        ))
    if missing:
        findings.append(_C.finding(
            "high", "固件组件缺失",
            {"detected": True, "components": missing},
            fix="补齐清单中的固件或从清单移除；不得跳过缺失项",
        ))

    extra = {
        "vendor": manifest.get("vendor", ""),
        "components": len(components),
        "verified": verified,
        "missing": len(missing),
        "hash_mismatch": len(hash_mismatch),
        "invalid_signature": len(invalid_signature),
        "invalid_components": invalid_signature,
        "expired": len(expired),
        "unsigned": len(unsigned),
        "weak_algo": len(weak_algo),
        "revoked": len(revoked_hits),
        "microcode_stale": len(microcode_stale),
        "trust_root_pinned": trust_root_pinned,
        "trust_root": root_cn,
    }
    summary = _C.summary_json("固件签名清单", findings, extra=extra, source=source)
    artifact = _C.write_artifact(ctx, f"{KEY}.json", {
        "summary": json.loads(summary), "components": components, "findings": findings,
    })
    return {"summary": summary, "artifacts": artifact, "findings": findings}
