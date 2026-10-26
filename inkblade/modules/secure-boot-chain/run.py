# -*- coding: utf-8 -*-
"""安全启动 + TPM 测量链 + UKI 签名（只读导出解析）。

输入（params.snapshot）：
```
{
  "secure_boot": true, "setup_mode": false, "eventlog_verified": true,
  "pcrs": {"0": "hex", "4": "hex", "7": "hex", "11": "hex"},
  "baseline": {"0": "hex", "4": "hex", "7": "hex", "11": "hex"},
  "dbx": {"present": true, "entries": 1234, "updated": "2026-10-01"},
  "tpm": {"version": "2.0", "pcr_bank": "sha256"},
  "uki": {"path": "...", "content_b64": "...", "signature_b64": "...",
          "public_key_pem": "...", "algorithm": "rsa-sha256",
          "authenticode_verified": true}
}
```

判定：
- Secure Boot 关闭/Setup Mode、eventlog 重放失败、PCR 与 golden 基线不一致 → high；
- dbx 缺失 → high；dbx 过旧、缺 golden 基线、缺 UKI 证据、PCR bank 非 SHA-256 → medium；
- UKI 未签名/签名校验失败/弱算法 → high。

UKI 签名口径（重要）：
- 本模块可以用 pinned 公钥验证 **detached raw 签名**（RSA PKCS#1 v1.5 / ECDSA raw r||s）；
- 真实 systemd-stub/UKI 使用 PE Authenticode/PKCS#7，本仓库**不实现** PKCS#7；
  若客户提供 `authenticode_verified`（来自 sbverify/pesign 等外部验证器），本模块只把它
  记为 `reported` 证据，并明确不把它当成本地密码学校验。
只读：不扩展 PCR、不重置 TPM、不写 NVRAM、不执行 sbverify。
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

from inkblade.tee._asn1 import DerError  # noqa: E402
from inkblade.tee.keys import (ALG_ECDSA_SHA256, ALG_ECDSA_SHA384, ALG_RSA_SHA256,  # noqa: E402
                              PublicKey)

KEY = "secure-boot-chain"

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


def _alg(value: str) -> str:
    key = str(value or "rsa-sha256").lower().replace("_", "-").replace(" ", "")
    return _ALGS.get(key, _ALGS.get(key.replace("-", ""), ""))


def _pcr_map(value) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(k): _C.norm_hex(v) for k, v in value.items()}


def _content(uki: dict) -> bytes:
    if uki.get("content_b64"):
        return _C.b64decode_any(uki["content_b64"])
    if uki.get("content") is not None:
        return str(uki["content"]).encode("utf-8")
    if uki.get("path"):
        return Path(str(uki["path"])).read_bytes()
    return b""


def _signature(uki: dict) -> bytes:
    if uki.get("signature_b64"):
        return _C.b64decode_any(uki["signature_b64"])
    if uki.get("signature") and uki.get("signature_path") is None:
        text = str(uki["signature"])
        if len(text) > 64 and "\n" not in text:
            try:
                return _C.b64decode_any(text)
            except ValueError:
                pass
    if uki.get("signature_file"):
        return Path(str(uki["signature_file"])).read_bytes()
    return b""


def _public_key(uki: dict):
    pem = uki.get("public_key_pem")
    if not pem and uki.get("public_key_file"):
        pem = Path(str(uki["public_key_file"])).read_text(encoding="utf-8")
    if not pem:
        return None
    try:
        return PublicKey.from_pem(str(pem))
    except (DerError, ValueError):
        return None


def _dbx_age_days(dbx: dict) -> int | None:
    updated = dbx.get("updated")
    if not updated:
        return None
    try:
        date = datetime.fromisoformat(str(updated).replace("Z", "+00:00"))
    except ValueError:
        return None
    if date.tzinfo is None:
        date = date.replace(tzinfo=timezone.utc)
    return max(0, int((datetime.now(timezone.utc) - date).total_seconds() // 86400))


def run(ctx: dict, params: dict) -> dict:
    doc, source = _C.load_snapshot(params)
    secure_boot = bool(doc.get("secure_boot"))
    setup_mode = bool(doc.get("setup_mode"))
    eventlog_verified = bool(doc.get("eventlog_verified"))
    pcrs = _pcr_map(doc.get("pcrs") or doc.get("pcr_values"))
    baseline = _pcr_map(doc.get("baseline") or doc.get("golden_pcrs"))
    dbx = doc.get("dbx") if isinstance(doc.get("dbx"), dict) else {}
    tpm = doc.get("tpm") if isinstance(doc.get("tpm"), dict) else {}
    uki = doc.get("uki") if isinstance(doc.get("uki"), dict) else {}

    findings: list[dict] = []
    mismatches: list[str] = []
    for key, expected in baseline.items():
        actual = pcrs.get(key, "")
        if not actual or actual != expected:
            mismatches.append(key)

    if not secure_boot or setup_mode:
        findings.append(_C.finding(
            "high", "Secure Boot 未启用或处于 Setup Mode",
            {"detected": True, "secure_boot": secure_boot, "setup_mode": setup_mode},
            mapping="UEFI Secure Boot / KEK/db/dbx",
            fix="启用 Secure Boot、退出 Setup Mode 并核对 db/dbx",
        ))
    if not eventlog_verified:
        findings.append(_C.finding(
            "high", "TPM 事件日志重放校验失败",
            {"detected": True, "eventlog_verified": eventlog_verified,
             "pcr_bank": tpm.get("pcr_bank")},
            mapping="TCG PC Client Platform Firmware Profile / eventlog replay",
            fix="重放 eventlog 到 PCR；不一致时拒绝远程证明/解密密钥释放",
        ))
    if baseline and mismatches:
        findings.append(_C.finding(
            "high", "PCR 测量值与 golden 基线不一致",
            {"detected": True, "pcr_mismatches": mismatches,
             "pcrs": {k: pcrs.get(k, "") for k in mismatches},
             "baseline": {k: baseline.get(k, "") for k in mismatches}},
            evidence=f"pcr_mismatches={mismatches}",
            mapping="TPM PCR 0/4/7/11 / measured boot",
            fix="核对固件/引导器/UKI 变更；更新 golden 基线只能走变更窗口",
        ))
    if not baseline:
        findings.append(_C.finding(
            "medium", "缺少 golden PCR 基线",
            {"detected": True, "pcr_bank": tpm.get("pcr_bank")},
            fix="为每个硬件/固件组合采集并签名 golden PCR 基线",
        ))
    if dbx.get("present") is False:
        findings.append(_C.finding(
            "high", "UEFI dbx 撤销库缺失",
            {"detected": True, "dbx": dbx},
            mapping="UEFI Revocation List / dbx",
            fix="应用厂商/微软 dbx 撤销列表；离线环境定期导入",
        ))
    age = _dbx_age_days(dbx)
    max_age = int(doc.get("dbx_max_age_days") or dbx.get("max_age_days") or 365)
    if age is not None and age > max_age:
        findings.append(_C.finding(
            "medium", "UEFI dbx 撤销库过旧",
            {"detected": True, "dbx_age_days": age, "max_age_days": max_age,
             "updated": dbx.get("updated")},
            fix="在变更窗口更新 dbx，并验证已知 bootkit 哈希已被撤销",
        ))
    if str(tpm.get("pcr_bank") or "").lower() not in ("", "sha256"):
        findings.append(_C.finding(
            "medium", "TPM PCR bank 非 SHA-256",
            {"detected": True, "pcr_bank": tpm.get("pcr_bank")},
            fix="使用 SHA-256 PCR bank；禁用 SHA-1 bank",
        ))

    uki_mode = "none"
    uki_valid = False
    uki_weak = False
    if uki:
        content = _content(uki)
        signature = _signature(uki)
        key = _public_key(uki)
        algorithm = str(uki.get("algorithm") or "rsa-sha256")
        if not content:
            findings.append(_C.finding(
                "medium", "缺少 UKI 内容（无法校验证书签名）",
                {"detected": True, "uki": {k: v for k, v in uki.items()
                                            if k not in ("content_b64", "signature_b64",
                                                         "public_key_pem")}},
                fix="导出 UKI 本体或其 SHA-256 与签名",
            ))
        if any(x in algorithm.lower() for x in ("sha1", "md5")):
            uki_weak = True
            findings.append(_C.finding(
                "high", "UKI 使用弱签名算法",
                {"detected": True, "algorithm": algorithm},
                fix="使用 SHA-256+ 的 RSA/ECDSA 签名；撤销 SHA-1 签名",
            ))
        elif uki.get("signed") is False or (not signature and not uki.get("authenticode_verified")):
            findings.append(_C.finding(
                "high", "UKI 未签名",
                {"detected": True, "signed": uki.get("signed"), "algorithm": algorithm},
                fix="对 UKI 做 Authenticode 签名并注册到 Secure Boot db",
            ))
        elif signature and key and content:
            alg = _alg(algorithm)
            if not alg:
                findings.append(_C.finding(
                    "medium", "UKI 签名算法无法识别",
                    {"detected": True, "algorithm": algorithm},
                    fix="使用 rsa-sha256 / ecdsa-sha256 / ecdsa-sha384 detached 签名",
                ))
            else:
                uki_valid = bool(key.verify(alg, content, signature))
                uki_mode = "local-detached"
                if not uki_valid:
                    findings.append(_C.finding(
                        "high", "UKI 签名校验失败",
                        {"detected": True, "algorithm": algorithm,
                         "content_bytes": len(content), "signature_bytes": len(signature),
                         "verification": uki_mode},
                        evidence="detached signature verify failed",
                        mapping="UKI detached raw signature (RSA/ECDSA)",
                        fix="拒绝该 UKI；重建/重签并在 Secure Boot db 中核对证书",
                    ))
        elif not key and signature:
            findings.append(_C.finding(
                "medium", "缺少 UKI 公钥/证书（无法校验签名）",
                {"detected": True, "algorithm": algorithm},
                fix="提供 pinned 公钥/证书；不要只信任签名存在",
            ))
        if uki.get("authenticode_verified") is not None:
            reported = bool(uki.get("authenticode_verified"))
            if uki_mode == "none":
                uki_mode = "reported"
            if not reported:
                findings.append(_C.finding(
                    "high", "UKI Authenticode 外部验证失败",
                    {"detected": True, "verification": "reported",
                     "authenticode_verified": reported},
                    fix="用 sbverify/pesign 重新验证 UKI 的 PE Authenticode 签名",
                ))
            elif uki_mode == "none":
                uki_valid = True
    else:
        findings.append(_C.finding(
            "medium", "未提供 UKI 签名证据",
            {"detected": True},
            fix="提供 UKI 本体+签名，或 sbverify/pesign 的 Authenticode 验证结果",
        ))

    extra = {
        "secure_boot": secure_boot,
        "setup_mode": setup_mode,
        "eventlog_verified": eventlog_verified,
        "pcr_bank": tpm.get("pcr_bank"),
        "pcr_mismatches": len(mismatches),
        "mismatched_pcrs": mismatches,
        "baseline_entries": len(baseline),
        "dbx_age_days": age,
        "dbx_present": dbx.get("present"),
        "uki_signature_mode": uki_mode,
        "uki_signature_valid": uki_valid,
        "uki_weak_algorithm": uki_weak,
    }
    summary = _C.summary_json("安全启动/TPM/UKI 链", findings, extra=extra, source=source)
    artifact = _C.write_artifact(ctx, f"{KEY}.json", {
        "summary": json.loads(summary), "pcrs": pcrs, "baseline": baseline,
        "uki": {k: v for k, v in uki.items()
                if k not in ("content_b64", "signature_b64", "public_key_pem")},
        "findings": findings,
    })
    return {"summary": summary, "artifacts": artifact, "findings": findings}
