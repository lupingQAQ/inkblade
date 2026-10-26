# -*- coding: utf-8 -*-
"""SPDM over PCIe DOE 姿态核验（版本/证书链/测量摘要/会话）。

输入（params.export 或 params.snapshot）：
```
{
  "device": "0000:01:00.0",
  "spdm": {
    "version": "1.3.0", "mutual_auth": true, "session": true,
    "measurement_hash_algo": "sha384",
    "measurement_record_hex": "…原始 MeasurementRecord 字节…",
    "measurement_summary": "…设备报告的摘要…",
    "chain_pem": "leaf+intermediate PEM", "trust_anchor_pem": "pinned root PEM"
  },
  "pcie": {"doe": true, "tdisp": true, "ide": true}
}
```

判定：
- SPDM < 1.1：无安全会话/双向认证（high）；
- 证书链签名/有效期/CA 位失败（high，过期单列）；
- MeasurementRecord 重算摘要 ≠ 设备报告摘要（high）；
- PCIe DOE 未启用（high）；未启用双向认证（high）；无安全会话（medium）；
- IDE/TDISP 均未启用（medium）；证书链未绑定 pinned 信任锚（high）。

边界：只解析导出/fixture；不直接读 SPDM sysfs、不发 DOE 请求。
MeasurementRecord 必须由导出端提供原始字节；本模块不猜测 DMTF 字段布局。
只读。
"""
from __future__ import annotations

import hashlib
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
from inkblade.tee.x509 import (load_certificates_pem, parse_certificate,  # noqa: E402
                              verify_chain)

KEY = "spdm-pcie-doe"


def _algo_name(value: str) -> str:
    low = str(value or "sha384").lower().replace("-", "").replace("_", "")
    return {"sha384": "sha384", "sha512": "sha512", "sha256": "sha256"}.get(low, "sha384")


def _split_chain(chain_pem: str, trust_pem: str):
    chain = load_certificates_pem(chain_pem)
    root = parse_certificate(load_certificates_pem(trust_pem)[0].der) if trust_pem else None
    if root is None and chain and chain[-1].is_ca and chain[-1].verify_self_signed():
        root = chain.pop()
    return chain, root


def run(ctx: dict, params: dict) -> dict:
    doc, source = _C.load_snapshot(params, "export", "snapshot")
    spdm = doc.get("spdm") if isinstance(doc.get("spdm"), dict) else doc
    pcie = doc.get("pcie") if isinstance(doc.get("pcie"), dict) else {}

    version = str(spdm.get("version") or doc.get("version") or "")
    version_ok = not _C.version_lt(version, (1, 1)) if version else False
    mutual_auth = spdm.get("mutual_auth")
    session = spdm.get("session")
    doe = pcie.get("doe", spdm.get("doe"))
    ide = bool(pcie.get("ide", spdm.get("ide", False)))
    tdisp = bool(pcie.get("tdisp", spdm.get("tdisp", False)))

    findings: list[dict] = []
    chain_errors: list[str] = []
    chain_ok = False
    expired = False
    root_cn = ""
    chain_len = 0
    chain_pem = str(spdm.get("chain_pem") or "")
    trust_pem = str(spdm.get("trust_anchor_pem") or "")
    if not chain_pem:
        chain_errors.append("缺少 SPDM 证书链")
    else:
        try:
            chain, root = _split_chain(chain_pem, trust_pem)
            chain_len = len(chain)
            now_dt = datetime.fromtimestamp(_C.now_ts(params), tz=timezone.utc)
            if root is None:
                chain_errors.append("未提供 pinned 信任锚（无法完成链校验）")
                for cert in chain:
                    if not cert.is_valid_at(now_dt):
                        chain_errors.append(
                            f"{cert.subject_cn or '<leaf>'}: 证书不在有效期内"
                            f"（{cert.not_before:%Y-%m-%d}~{cert.not_after:%Y-%m-%d}）")
            else:
                root_cn = root.subject_cn
                chain_errors.extend(verify_chain(chain, root, now=now_dt))
            chain_ok = not chain_errors
            expired = any("不在有效期" in e for e in chain_errors)
        except (DerError, ValueError) as exc:
            chain_errors.append(f"证书链解析失败：{exc}")
    if not chain_ok:
        title = ("SPDM 证书已过期" if expired
                 else "SPDM 证书链校验失败")
        findings.append(_C.finding(
            "high", title,
            {"detected": True, "chain_length": chain_len, "trust_anchor": root_cn,
             "errors": chain_errors},
            evidence="; ".join(chain_errors),
            mapping="DMTF SPDM 1.x certificate chain / pinned trust anchor",
            fix="替换过期/无效证书并重新绑定厂商根；拒绝未固定根的设备身份",
        ))

    if version and not version_ok:
        findings.append(_C.finding(
            "high", "SPDM 版本过低（无安全会话/双向认证）",
            {"detected": True, "version": version, "minimum": "1.1"},
            evidence=f"spdm_version={version}",
            mapping="DMTF DSP0274 SPDM 1.1 secure session / mutual authentication",
            fix="升级设备固件/驱动到 SPDM 1.1+；优先 1.3+ 获取事件与多密钥支持",
        ))
    elif not version:
        findings.append(_C.finding(
            "medium", "未提供 SPDM 版本",
            {"detected": True},
            fix="导出 GET_VERSION/VERSION 或 sysfs spdm_version",
        ))

    if not mutual_auth:
        findings.append(_C.finding(
            "high", "SPDM 未启用双向认证",
            {"detected": True, "mutual_auth": mutual_auth},
            mapping="DMTF SPDM mutual authentication",
            fix="启用双向认证，要求设备证书与主机证书都验签",
        ))
    if not session:
        findings.append(_C.finding(
            "medium", "SPDM 未建立安全会话",
            {"detected": True, "session": session},
            mapping="DMTF SPDM secured messages / key exchange",
            fix="启用 SPDM 安全会话并对测量/固件更新通道加密",
        ))
    if doe is False:
        findings.append(_C.finding(
            "high", "PCIe DOE 未启用（SPDM 无法在带内完成组件认证）",
            {"detected": True, "doe": doe, "device": doc.get("device", "")},
            evidence="pcie.doe=false",
            mapping="PCI-SIG Data Object Exchange (DOE) / CMA-SPDM",
            fix="启用 PCIe DOE 扩展能力；确认固件与内核 SPDM/CMA 支持",
        ))
    if not ide and not tdisp:
        findings.append(_C.finding(
            "medium", "PCIe IDE/TDISP 未启用（设备数据路径未加密/未隔离）",
            {"detected": True, "ide": ide, "tdisp": tdisp},
            mapping="PCI-SIG IDE / TDISP / TEE-IO",
            fix="机密 VM + 直通设备场景启用 IDE/TDISP；核对 TSM/DSM 配置",
        ))

    summary = ""
    summary_match = False
    record_hex = spdm.get("measurement_record_hex") or ""
    reported = _C.norm_hex(spdm.get("measurement_summary") or "")
    if record_hex:
        record = _C.hex_bytes(record_hex)
        algo = _algo_name(spdm.get("measurement_hash_algo"))
        computed = hashlib.new(algo, record).hexdigest()
        summary_match = bool(reported) and computed == reported
        if not reported:
            findings.append(_C.finding(
                "medium", "缺少 SPDM 设备测量摘要",
                {"detected": True, "record_bytes": len(record), "computed": computed},
                fix="导出 GET_MEASUREMENTS 的 MeasurementSummaryHash",
            ))
        elif not summary_match:
            findings.append(_C.finding(
                "high", "SPDM 测量摘要不一致",
                {"detected": True, "algo": algo, "record_bytes": len(record),
                 "computed_summary": computed, "reported_summary": reported},
                evidence=f"computed={computed[:16]}… reported={reported[:16]}…",
                mapping="DMTF SPDM MeasurementRecord / MeasurementSummaryHash",
                fix="拒绝该设备；重取测量并核对固件/RIM 基线",
            ))
        summary = computed
    else:
        findings.append(_C.finding(
            "medium", "缺少 SPDM MeasurementRecord（无法复核测量摘要）",
            {"detected": True, "reported_summary": reported},
            fix="导出原始 MeasurementRecord 字节，而不是只导出摘要",
        ))

    if not trust_pem and chain_ok:
        findings.append(_C.finding(
            "high", "SPDM 证书链未绑定信任锚",
            {"detected": True, "trust_anchor_pinned": False},
            fix="把厂商根证书固定到设备/平台策略；拒绝动态信任任意根",
        ))

    extra = {
        "device": doc.get("device", ""),
        "version": version,
        "version_ok": version_ok,
        "chain_ok": chain_ok,
        "chain_length": chain_len,
        "cert_expired": expired,
        "trust_anchor": root_cn,
        "trust_anchor_pinned": bool(trust_pem),
        "doe": doe,
        "mutual_auth": mutual_auth,
        "session": session,
        "ide": ide,
        "tdisp": tdisp,
        "measurement_match": summary_match,
        "measurement_summary": reported,
        "computed_summary": summary,
        "expected_measurement_summary": _C.norm_hex(
            spdm.get("expected_measurement_summary") or ""),
        "chain_errors": chain_errors,
    }
    summary_doc = _C.summary_json("SPDM/PCIe DOE 姿态", findings,
                                  extra=extra, source=source)
    artifact = _C.write_artifact(ctx, f"{KEY}.json", {
        "summary": json.loads(summary_doc), "spdm": spdm, "pcie": pcie,
        "findings": findings,
    })
    return {"summary": summary_doc, "artifacts": artifact, "findings": findings}
