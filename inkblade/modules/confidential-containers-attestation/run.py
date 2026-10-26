# -*- coding: utf-8 -*-
"""CoCo/Kata/SEV-SNP 容器证明面（主动探测，只读）。

GET /coco/attestation + /coco/policy：
- 证明测量值与预期不一致 → high；
- 未强制证明或 allowed_images 含 * → high；
- SNP debug 开启 / report_data 未绑定 / 报告未签名 → medium。

只读：不向 TEE、KBS 或 Kata runtime 写入任何策略。
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_infra2026_common", _PARENT / "_infra2026-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "confidential-containers-attestation"


def run(ctx: dict, params: dict) -> dict:
    target = str(params.get("target") or "").rstrip("/")
    if not target:
        return _C.no_target()
    t = _C.Trace(ctx, KEY)
    att_entry = t.get(f"{target}/coco/attestation")
    pol_entry = t.get(f"{target}/coco/policy")
    att, pol = _C.resp(att_entry), _C.resp(pol_entry)
    findings: list[dict] = []

    measurement = str(att.get("measurement") or "")
    expected = str(att.get("expected_measurement") or "")
    measurement_matches = bool(measurement and expected and measurement == expected)
    snp = att.get("snp_policy") or {}
    debug = bool(snp.get("debug"))
    binding = bool(att.get("report_data_binding"))
    signed = bool(att.get("signed"))
    require = bool(pol.get("require_attestation"))
    allowed = [str(x) for x in _C.as_list(pol.get("allowed_images"))]
    wildcard = "*" in allowed
    policy_enforced = require and not wildcard
    initdata = bool(pol.get("initdata_verified"))

    if att_entry.get("status") == 200 and not measurement_matches:
        findings.append(_C.finding(
            "high", "CoCo 证明测量值不匹配",
            {"detected": True, "tee": att.get("tee"), "measurement": measurement,
             "expected_measurement": expected, "guest_svn": att.get("guest_svn")},
            evidence=f"GET /coco/attestation -> 200 measurement={measurement[:24]}…",
            mapping="CoCo/Kata + SEV-SNP SNP_LAUNCH_MEASURE / KBS 证明策略",
            fix="重新以 expected measurement 启动 Kata VM；拒绝不匹配证明并轮换 KBS 策略",
        ))
    if pol_entry.get("status") == 200 and not policy_enforced:
        findings.append(_C.finding(
            "high", "CoCo 未强制证明或允许任意镜像",
            {"detected": True, "require_attestation": require,
             "allowed_images": allowed, "runtime_class": pol.get("runtime_class"),
             "initdata_verified": initdata},
            evidence=f"GET /coco/policy -> require_attestation={require} allowed_images={allowed}",
            mapping="Confidential Containers admission / initdata 校验",
            fix="require_attestation=true；allowed_images 固定到 digest；启用 initdata 校验",
        ))
    if debug or not binding:
        findings.append(_C.finding(
            "medium", "CoCo TEE debug 开启或 report_data 未绑定",
            {"detected": True, "debug": debug, "report_data_binding": binding,
             "snp_policy": snp},
            evidence=f"snp_policy.debug={debug} report_data_binding={binding}",
            mapping="SEV-SNP policy / attestation report_data (nonce 绑定)",
            fix="关闭 SNP debug；将 nonce/工作负载公钥绑定到 report_data",
        ))
    if att_entry.get("status") == 200 and not signed:
        findings.append(_C.finding(
            "medium", "CoCo 证明报告未签名",
            {"detected": True, "signed": signed, "tee": att.get("tee")},
            evidence="attestation.signed=false",
            mapping="SEV-SNP VCEK 报告签名 / KBS 验证",
            fix="使用 VCEK/ASK-ARK 链验证报告签名，拒绝 unsigned report",
        ))

    extra = {
        "tee": att.get("tee"),
        "measurement_matches": measurement_matches,
        "policy_enforced": policy_enforced,
        "debug": debug,
        "report_data_binding": binding,
        "signed": signed,
        "initdata_verified": initdata,
        "attestation_status": att_entry.get("status"),
        "policy_status": pol_entry.get("status"),
    }
    summary = _C.summary_json("CoCo 容器证明面", findings, extra=extra, source=target)
    artifact = _C.write_artifact(ctx, f"{KEY}.json", {
        "summary": json.loads(summary), "attestation": att, "policy": pol,
        "findings": findings,
    })
    trace = t.dump()
    artifacts = ([str(trace)] if trace else []) + artifact
    return {"summary": summary, "artifacts": artifacts, "findings": findings}
