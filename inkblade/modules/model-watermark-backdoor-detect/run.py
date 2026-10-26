# -*- coding: utf-8 -*-
"""模型水印与后门检测面（主动探测，只读）。

GET /model/watermark：
- 无可验证水印 → high；
- 未执行触发器/后门扫描 → high；
- 来源未签名/权重哈希未绑定 → medium。

只读：不修改模型权重、不触发模型推理。
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_infra2026_common", _PARENT / "_infra2026-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "model-watermark-backdoor-detect"


def run(ctx: dict, params: dict) -> dict:
    target = str(params.get("target") or "").rstrip("/")
    if not target:
        return _C.no_target()
    t = _C.Trace(ctx, KEY)
    entry = t.get(f"{target}/model/watermark")
    doc = _C.resp(entry)
    wm = doc.get("watermark") or {}
    scan = doc.get("backdoor_scan") or {}
    findings: list[dict] = []

    present = bool(wm.get("present")) and bool(wm.get("verify_endpoint"))
    performed = bool(scan.get("performed")) and bool(scan.get("trigger_scan"))
    provenance = str(doc.get("provenance") or "unknown")
    weights = _C.sha256_ref(doc.get("weights_hash"))

    if not present:
        findings.append(_C.finding(
            "high", "模型未嵌入可验证水印",
            {"detected": True, "present": wm.get("present"),
             "algorithm": wm.get("algorithm"),
             "verify_endpoint": wm.get("verify_endpoint")},
            evidence=f"watermark.present={wm.get('present')} verify={wm.get('verify_endpoint')}",
            mapping="LLM watermark / KGW / 来源追溯",
            fix="发布前嵌入可验证水印并提供验证端点；保留密钥与采样参数",
        ))
    if not performed:
        findings.append(_C.finding(
            "high", "未执行后门或触发器扫描",
            {"detected": True, "performed": scan.get("performed"),
             "trigger_scan": scan.get("trigger_scan")},
            evidence=f"backdoor_scan={scan}",
            mapping="模型后门 / 触发器扫描 / 供应链检测",
            fix="对权重与 adapter 做触发器/后门扫描；高风险模型隔离并人工复核",
        ))
    if provenance != "sigstore" or not weights:
        findings.append(_C.finding(
            "medium", "模型来源未签名",
            {"detected": True, "provenance": provenance, "weights_hash": weights},
            evidence=f"provenance={provenance} weights_hash={weights or 'missing'}",
            mapping="模型签名 / OCI artifact / Sigstore",
            fix="模型制品签名并绑定 digest；准入验证签名与来源证明",
        ))

    extra = {
        "model": doc.get("model"),
        "watermark_present": present,
        "backdoor_scanned": performed,
        "provenance": provenance,
        "weights_hash": weights,
        "status": entry.get("status"),
    }
    summary = _C.summary_json("模型水印与后门检测", findings, extra=extra, source=target)
    artifact = _C.write_artifact(ctx, f"{KEY}.json", {
        "summary": json.loads(summary), "model": doc, "findings": findings,
    })
    trace = t.dump()
    artifacts = ([str(trace)] if trace else []) + artifact
    return {"summary": summary, "artifacts": artifacts, "findings": findings}
