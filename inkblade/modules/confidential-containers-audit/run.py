# -*- coding: utf-8 -*-
"""Confidential-container runtime / attestation audit (read-only)."""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_emerging_common", _PARENT / "_emerging-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "confidential-containers-audit"


def run(ctx: dict, params: dict) -> dict:
    doc = _C.collection(params)
    state = _C.surface_state(ctx.get("meta") or {}, params, doc)
    if state.get("status") != "deployed":
        return _C.not_deployed(ctx, KEY, state)

    findings: list[dict] = []
    runtime_classes = [o for o in _C.objects(doc, "RuntimeClass")
                       if "kata" in str(o.get("name", "")).lower()
                       or "cc" == str(o.get("name", "")).lower()]
    cc_pods = []
    for pod in _C.objects(doc, "Pod"):
        ann = " ".join(f"{k}={v}" for k, v in (pod.get("annotations") or {}).items()).lower()
        if any(x in ann for x in ("katacontainers", "confidential", "tdx", "sev-snp")):
            cc_pods.append(pod)
    configs = [f for f in _C.files(doc) if "kata" in str(f.get("path", "")).lower()
               or "confidential" in str(f.get("path", "")).lower()]

    if runtime_classes and not configs:
        findings.append(_C.finding(
            "medium", "机密容器 RuntimeClass 已部署但缺少证明/TEE 配置证据",
            {"runtime_classes": [o.get("name") for o in runtime_classes],
             "pods": [p.get("name") for p in cc_pods][:20],
             "config_exports": 0},
            evidence="RuntimeClass present; no kata/TEE attestation config in collection"))
    debug_pods = [p.get("name") for p in cc_pods
                  if "debug" in str(p.get("annotations") or {}).lower()
                  or "ignore_msrs" in str(p.get("annotations") or {}).lower()]
    if debug_pods:
        findings.append(_C.finding(
            "high", "机密容器启用调试/放宽参数，削弱 TEE 边界",
            {"pods": debug_pods}, evidence="pod annotations contain debug/ignore_msrs"))
    attestation = params.get("attestation") or {}
    if attestation and attestation.get("enabled") is False:
        findings.append(_C.finding(
            "high", "机密容器运行时显式关闭证明",
            {"attestation": attestation}, evidence="params attestation.enabled=false"))

    return _C.result(ctx, KEY, state, findings,
                     f"runtime_classes={len(runtime_classes)} cc_pods={len(cc_pods)} "
                     f"configs={len(configs)} findings={len(findings)}",
                     {"runtime_classes": [o.get("name") for o in runtime_classes],
                      "cc_pods": [p.get("name") for p in cc_pods][:50]})
