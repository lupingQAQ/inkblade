# -*- coding: utf-8 -*-
"""WASM runtime audit (read-only; quarantined by default)."""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_emerging_common", _PARENT / "_emerging-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "wasm-runtime-audit"


def run(ctx: dict, params: dict) -> dict:
    doc = _C.collection(params)
    state = _C.surface_state(ctx.get("meta") or {}, params, doc)
    if state.get("status") != "deployed":
        return _C.not_deployed(ctx, KEY, state)

    findings: list[dict] = []
    runtimes = [o for o in _C.objects(doc, "RuntimeClass")
                if "wasm" in str(o.get("name", "")).lower()]
    wasm_files = [f for f in _C.files(doc) if str(f.get("path", "")).lower().endswith(".wasm")]
    host_mounts = params.get("host_mounts") or []
    if runtimes and host_mounts:
        findings.append(_C.finding(
            "high", "WASM 运行时允许宿主目录挂载，沙箱边界失效",
            {"runtime_classes": [o.get("name") for o in runtimes],
             "host_mounts": host_mounts}, evidence="params host_mounts non-empty"))
    if runtimes and params.get("network_mode") == "host":
        findings.append(_C.finding(
            "high", "WASM 工作负载使用 host 网络",
            {"runtime_classes": [o.get("name") for o in runtimes]},
            evidence="params network_mode=host"))

    return _C.result(ctx, KEY, state, findings,
                     f"runtime_classes={len(runtimes)} wasm_files={len(wasm_files)} "
                     f"findings={len(findings)}",
                     {"runtime_classes": [o.get("name") for o in runtimes],
                      "wasm_files": [f.get("path") for f in wasm_files][:50]})
