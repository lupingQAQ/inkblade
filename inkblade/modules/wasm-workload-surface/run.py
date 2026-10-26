# -*- coding: utf-8 -*-
"""WASM 工作负载权限面（主动探测，只读）。

GET /wasm/modules：
- 模块获得宿主文件系统或网络能力 → high；
- 模块未签名 → high；
- 启用 WASI unstable 或继承环境变量 → medium。

只读：不部署/调用 WASM 模块，不修改 SpinKube/wasmCloud 配置。
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_infra2026_common", _PARENT / "_infra2026-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "wasm-workload-surface"


def run(ctx: dict, params: dict) -> dict:
    target = str(params.get("target") or "").rstrip("/")
    if not target:
        return _C.no_target()
    t = _C.Trace(ctx, KEY)
    entry = t.get(f"{target}/wasm/modules")
    doc = _C.resp(entry)
    modules = [m for m in _C.as_list(doc.get("modules")) if isinstance(m, dict)]
    findings: list[dict] = []

    over: list[dict] = []
    unsigned: list[str] = []
    unstable: list[dict] = []
    for module in modules:
        caps = module.get("capabilities") or {}
        fs = [str(x) for x in _C.as_list(caps.get("filesystem"))]
        net = [str(x) for x in _C.as_list(caps.get("network"))]
        env = [str(x) for x in _C.as_list(caps.get("env"))]
        if fs or net:
            over.append({"name": module.get("name"), "filesystem": fs, "network": net})
        if not bool(module.get("signed")):
            unsigned.append(str(module.get("name")))
        if bool(caps.get("allow_wasi_unstable")) or env:
            unstable.append({"name": module.get("name"), "env": env,
                             "allow_wasi_unstable": bool(caps.get("allow_wasi_unstable"))})

    if over:
        findings.append(_C.finding(
            "high", "WASM 模块获得宿主文件系统或网络能力",
            {"detected": True, "modules": over},
            evidence=f"overprivileged_modules={len(over)}",
            mapping="WASI capability model / SpinKube / wasmCloud",
            fix="移除 filesystem/network 能力；按需挂载只读路径与显式出站白名单",
        ))
    if unsigned:
        findings.append(_C.finding(
            "high", "WASM 模块未签名",
            {"detected": True, "modules": unsigned},
            evidence=f"unsigned_modules={len(unsigned)}",
            mapping="OCI artifact / Cosign / WASM 供应链",
            fix="对 WASM OCI artifact 签名并在准入时验证 digest 与签名",
        ))
    if unstable:
        findings.append(_C.finding(
            "medium", "WASM 启用 WASI unstable 或继承环境变量",
            {"detected": True, "modules": unstable},
            evidence=f"unstable_modules={len(unstable)}",
            mapping="WASI preview / 环境变量隔离",
            fix="固定 WASI 版本；显式 allowlist 环境变量，禁止继承宿主 env",
        ))

    extra = {
        "runtime": doc.get("runtime"),
        "modules": len(modules),
        "overprivileged_modules": len(over),
        "unsigned_modules": len(unsigned),
        "unstable_modules": len(unstable),
        "status": entry.get("status"),
    }
    summary = _C.summary_json("WASM 工作负载权限面", findings, extra=extra, source=target)
    artifact = _C.write_artifact(ctx, f"{KEY}.json", {
        "summary": json.loads(summary), "wasm": doc, "findings": findings,
    })
    trace = t.dump()
    artifacts = ([str(trace)] if trace else []) + artifact
    return {"summary": summary, "artifacts": artifacts, "findings": findings}
