# -*- coding: utf-8 -*-
"""gVisor/Firecracker 沙箱运行时面（只读侦察）。

GET /sandbox/runtime：
- Agent Pod 使用 runc/非沙箱 runtime → high；
- seccomp=Unconfined 或持有 SYS_ADMIN → high；
- hostPID/hostNetwork 旁路沙箱边界 → medium。

只读：不修改 RuntimeClass、Pod 或节点配置。
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_infra2026_common", _PARENT / "_infra2026-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "sandbox-runtime-surface"


def run(ctx: dict, params: dict) -> dict:
    target = str(params.get("target") or "").rstrip("/")
    if not target:
        return _C.no_target()
    t = _C.Trace(ctx, KEY)
    entry = t.get(f"{target}/sandbox/runtime")
    doc = _C.resp(entry)
    pods = [p for p in _C.as_list(doc.get("pods")) if isinstance(p, dict)]
    classes = {str(c.get("name")): bool(c.get("sandboxed"))
               for c in _C.as_list(doc.get("runtime_classes")) if isinstance(c, dict)}
    findings: list[dict] = []

    unsandboxed = [p for p in pods
                   if not bool(p.get("sandboxed"))
                   or str(p.get("runtime")) in ("runc", "")
                   or not classes.get(str(p.get("runtime")), True)]
    dangerous = [p for p in pods
                 if str(p.get("seccomp")) in ("Unconfined", "")
                 or "SYS_ADMIN" in [str(c) for c in _C.as_list(p.get("capabilities"))]]
    host_ns = [p for p in pods if p.get("host_pid") or p.get("host_network")]

    if unsandboxed:
        findings.append(_C.finding(
            "high", "Agent Pod 使用非沙箱运行时",
            {"detected": True,
             "pods": [{"name": p.get("name"), "namespace": p.get("namespace"),
                       "runtime": p.get("runtime")} for p in unsandboxed],
             "runtime_classes": classes},
            evidence=f"unsandboxed_pods={[p.get('name') for p in unsandboxed]}",
            mapping="gVisor runsc / Firecracker / Kata RuntimeClass",
            fix="Agent 工作负载固定到 gVisor/Firecracker RuntimeClass；禁止 runc 直跑不可信代码",
        ))
    if dangerous:
        findings.append(_C.finding(
            "high", "Pod 关闭 seccomp 或持有 SYS_ADMIN",
            {"detected": True,
             "pods": [{"name": p.get("name"), "seccomp": p.get("seccomp"),
                       "capabilities": p.get("capabilities")} for p in dangerous]},
            evidence=f"dangerous_pods={[p.get('name') for p in dangerous]}",
            mapping="Pod Security Standards / seccomp / Linux capabilities",
            fix="seccomp=RuntimeDefault；drop ALL capabilities；仅按需 add",
        ))
    if host_ns:
        findings.append(_C.finding(
            "medium", "hostPID/hostNetwork 旁路沙箱边界",
            {"detected": True,
             "pods": [{"name": p.get("name"), "host_pid": p.get("host_pid"),
                       "host_network": p.get("host_network")} for p in host_ns]},
            evidence=f"host_namespace_pods={[p.get('name') for p in host_ns]}",
            mapping="沙箱边界 / 宿主命名空间",
            fix="关闭 hostPID/hostNetwork；需要节点能力时使用受控 DaemonSet 与独立节点池",
        ))

    extra = {
        "runtime_count": len(classes),
        "gvisor": bool(doc.get("gvisor")),
        "firecracker": bool(doc.get("firecracker")),
        "pods": len(pods),
        "unsandboxed_pods": len(unsandboxed),
        "dangerous_pods": len(dangerous),
        "host_namespace_pods": len(host_ns),
        "runtime_status": entry.get("status"),
    }
    summary = _C.summary_json("沙箱运行时面", findings, extra=extra, source=target)
    artifact = _C.write_artifact(ctx, f"{KEY}.json", {
        "summary": json.loads(summary), "runtime": doc, "findings": findings,
    })
    trace = t.dump()
    artifacts = ([str(trace)] if trace else []) + artifact
    return {"summary": summary, "artifacts": artifacts, "findings": findings}
