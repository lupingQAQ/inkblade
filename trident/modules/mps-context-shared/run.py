"""MPS context 共享 — 跨租户客户端共用 MPS server/pipe（context 隔离失效）。

检测面：GET /gpu/mps/status 返回 shared_context=true 或 cross_tenant_clients=true，
且 contexts 中出现非本租户 client/pipe。fixed：按 X-Tenant 过滤 + 独立 pipe。
"""
from __future__ import annotations

import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[3]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from trident.modules._gpu_cloud_common import (  # noqa: E402
    Trace, base_url, detail, ok, read_headers, resolve_mode, resp,
)

KEY = "mps-context-shared"
WRITES = False


def run(ctx: dict, params: dict) -> dict:
    base = base_url(params)
    mode, note = resolve_mode(params, WRITES)
    if not base:
        return {"summary": "no-target", "artifacts": [], "findings": []}
    tenant = str(params.get("tenant") or "tenant-a")
    t = Trace(ctx, KEY)
    findings: list[dict] = []

    status = t.call("GET", f"{base}/gpu/mps/status", headers=read_headers(params))
    payload = resp(status)
    contexts = payload.get("contexts") or []
    foreign = [c for c in contexts if c.get("tenant") != tenant]
    shared = bool(payload.get("shared_context")) or bool(payload.get("cross_tenant_clients"))
    if ok(status) and (shared or foreign):
        clients = [{"tenant": c.get("tenant"), "client": c.get("client"),
                    "pid": c.get("pid"), "pipe": c.get("pipe"),
                    "namespace": c.get("namespace")} for c in contexts]
        findings.append({
            "sev": "high",
            "title": "MPS context 跨租户共享（client/pipe 隔离失效）",
            "detail": detail({
                "route": "/gpu/mps/status",
                "http_status": status.get("status"),
                "auth": "none",
                "requester_tenant": tenant,
                "server": payload.get("server", ""),
                "shared_context": shared,
                "cross_tenant_clients": bool(payload.get("cross_tenant_clients")),
                "foreign_context_count": len(foreign),
                "contexts": clients,
                "foreign_clients": [c.get("client") for c in foreign],
                "note": "MPS server 共享时 context/显存未按租户隔离：客户端可观察他租户进程并复用上下文",
            }),
        })

    artifact = t.dump()
    summary = (f"mps={status.get('status')} shared={str(shared).lower()} "
               f"foreign={len(foreign)} findings={len(findings)} mode={mode}")
    if note:
        summary += f"；{note}"
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
