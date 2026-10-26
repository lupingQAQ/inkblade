"""GPU 指标租户泄露 — DCGM 风格 /gpu/metrics 暴露他租户进程名、namespace 与模型标记。

检测面：GET /gpu/metrics（无 token / 仅低权租户身份）→ 200 且进程列表含非本租户 tenant；
fixed：按 X-Tenant 过滤，仅本租户进程可见。
"""
from __future__ import annotations

import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[3]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from inkblade.modules._gpu_cloud_common import (  # noqa: E402
    Trace, base_url, detail, ok, read_headers, resolve_mode, resp,
)

KEY = "gpu-metrics-tenant-leak"
WRITES = False


def run(ctx: dict, params: dict) -> dict:
    base = base_url(params)
    mode, note = resolve_mode(params, WRITES)
    if not base:
        return {"summary": "no-target", "artifacts": [], "findings": []}
    tenant = str(params.get("tenant") or "tenant-a")
    t = Trace(ctx, KEY)
    findings: list[dict] = []

    metrics = t.call("GET", f"{base}/gpu/metrics", headers=read_headers(params))
    payload = resp(metrics)
    leaked = []
    for gpu in payload.get("gpus") or []:
        for proc in gpu.get("processes") or []:
            if proc.get("tenant") == tenant:
                continue
            leaked.append({
                "device": gpu.get("device"),
                "pid": proc.get("pid"),
                "process": proc.get("name"),
                "tenant": proc.get("tenant"),
                "namespace": proc.get("namespace"),
                "model_marker": proc.get("model_marker"),
            })
    if ok(metrics) and leaked:
        findings.append({
            "sev": "high",
            "title": "DCGM 指标泄露他租户进程名与租户标签",
            "detail": detail({
                "route": "/gpu/metrics",
                "http_status": metrics.get("status"),
                "auth": "none",
                "requester_tenant": tenant,
                "tenant_filter": payload.get("tenant_filter", ""),
                "leaked_tenants": sorted({p["tenant"] for p in leaked}),
                "leaked_processes": leaked,
                "process_count": len(leaked),
                "gpu_count": len(payload.get("gpus") or []),
                "note": "DCGM exporter 未按租户过滤：进程名/命名空间/模型标记可被任意租户枚举",
            }),
        })

    artifact = t.dump()
    summary = (f"metrics={metrics.get('status')} leaked_processes={len(leaked)} "
               f"findings={len(findings)} mode={mode}")
    if note:
        summary += f"；{note}"
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
