"""GPU 设备跨 namespace — 同一物理设备被不同 namespace 的 Pod 同时挂载。

检测面：GET /gpu/pools 的设备 pods 中出现 >1 个 namespace（或跨租户），
说明 device plugin / 池调度未做 namespace 级独占；fixed：租户过滤且每设备单 namespace。
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

KEY = "gpu-device-cross-namespace"
WRITES = False


def run(ctx: dict, params: dict) -> dict:
    base = base_url(params)
    mode, note = resolve_mode(params, WRITES)
    if not base:
        return {"summary": "no-target", "artifacts": [], "findings": []}
    tenant = str(params.get("tenant") or "tenant-a")
    t = Trace(ctx, KEY)
    findings: list[dict] = []

    pools = t.call("GET", f"{base}/gpu/pools", headers=read_headers(params))
    payload = resp(pools)
    shared = []
    for device in payload.get("devices") or []:
        pods = device.get("pods") or []
        namespaces = sorted({str(p.get("namespace") or "") for p in pods})
        pod_tenants = sorted({str(p.get("tenant") or "") for p in pods})
        if len(namespaces) > 1 or len(pod_tenants) > 1:
            shared.append({
                "device": device.get("device"),
                "device_tenant": device.get("tenant"),
                "namespaces": namespaces,
                "pod_tenants": pod_tenants,
                "allocation": device.get("allocation"),
                "mig_profile": (device.get("mig") or {}).get("active", ""),
                "pods": pods,
            })
    if ok(pools) and shared:
        findings.append({
            "sev": "high",
            "title": "GPU 设备跨 namespace 共享挂载（同卡多租户/多命名空间）",
            "detail": detail({
                "route": "/gpu/pools",
                "http_status": pools.get("status"),
                "auth": "none",
                "requester_tenant": tenant,
                "shared_device_count": len(shared),
                "devices": shared,
                "note": "device plugin 未做 namespace 独占：同卡被不同 namespace Pod 同时打开 → 显存/上下文互读",
            }),
        })

    artifact = t.dump()
    summary = (f"pools={pools.get('status')} shared_devices={len(shared)} "
               f"findings={len(findings)} mode={mode}")
    if note:
        summary += f"；{note}"
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
