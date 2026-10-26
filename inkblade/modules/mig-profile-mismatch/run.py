"""MIG profile 不匹配 — 请求档位与生效档位不一致（隔离档位降级/跨租户共享 slice）。

检测面：GET /gpu/mig/profiles?device=... 断言 active != requested；backup-write 下
POST /gpu/mig/profiles 以无鉴权身份在线重配（含已分配设备）→ 200 即调度面可任意改隔离档位。
fixed：租户过滤 + admin/同租户校验 + 已分配设备 409。
"""
from __future__ import annotations

import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[3]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from trident.modules._gpu_cloud_common import (  # noqa: E402
    Trace, base_url, detail, ok, read_headers, resolve_mode, resp, write_headers,
)

KEY = "mig-profile-mismatch"
WRITES = True


def run(ctx: dict, params: dict) -> dict:
    base = base_url(params)
    mode, note = resolve_mode(params, WRITES)
    if not base:
        return {"summary": "no-target", "artifacts": [], "findings": []}
    tenant = str(params.get("tenant") or "tenant-a")
    device_name = str(params.get("device") or "gpu-b-1")
    target_profile = str(params.get("profile") or "1g.10gb")
    t = Trace(ctx, KEY)
    findings: list[dict] = []

    listing = t.call("GET", f"{base}/gpu/mig/profiles?device={device_name}",
                     headers=read_headers(params))
    payload = resp(listing)
    mismatch_count = int(payload.get("mismatch_count") or 0)
    for row in payload.get("devices") or []:
        if not row.get("mismatch"):
            continue
        findings.append({
            "sev": "high",
            "title": "MIG profile 请求与生效不一致（隔离档位降级/共享 slice）",
            "detail": detail({
                "route": "/gpu/mig/profiles",
                "http_status": listing.get("status"),
                "device": row.get("device"),
                "tenant": row.get("tenant"),
                "active": row.get("active"),
                "requested": row.get("requested"),
                "allocation": row.get("allocation"),
                "isolation": row.get("isolation"),
                "note": "调度声明与设备实际 profile 不一致：租户按请求档位评估隔离，实际共享/降级",
            }),
        })

    reconfigure = {}
    if mode == "backup-write":
        reconfigure = t.call("POST", f"{base}/gpu/mig/profiles", {
            "tenant": tenant,
            "device": device_name,
            "profile": target_profile,
        }, headers=write_headers(params))
        payload = resp(reconfigure)
        if ok(reconfigure):
            findings.append({
                "sev": "high",
                "title": "MIG 在线重配无鉴权（任意租户可改隔离档位）",
                "detail": detail({
                    "route": "/gpu/mig/profiles",
                    "http_status": reconfigure.get("status"),
                    "auth": "none",
                    "tenant": tenant,
                    "device": device_name,
                    "previous_profile": payload.get("previous_profile", ""),
                    "active": payload.get("active", ""),
                    "requested": payload.get("requested", ""),
                    "applied": payload.get("applied", False),
                    "isolation_downgraded": payload.get("isolation_downgraded", False),
                    "state_sha256": payload.get("state_sha256", ""),
                    "note": "已分配设备仍可在线重配 MIG：同卡其他租户的 slice 边界被改写",
                }),
            })

    artifact = t.dump()
    summary = (f"profiles={listing.get('status')} mismatch={mismatch_count} "
               f"reconfigure={reconfigure.get('status', '-')} findings={len(findings)} mode={mode}")
    if note:
        summary += f"；{note}"
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
