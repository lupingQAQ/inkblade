"""云安全组放开 IMDS — 0.0.0.0/0 入站 + IMDSv1（http_tokens=optional）+ hop limit > 1。

检测面：GET /cloud/security-group?group=sg-gpu-nodes 返回公网入站、metadata options 允许
IMDSv1、hop limit=2；fixed：内网入站 + http_tokens=required + hop limit=1。
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

KEY = "cloud-sg-imds-exposure"
WRITES = False


def run(ctx: dict, params: dict) -> dict:
    base = base_url(params)
    mode, note = resolve_mode(params, WRITES)
    if not base:
        return {"summary": "no-target", "artifacts": [], "findings": []}
    group = str(params.get("group") or "sg-gpu-nodes")
    t = Trace(ctx, KEY)
    findings: list[dict] = []

    sg = t.call("GET", f"{base}/cloud/security-group?group={group}", headers=read_headers(params))
    payload = resp(sg)
    metadata = payload.get("metadata_options") or {}
    hop = int(metadata.get("http_put_response_hop_limit") or 0)
    imds_v1 = str(metadata.get("http_tokens") or "") == "optional"
    public = bool(payload.get("public_ingress"))
    if ok(sg) and (imds_v1 or public or hop > 1):
        findings.append({
            "sev": "high",
            "title": "云安全组放开 IMDS：公网入站 + IMDSv1/hop limit 允许 Pod 直取节点角色",
            "detail": detail({
                "route": "/cloud/security-group",
                "http_status": sg.get("status"),
                "group": group,
                "owner": payload.get("owner", ""),
                "public_ingress": public,
                "imds_v1_disabled": bool(payload.get("imds_v1_disabled")),
                "imds_reachable_from_internet": bool(payload.get("imds_reachable_from_internet")),
                "metadata_options": metadata,
                "http_tokens": metadata.get("http_tokens", ""),
                "http_put_response_hop_limit": hop,
                "ingress": payload.get("ingress") or [],
                "egress": payload.get("egress") or [],
                "note": "安全组/IMDS 选项是跨租户凭据面的入口：任意 Pod 可经 169.254.169.254 取节点角色",
            }),
        })

    artifact = t.dump()
    summary = (f"security_group={sg.get('status')} public_ingress={str(public).lower()} "
               f"http_tokens={metadata.get('http_tokens', '-')} hop_limit={hop} "
               f"findings={len(findings)} mode={mode}")
    if note:
        summary += f"；{note}"
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
