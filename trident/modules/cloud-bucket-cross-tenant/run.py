"""云桶跨租户 — public 桶策略 + 匿名/跨租户列目录（S3/OSS/COS/Blob）。

检测面：
1) GET /cloud/bucket/policy?bucket=weights-b 返回 Principal="*" / public=true / cross_tenant_read=true；
2) GET /cloud/bucket/list?bucket=weights-b 以他租户身份返回对象清单（模型/检查点/tokenizer）。
fixed：桶策略收敛到 owner 账户，列目录仅 owner（403）。
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

KEY = "cloud-bucket-cross-tenant"
WRITES = False


def run(ctx: dict, params: dict) -> dict:
    base = base_url(params)
    mode, note = resolve_mode(params, WRITES)
    if not base:
        return {"summary": "no-target", "artifacts": [], "findings": []}
    bucket_name = str(params.get("bucket") or "weights-b")
    prefix = str(params.get("prefix") or "")
    t = Trace(ctx, KEY)
    findings: list[dict] = []

    policy = t.call("GET", f"{base}/cloud/bucket/policy?bucket={bucket_name}",
                    headers=read_headers(params))
    policy_payload = resp(policy)
    public = bool(policy_payload.get("public"))
    if ok(policy) and public:
        findings.append({
            "sev": "high",
            "title": "权重桶策略 public（Principal='*' 可读/列目录）",
            "detail": detail({
                "route": "/cloud/bucket/policy",
                "http_status": policy.get("status"),
                "bucket": bucket_name,
                "provider": policy_payload.get("provider", ""),
                "owner": policy_payload.get("owner", ""),
                "public": True,
                "cross_tenant_read": bool(policy_payload.get("cross_tenant_read")),
                "list_requires_auth": bool(policy_payload.get("list_requires_auth")),
                "policy": policy_payload.get("policy"),
                "provider_variants": policy_payload.get("provider_variants"),
            }),
        })

    listing = t.call("GET", f"{base}/cloud/bucket/list?bucket={bucket_name}&prefix={prefix}",
                     headers=read_headers(params))
    list_payload = resp(listing)
    objects = list_payload.get("objects") or []
    if ok(listing) and objects:
        cross = bool(list_payload.get("cross_tenant"))
        findings.append({
            "sev": "high",
            "title": "公共桶跨租户列目录成功（权重/检查点清单泄露）",
            "detail": detail({
                "route": "/cloud/bucket/list",
                "http_status": listing.get("status"),
                "bucket": bucket_name,
                "bucket_owner": list_payload.get("bucket_owner", ""),
                "requester": list_payload.get("requester", ""),
                "cross_tenant": cross,
                "prefix": list_payload.get("prefix", ""),
                "object_count": len(objects),
                "objects": [o.get("key") for o in objects],
                "object_meta": objects,
                "note": "匿名/跨租户列目录成功：可直接下载权重与检查点（读权限即完整模型泄露）",
            }),
        })

    artifact = t.dump()
    summary = (f"policy={policy.get('status')} public={str(public).lower()} "
               f"list={listing.get('status')} objects={len(objects)} "
               f"findings={len(findings)} mode={mode}")
    if note:
        summary += f"；{note}"
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
