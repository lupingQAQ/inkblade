"""aigateway-cache-cross-tenant — 语义缓存共享前缀键 → 跨租户命中。

Ruling：只读（lookup）；victim 条目由靶场预置或由对方租户正常写入，模块不自建缓存。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_aigateway_common", _PARENT / "_aigateway-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

KEY = "aigateway-cache-cross-tenant"
WRITES = False
Trace, finding = _COMMON.Trace, _COMMON.finding
bearer, tenant_key, victim_tenant_key = _COMMON.bearer, _COMMON.tenant_key, _COMMON.victim_tenant_key
ok, resp, target = _COMMON.ok, _COMMON.resp, _COMMON.target
status = _COMMON.status
DEFAULT_VICTIM_PROMPT = _COMMON.DEFAULT_VICTIM_PROMPT


def run(ctx: dict, params: dict) -> dict:
    base = target(params)
    if not base:
        return {"summary": "no-target", "artifacts": [], "findings": []}
    requester = str(params.get("requester_tenant") or "tenant-a")
    victim = str(params.get("victim_tenant") or "tenant-b")
    prompt = str(params.get("victim_prompt") or DEFAULT_VICTIM_PROMPT)

    t = Trace(ctx, KEY)
    lookup_requester = t.call("POST", f"{base}/cache/lookup", {"text": prompt},
                              {**bearer(tenant_key(params)), "X-Tenant": requester})
    lookup_victim = t.call("POST", f"{base}/cache/lookup", {"text": prompt},
                           {**bearer(victim_tenant_key(params)), "X-Tenant": victim})

    requester_payload = resp(lookup_requester)
    victim_payload = resp(lookup_victim)
    entry = requester_payload.get("entry") or {}
    entry_tenant = str(entry.get("tenant") or "")
    cache_key = str(requester_payload.get("cache_key") or "")
    victim_key = str(victim_payload.get("cache_key") or "")
    shared_key = bool(cache_key) and cache_key == victim_key
    hit = bool(requester_payload.get("hit"))

    findings: list[dict] = []
    if ok(lookup_requester) and hit and entry_tenant and entry_tenant != requester:
        detail = {
            "route": "/cache/lookup",
            "http_status": status(lookup_requester),
            "hit": True,
            "requester_tenant": requester,
            "entry_tenant": entry_tenant,
            "cache_key": cache_key,
            "victim_cache_key": victim_key,
            "shared_key": shared_key,
            "victim_http_status": status(lookup_victim),
            "response_excerpt": str(entry.get("response") or "")[:80],
            "note": "语义缓存键未绑定租户：共享前缀哈希导致跨租户命中，直接泄露受害租户模型响应",
        }
        findings.append(finding(
            "high", f"语义缓存跨租户命中：{requester} 读取到 {entry_tenant} 的缓存响应", detail))

    artifact = t.dump()
    summary = (f"requester={requester} hit={hit} entry_tenant={entry_tenant or '-'} "
               f"shared_key={shared_key} victim_hit={victim_payload.get('hit')} "
               f"status={status(lookup_requester)}")
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
