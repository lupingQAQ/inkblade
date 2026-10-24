"""vector-db-exposure — 向量库 collection/检索面跨租户暴露。

Ruling：只读检索 top_k 小样张（<=2 条，单条截断 80 字符），不导出全量文档。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_aigateway_common", _PARENT / "_aigateway-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

KEY = "vector-db-exposure"
WRITES = False
Trace, finding = _COMMON.Trace, _COMMON.finding
bearer, tenant_key, target = _COMMON.bearer, _COMMON.tenant_key, _COMMON.target
ok, resp, status = _COMMON.ok, _COMMON.resp, _COMMON.status


def run(ctx: dict, params: dict) -> dict:
    base = target(params)
    if not base:
        return {"summary": "no-target", "artifacts": [], "findings": []}
    tenant = str(params.get("tenant") or "tenant-a")
    victim_collection = str(params.get("victim_collection") or "tenant-b-docs")
    headers = {**bearer(tenant_key(params)), "X-Tenant": tenant}

    t = Trace(ctx, KEY)
    collections_anon = t.call("GET", f"{base}/vector/collections")
    collections_tenant = t.call("GET", f"{base}/vector/collections", headers=headers)
    query = t.call("POST", f"{base}/vector/query",
                   {"collection": victim_collection, "query": "acquisition revenue", "top_k": 2},
                   headers)

    source = collections_anon if ok(collections_anon) else collections_tenant
    rows = resp(source).get("collections") or []
    names = [str(c.get("name")) for c in rows]
    other_tenant = [str(c.get("name")) for c in rows
                    if str(c.get("tenant")) not in ("shared", tenant)]
    query_payload = resp(query)
    matches = query_payload.get("matches") or []
    cross_tenant_match = (ok(query) and
                          str(query_payload.get("collection_tenant")) not in ("shared", tenant) and
                          bool(matches))

    findings: list[dict] = []
    if ok(collections_anon) and (other_tenant or cross_tenant_match):
        detail = {
            "route": "/vector/collections",
            "http_status": status(collections_anon),
            "collections": names,
            "other_tenant_collections": other_tenant,
            "query_route": "/vector/query",
            "query_status": status(query),
            "collection": victim_collection,
            "collection_tenant": query_payload.get("collection_tenant"),
            "match_count": len(matches),
            "content_excerpts": [str((m or {}).get("content") or "")[:80] for m in matches],
            "tenant_view_status": status(collections_tenant),
            "note": "向量库未做租户 scope：collection 枚举与相似度检索均可跨租户读取文档内容",
        }
        findings.append(finding(
            "high", f"向量库跨租户暴露：{len(other_tenant)} 个他租户 collection / 命中 {len(matches)} 条文档",
            detail))

    artifact = t.dump()
    summary = (f"anon={status(collections_anon)} tenant={status(collections_tenant)} "
               f"collections={len(names)} other={len(other_tenant)} "
               f"query={status(query)} matches={len(matches)}")
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
