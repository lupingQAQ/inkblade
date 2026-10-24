"""model-registry-exposure — 模型注册表/路由表未鉴权暴露私有模型与后端地址。

Ruling：匿名与同租户两条读取路径对照；fixed 下匿名 401 且同租户响应不含 backend 即不产出 finding。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_aigateway_common", _PARENT / "_aigateway-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

KEY = "model-registry-exposure"
WRITES = False
Trace, finding = _COMMON.Trace, _COMMON.finding
bearer, tenant_key, target = _COMMON.bearer, _COMMON.tenant_key, _COMMON.target
ok, resp, status = _COMMON.ok, _COMMON.resp, _COMMON.status


def run(ctx: dict, params: dict) -> dict:
    base = target(params)
    if not base:
        return {"summary": "no-target", "artifacts": [], "findings": []}
    tenant = str(params.get("tenant") or "tenant-a")
    headers = {**bearer(tenant_key(params)), "X-Tenant": tenant}

    t = Trace(ctx, KEY)
    models_anon = t.call("GET", f"{base}/models")
    models_tenant = t.call("GET", f"{base}/models", headers=headers)
    routes = t.call("GET", f"{base}/ai/route")

    source = models_anon if ok(models_anon) else models_tenant
    payload = resp(source)
    rows = payload.get("data") or []
    private_models = [str(m.get("id")) for m in rows if m.get("visibility") == "private"]
    other_tenant_models = [str(m.get("id")) for m in rows
                           if str(m.get("tenant")) not in ("shared", tenant)]
    backend_exposed = [str(m.get("id")) for m in rows if m.get("backend")]

    findings: list[dict] = []
    if ok(models_anon) and (private_models or other_tenant_models or backend_exposed):
        detail = {
            "route": "/models",
            "http_status": status(models_anon),
            "model_count": len(rows),
            "private_models": private_models,
            "other_tenant_models": other_tenant_models,
            "backend_exposed": backend_exposed,
            "route_table_status": status(routes),
            "tenant_view_status": status(models_tenant),
            "note": "模型注册表匿名可读：私有模型、租户归属与内网后端地址暴露（为路由劫持/模型盗用提供目标）",
        }
        findings.append(finding(
            "high", f"模型注册表暴露：{len(private_models)} 个私有模型 / {len(backend_exposed)} 个后端地址可读", detail))

    artifact = t.dump()
    summary = (f"anon={status(models_anon)} tenant={status(models_tenant)} "
               f"models={len(rows)} private={len(private_models)} backend={len(backend_exposed)}")
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
