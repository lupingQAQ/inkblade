"""aigateway-fingerprint — AI 网关指纹与未鉴权面测绘（只读）。

Ruling：仅 GET 只读路由；默认 master key 只做存在性判定，不在 finding 中回显完整值。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_aigateway_common", _PARENT / "_aigateway-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

KEY = "aigateway-fingerprint"
WRITES = False
Trace, finding = _COMMON.Trace, _COMMON.finding
ok, resp, status, target = _COMMON.ok, _COMMON.resp, _COMMON.status, _COMMON.target


def run(ctx: dict, params: dict) -> dict:
    base = target(params)
    if not base:
        return {"summary": "no-target", "artifacts": [], "findings": []}
    t = Trace(ctx, KEY)
    health = t.call("GET", f"{base}/health")
    models = t.call("GET", f"{base}/models")
    keyinfo = t.call("GET", f"{base}/key/info")
    config = t.call("GET", f"{base}/config")
    console = t.call("GET", f"{base}/admin/console")

    payload = resp(health)
    product = str(payload.get("product") or "unknown")
    version = str(payload.get("version") or "")
    master_present = bool(payload.get("master_key"))
    admin_auth = (payload.get("admin_api") or {}).get("auth")

    surfaces = [
        {"route": "/models", "status": status(models)},
        {"route": "/key/info", "status": status(keyinfo)},
        {"route": "/config", "status": status(config)},
        {"route": "/admin/console", "status": status(console)},
    ]
    open_routes = [row["route"] for row in surfaces if row["status"] == 200]

    findings: list[dict] = []
    if open_routes or master_present:
        critical_surface = any(route in ("/config", "/admin/console") for route in open_routes)
        sev = "high" if critical_surface or master_present else "medium"
        detail = {
            "product": product,
            "version": version,
            "health_status": status(health),
            "admin_api_auth": admin_auth,
            "default_master_key_present": master_present,
            "open_surfaces": open_routes,
            "surfaces": surfaces,
            "note": "网关指纹识别成功且存在未鉴权面：默认 master key 泄露/管理面无鉴权可直接进入凭据外泄链",
        }
        findings.append(finding(
            sev, f"AI 网关 {product} 指纹命中：{len(open_routes)} 个管理面无需凭据可读", detail))

    artifact = t.dump()
    summary = (f"product={product} version={version or '-'} "
               f"open={','.join(open_routes) or 'none'} master_leak={master_present}")
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
