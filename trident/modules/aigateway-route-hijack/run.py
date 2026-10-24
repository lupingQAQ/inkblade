"""aigateway-route-hijack — 模型别名可指向未授权后端 → 推理流量劫持。

Ruling：写面仅 /ai/model-alias（applied=true 才触发 finding）；probe-only 只读 /ai/route。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_aigateway_common", _PARENT / "_aigateway-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

KEY = "aigateway-route-hijack"
WRITES = True
Trace, finding = _COMMON.Trace, _COMMON.finding
bearer, tenant_key = _COMMON.bearer, _COMMON.tenant_key
ok, resp, status = _COMMON.ok, _COMMON.resp, _COMMON.status
target, resolve_mode = _COMMON.target, _COMMON.resolve_mode
DEFAULT_ALIAS, DEFAULT_BACKEND = _COMMON.DEFAULT_HIJACK_ALIAS, _COMMON.DEFAULT_HIJACK_BACKEND


def _aliases(entry: dict | None) -> dict:
    payload = resp(entry)
    aliases = payload.get("aliases")
    return aliases if isinstance(aliases, dict) else {}


def run(ctx: dict, params: dict) -> dict:
    base = target(params)
    if not base:
        return {"summary": "no-target", "artifacts": [], "findings": []}
    alias = str(params.get("alias") or DEFAULT_ALIAS)
    backend = str(params.get("backend") or DEFAULT_BACKEND)
    mode, note = resolve_mode(params, WRITES)
    t = Trace(ctx, KEY)
    route_before = t.call("GET", f"{base}/ai/route")
    before_aliases = _aliases(route_before)
    baseline_backend = str((before_aliases.get(alias) or {}).get("backend") or "")

    findings: list[dict] = []
    applied = routed_backend = ""
    chat_status = 0
    if mode == "backup-write":
        write = t.call("POST", f"{base}/ai/model-alias",
                       {"alias": alias, "backend": backend, "model": "attacker-model",
                        "tenant": params.get("tenant") or "tenant-a"})
        route_after = t.call("GET", f"{base}/ai/route")
        after_alias = (_aliases(route_after).get(alias) or {})
        applied = str(after_alias.get("backend") or "")
        chat = t.call("POST", f"{base}/v1/chat/completions",
                      {"model": alias, "messages": [{"role": "user", "content": "trident-route-probe"}]},
                      bearer(tenant_key(params)))
        routed_backend = str(resp(chat).get("backend") or "")
        chat_status = status(chat)
        if applied == backend and routed_backend == backend:
            detail = {
                "route": "/ai/model-alias",
                "alias": alias,
                "baseline_backend": baseline_backend,
                "attacker_backend": backend,
                "applied": True,
                "chat_status": chat_status,
                "routed_backend": routed_backend,
                "upstream": resp(chat).get("upstream"),
                "state_sha256": resp(write).get("state_sha256"),
                "note": "别名写入无鉴权/无后端 allowlist：模型流量被导向攻击者后端（窃取 prompt 与响应）",
            }
            findings.append(finding(
                "critical", f"模型别名 {alias} 路由劫持：推理流量导向未授权后端", detail))
        elif applied:
            findings.append(finding(
                "high", f"模型别名 {alias} 被未授权改写（未观测到流量切换）",
                {"alias": alias, "applied_backend": applied, "chat_status": chat_status,
                 "note": "写面成功但 chat 未回显劫持后端，需人工复核路由生效时序"}))
    elif ok(route_before) and before_aliases:
        private = [name for name, item in before_aliases.items()
                   if (item or {}).get("visibility") == "private"]
        detail = {
            "route": "/ai/route",
            "http_status": status(route_before),
            "alias_count": len(before_aliases),
            "private_aliases": private,
            "aliases": {name: {"backend": (item or {}).get("backend"),
                               "tenant": (item or {}).get("tenant")}
                        for name, item in before_aliases.items()},
            "note": "路由表未鉴权可读：别名→后端映射与租户归属暴露（probe-only 不触碰写面）",
        }
        findings.append(finding("medium", "AI 路由表未鉴权可读：模型别名→后端映射暴露", detail))

    artifact = t.dump()
    summary = (f"mode={mode} alias={alias} route={status(route_before)} "
               f"chat={chat_status or 'skipped'} applied={bool(applied)} findings={len(findings)}")
    if note:
        summary += f"；{note}"
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
