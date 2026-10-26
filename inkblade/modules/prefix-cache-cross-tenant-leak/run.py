# -*- coding: utf-8 -*-
"""prefix cache 跨租户泄露 — 无 cache_salt 时复用其他租户的 prefix KV。

检测口径（真实 HTTP usage 证据）：
1) 租户 A 带 cache_salt 预热 prefix；
2) 租户 B 携带同一 prefix 且不带 cache_salt；
3) B 响应 usage.cached_tokens > 0 → 跨租户 prefix 复用（high）。
fixed 姿态：跨租户无 cache_salt 403；同租户带 salt 仍可命中（正对照）。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_longctx_common", _PARENT / "_longctx-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

KEY = "prefix-cache-cross-tenant-leak"
WRITES = False
PRIME_TENANT = "tenant-a"
REUSE_TENANT = "tenant-b"


def run(ctx: dict, params: dict) -> dict:
    target = _COMMON.target_of(params)
    if not target:
        return _COMMON.no_target()
    marker = _COMMON.marker_of(ctx, params)
    prefix = str(params.get("prompt_prefix") or f"INKBLADE-PREFIX-{marker}")
    prefix_tokens = _COMMON.int_of(params.get("prefix_tokens"), 4096) or 4096
    salt = str(params.get("cache_salt") or "salt-tenant-a")
    body_base = {
        "model": "longctx-mock",
        "messages": [{"role": "user", "content": "inkblade prefix cache probe"}],
        "context_window": "128k",
        "prompt_prefix": prefix,
        "prefix_tokens": prefix_tokens,
        "prompt_tokens": prefix_tokens,
        "max_tokens": 1,
    }
    t = _COMMON.Trace(ctx, KEY)
    prime_body = dict(body_base, cache_salt=salt)
    prime = t.call("POST", f"{target}/v1/chat/completions", prime_body,
                   {_COMMON.TENANT_HEADER: PRIME_TENANT})
    reuse_body = dict(body_base, cache_salt=None)
    reuse = t.call("POST", f"{target}/v1/chat/completions", reuse_body,
                   {_COMMON.TENANT_HEADER: REUSE_TENANT})

    prime_cached = _COMMON.int_of((_COMMON.resp(prime).get("usage") or {}).get("cached_tokens"))
    reuse_cached = _COMMON.int_of((_COMMON.resp(reuse).get("usage") or {}).get("cached_tokens"))
    detail = {
        "route": "/v1/chat/completions",
        "prime_tenant": PRIME_TENANT,
        "reuse_tenant": REUSE_TENANT,
        "prime_status": prime.get("status"),
        "reuse_status": reuse.get("status"),
        "prime_cached_tokens": prime_cached,
        "cached_tokens": reuse_cached,
        "prefix_tokens": prefix_tokens,
        "cache_salt_present_on_reuse": False,
        "cross_tenant": True,
    }
    findings: list[dict] = []
    if _COMMON.is_ok(reuse) and reuse_cached > 0:
        detail["http_status"] = reuse.get("status")
        findings.append(_COMMON.finding(
            "high", "prefix cache 跨租户复用：无 cache_salt 仍命中他租户 prefix", detail))
    else:
        detail["http_status"] = reuse.get("status")
        findings.append(_COMMON.finding(
            "info", "prefix cache 未跨租户复用（cached_tokens=0 或复用被拒绝）", detail))

    artifact = t.dump()
    _COMMON.write_artifact(ctx, "prefix-cache-cross-tenant-leak.json", detail)
    summary = (f"prime={prime.get('status')}/{prime_cached} "
               f"reuse={reuse.get('status')}/{reuse_cached} cached_tokens")
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
