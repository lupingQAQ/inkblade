# -*- coding: utf-8 -*-
"""cache-salt-policy-audit — 缓存隔离策略配置面审计（cache_salt/租户隔离缺失）。

检测口径（配置面 + 行为差分双确认）：
1) GET /config 读缓存策略（cache_salt_policy / approx_cache / kv_pool / router_metrics）；
2) 行为差分：租户 A 携 cache_salt 预热 prefix → 租户 B 同 prefix 不带 salt 复用；
3) vulnerable：配置面 salt 关闭/全局键 scope + 跨租户 cached_tokens>0 → high；
   仅配置面弱而差分未复现 → medium；fixed：配置面 401/加固 + 跨租户 cached_tokens=0 → info。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_cache_common", _PARENT / "_cache-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

KEY = "cache-salt-policy-audit"
WRITES = False
PRIME_TENANT = "tenant-a"
REUSE_TENANT = "tenant-b"


def run(ctx: dict, params: dict) -> dict:
    target = _COMMON.target_of(params)
    if not target:
        return _COMMON.no_target()
    marker = _COMMON.marker_of(ctx, params)
    prefix = str(params.get("prompt_prefix") or f"INKBLADE-CACHE-SALT-{marker}")
    prefix_tokens = _COMMON.int_of(params.get("prefix_tokens"), 2048) or 2048
    salt = str(params.get("cache_salt") or "salt-tenant-a")

    t = _COMMON.Trace(ctx, KEY)
    config = t.call("GET", f"{target}/config")
    config_payload = _COMMON.resp(config)
    policy = config_payload.get("cache_salt_policy") or {}
    weak_config = bool(
        _COMMON.is_ok(config)
        and (policy.get("enabled") is False
             or policy.get("per_tenant_salt") is False
             or policy.get("key_scope") == "global")
    )

    prime = t.call("POST", f"{target}/v1/chat/completions", {
        "prompt_prefix": prefix, "prefix_tokens": prefix_tokens, "max_tokens": 1,
        "cache_salt": salt,
    }, {_COMMON.TENANT_HEADER: PRIME_TENANT})
    reuse = t.call("POST", f"{target}/v1/chat/completions", {
        "prompt_prefix": prefix, "prefix_tokens": prefix_tokens, "max_tokens": 1,
    }, {_COMMON.TENANT_HEADER: REUSE_TENANT})
    prime_cached = _COMMON.int_of((_COMMON.resp(prime).get("usage") or {}).get("cached_tokens"))
    reuse_cached = _COMMON.int_of((_COMMON.resp(reuse).get("usage") or {}).get("cached_tokens"))
    cross_tenant_hit = _COMMON.is_ok(reuse) and reuse_cached > 0

    detail = {
        "route_config": "/config",
        "route_probe": "/v1/chat/completions",
        "config_status": config.get("status"),
        "cache_salt_policy": policy,
        "approx_scope": (config_payload.get("approx_cache") or {}).get("scope"),
        "kv_pool_residue_policy": (config_payload.get("kv_pool") or {}).get("residue_policy"),
        "kv_pool_namespace_isolation": (config_payload.get("kv_pool") or {}).get("namespace_isolation"),
        "weak_config": weak_config,
        "prime_status": prime.get("status"),
        "reuse_status": reuse.get("status"),
        "prime_cached_tokens": prime_cached,
        "cross_tenant_cached_tokens": reuse_cached,
        "cross_tenant_hit": cross_tenant_hit,
        "prime_tenant": PRIME_TENANT,
        "reuse_tenant": REUSE_TENANT,
    }
    findings: list[dict] = []
    if weak_config and cross_tenant_hit:
        detail["http_status"] = reuse.get("status")
        findings.append(_COMMON.finding(
            "high",
            "缓存隔离策略缺失：cache_salt 未启用（配置面+差分双确认，跨租户 prefix 命中）",
            detail))
    elif weak_config:
        findings.append(_COMMON.finding(
            "medium", "缓存策略配置面薄弱（cache_salt 关闭/全局键），行为差分未复现", detail))
    else:
        findings.append(_COMMON.finding(
            "info", "缓存隔离策略已加固（配置面不可读或已启用逐租户 salt，跨租户未命中）", detail))

    artifact = t.dump()
    _COMMON.write_artifact(ctx, "cache-salt-policy-audit.json", detail)
    summary = (f"config={config.get('status')} weak={weak_config} "
               f"cross_tenant_cached={reuse_cached}")
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
