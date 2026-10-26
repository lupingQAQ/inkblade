# -*- coding: utf-8 -*-
"""remote-kv-pool-isolation — 远程 KV 池（Mooncake/LMCache 风格）租户命名空间绕过。

检测口径（只读差分）：
1) 正对照：读本租户对照块（tenant-a/ctx/control-001）→ 200 found；
2) 攻击：直接读受害租户块（tenant-b/ctx/seed-001）——
   vulnerable：无命名空间校验 → 200 found，块归属 tenant-b、值含 benign 标记 → high；
   fixed：块按租户命名空间隔离 → 403 → info。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
from urllib.parse import quote

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_cache_common", _PARENT / "_cache-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

KEY = "remote-kv-pool-isolation"
WRITES = False
DEFAULT_VICTIM_BLOCK = "tenant-b/ctx/seed-001"
DEFAULT_CONTROL_BLOCK = "tenant-a/ctx/control-001"


def run(ctx: dict, params: dict) -> dict:
    target = _COMMON.target_of(params)
    if not target:
        return _COMMON.no_target()
    tenant = _COMMON.tenant_of(params)
    victim_tenant = _COMMON.victim_tenant_of(params)
    victim_block = str(params.get("victim_block") or DEFAULT_VICTIM_BLOCK)
    control_block = str(params.get("control_block") or DEFAULT_CONTROL_BLOCK)
    marker_needle = str(params.get("marker_needle") or "INKBLADE-BENIGN-POOL-VICTIM")

    t = _COMMON.Trace(ctx, KEY)
    headers = _COMMON.headers_for(params)
    control = t.call("GET", f"{target}/kvpool/blocks/{quote(control_block, safe='')}",
                     headers=headers)
    victim = t.call("GET", f"{target}/kvpool/blocks/{quote(victim_block, safe='')}",
                    headers=headers)
    victim_payload = _COMMON.resp(victim)
    block_tenant = str(victim_payload.get("tenant") or "")
    value_text = str(victim_payload.get("value") or "")
    cross_tenant_read = bool(
        _COMMON.is_ok(victim) and victim_payload.get("found")
        and block_tenant and block_tenant != tenant)

    detail = {
        "route": "/kvpool/blocks/{block}",
        "transport": "kv-pool (mooncake/lmcache style)",
        "victim_block": victim_block,
        "control_block": control_block,
        "control_status": control.get("status"),
        "control_found": bool(_COMMON.resp(control).get("found")),
        "victim_status": victim.get("status"),
        "victim_found": bool(victim_payload.get("found")),
        "block_tenant": block_tenant,
        "requester_tenant": tenant,
        "cross_tenant_read": cross_tenant_read,
        "marker_present": marker_needle in value_text,
        "value_excerpt": value_text[:96],
        "namespace_check": "absent" if cross_tenant_read else "enforced",
    }
    findings: list[dict] = []
    if cross_tenant_read:
        detail["http_status"] = victim.get("status")
        findings.append(_COMMON.finding(
            "high",
            f"远程 KV 池命名空间绕过：{tenant} 直接读回 {block_tenant} 的 KV 块"
            "（Mooncake/LMCache 风格块存储无租户命名空间校验）",
            detail))
    else:
        detail["http_status"] = victim.get("status")
        findings.append(_COMMON.finding(
            "info", "远程 KV 池块读按租户命名空间隔离（越权 403 或块不可见）", detail))

    artifact = t.dump()
    _COMMON.write_artifact(ctx, "remote-kv-pool-isolation.json", detail)
    summary = (f"control={control.get('status')} victim={victim.get('status')} "
               f"block_tenant={block_tenant or '-'} marker={detail['marker_present']}")
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
