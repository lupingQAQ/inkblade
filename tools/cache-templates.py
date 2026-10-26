# -*- coding: utf-8 -*-
"""Author the six remaining cache templates (real two-state checks)."""
from __future__ import annotations

import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULES = ROOT / "inkblade" / "modules"
VICTIM_RESIDUE = ("tenant-b residue corpus marker INKBLADE-BENIGN-RESIDUE-VICTIM "
                  "quarterly close data pack appendix")
VICTIM_APPROX = ("tenant-b quarterly revenue guidance for fiscal 2026 total pipeline "
                 "equals 42.7M USD with eighteen percent growth")


def meta(key: str) -> dict:
    module = json.loads((MODULES / key / "module.json").read_text(encoding="utf-8"))
    return {
        "name": module["name"], "series": module["series"],
        "min_level": module["min_level"], "writes": bool(module["writes"]),
        "requires": list(module.get("requires") or []),
        "surfaces": [str(s) for s in (module.get("surfaces") or [])],
        "cves": list(module.get("verification_cves") or []),
        "fidelity": "equivalent",
    }


def base(key: str) -> dict:
    return {
        "schema": "inkblade-probe-template-v1", "key": key, "version": "1.0.0",
        "meta": meta(key),
        "inputs": {"target": {"from": "params.target", "required": True}},
        "defaults": {"timeout_ms": 8000, "tls_verify": False},
        "payloads": {"benign": {"marker": "INKBLADE-BENIGN",
                                "note": "benign cache-lab markers only"}},
        "limits": {"timeout_ms": 30000, "max_http_requests": 16},
    }


def artifact(key: str, fields: dict) -> list[dict]:
    return [{"name": f"{key}.json", "kind": "json", "fields": fields}]


def write(doc: dict) -> None:
    path = MODULES / doc["key"] / "template.json"
    path.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("wrote", doc["key"])


# 1 ---------------------------------------------------------------- residue
key = "cache-eviction-residue"
doc = base(key)
doc["computed"] = {
    "found": "steps.residue.status == 200 and steps.residue.json.found == true",
    "cross_tenant": "steps.residue.json.tenant == 'tenant-b'",
    "marker_present": "contains(steps.residue.json.prefix_preview, 'INKBLADE-BENIGN-RESIDUE-VICTIM')",
}
doc["steps"] = [
    {
        "id": "flood", "op": "http", "method": "POST",
        "url": "{{input.target}}/v1/chat/completions",
        "headers": {"X-Tenant": "tenant-a"},
        "body": {"prompt_prefix": "evict-flood-{{ctx.marker}}-{{i}} unique corpus pressure",
                 "prefix_tokens": 2048, "max_tokens": 1},
        "repeat": 140, "save": "flood", "allow_failure": True,
    },
    {
        "id": "residue", "op": "http", "method": "GET",
        "url": "{{input.target}}/cache/residue?prefix=" + VICTIM_RESIDUE.replace(" ", "%20"),
        "headers": {"X-Tenant": "tenant-a"}, "save": "residue", "allow_failure": True,
    },
]
doc["findings"] = [
    {"id": "residue", "when": "computed.found and computed.cross_tenant and computed.marker_present",
     "sev": "high", "title": "逐出后前缀残留跨租户可读（tenant-b 语料泄漏）",
     "detail": "route=/cache/residue found=true tenant=tenant-b prefix_preview={{steps.residue.json.prefix_preview}} evicted_at={{steps.residue.json.evicted_at}}",
     "evidence": "{{steps.residue.sha256}}", "mapping": "KV 池 LRU 逐出残留；cache-eviction-residue",
     "fix": "逐出即 zeroize；残留层按租户隔离并加密"},
    {"id": "clean", "when": "not (computed.found and computed.cross_tenant and computed.marker_present)",
     "sev": "info", "title": "未发现跨租户逐出残留（zeroize 或租户隔离生效）",
     "detail": "status={{steps.residue.status}} error={{steps.residue.error}}"},
]
doc["artifacts"] = artifact(key, {
    "route": "'/cache/residue'", "found": "computed.found",
    "cross_tenant": "computed.cross_tenant", "marker_present": "computed.marker_present",
    "tenant": "steps.residue.json.tenant", "preview": "steps.residue.json.prefix_preview"})
write(doc)

# 2 ------------------------------------------------------------ salt policy
key = "cache-salt-policy-audit"
doc = base(key)
doc["computed"] = {
    "weak_config": "steps.config.status == 200 and steps.config.json.cache_salt_policy.enabled == false",
    "cross_hit": "steps.reuse.status == 200 and steps.reuse.json.usage.cached_tokens > 0",
}
doc["steps"] = [
    {"id": "config", "op": "http", "method": "GET", "url": "{{input.target}}/config",
     "headers": {"X-Tenant": "tenant-a"}, "save": "config", "allow_failure": True},
    {"id": "prime", "op": "http", "method": "POST",
     "url": "{{input.target}}/v1/chat/completions",
     "headers": {"X-Tenant": "tenant-b"},
     "body": {"prompt_prefix": VICTIM_APPROX, "prefix_tokens": 2048, "max_tokens": 1},
     "save": "prime", "allow_failure": True},
    {"id": "reuse", "op": "http", "method": "POST",
     "url": "{{input.target}}/v1/chat/completions",
     "headers": {"X-Tenant": "tenant-a"},
     "body": {"prompt_prefix": VICTIM_APPROX, "prefix_tokens": 2048, "max_tokens": 1},
     "save": "reuse", "allow_failure": True},
]
doc["findings"] = [
    {"id": "weak", "when": "computed.weak_config and computed.cross_hit", "sev": "high",
     "title": "cache_salt 缺失且跨租户前缀命中：缓存键全局共享",
     "detail": "cache_salt_policy={{str(steps.config.json.cache_salt_policy)}} cached_tokens={{steps.reuse.json.usage.cached_tokens}} reuse_status={{steps.reuse.status}}",
     "evidence": "{{steps.config.sha256}}", "mapping": "cache-salt-policy-audit",
     "fix": "启用 per-tenant cache_salt，缓存键包含 tenant|salt"},
    {"id": "partial", "when": "not (computed.weak_config and computed.cross_hit) and (computed.cross_hit or computed.weak_config)",
     "sev": "medium", "title": "缓存租户隔离存在部分缺口（弱配置或跨租户命中之一）",
     "detail": "weak_config={{computed.weak_config}} cross_hit={{computed.cross_hit}}"},
    {"id": "clean", "when": "not computed.cross_hit and not computed.weak_config", "sev": "info",
     "title": "cache_salt 策略完整且未观察到跨租户命中",
     "detail": "config_status={{steps.config.status}} reuse_status={{steps.reuse.status}}"},
]
doc["artifacts"] = artifact(key, {
    "route": "'/config + /v1/chat/completions'", "weak_config": "computed.weak_config",
    "cross_hit": "computed.cross_hit", "cached_tokens": "steps.reuse.json.usage.cached_tokens",
    "salt_policy": "steps.config.json.cache_salt_policy"})
write(doc)

# 3 ------------------------------------------------------------ kv pool
key = "remote-kv-pool-isolation"
doc = base(key)
doc["computed"] = {
    "found": "steps.victim.status == 200 and steps.victim.json.found == true",
    "cross_tenant": "steps.victim.json.tenant == 'tenant-b'",
    "marker": "contains(str(steps.victim.json.value), 'INKBLADE-BENIGN-POOL-VICTIM')",
}
doc["steps"] = [{
    "id": "victim", "op": "http", "method": "GET",
    "url": "{{input.target}}/kvpool/blocks/tenant-b%2Fctx%2Fseed-001",
    "headers": {"X-Tenant": "tenant-a"}, "save": "victim", "allow_failure": True,
}]
doc["findings"] = [
    {"id": "cross-tenant", "when": "computed.found and computed.cross_tenant", "sev": "high",
     "title": "远程 KV 池跨租户命名空间读：tenant-a 读取 tenant-b 块",
     "detail": "block=tenant-b/ctx/seed-001 status={{steps.victim.status}} tenant={{steps.victim.json.tenant}} marker_present={{computed.marker}} sha256={{steps.victim.json.sha256}}",
     "evidence": "{{steps.victim.sha256}}", "mapping": "remote-kv-pool-isolation",
     "fix": "KV 池按租户命名空间鉴权；block id 校验 tenant 前缀"},
    {"id": "clean", "when": "not (computed.found and computed.cross_tenant)", "sev": "info",
     "title": "KV 池命名空间隔离生效（跨租户读被拒绝）",
     "detail": "status={{steps.victim.status}} error={{steps.victim.error}}"},
]
doc["artifacts"] = artifact(key, {
    "route": "'/kvpool/blocks/tenant-b/ctx/seed-001'", "found": "computed.found",
    "cross_tenant": "computed.cross_tenant", "marker_present": "computed.marker",
    "status": "steps.victim.status"})
write(doc)

# 4 ------------------------------------------------------------ router metrics
key = "router-cache-metrics-leak"
doc = base(key)
doc["vars"] = {"victim_tenant": "tenant-b"}
doc["computed"] = {
    "status_ok": "steps.metrics.status == 200",
    "victim_visible": "steps.metrics.json.per_tenant.tenant-b != null",
    "scope": "steps.metrics.json.aggregated.scope",
}
doc["steps"] = [{
    "id": "metrics", "op": "http", "method": "GET", "url": "{{input.target}}/router/metrics",
    "headers": {"X-Tenant": "tenant-a"}, "save": "metrics", "allow_failure": True,
}]
doc["findings"] = [
    {"id": "leak", "when": "computed.status_ok and computed.victim_visible", "sev": "high",
     "title": "路由/缓存指标跨租户泄漏：tenant-b 统计可见",
     "detail": "route=/router/metrics scope={{computed.scope}} visible_tenants={{steps.metrics.json.aggregated.tenants_visible}} victim_requests={{steps.metrics.json.per_tenant.tenant-b.requests}}",
     "evidence": "{{steps.metrics.sha256}}", "mapping": "router-cache-metrics-leak",
     "fix": "指标按调用主体做租户过滤；管理面单独鉴权"},
    {"id": "clean", "when": "computed.status_ok and not computed.victim_visible", "sev": "info",
     "title": "路由指标按租户过滤（未见 tenant-b 统计）",
     "detail": "scope={{computed.scope}}"},
]
doc["artifacts"] = artifact(key, {
    "route": "'/router/metrics'", "victim_visible": "computed.victim_visible",
    "scope": "computed.scope", "tenants_visible": "steps.metrics.json.aggregated.tenants_visible"})
write(doc)

# 5 ------------------------------------------------------------ similarity
key = "similarity-cache-false-hit"
doc = base(key)
doc["computed"] = {
    "hit": "steps.attack.status == 200 and steps.attack.json.hit == true",
    "cross_tenant": "steps.attack.json.matched.tenant == 'tenant-b'",
    "victim_response": "contains(str(steps.attack.json.matched.response), 'INKBLADE-BENIGN-APPROX-VICTIM')",
    "similarity": "steps.attack.json.best_similarity",
}
doc["steps"] = [{
    "id": "attack", "op": "http", "method": "POST",
    "url": "{{input.target}}/approx/lookup",
    "headers": {"X-Tenant": "tenant-a"},
    "body": {"text": VICTIM_APPROX + " revised 2026 estimate"},
    "save": "attack", "allow_failure": True,
}]
doc["findings"] = [
    {"id": "false-hit", "when": "computed.hit and computed.cross_tenant", "sev": "high",
     "title": "近似缓存跨租户假命中：返回 tenant-b 机密响应",
     "detail": "similarity={{computed.similarity}} threshold={{steps.attack.json.threshold}} requester={{steps.attack.json.requester_tenant}} matched_tenant={{steps.attack.json.matched.tenant}} victim_marker={{computed.victim_response}}",
     "evidence": "{{steps.attack.sha256}}", "mapping": "similarity-cache-false-hit",
     "fix": "近似缓存按租户分区；相似度检索先做租户过滤"},
    {"id": "clean", "when": "not (computed.hit and computed.cross_tenant)", "sev": "info",
     "title": "近似缓存按租户隔离（未跨租户命中）",
     "detail": "status={{steps.attack.status}} hit={{computed.hit}} scope={{steps.attack.json.scope}}"},
]
doc["artifacts"] = artifact(key, {
    "route": "'/approx/lookup'", "hit": "computed.hit",
    "cross_tenant": "computed.cross_tenant", "similarity": "computed.similarity",
    "matched": "steps.attack.json.matched"})
write(doc)

# 6 ------------------------------------------------------------ poison
key = "cache-poison-persistence"
doc = base(key)
doc["meta"]["fidelity"] = "equivalent"
doc["modes"] = {"probe_only": True, "backup_write": True, "requires_backup": True}
doc["computed"] = {
    "victim_found": "steps.probe.status == 200 and steps.probe.json.found == true",
    "pinned_applied": "steps.write.json.pinned == true",
    "readback_found": "steps.readback.status == 200 and steps.readback.json.found == true",
}
doc["steps"] = [
    {"id": "probe", "op": "http", "method": "GET",
     "url": "{{input.target}}/kvpool/blocks/tenant-b%2Fctx%2Fseed-001",
     "headers": {"X-Tenant": "tenant-a"}, "save": "probe", "allow_failure": True},
    {"id": "write", "op": "http", "method": "POST", "write": True,
     "when": "params.mode == 'backup-write'",
     "url": "{{input.target}}/kvpool/blocks",
     "headers": {"X-Tenant": "tenant-a"},
     "body": {"block_id": "poison-{{ctx.marker}}", "namespace": "tenant-a",
              "value": "{\"marker\": \"{{ctx.marker}}\", \"benign\": true, \"class\": \"inkblade-lab-poison\"}",
              "eviction_policy": "pinned"},
     "save": "write", "allow_failure": True},
    {"id": "readback", "op": "http", "method": "GET",
     "when": "params.mode == 'backup-write'",
     "url": "{{input.target}}/kvpool/blocks/poison-{{ctx.marker}}",
     "headers": {"X-Tenant": "tenant-a"}, "save": "readback", "allow_failure": True},
]
doc["findings"] = [
    {"id": "victim", "when": "computed.victim_found", "sev": "high",
     "title": "KV 池 victim 块可跨租户读取（probe-only）",
     "detail": "block=tenant-b/ctx/seed-001 status={{steps.probe.status}} tenant={{steps.probe.json.tenant}}",
     "evidence": "{{steps.probe.sha256}}", "mapping": "cache-poison-persistence",
     "fix": "KV 池按租户鉴权；禁止跨命名空间读"},
    {"id": "pinned", "when": "params.mode == 'backup-write' and steps.write.ok and computed.pinned_applied and computed.readback_found",
     "sev": "high", "title": "pinned 逐出策略可被租户写入：毒化块持久驻留",
     "detail": "block_id={{steps.write.json.block_id}} pinned={{computed.pinned_applied}} readback_sha256={{steps.readback.json.sha256}}",
     "evidence": "{{steps.readback.sha256}}", "mapping": "cache-poison-persistence",
     "fix": "pinned 仅管理面可用；块命名空间绑定租户"},
    {"id": "clean", "when": "not computed.victim_found", "sev": "info",
     "title": "未发现跨租户 KV 块读取", "detail": "status={{steps.probe.status}}"},
]
doc["artifacts"] = artifact(key, {
    "route": "'/kvpool/blocks'", "victim_found": "computed.victim_found",
    "pinned_applied": "computed.pinned_applied", "readback_found": "computed.readback_found",
    "mode": "params.mode"})
write(doc)
