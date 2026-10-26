# -*- coding: utf-8 -*-
"""Author the eight long-context templates (two-state against longctx_sim)."""
from __future__ import annotations

import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULES = ROOT / "inkblade" / "modules"
CHAT = {"model": "longctx-mock", "max_tokens": 8,
        "messages": [{"role": "user", "content": "INKBLADE-BENIGN long context probe"}]}


def meta(key: str) -> dict:
    m = json.loads((MODULES / key / "module.json").read_text(encoding="utf-8"))
    return {"name": m["name"], "series": m["series"], "min_level": m["min_level"],
            "writes": bool(m["writes"]), "requires": list(m.get("requires") or []),
            "surfaces": [str(s) for s in (m.get("surfaces") or [])],
            "cves": list(m.get("verification_cves") or []), "fidelity": "equivalent"}


def base(key: str) -> dict:
    return {"schema": "inkblade-probe-template-v1", "key": key, "version": "1.0.0",
            "meta": meta(key),
            "inputs": {"target": {"from": "params.target", "required": True}},
            "defaults": {"timeout_ms": 8000},
            "payloads": {"benign": {"marker": "INKBLADE-BENIGN"}},
            "limits": {"timeout_ms": 30000, "max_http_requests": 16}}


def write(doc: dict) -> None:
    (MODULES / doc["key"] / "template.json").write_text(
        json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("wrote", doc["key"])


def art(key: str, fields: dict) -> list[dict]:
    return [{"name": f"{key}.json", "kind": "json", "fields": fields}]


# 1 ------------------------------------------------------ prefix cache leak
key = "prefix-cache-cross-tenant-leak"
d = base(key)
d["computed"] = {
    "prime_ok": "steps.prime.status == 200",
    "reuse_cached": "steps.reuse.json.usage.cached_tokens",
    "leak": "steps.reuse.status == 200 and steps.reuse.json.usage.cached_tokens > 0",
}
d["steps"] = [
    {"id": "prime", "op": "http", "method": "POST",
     "url": "{{input.target}}/v1/chat/completions",
     "headers": {"X-Tenant": "tenant-b"},
     "body": {"model": "longctx-mock", "max_tokens": 1,
              "messages": [{"role": "user", "content": "tenant-b confidential prefix INKBLADE-BENIGN cache seed"}]},
     "save": "prime", "allow_failure": True},
    {"id": "reuse", "op": "http", "method": "POST",
     "url": "{{input.target}}/v1/chat/completions",
     "headers": {"X-Tenant": "tenant-a"},
     "body": {"model": "longctx-mock", "max_tokens": 1,
              "messages": [{"role": "user", "content": "tenant-b confidential prefix INKBLADE-BENIGN cache seed"}]},
     "save": "reuse", "allow_failure": True},
]
d["findings"] = [
    {"id": "leak", "when": "computed.leak", "sev": "high",
     "title": "长上下文前缀缓存跨租户命中（tenant-a 复用 tenant-b 前缀）",
     "detail": "cached_tokens={{computed.reuse_cached}} context_window={{steps.reuse.json.context_window}} tenant=tenant-a",
     "evidence": "{{steps.reuse.sha256}}", "mapping": "OWASP LLM08",
     "fix": "前缀键包含 tenant|salt；跨租户复用返回 403"},
    {"id": "clean", "when": "not computed.leak", "sev": "info",
     "title": "前缀缓存按租户隔离",
     "detail": "status={{steps.reuse.status}} cached={{steps.reuse.json.usage.cached_tokens}}"},
]
d["artifacts"] = art(key, {"leak": "computed.leak", "cached_tokens": "computed.reuse_cached",
                            "route": "'/v1/chat/completions'"})
write(d)

# 2 ------------------------------------------------------ PD KV channel
key = "prefill-decode-kv-channel-unauth"
d = base(key)
d["computed"] = {
    "channel_open": "steps.kv.status == 200 and steps.kv.json.service == 'longctx-infer'",
    "metrics_open": "steps.metrics.status == 200",
}
d["steps"] = [
    {"id": "metrics", "op": "http", "method": "GET", "url": "{{input.target}}/metrics",
     "headers": {"X-Tenant": "tenant-a"}, "save": "metrics", "allow_failure": True},
    {"id": "kv", "op": "http", "method": "POST", "url": "{{input.target}}/kv/transfer",
     "headers": {"X-Tenant": "tenant-a"},
     "body": {"op": "read", "block_id": "tenant-b/ctx/seed-001"},
     "save": "kv", "allow_failure": True},
]
d["findings"] = [
    {"id": "open", "when": "computed.channel_open", "sev": "high",
     "title": "Prefill/Decode KV 传输通道未鉴权可读",
     "detail": "status={{steps.kv.status}} found={{steps.kv.json.found}} block={{steps.kv.json.block_id}} layer={{steps.kv.json.layer}}",
     "evidence": "{{steps.kv.sha256}}", "mapping": "PD KV channel isolation",
     "fix": "KV 通道强制 mTLS/租户鉴权；block 命名空间校验"},
    {"id": "clean", "when": "not computed.channel_open", "sev": "info",
     "title": "KV 传输通道鉴权生效", "detail": "status={{steps.kv.status}}"},
]
d["artifacts"] = art(key, {"channel_open": "computed.channel_open",
                            "found": "steps.kv.json.found", "block": "steps.kv.json.block_id",
                            "kv_cache_usage": "steps.metrics.json.kv_cache_usage"})
write(d)

# 3 ------------------------------------------------------ context limit
key = "context-limit-bypass"
d = base(key)
d["computed"] = {
    "prefill": "steps.chat.json.usage.prefill_tokens",
    "window": "steps.chat.json.context_window",
    "over": "steps.chat.json.usage.prefill_tokens > steps.chat.json.context_window",
    "accepted": "steps.chat.status == 200",
}
d["steps"] = [
    {"id": "before", "op": "http", "method": "GET", "url": "{{input.target}}/metrics",
     "headers": {"X-Tenant": "tenant-a"}, "save": "before", "allow_failure": True},
    {"id": "chat", "op": "http", "method": "POST", "url": "{{input.target}}/v1/chat/completions",
     "headers": {"X-Tenant": "tenant-a"},
     "body": {"model": "longctx-mock", "max_tokens": 8, "prompt_tokens": 200000,
              "context_window": 131072,
              "messages": [{"role": "user", "content": "INKBLADE-BENIGN over-window probe"}]},
     "save": "chat", "allow_failure": True},
    {"id": "after", "op": "http", "method": "GET", "url": "{{input.target}}/metrics",
     "headers": {"X-Tenant": "tenant-a"}, "save": "after", "allow_failure": True},
]
d["findings"] = [
    {"id": "bypass", "when": "computed.accepted and computed.over", "sev": "high",
     "title": "上下文窗口上限被绕过：超窗 prompt 仍被接受",
     "detail": "prefill={{computed.prefill}} window={{computed.window}} finish={{steps.chat.json.choices[0].finish_reason}} queue={{steps.chat.json.queue_depth}}",
     "evidence": "{{steps.chat.sha256}}", "mapping": "long-context-window-exhaustion",
     "fix": "在 tokenizer 层强制 prompt_tokens <= context_window；超窗 400"},
    {"id": "clean", "when": "not (computed.accepted and computed.over)", "sev": "info",
     "title": "上下文窗口上限生效", "detail": "status={{steps.chat.status}}"},
]
d["artifacts"] = art(key, {"prefill": "computed.prefill", "window": "computed.window",
                            "over": "computed.over", "accepted": "computed.accepted"})
write(d)

# 4 ------------------------------------------------------ window exhaustion
key = "long-context-window-exhaustion"
d = base(key)
d["computed"] = {
    "over": "steps.chat.json.usage.prefill_tokens > steps.chat.json.context_window",
    "accepted": "steps.chat.status == 200",
    "queue_before": "steps.before.json.queue_depth",
    "queue_after": "steps.after.json.queue_depth",
    "queue_grew": "steps.after.json.queue_depth > steps.before.json.queue_depth",
}
d["steps"] = [
    {"id": "before", "op": "http", "method": "GET", "url": "{{input.target}}/metrics",
     "save": "before", "allow_failure": True},
    {"id": "chat", "op": "http", "method": "POST", "url": "{{input.target}}/v1/chat/completions",
     "headers": {"X-Tenant": "tenant-a"},
     "body": {"model": "longctx-mock", "max_tokens": 8, "prompt_tokens": 200000,
              "messages": [{"role": "user", "content": "INKBLADE-BENIGN exhaustion probe"}]},
     "save": "chat", "allow_failure": True},
    {"id": "after", "op": "http", "method": "GET", "url": "{{input.target}}/metrics",
     "save": "after", "allow_failure": True},
]
d["findings"] = [
    {"id": "exhaust", "when": "computed.accepted and (computed.over or computed.queue_grew)",
     "sev": "high", "title": "超窗请求进入队列：prefill 资源被长上下文耗尽",
     "detail": "queue_before={{computed.queue_before}} queue_after={{computed.queue_after}} over={{computed.over}}",
     "evidence": "{{steps.chat.sha256}}", "mapping": "long-context-window-exhaustion",
     "fix": "超窗 400；队列按租户配额与 prompt 长度加权"},
    {"id": "clean", "when": "not (computed.accepted and (computed.over or computed.queue_grew))",
     "sev": "info", "title": "超窗请求被拒绝/未放大队列",
     "detail": "status={{steps.chat.status}} queue={{computed.queue_after}}"},
]
d["artifacts"] = art(key, {"over": "computed.over", "queue_before": "computed.queue_before",
                            "queue_after": "computed.queue_after"})
write(d)

# 5 ------------------------------------------------------ memory amplification
key = "long-context-memory-amplification"
d = base(key)
d["computed"] = {
    "kv_before": "steps.before.json.kv_cache_bytes",
    "kv_after": "steps.after.json.kv_cache_bytes",
    "delta": "steps.after.json.kv_cache_bytes - steps.before.json.kv_cache_bytes",
    "amplified": "steps.after.json.kv_cache_bytes - steps.before.json.kv_cache_bytes > 50000",
}
d["steps"] = [
    {"id": "before", "op": "http", "method": "GET", "url": "{{input.target}}/metrics",
     "headers": {"X-Tenant": "tenant-a"}, "save": "before", "allow_failure": True},
    {"id": "chat", "op": "http", "method": "POST", "url": "{{input.target}}/v1/chat/completions",
     "headers": {"X-Tenant": "tenant-a"},
     "body": {"model": "longctx-mock", "max_tokens": 1, "prompt_tokens": 32768,
              "messages": [{"role": "user", "content": "INKBLADE-BENIGN memory amplification"}]},
     "save": "chat", "allow_failure": True},
    {"id": "after", "op": "http", "method": "GET", "url": "{{input.target}}/metrics",
     "headers": {"X-Tenant": "tenant-a"}, "save": "after", "allow_failure": True},
]
d["findings"] = [
    {"id": "amplify", "when": "steps.chat.status == 200 and computed.amplified", "sev": "medium",
     "title": "长上下文 KV 预留放大：单请求显著抬升 KV 占用",
     "detail": "kv_before={{computed.kv_before}} kv_after={{computed.kv_after}} delta={{computed.delta}}",
     "evidence": "{{steps.after.sha256}}", "mapping": "long-context-memory-amplification",
     "fix": "按实际 prompt+decode 预留；KV 池配额与驱逐策略"},
    {"id": "clean", "when": "not (steps.chat.status == 200 and computed.amplified)", "sev": "info",
     "title": "KV 预留按实际 token 计算", "detail": "delta={{computed.delta}}"},
]
d["artifacts"] = art(key, {"kv_before": "computed.kv_before", "kv_after": "computed.kv_after",
                            "delta": "computed.delta"})
write(d)

# 6 ------------------------------------------------------ KV integrity poison
key = "kv-cache-integrity-poison"
d = base(key)
d["modes"] = {"probe_only": True, "backup_write": True, "requires_backup": True}
d["computed"] = {
    "found": "steps.read.status == 200 and steps.read.json.found == true",
    "marker": "contains(str(steps.read.json.value), 'INKBLADE')",
    "readback": "steps.readback.status == 200 and steps.readback.json.found == true",
}
d["steps"] = [
    {"id": "read", "op": "http", "method": "POST", "url": "{{input.target}}/kv/transfer",
     "headers": {"X-Tenant": "tenant-a"},
     "body": {"op": "read", "block_id": "tenant-b/ctx/seed-001"},
     "save": "read", "allow_failure": True},
    {"id": "write", "op": "http", "method": "POST", "write": True,
     "when": "params.mode == 'backup-write'",
     "url": "{{input.target}}/kv/transfer", "headers": {"X-Tenant": "tenant-a"},
     "body": {"op": "write", "block_id": "poison-{{ctx.marker}}",
              "value": "INKBLADE-BENIGN-POISON {{ctx.marker}}"},
     "save": "write", "allow_failure": True},
    {"id": "readback", "op": "http", "method": "POST",
     "when": "params.mode == 'backup-write'",
     "url": "{{input.target}}/kv/transfer", "headers": {"X-Tenant": "tenant-a"},
     "body": {"op": "read", "block_id": "poison-{{ctx.marker}}"},
     "save": "readback", "allow_failure": True},
]
d["findings"] = [
    {"id": "cross", "when": "computed.found", "sev": "high",
     "title": "KV 块跨租户可读（block 命名空间未校验）",
     "detail": "block={{steps.read.json.block_id}} found={{steps.read.json.found}} layer={{steps.read.json.layer}}",
     "evidence": "{{steps.read.sha256}}", "mapping": "kv-cache-integrity-poison",
     "fix": "block id 绑定租户；读取前校验 namespace"},
    {"id": "poison", "when": "params.mode == 'backup-write' and computed.readback and steps.write.ok",
     "sev": "high", "title": "KV 块写入持久化（可注入跨请求缓存内容）",
     "detail": "block=poison-{{ctx.marker}} readback_found={{computed.readback}}",
     "evidence": "{{steps.readback.sha256}}", "mapping": "kv-cache-integrity-poison",
     "fix": "KV 写入仅同租户；内容签名/哈希校验"},
]
d["artifacts"] = art(key, {"found": "computed.found", "readback": "computed.readback",
                            "mode": "params.mode"})
write(d)

# 7 ------------------------------------------------------ checkpoint shard
key = "checkpoint-shard-poison"
d = base(key)
d["modes"] = {"probe_only": True, "backup_write": True, "requires_backup": True}
d["computed"] = {
    "exists": "steps.read.status == 200",
    "marker": "contains(steps.read.text, 'INKBLADE')",
    "write_ok": "steps.write.status == 200",
    "readback_marker": "contains(steps.readback.text, 'INKBLADE')",
}
d["steps"] = [
    {"id": "metrics", "op": "http", "method": "GET", "url": "{{input.target}}/metrics",
     "headers": {"X-Tenant": "tenant-a"}, "save": "metrics", "allow_failure": True},
    {"id": "read", "op": "http", "method": "GET",
     "url": "{{input.target}}/checkpoint/shards/shard-00000",
     "headers": {"X-Tenant": "tenant-a"}, "save": "read", "allow_failure": True},
    {"id": "write", "op": "http", "method": "POST", "write": True,
     "when": "params.mode == 'backup-write'",
     "url": "{{input.target}}/checkpoint/shards", "headers": {"X-Tenant": "tenant-a"},
     "body": {"shard_id": "poison-{{ctx.marker}}", "payload": "INKBLADE-BENIGN-SHARD {{ctx.marker}}"},
     "save": "write", "allow_failure": True},
    {"id": "readback", "op": "http", "method": "GET",
     "when": "params.mode == 'backup-write'",
     "url": "{{input.target}}/checkpoint/shards/poison-{{ctx.marker}}",
     "headers": {"X-Tenant": "tenant-a"}, "save": "readback", "allow_failure": True},
]
d["findings"] = [
    {"id": "read", "when": "steps.metrics.status == 200 and computed.exists and computed.marker", "sev": "high",
     "title": "checkpoint shard 可跨租户读取（含训练数据标记）",
     "detail": "shard=shard-00001 status={{steps.read.status}} marker={{computed.marker}}",
     "evidence": "{{steps.read.sha256}}", "mapping": "checkpoint-shard-poison",
     "fix": "shard 存储按租户/作业隔离；读取鉴权"},
    {"id": "poison", "when": "params.mode == 'backup-write' and computed.write_ok and computed.readback_marker",
     "sev": "high", "title": "checkpoint shard 可写并读回：训练数据投毒路径",
     "detail": "shard=poison-{{ctx.marker}} readback_marker={{computed.readback_marker}}",
     "evidence": "{{steps.readback.sha256}}", "mapping": "checkpoint-shard-poison",
     "fix": "checkpoint 写入仅训练作业 SA；内容签名+版本 pinning"},
]
d["artifacts"] = art(key, {"exists": "computed.exists", "marker": "computed.marker",
                            "readback_marker": "computed.readback_marker",
                            "mode": "params.mode"})
write(d)

# 8 ------------------------------------------------------ training collective
key = "long-context-training-collective-surface"
d = base(key)
d["computed"] = {
    "metrics_ok": "steps.metrics.status == 200",
    "training": "steps.metrics.json.training",
    "exposed": "steps.metrics.status == 200 and steps.metrics.json.training != null",
}
d["steps"] = [{"id": "metrics", "op": "http", "method": "GET",
               "url": "{{input.target}}/metrics", "headers": {"X-Tenant": "tenant-a"},
               "save": "metrics", "allow_failure": True}]
d["findings"] = [
    {"id": "exposed", "when": "computed.exposed", "sev": "medium",
     "title": "训练/集合通信配置随 metrics 暴露",
     "detail": "training={{str(steps.metrics.json.training)}} decode_pool={{str(steps.metrics.json.decode_pool)}}",
     "evidence": "{{steps.metrics.sha256}}", "mapping": "long-context-training-collective-surface",
     "fix": "metrics 拆分公开/管理面；训练拓扑与集合通信参数仅管理面可见"},
    {"id": "clean", "when": "not computed.exposed", "sev": "info",
     "title": "metrics 未暴露训练集合通信配置", "detail": "status={{steps.metrics.status}}"},
]
d["artifacts"] = art(key, {"exposed": "computed.exposed",
                            "training": "steps.metrics.json.training",
                            "queue_depth": "steps.metrics.json.queue_depth"})
write(d)
