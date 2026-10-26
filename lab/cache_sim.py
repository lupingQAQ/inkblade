"""lab/cache_sim.py — 多租户推理缓存安全仿真靶场（前缀缓存/近似缓存/远程 KV 池/路由指标）。

仅监听 127.0.0.1，仅标准库。两种姿态（与真实框架修复语义同构）：

- vulnerable（fail-open）：
  * prefix cache 键 = sha256(prefix) 全局共享（cache_salt 参数被忽略，跨租户命中）；
  * 近似/语义缓存全局检索（相似度阈值内返回他租户条目 → 误命中泄露）；
  * 远程 KV 池（Mooncake/LMCache 风格块存储）无租户命名空间校验（任意租户可读写任意块），
    LRU 逐出后残留可跨租户读，逐出策略（pinned）可被任意租户设置；
  * EPP 路由器指标无鉴权、按租户粒度暴露（KV 利用率/命中率/前缀样本 → 缓存状态侧信道）；
  * /config 明文暴露弱缓存策略。
- fixed（加固）：
  * prefix 键 = sha256(tenant|salt|prefix)（cache_salt 与租户共同进键，vLLM 同构加强）：
    跨租户探测恒为未命中（不提供 403 存在性 oracle）、同租户同 salt 命中、换 salt 不命中；
  * 近似缓存仅本租户检索（他租户 miss）；
  * KV 池块归属租户命名空间（越权 403），pinned 仅管理密钥可设，
    逐出残留立即 zeroize（404）；
  * 路由指标：无身份 401，租户头仅本租户视图，admin 密钥全局视图；
  * /config 需要管理密钥（返回加固后策略）。

预置 benign 种子（全部 INKBLADE-BENIGN- 前缀，无真实数据）：
- 租户 tenant-b 的 30 条成员前缀（时序侧信道成员推断字典靶）；
- 租户 tenant-b 的残留靶前缀（含 INKBLADE-BENIGN-RESIDUE-VICTIM）；
- KV 池 tenant-b/ctx/seed-001（含 INKBLADE-BENIGN-POOL-VICTIM）与 tenant-a 对照块；
- 近似缓存 tenant-b 受害条目 + tenant-a 对照条目。

TTFT 口径：命中 = 22–31ms、未命中 = 185–274ms（由 sha256 摘要推导的确定性抖动，
非真实 GPU 计时；效果级验证以报告值差分 + 显著性检验表达）。

命令行：python lab/cache_sim.py [--port N] [--mode vulnerable|fixed] [--threshold F]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import threading
import time
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

HOST = "127.0.0.1"
MODES = ("vulnerable", "fixed")
DEFAULT_MODE = "vulnerable"
ADMIN_TOKEN = "cache-admin-key"
TENANT_HEADER = "X-Tenant"
ALLOWED_TENANTS = ("tenant-a", "tenant-b", "tenant-c")
REQUESTER_TENANT = "tenant-a"
VICTIM_TENANT = "tenant-b"

POOL_CAPACITY_BLOCKS = 128
APPROX_SIMILARITY_THRESHOLD = 0.85
MEMBER_SEED_COUNT = 30
RESIDUE_SAMPLE_LIMIT = 5

TTFT_HIT_BASE_MS = 22
TTFT_HIT_JITTER_MS = 10
TTFT_MISS_BASE_MS = 185
TTFT_MISS_JITTER_MS = 90

VICTIM_APPROX_TEXT = (
    "tenant-b quarterly revenue guidance for fiscal 2026 total pipeline "
    "equals 42.7M USD with eighteen percent growth"
)
VICTIM_APPROX_RESPONSE = (
    "tenant-b confidential guidance: 42.7M USD, growth 18 percent "
    "[INKBLADE-BENIGN-APPROX-VICTIM]"
)
CONTROL_APPROX_TEXT = (
    "tenant-a infrastructure capacity plan for fiscal 2026 total gpu "
    "nodes equals 512 units"
)
CONTROL_APPROX_RESPONSE = (
    "tenant-a plan: 512 gpu nodes [INKBLADE-BENIGN-APPROX-CONTROL]"
)
VICTIM_RESIDUE_PREFIX = (
    "tenant-b residue corpus marker INKBLADE-BENIGN-RESIDUE-VICTIM "
    "quarterly close data pack appendix"
)
VICTIM_POOL_BLOCK_ID = "tenant-b/ctx/seed-001"
CONTROL_POOL_BLOCK_ID = "tenant-a/ctx/control-001"
VICTIM_POOL_MARKER = "INKBLADE-BENIGN-POOL-VICTIM"
TIMING_MARKER = "INKBLADE-BENIGN-TIMING"


def member_prefix(index: int) -> str:
    """租户 victim 的成员前缀（时序侧信道成员字典靶，确定性生成）。"""
    return (f"tenant-b member context {index:02d} {TIMING_MARKER} "
            f"corpus analytics monthly summary {index:02d}")


def member_prefixes(count: int = MEMBER_SEED_COUNT) -> list[str]:
    return [member_prefix(i) for i in range(count)]


def _utcnow_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def prefix_digest(prefix: str, tenant: str = "", salt: str = "",
                  mode: str = "vulnerable") -> str:
    """前缀块键派生：vulnerable=sha256(prefix)（salt 被忽略 → 全局共享）；
    fixed=sha256(tenant|salt|prefix)（键含租户与 salt → 跨租户探测恒为未命中，
    不以 403 区分"存在/不存在"，避免二次 oracle）。"""
    if mode == "fixed":
        return _sha256_text(f"{tenant}|{salt}|{prefix}")[:16]
    return _sha256_text(prefix)[:16]


def similarity(a: str, b: str) -> float:
    """词集 Jaccard 相似度（近似缓存检索口径，0–1）。"""
    wa = {w.strip(".,:;").lower() for w in str(a).split() if w.strip(".,:;")}
    wb = {w.strip(".,:;").lower() for w in str(b).split() if w.strip(".,:;")}
    if not wa or not wb:
        return 0.0
    return len(wa & wb) / len(wa | wb)


class _RequestContext:
    def __init__(self, mode, state, headers, body, path, query, params, entry):
        self.mode = mode
        self.state = state
        self.headers = headers
        self.body = body
        self.path = path
        self.query = query
        self.params = params
        self.entry = entry

    @property
    def admin(self) -> bool:
        return (self.headers.get("Authorization") or "") == f"Bearer {ADMIN_TOKEN}"

    @property
    def tenant(self) -> str:
        return (self.headers.get(TENANT_HEADER) or self.headers.get("x-tenant") or "").strip()


# ---------------------------------------------------------------------------
# 行为函数（返回 (status, payload)）
# ---------------------------------------------------------------------------


def _chat_completions(ctx: _RequestContext):
    state = ctx.state
    tenant = ctx.tenant
    if not tenant:
        return 400, {"error": "missing_tenant_header", "hint": f"需要 {TENANT_HEADER} 请求头"}
    if ctx.mode == "fixed" and tenant not in ALLOWED_TENANTS:
        return 401, {"error": "unknown_tenant", "tenant": tenant}

    body = ctx.body
    prefix = str(body.get("prompt_prefix") or "")
    if not prefix:
        return 400, {"error": "missing_prompt_prefix",
                     "hint": "本仿真以 prompt_prefix 驱动前缀缓存行为"}
    salt = str(body.get("cache_salt") or "")
    try:
        prefix_tokens = int(body.get("prefix_tokens") or 2048)
    except (TypeError, ValueError):
        prefix_tokens = 2048
    prefix_tokens = max(1, prefix_tokens)
    try:
        max_tokens = int(body.get("max_tokens") or 1)
    except (TypeError, ValueError):
        max_tokens = 1

    digest = prefix_digest(prefix, tenant, salt, ctx.mode)
    with state.lock:
        state.requests += 1
        stats = state.tenant_stats.setdefault(
            tenant, {"requests": 0, "hits": 0, "cached_tokens_total": 0})
        stats["requests"] += 1
        entry = state.pool.get(digest)
        hit = False
        cached_tokens = 0
        if entry is not None:
            if ctx.mode == "fixed" and entry["tenant"] != tenant and not salt:
                return 403, {
                    "error": "cache_salt_required_for_cross_tenant_prefix",
                    "hint": "跨租户复用 prefix cache 必须携带一致的 cache_salt",
                }
            if ctx.mode != "fixed" or (entry["tenant"] == tenant and entry["salt"] == salt):
                hit = True
                cached_tokens = min(int(entry.get("tokens") or 0), prefix_tokens)
                state.pool.move_to_end(digest)
                entry["last_used"] = _utcnow_iso()
        if hit:
            stats["hits"] += 1
            stats["cached_tokens_total"] += cached_tokens
        else:
            _pool_insert(state, digest, {
                "kind": "prefix",
                "block_id": digest,
                "tenant": tenant,
                "salt": salt,
                "tokens": prefix_tokens,
                "prefix": prefix,
                "policy": "lru",
                "pinned": False,
                "created_at": _utcnow_iso(),
                "last_used": _utcnow_iso(),
            }, ctx.mode)
        jitter = int(_sha256_text(f"{digest}|{state.requests}")[:6], 16)
        if hit:
            ttft = TTFT_HIT_BASE_MS + jitter % TTFT_HIT_JITTER_MS
        else:
            ttft = TTFT_MISS_BASE_MS + jitter % TTFT_MISS_JITTER_MS
        live_blocks = len(state.pool)

    return 200, {
        "id": "chatcmpl-cache-" + _sha256_text(f"{digest}|{state.requests}")[:10],
        "object": "chat.completion",
        "created": int(time.time()),
        "mode": ctx.mode,
        "model": str(body.get("model") or "cache-plane-mock"),
        "tenant": tenant,
        "choices": [{"index": 0, "finish_reason": "stop",
                     "message": {"role": "assistant", "content": "mock cache-plane response"}}],
        "usage": {
            "prompt_tokens": prefix_tokens,
            "completion_tokens": max(1, max_tokens),
            "total_tokens": prefix_tokens + max(1, max_tokens),
            "cached_tokens": cached_tokens,
        },
        "cache": {"hit": hit, "digest": digest, "salt_present": bool(salt)},
        "ttft_ms": ttft,
        "pool_live_blocks": live_blocks,
    }


def _pool_insert(state, block_id: str, entry: dict, mode: str) -> int:
    """插入块并执行 LRU 逐出（跳过 pinned）；返回逐出条数。

    逐出的 kind=prefix 块：vulnerable 进入残留层（residue 可跨租户读）；
    fixed 立即 zeroize（丢弃）。
    """
    evicted = 0
    state.pool[block_id] = entry
    while len(state.pool) > state.capacity:
        victim_id = next((k for k, v in state.pool.items() if not v.get("pinned")), None)
        if victim_id is None:
            break
        victim = state.pool.pop(victim_id)
        evicted += 1
        state.evictions_total += 1
        if victim.get("kind") == "prefix":
            if mode == "vulnerable":
                state.residue[victim_id] = {
                    "digest": victim_id,
                    "tenant": victim["tenant"],
                    "salt": victim.get("salt", ""),
                    "tokens": victim.get("tokens", 0),
                    "prefix_preview": str(victim.get("prefix", ""))[:96],
                    "evicted_at": _utcnow_iso(),
                }
            # fixed：zeroize（不留残留层）
    return evicted


def _config(ctx: _RequestContext):
    if ctx.mode == "fixed" and not ctx.admin:
        return 401, {"error": "unauthorized", "service": "cache-plane-sim",
                     "hint": "fixed 模式 /config 需要管理密钥"}
    if ctx.mode == "fixed":
        return 200, {
            "service": "cache-plane-sim", "mode": ctx.mode,
            "cache_salt_policy": {"enabled": True, "per_tenant_salt": True,
                                  "key_scope": "tenant"},
            "approx_cache": {"enabled": True,
                             "similarity_threshold": ctx.state.approx_threshold,
                             "scope": "tenant"},
            "kv_pool": {"capacity": ctx.state.capacity, "eviction": "lru",
                        "residue_policy": "zeroize", "pin_policy": "admin-only",
                        "namespace_isolation": True},
            "router_metrics": {"auth": True, "granularity": "tenant-scoped"},
        }
    return 200, {
        "service": "cache-plane-sim", "mode": ctx.mode,
        "cache_salt_policy": {"enabled": False, "per_tenant_salt": False,
                              "key_scope": "global"},
        "approx_cache": {"enabled": True,
                         "similarity_threshold": ctx.state.approx_threshold,
                         "scope": "global"},
        "kv_pool": {"capacity": ctx.state.capacity, "eviction": "lru",
                    "residue_policy": "retain", "pin_policy": "open",
                    "namespace_isolation": False},
        "router_metrics": {"auth": False, "granularity": "per-tenant"},
    }


def _tenant_metrics(state, tenant: str) -> dict:
    stats = state.tenant_stats.get(tenant) or {"requests": 0, "hits": 0,
                                               "cached_tokens_total": 0}
    prefix_entries = [v for v in state.pool.values()
                      if v.get("kind") == "prefix" and v.get("tenant") == tenant]
    samples = [{"digest": e["block_id"], "preview": str(e.get("prefix", ""))[:32]}
               for e in prefix_entries[:RESIDUE_SAMPLE_LIMIT]]
    requests = int(stats.get("requests") or 0)
    hits = int(stats.get("hits") or 0)
    return {
        "requests": requests,
        "cache_hits": hits,
        "prefix_hit_rate": round(hits / requests, 4) if requests else 0.0,
        "cached_tokens_total": int(stats.get("cached_tokens_total") or 0),
        "distinct_prefixes": len(prefix_entries),
        "top_prefix_samples": samples,
    }


def _router_metrics(ctx: _RequestContext):
    state = ctx.state
    tenant = ctx.tenant
    if ctx.mode == "fixed" and not ctx.admin and not tenant:
        return 401, {"error": "unauthorized", "service": "cache-plane-sim",
                     "hint": "fixed 模式路由指标需要租户头或管理密钥"}
    with state.lock:
        tenants = sorted({v.get("tenant", "") for v in state.pool.values()
                          if v.get("tenant")} | set(state.tenant_stats))
        if ctx.mode == "fixed" and not ctx.admin:
            tenants = [t for t in tenants if t == tenant]  # 仅本租户视图
        per_tenant = {t: _tenant_metrics(state, t) for t in tenants}
        total_requests = sum(int(s.get("requests") or 0)
                             for s in state.tenant_stats.values())
        payload = {
            "service": "epp-router-sim", "mode": ctx.mode,
            "pool": {
                "capacity": state.capacity,
                "live_blocks": len(state.pool),
                "utilization": round(len(state.pool) / state.capacity, 4),
                "evictions_total": state.evictions_total,
                "kv_cache_usage": round(len(state.pool) / state.capacity, 4),
            },
            "aggregated": {
                "requests_total": total_requests,
                "tenants_visible": len(per_tenant),
                "scope": "own-tenant" if (ctx.mode == "fixed" and not ctx.admin) else "global",
            },
            "per_tenant": per_tenant,
        }
    return 200, payload


def _approx_lookup(ctx: _RequestContext):
    tenant = ctx.tenant
    if not tenant:
        return 400, {"error": "missing_tenant_header"}
    text = str(ctx.body.get("text") or ctx.body.get("prompt") or "")
    if not text:
        return 400, {"error": "missing_text"}
    with ctx.state.lock:
        candidates = list(ctx.state.approx)
    if ctx.mode == "fixed":
        candidates = [e for e in candidates if e["tenant"] == tenant]
    best, best_sim = None, 0.0
    for entry in candidates:
        sim = similarity(text, entry["text"])
        if sim > best_sim:
            best, best_sim = entry, sim
    hit = best is not None and best_sim >= ctx.state.approx_threshold
    return 200, {
        "service": "cache-plane-sim", "mode": ctx.mode,
        "requester_tenant": tenant,
        "hit": bool(hit),
        "threshold": ctx.state.approx_threshold,
        "best_similarity": round(best_sim, 4),
        "searched_entries": len(candidates),
        "scope": "tenant" if ctx.mode == "fixed" else "global",
        "matched": ({
            "tenant": best["tenant"],
            "similarity": round(best_sim, 4),
            "response": best["response"],
            "created_at": best["created_at"],
        } if hit else None),
    }


def _approx_store(ctx: _RequestContext):
    tenant = ctx.tenant
    if not tenant:
        return 400, {"error": "missing_tenant_header"}
    text = str(ctx.body.get("text") or "")
    if not text:
        return 400, {"error": "missing_text"}
    with ctx.state.lock:
        ctx.state.approx.append({
            "tenant": tenant,
            "text": text,
            "response": str(ctx.body.get("response") or ""),
            "created_at": _utcnow_iso(),
        })
    return 200, {"service": "cache-plane-sim", "mode": ctx.mode, "stored": True,
                 "tenant": tenant, "scope": "tenant" if ctx.mode == "fixed" else "global"}


def _kvpool_read(ctx: _RequestContext):
    block_id = unquote(str((ctx.params or {}).get("block") or ""))
    if not block_id:
        return 400, {"error": "missing_block_id"}
    tenant = ctx.tenant
    with ctx.state.lock:
        block = ctx.state.pool.get(block_id)
        if block is not None:
            ctx.state.pool.move_to_end(block_id)
    if block is None:
        return 404, {"error": "block_not_found", "block_id": block_id, "found": False}
    if ctx.mode == "fixed" and not ctx.admin and block.get("tenant") != tenant:
        return 403, {"error": "kv_pool_namespace_isolation",
                     "block_tenant": block.get("tenant"), "requester_tenant": tenant,
                     "hint": "fixed 模式 KV 池块按租户命名空间隔离"}
    return 200, {
        "service": "cache-plane-sim", "mode": ctx.mode, "found": True,
        "block_id": block_id,
        "tenant": block.get("tenant"),
        "kind": block.get("kind"),
        "value": block.get("value"),
        "sha256": block.get("sha256", ""),
        "policy": block.get("policy"),
        "pinned": bool(block.get("pinned")),
        "updated_at": block.get("last_used") or block.get("created_at"),
    }


def _kvpool_write(ctx: _RequestContext):
    tenant = ctx.tenant
    if not tenant and not ctx.admin:
        return 400, {"error": "missing_tenant_header"}
    body = ctx.body
    block_id = str(body.get("block_id") or "")
    if not block_id:
        return 400, {"error": "missing_block_id"}
    if "value" not in body:
        return 400, {"error": "missing_value"}
    namespace = str(body.get("namespace") or tenant or "global")
    policy = str(body.get("eviction_policy") or "lru").lower()
    if ctx.mode == "fixed":
        if not ctx.admin and namespace not in ("", tenant):
            return 403, {"error": "cross_tenant_kv_write_denied",
                         "namespace": namespace, "requester_tenant": tenant}
        if policy == "pinned" and not ctx.admin:
            # fixed：pinned 属管理面策略，普通租户强制降级 lru（防逐出策略绕过）
            policy = "lru"
            pin_denied = True
        else:
            pin_denied = False
    else:
        pin_denied = False
    value = body.get("value")
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False,
                                                           sort_keys=True)
    entry = {
        "kind": "raw",
        "block_id": block_id,
        "tenant": namespace if ctx.mode != "fixed" else (namespace or tenant),
        "namespace": namespace,
        "value": value,
        "sha256": _sha256_text(text),
        "tokens": max(1, int(body.get("tokens") or 256)),
        "policy": policy,
        "pinned": policy == "pinned",
        "created_at": _utcnow_iso(),
        "last_used": _utcnow_iso(),
    }
    with ctx.state.lock:
        evicted = _pool_insert(ctx.state, block_id, entry, ctx.mode)
    payload = {
        "service": "cache-plane-sim", "mode": ctx.mode, "stored": True,
        "block_id": block_id, "namespace": namespace,
        "policy": policy, "pinned": entry["pinned"],
        "sha256": entry["sha256"], "bytes": len(text.encode("utf-8")),
        "evicted": evicted,
    }
    if pin_denied:
        payload["pinning_denied"] = True
        payload["hint"] = "fixed 模式 pinned 逐出策略仅管理密钥可设置"
    return 200, payload


def _cache_residue(ctx: _RequestContext):
    """被逐出前缀块的残留读：vulnerable 保留残留层（跨租户可读）；fixed zeroize。"""
    query = ctx.query
    prefix = str((query.get("prefix") or [""])[0])
    digest = str((query.get("digest") or [""])[0])
    if not prefix and not digest:
        return 400, {"error": "missing_prefix_or_digest"}
    if ctx.mode == "fixed":
        return 404, {"error": "residue_zeroized", "found": False,
                     "hint": "fixed 模式逐出即 zeroize，残留层不保留"}
    if not digest:
        digest = prefix_digest(prefix)  # vulnerable 派生口径（全局键）
    with ctx.state.lock:
        entry = ctx.state.residue.get(digest)
    if entry is None:
        return 404, {"error": "residue_not_found", "digest": digest, "found": False}
    return 200, {
        "service": "cache-plane-sim", "mode": ctx.mode, "found": True,
        "digest": digest,
        "tenant": entry["tenant"],
        "prefix_preview": entry["prefix_preview"],
        "tokens": entry["tokens"],
        "evicted_at": entry["evicted_at"],
    }


def _routes_manifest(ctx: _RequestContext):
    return 200, {
        "service": "inkblade-cache-lab",
        "mode": ctx.mode,
        "host": HOST,
        "admin_token_hint": f"fixed 模式管理密钥 = Authorization: Bearer {ADMIN_TOKEN}",
        "tenant_header": TENANT_HEADER,
        "seeds": {
            "member_prefixes": MEMBER_SEED_COUNT,
            "victim_residue_prefix": True,
            "victim_pool_block": VICTIM_POOL_BLOCK_ID,
            "control_pool_block": CONTROL_POOL_BLOCK_ID,
        },
        "route_count": len(ROUTE_TABLE),
        "routes": [{k: v for k, v in e.items() if k != "behavior"} for e in ROUTE_TABLE],
    }


# ---------------------------------------------------------------------------
# 路由表（vulnerable/fixed = 规范探针请求的基线状态码）
# ---------------------------------------------------------------------------

ROUTE_TABLE = [
    {"service": "cache-plane", "title": "OpenAI 兼容对话补全（前缀缓存）", "method": "POST",
     "path": "/v1/chat/completions", "vulnerable": 200, "fixed": 200, "gate": "tenant",
     "writes": False,
     "description": "前缀缓存语义：vulnerable 全局键跨租户命中（cached_tokens>0、TTFT 命中档）；"
                    "fixed 键含 tenant|salt，跨租户无 salt 403",
     "behavior": _chat_completions},
    {"service": "cache-plane", "title": "缓存策略配置", "method": "GET", "path": "/config",
     "vulnerable": 200, "fixed": 401, "gate": "admin", "writes": False,
     "description": "vulnerable 明文暴露弱策略（cache_salt 关闭/近似缓存全局/残留 retain/pin open）；"
                    "fixed 401（管理密钥 200 返回加固策略）",
     "behavior": _config},
    {"service": "epp-router", "title": "路由器缓存指标", "method": "GET", "path": "/router/metrics",
     "vulnerable": 200, "fixed": 401, "gate": "tenant", "writes": False,
     "description": "vulnerable 无鉴权按租户暴露 KV 利用率/命中率/前缀样本；"
                    "fixed 无身份 401，租户头仅本租户视图",
     "behavior": _router_metrics},
    {"service": "cache-plane", "title": "近似缓存查询", "method": "POST", "path": "/approx/lookup",
     "vulnerable": 200, "fixed": 200, "gate": "tenant", "writes": False,
     "description": "相似度阈值检索：vulnerable 全局检索（他租户误命中返回其响应）；"
                    "fixed 仅本租户条目",
     "behavior": _approx_lookup},
    {"service": "cache-plane", "title": "近似缓存写入", "method": "POST", "path": "/approx/store",
     "vulnerable": 200, "fixed": 200, "gate": "tenant", "writes": False,
     "description": "按请求租户写入近似缓存条目（种靶/对照用）",
     "behavior": _approx_store},
    {"service": "kv-pool", "title": "远程 KV 池块读", "method": "GET",
     "path": "/kvpool/blocks/{block}", "wildcard": True, "vulnerable": 200, "fixed": 403,
     "gate": "tenant", "writes": False,
     "description": "vulnerable 无命名空间校验（任意租户可读任意块）；fixed 块归属租户隔离，越权 403",
     "behavior": _kvpool_read},
    {"service": "kv-pool", "title": "远程 KV 池块写", "method": "POST", "path": "/kvpool/blocks",
     "vulnerable": 200, "fixed": 200, "gate": "tenant", "writes": True,
     "description": "vulnerable 任意命名空间可写且可设 pinned 逐出策略；"
                    "fixed 跨租户命名空间 403、pinned 仅管理密钥（普通租户降级 lru）",
     "behavior": _kvpool_write},
    {"service": "cache-plane", "title": "逐出残留读", "method": "GET", "path": "/cache/residue",
     "vulnerable": 200, "fixed": 404, "gate": "tenant", "writes": False,
     "description": "LRU 逐出后的前缀块残留：vulnerable 保留残留层且跨租户可读；fixed 逐出即 zeroize",
     "behavior": _cache_residue},
    {"service": "meta", "title": "路由清单", "method": "GET", "path": "/__routes__",
     "vulnerable": 200, "fixed": 200, "gate": "open", "writes": False,
     "description": "返回本清单 JSON（供测试与模块发现）",
     "behavior": _routes_manifest},
]


def _normalize(path: str) -> str:
    stripped = path.rstrip("/")
    return stripped or "/"


def _prefix_of(entry: dict) -> str:
    return entry["path"].replace("{block}", "").rstrip("/")


_EXACT_ROUTES: dict[tuple[str, str], dict] = {}
_PREFIX_ROUTES: list[tuple[str, dict]] = []
for _entry in ROUTE_TABLE:
    if _entry.get("wildcard"):
        _PREFIX_ROUTES.append((_entry["method"], _entry))
    else:
        _EXACT_ROUTES[(_entry["method"], _normalize(_entry["path"]))] = _entry


def _resolve(method: str, norm: str) -> dict | None:
    entry = _EXACT_ROUTES.get((method, norm))
    if entry is not None:
        return entry
    for prefix_method, candidate in _PREFIX_ROUTES:
        if prefix_method == method and (norm == _prefix_of(candidate)
                                        or norm.startswith(_prefix_of(candidate) + "/")):
            return candidate
    return None


def _path_params(entry: dict, norm: str) -> dict[str, str]:
    prefix = _prefix_of(entry)
    rest = norm[len(prefix):].strip("/")
    return {"block": rest} if rest else {}


# ---------------------------------------------------------------------------
# 服务状态与 HTTP 基座
# ---------------------------------------------------------------------------


class _CacheState:
    def __init__(self, mode: str, capacity: int, approx_threshold: float):
        self.lock = threading.Lock()
        self.capacity = capacity
        self.approx_threshold = approx_threshold
        self.pool: OrderedDict[str, dict] = OrderedDict()
        self.residue: dict[str, dict] = {}
        self.approx: list[dict] = []
        self.tenant_stats: dict[str, dict] = {}
        self.evictions_total = 0
        self.requests = 0
        self._seed(mode)

    def _seed(self, mode: str) -> None:
        """预置 victim/对照种子（全部 benign marker，无真实数据）。"""
        for text in member_prefixes(MEMBER_SEED_COUNT):
            digest = prefix_digest(text, VICTIM_TENANT, "", mode)
            self.pool[digest] = {
                "kind": "prefix", "block_id": digest, "tenant": VICTIM_TENANT,
                "salt": "", "tokens": 2048, "prefix": text, "policy": "lru",
                "pinned": False, "created_at": _utcnow_iso(), "last_used": _utcnow_iso(),
            }
        residue_digest = prefix_digest(VICTIM_RESIDUE_PREFIX, VICTIM_TENANT, "", mode)
        self.pool[residue_digest] = {
            "kind": "prefix", "block_id": residue_digest, "tenant": VICTIM_TENANT,
            "salt": "", "tokens": 2048, "prefix": VICTIM_RESIDUE_PREFIX, "policy": "lru",
            "pinned": False, "created_at": _utcnow_iso(), "last_used": _utcnow_iso(),
        }
        self.tenant_stats[VICTIM_TENANT] = {
            "requests": MEMBER_SEED_COUNT + 1, "hits": 0, "cached_tokens_total": 0}
        for block_id, tenant, marker in (
            (VICTIM_POOL_BLOCK_ID, VICTIM_TENANT, VICTIM_POOL_MARKER),
            (CONTROL_POOL_BLOCK_ID, REQUESTER_TENANT, "INKBLADE-BENIGN-POOL-CONTROL"),
        ):
            value = json.dumps({"marker": marker, "tenant": tenant, "benign": True},
                               ensure_ascii=False, sort_keys=True)
            self.pool[block_id] = {
                "kind": "raw", "block_id": block_id, "tenant": tenant,
                "namespace": tenant, "value": value, "sha256": _sha256_text(value),
                "tokens": 256, "policy": "lru", "pinned": False,
                "created_at": _utcnow_iso(), "last_used": _utcnow_iso(),
            }
        now = _utcnow_iso()
        self.approx = [
            {"tenant": VICTIM_TENANT, "text": VICTIM_APPROX_TEXT,
             "response": VICTIM_APPROX_RESPONSE, "created_at": now},
            {"tenant": REQUESTER_TENANT, "text": CONTROL_APPROX_TEXT,
             "response": CONTROL_APPROX_RESPONSE, "created_at": now},
        ]


class _CacheHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, mode: str, capacity: int, approx_threshold: float):
        super().__init__(address, _CacheHandler)
        self.lab_mode = mode
        self.lab_state = _CacheState(mode, capacity, approx_threshold)


class _CacheHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "InkBladeCacheSim/0.1.0"

    def log_message(self, fmt, *args):  # 静默访问日志
        return

    def _send(self, status: int, payload):
        if isinstance(payload, str):
            body = payload.encode("utf-8")
            content_type = "text/plain; charset=utf-8"
        else:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            content_type = "application/json; charset=utf-8"
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length > 0 else b""
        if not raw:
            return {}
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except ValueError:
            return {"_raw": raw.decode("utf-8", "replace")}
        return parsed if isinstance(parsed, dict) else {"_value": parsed}

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def _dispatch(self, method: str):
        split = urlsplit(self.path)
        norm = _normalize(split.path)
        entry = _resolve(method, norm)
        if entry is None:
            others = [m for m in ("GET", "POST") if m != method
                      and _resolve(m, norm) is not None]
            if others:
                self._send(405, {"error": "method not allowed", "path": split.path})
            else:
                self._send(404, {"error": "not found", "path": split.path})
            return
        server = self.server  # type: _CacheHTTPServer
        ctx = _RequestContext(
            mode=server.lab_mode,
            state=server.lab_state,
            headers=self.headers,
            body=self._read_body() if method == "POST" else {},
            path=split.path,
            query=parse_qs(split.query),
            params=_path_params(entry, norm),
            entry=entry,
        )
        try:
            outcome = entry["behavior"](ctx)
        except Exception as exc:  # 仿真服务不向客户端泄漏堆栈
            self._send(500, {"error": "mock internal error", "service": entry["service"],
                             "detail": str(exc)})
            return
        self._send(outcome[0], outcome[1])


class Server:
    """仿真服务句柄：.port/.mode/.url()/.routes() + shutdown()；可作上下文管理器。"""

    def __init__(self, httpd: _CacheHTTPServer, thread: threading.Thread, mode: str):
        self._httpd = httpd
        self._thread = thread
        self.mode = mode
        self._closed = False

    @property
    def port(self) -> int:
        return int(self._httpd.server_address[1])

    @property
    def state(self) -> _CacheState:
        return self._httpd.lab_state

    def url(self, path: str = "/") -> str:
        return f"http://{HOST}:{self.port}{path}"

    def routes(self) -> list[dict]:
        return [{k: v for k, v in e.items() if k != "behavior"} for e in ROUTE_TABLE]

    def shutdown(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._thread.join(timeout=5)
        except Exception:
            pass

    def __enter__(self) -> "Server":
        return self

    def __exit__(self, *exc_info) -> None:
        self.shutdown()


def start_all(port: int = 0, mode: str = DEFAULT_MODE,
              capacity: int = POOL_CAPACITY_BLOCKS,
              approx_threshold: float = APPROX_SIMILARITY_THRESHOLD) -> Server:
    """启动缓存安全仿真服务（单服务器，仅 127.0.0.1）。

    port=0 自动分配；mode ∈ {vulnerable, fixed}；capacity/approx_threshold 可配
    （LRU 容量与近似缓存相似度阈值）。
    """
    if mode not in MODES:
        raise ValueError(f"mode 必须是 {MODES} 之一，收到：{mode!r}")
    httpd = _CacheHTTPServer((HOST, int(port)), mode, int(capacity),
                             float(approx_threshold))
    thread = threading.Thread(target=httpd.serve_forever,
                              kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    return Server(httpd, thread, mode)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="InkBlade 多租户缓存安全仿真（仅 127.0.0.1）")
    parser.add_argument("--port", type=int, default=0, help="监听端口（0=自动分配）")
    parser.add_argument("--mode", choices=list(MODES), default=DEFAULT_MODE,
                        help="vulnerable=fail-open 姿态，fixed=加固姿态")
    parser.add_argument("--capacity", type=int, default=POOL_CAPACITY_BLOCKS,
                        help="KV 池块数容量（LRU 逐出阈值）")
    parser.add_argument("--threshold", type=float, default=APPROX_SIMILARITY_THRESHOLD,
                        help="近似缓存相似度阈值")
    args = parser.parse_args(argv)
    server = start_all(port=args.port, mode=args.mode, capacity=args.capacity,
                       approx_threshold=args.threshold)
    print(f"cache sim: {server.url('/')} mode={server.mode} "
          f"capacity={args.capacity} threshold={args.threshold}")
    print(f"路由清单: {server.url('/__routes__')}（共 {len(ROUTE_TABLE)} 条）")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("正在关闭缓存仿真…")
    finally:
        server.shutdown()
    return 0


__all__ = [
    "ADMIN_TOKEN", "ALLOWED_TENANTS", "APPROX_SIMILARITY_THRESHOLD", "CONTROL_APPROX_TEXT",
    "CONTROL_APPROX_RESPONSE", "CONTROL_POOL_BLOCK_ID", "MEMBER_SEED_COUNT",
    "POOL_CAPACITY_BLOCKS", "REQUESTER_TENANT", "ROUTE_TABLE", "TENANT_HEADER",
    "TIMING_MARKER", "TTFT_HIT_BASE_MS", "TTFT_MISS_BASE_MS",
    "VICTIM_APPROX_RESPONSE", "VICTIM_APPROX_TEXT", "VICTIM_POOL_BLOCK_ID",
    "VICTIM_POOL_MARKER", "VICTIM_RESIDUE_PREFIX", "VICTIM_TENANT",
    "Server", "member_prefix", "member_prefixes", "prefix_digest", "similarity",
    "start_all",
]
