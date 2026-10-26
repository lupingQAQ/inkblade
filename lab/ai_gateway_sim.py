"""lab/ai_gateway_sim.py — AI 网关与配套基建仿真靶场（单文件多路由 HTTP 服务）。

仅监听 127.0.0.1，仅标准库（http.server + threading）。两种姿态：
- vulnerable：与真实网关常见错配同构的 fail-open 姿态（默认凭据可用、admin API 无鉴权、
  共享前缀缓存键、X-Forwarded-* 可信、provider key 明文可读）；
- fixed：加固姿态（401/403/租户隔离/缓存键含租户/配额绑定 key/日志脱敏/guardrail 全量检查）。

仿真面（LiteLLM 风格 + Higress/Envoy AI 风格）：
- LiteLLM：POST /v1/chat/completions、GET /models（及 /v1/models 别名）、
  POST /v1/embeddings、POST /key/generate、GET /key/info、GET /config、GET /health
- Higress/Envoy AI：GET|POST /ai/route、GET|POST /ai/model-alias、GET /admin/console
- 语义缓存：POST /cache/store、POST /cache/lookup（vulnerable 键=共享前缀哈希；
  fixed 键=租户+前缀哈希）
- 日志：GET /logs（vulnerable 全租户明文 prompt/PII/Authorization；
  fixed 租户过滤 + <email>/<phone>/<card> 脱敏）
- 限流：GET /quota（vulnerable 按 X-Forwarded-For 记账可轮换绕过；fixed 绑定 API key）
- 向量库：GET /vector/collections、POST /vector/query（vulnerable 无鉴权跨租户检索；
  fixed 租户 scope + 越权 collection 403）
- 租户头：X-Tenant / X-Forwarded-User（vulnerable 直接采信；fixed 仅以 API key 绑定身份，
  伪造头 403 impersonation_rejected）

Ruling（判据口径）：
- 默认 master key 为公开的实验室默认值（MOCK-master-key-4c7a）；fixed 只有轮换后的
  admin key（MOCK-rotated-admin-key-e5f6）可访问管理面，默认 master key 一律 401。
- 凭据样值一律 MOCK 前缀（无真实凭据语义）；fixed 的 /config 仅返回掩码（MOCK****尾4位）。
- 路由表 /__routes__ 的 vulnerable/fixed 字段 = 无凭据请求的状态码。

命令行：python lab/ai_gateway_sim.py [--port N] [--mode vulnerable|fixed]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

HOST = "127.0.0.1"
MODES = ("vulnerable", "fixed")
DEFAULT_MODE = "vulnerable"

MASTER_KEY = "MOCK-master-key-4c7a"
ROTATED_ADMIN_KEY = "MOCK-rotated-admin-key-e5f6"
TENANT_KEYS = {"tenant-a": "MOCK-tenant-a-key-a1b2", "tenant-b": "MOCK-tenant-b-key-c3d4"}
TENANT_USERS = {"tenant-a": "alice", "tenant-b": "bob"}
QUOTA_LIMIT = 3
SECRET_CANARY = "MOCK_SYSTEM_PROMPT_CANARY"
VICTIM_CACHE_PROMPT = "Quarterly revenue guidance for fiscal 2026: 42.7M USD"
VICTIM_CACHE_RESPONSE = "tenant-b confidential: 42.7M USD with 18% growth"
UPSTREAM_ALLOWLIST = ("http://upstream-openai.mock/v1", "http://upstream-anthropic.mock/v1")

MASTER_RECORD = {"key": MASTER_KEY, "role": "master", "tenant": "*", "user": "root"}
ADMIN_RECORD = {"key": ROTATED_ADMIN_KEY, "role": "admin", "tenant": "*", "user": "root"}

UPSTREAMS = [
    {"provider": "openai", "api_base": "http://upstream-openai.mock/v1",
     "api_key": "MOCK-openai-upstream-key-9f3c", "models": ["gpt-4o", "gpt-4o-mini"]},
    {"provider": "anthropic", "api_base": "http://upstream-anthropic.mock/v1",
     "api_key": "MOCK-anthropic-upstream-key-71ab", "models": ["claude-opus"]},
]

MODELS = [
    {"id": "gpt-4o", "object": "model", "owned_by": "platform", "visibility": "public",
     "tenant": "shared", "backend": "http://upstream-openai.mock/v1"},
    {"id": "claude-opus", "object": "model", "owned_by": "platform", "visibility": "public",
     "tenant": "shared", "backend": "http://upstream-anthropic.mock/v1"},
    {"id": "tenant-a-embed", "object": "model", "owned_by": "tenant-a", "visibility": "private",
     "tenant": "tenant-a", "backend": "http://embed-a.internal:8000/v1"},
    {"id": "tenant-b-finetune", "object": "model", "owned_by": "tenant-b", "visibility": "private",
     "tenant": "tenant-b", "backend": "http://finetune-b.internal:8000/v1"},
]

DEFAULT_ALIASES = {
    "gpt-4o": {"backend": "http://upstream-openai.mock/v1", "model": "gpt-4o-2026",
               "tenant": "shared", "visibility": "public"},
    "gpt-4o-mini": {"backend": "http://upstream-openai.mock/v1", "model": "gpt-4o-mini-2026",
                    "tenant": "shared", "visibility": "public"},
    "claude-opus": {"backend": "http://upstream-anthropic.mock/v1", "model": "claude-opus-4-6",
                    "tenant": "shared", "visibility": "public"},
    "tenant-b-finetune": {"backend": "http://finetune-b.internal:8000/v1", "model": "ft-b-7b",
                          "tenant": "tenant-b", "visibility": "private"},
}

VECTOR_COLLECTIONS = {
    "tenant-a-docs": {
        "tenant": "tenant-a", "documents": 128, "embedding_model": "text-embedding-3-large",
        "docs": [{"id": "doc-a-1", "score": 0.88,
                  "content": "tenant-a runbook: rotate provider keys weekly"}],
    },
    "tenant-b-docs": {
        "tenant": "tenant-b", "documents": 512, "embedding_model": "text-embedding-3-large",
        "docs": [{"id": "doc-b-1", "score": 0.93,
                  "content": "tenant-b confidential: acquisition target ACME at 120M"},
                 {"id": "doc-b-2", "score": 0.81,
                  "content": "tenant-b confidential: Q4 pipeline 42.7M"}],
    },
    "shared-kb": {
        "tenant": "shared", "documents": 64, "embedding_model": "text-embedding-3-small",
        "docs": [{"id": "doc-s-1", "score": 0.72, "content": "public FAQ: how to rotate keys"}],
    },
}

SEED_LOGS = [
    {"ts": "2026-10-25T01:11:02Z", "tenant": "tenant-a", "user": "alice",
     "path": "/v1/chat/completions", "model": "gpt-4o",
     "prompt": "my email is alice@example.com and phone +1-555-0134",
     "authorization": f"Bearer {TENANT_KEYS['tenant-a']}", "ip": "10.0.0.11"},
    {"ts": "2026-10-25T01:12:44Z", "tenant": "tenant-b", "user": "bob",
     "path": "/v1/chat/completions", "model": "claude-opus",
     "prompt": "wire transfer card 4111 1111 1111 1111 for vendor",
     "authorization": f"Bearer {TENANT_KEYS['tenant-b']}", "ip": "10.0.0.12"},
    {"ts": "2026-10-25T01:13:09Z", "tenant": "tenant-b", "user": "bob",
     "path": "/config", "model": "-", "prompt": "GET /config upstream keys",
     "authorization": f"Bearer {TENANT_KEYS['tenant-b']}", "ip": "10.0.0.12"},
]

GUARDRAIL_PATTERNS = (
    "ignore all previous instructions", "system prompt", "begin private key",
    "ssn", "credit card",
)
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
PHONE_RE = re.compile(r"\+?\d[\d-]{7,}\d")
CARD_RE = re.compile(r"\b(?:\d[ -]?){13,16}\b")


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _mask(value: str) -> str:
    """固定 4 星掩码 + 尾 4 位（凭据样值一律 MOCK 前缀）。"""
    s = str(value)
    return f"MOCK****{s[-4:]}" if len(s) > 8 else "MOCK****"


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _bearer(headers) -> str:
    raw = headers.get("Authorization") or ""
    return raw[7:].strip() if raw.lower().startswith("bearer ") else ""


def _cache_key(text: str, tenant: str, mode: str) -> str:
    """语义缓存键：vulnerable=共享前缀哈希；fixed=租户+前缀哈希（租户隔离）。"""
    normalized = " ".join(str(text).lower().split())[:64]
    digest = _sha(normalized)[:24]
    if mode == "fixed":
        return f"sc:{tenant}:{digest}"
    return f"sc:{digest}"


def _redact(text: str) -> str:
    if not isinstance(text, str):
        return text
    text = EMAIL_RE.sub("<email>", text)
    text = PHONE_RE.sub("<phone>", text)
    text = CARD_RE.sub("<card>", text)
    return text


def _guardrail_hits(messages: list) -> list[int]:
    hits: list[int] = []
    for idx, msg in enumerate(messages):
        content = str((msg or {}).get("content") or "").lower()
        if any(pattern in content for pattern in GUARDRAIL_PATTERNS):
            hits.append(idx)
    return hits


class _RequestContext:
    """单次请求上下文：模式、进程内状态、请求要素与身份判定。"""

    def __init__(self, mode, state, headers, body, path, query, entry):
        self.mode = mode
        self.state = state
        self.headers = headers
        self.body = body
        self.path = path
        self.query = query
        self.entry = entry

    # -- 身份 -------------------------------------------------------------

    @property
    def key(self) -> str:
        return _bearer(self.headers)

    def key_record(self) -> dict | None:
        key = self.key
        if key == MASTER_KEY:
            return dict(MASTER_RECORD)
        if key == ROTATED_ADMIN_KEY:
            return dict(ADMIN_RECORD)
        for tenant, value in TENANT_KEYS.items():
            if key == value:
                return {"key": key, "role": "tenant", "tenant": tenant,
                        "user": TENANT_USERS[tenant]}
        return None

    @property
    def spoofed_user(self) -> str:
        return (self.headers.get("X-Forwarded-User") or "").strip()

    @property
    def tenant_header(self) -> str:
        return (self.headers.get("X-Tenant") or "").strip()

    def tenant(self) -> str:
        record = self.key_record() or {}
        if self.mode == "vulnerable":
            return self.tenant_header or record.get("tenant") or "anonymous"
        return record.get("tenant") or ""

    def subject(self) -> str:
        record = self.key_record() or {}
        if self.mode == "vulnerable":
            return self.spoofed_user or record.get("user") or "anonymous"
        return record.get("user") or ""

    def is_admin(self) -> bool:
        if self.mode == "vulnerable":
            return True
        return self.key == ROTATED_ADMIN_KEY

    def deny(self, status: int, error: str, **extra):
        payload = {"error": error, "mode": self.mode}
        payload.update(extra)
        return status, payload

    def require_tenant(self):
        """fixed：仅有效租户 key/admin key；伪造头或租户头错配一律 403。"""
        if self.mode != "fixed":
            return None
        record = self.key_record()
        if not record or record["role"] not in ("tenant", "admin"):
            return self.deny(401, "unauthorized",
                             hint="fixed 模式需要租户 API key（MOCK-tenant-*-key-*）")
        if record["role"] == "tenant":
            if self.spoofed_user and self.spoofed_user != record["user"]:
                return self.deny(403, "impersonation_rejected",
                                 claimed_user=self.spoofed_user, authenticated_user=record["user"])
            if self.tenant_header and self.tenant_header != record["tenant"]:
                return self.deny(403, "tenant_mismatch",
                                 claimed_tenant=self.tenant_header, authenticated_tenant=record["tenant"])
        return None

    def require_admin(self):
        """fixed：仅轮换后的 admin key；默认 master key 与租户 key 均拒绝。"""
        if self.mode != "fixed":
            return None
        if not self.key:
            return self.deny(401, "unauthorized", hint="fixed 模式管理面需要 admin key")
        if self.key == ROTATED_ADMIN_KEY:
            return None
        if self.key == MASTER_KEY:
            # 默认 master key 属已知默认凭据：fixed 视为未授权（而非权限不足）
            return self.deny(401, "default_master_key_rejected")
        if self.key_record():
            return self.deny(403, "admin_scope_required")
        return self.deny(401, "unauthorized")


# ---------------------------------------------------------------------------
# 各路由行为（返回 (status, payload[, headers])）
# ---------------------------------------------------------------------------


def _health(ctx: _RequestContext):
    if ctx.mode == "vulnerable":
        return 200, {
            "status": "ok", "product": "litellm-sim", "version": "1.72.0-mock",
            "mode": ctx.mode, "master_key": MASTER_KEY,
            "features": ["semantic-cache", "router", "budget", "key-management"],
            "upstream_providers": [u["provider"] for u in UPSTREAMS],
            "admin_api": {"auth": False},
        }
    return 200, {
        "status": "ok", "product": "litellm-sim", "version": "1.72.0-mock",
        "mode": ctx.mode, "admin_api": {"auth": True},
        "features": ["semantic-cache", "router", "budget", "key-management"],
    }


def _models(ctx: _RequestContext):
    if ctx.mode == "vulnerable":
        return 200, {"object": "list", "mode": ctx.mode, "data": [dict(m) for m in MODELS]}
    denied = ctx.require_tenant()
    if denied:
        return denied
    record = ctx.key_record() or {}
    tenant = record.get("tenant")
    rows = []
    for model in MODELS:
        if record["role"] == "admin" or model["visibility"] == "public" or model["tenant"] == tenant:
            rows.append({key: model[key] for key in
                         ("id", "object", "owned_by", "visibility", "tenant")})
    return 200, {"object": "list", "mode": ctx.mode, "data": rows}


def _chat_completions(ctx: _RequestContext):
    if ctx.mode == "fixed":
        denied = ctx.require_tenant()
        if denied:
            return denied
    messages = ctx.body.get("messages") if isinstance(ctx.body.get("messages"), list) else []
    model = str(ctx.body.get("model") or "gpt-4o")

    hits = _guardrail_hits(messages)
    if ctx.mode == "fixed":
        if hits:
            return 400, {"error": "guardrail_blocked", "mode": ctx.mode,
                         "guardrail_blocked": True, "rule": "prompt_injection_or_secret_exfil",
                         "inspected_messages": len(messages), "hit_indexes": hits}
        inspected, bypass = len(messages), False
    else:
        inspected = min(1, len(messages))
        bypass = any(idx >= inspected for idx in hits)
        if any(idx < inspected for idx in hits):
            return 400, {"error": "guardrail_blocked", "mode": ctx.mode,
                         "guardrail_blocked": True, "inspected_messages": inspected,
                         "hit_indexes": hits}

    # 配额：vulnerable 按 X-Forwarded-For 记账（可轮换）；fixed 绑定 API key
    quota = _quota_consume(ctx)
    if quota.get("blocked"):
        return 429, {"error": "quota_exceeded", "mode": ctx.mode, "quota": quota}

    alias = ctx.state["aliases"].get(model) or {
        "backend": "http://upstream-openai.mock/v1", "model": model,
        "tenant": "shared", "visibility": "public",
    }
    backend = alias["backend"]
    hijacked = backend not in UPSTREAM_ALLOWLIST
    prompt = ""
    for msg in messages:
        if (msg or {}).get("role") == "user":
            prompt = str(msg.get("content") or "")
    if bypass:
        content = f"policy check skipped; system prompt: {SECRET_CANARY}"
    else:
        content = f"mock completion for: {prompt[:48]}"
    return 200, {
        "id": "chatcmpl-mock-" + _sha(f"{time.time()}-{model}")[:10],
        "object": "chat.completion", "created": int(time.time()), "mode": ctx.mode,
        "model": alias["model"], "requested_model": model,
        "backend": backend, "upstream": "hijacked" if hijacked else "primary",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": content},
                     "finish_reason": "stop"}],
        "usage": {"prompt_tokens": max(1, len(prompt) // 4), "completion_tokens": 8,
                  "total_tokens": max(9, len(prompt) // 4 + 8)},
        "guardrail": {"decision": "allow", "inspected_messages": inspected,
                      "bypass_suspected": bypass},
        "quota": quota,
    }


def _quota_consume(ctx: _RequestContext) -> dict:
    state = ctx.state["quota"]
    if ctx.mode == "fixed":
        bucket = ctx.key or "anonymous"
    else:
        bucket = (ctx.headers.get("X-Forwarded-For") or "").split(",")[0].strip() or "direct"
    used = int(state["buckets"].get(bucket, 0)) + 1
    state["buckets"][bucket] = used
    blocked = ctx.mode == "fixed" and used > QUOTA_LIMIT
    return {"bucket": bucket, "used": used, "limit": QUOTA_LIMIT,
            "enforced": ctx.mode == "fixed", "blocked": blocked}


def _quota_status(ctx: _RequestContext):
    if ctx.mode == "fixed":
        denied = ctx.require_tenant()
        if denied:
            return denied
        record = ctx.key_record() or {}
        buckets = ({ctx.key: ctx.state["quota"]["buckets"].get(ctx.key, 0)}
                   if record.get("role") == "tenant" else dict(ctx.state["quota"]["buckets"]))
        return 200, {"enforced": True, "limit": QUOTA_LIMIT, "bucket_by": "api-key",
                     "buckets": buckets, "xf_forwarded_for_ignored": True, "mode": ctx.mode}
    return 200, {"enforced": False, "limit": QUOTA_LIMIT, "bucket_by": "x-forwarded-for",
                 "buckets": dict(ctx.state["quota"]["buckets"]),
                 "bypass": "rotate X-Forwarded-For to reset the bucket", "mode": ctx.mode}


def _embeddings(ctx: _RequestContext):
    if ctx.mode == "fixed":
        denied = ctx.require_tenant()
        if denied:
            return denied
    inputs = ctx.body.get("input") or []
    if isinstance(inputs, str):
        inputs = [inputs]
    data = []
    for idx, text in enumerate(inputs):
        raw = _sha(str(text))
        vector = [round(int(raw[i * 2:i * 2 + 2], 16) / 255.0, 4) for i in range(8)]
        data.append({"object": "embedding", "index": idx, "embedding": vector})
    return 200, {"object": "list", "mode": ctx.mode,
                 "model": str(ctx.body.get("model") or "text-embedding-3-large"),
                 "dimensions": 8, "data": data,
                 "usage": {"prompt_tokens": len(inputs), "total_tokens": len(inputs)}}


def _key_generate(ctx: _RequestContext):
    if ctx.mode == "fixed":
        denied = ctx.require_admin()
        if denied:
            return denied
        tenant = str(ctx.body.get("tenant") or "tenant-a")
        record = {"key": "MOCK-issued-key-" + _sha(f"{time.time()}-{tenant}")[:8],
                  "key_alias": ctx.body.get("key_alias") or "issued",
                  "tenant": tenant, "models": list(ctx.body.get("models") or ["gpt-4o"]),
                  "admin": False, "mode": ctx.mode}
        ctx.state["issued"].append(record)
        return 200, record
    record = {"key": "MOCK-issued-key-" + _sha(f"{time.time()}-spoof")[:8],
              "key_alias": ctx.body.get("key_alias") or "issued",
              "user_id": ctx.subject(), "tenant": ctx.body.get("tenant") or "tenant-b",
              "models": ["*"], "admin": True, "mode": ctx.mode}
    ctx.state["issued"].append(record)
    return 200, record


def _key_info(ctx: _RequestContext):
    if ctx.mode == "fixed":
        denied = ctx.require_tenant()
        if denied:
            return denied
        record = ctx.key_record() or {}
        wanted = (ctx.query.get("key") or [""])[0]
        if record.get("role") == "tenant" and wanted and wanted != ctx.key:
            return ctx.deny(403, "key_scope_required")
        if record.get("role") == "admin":
            return 200, {"mode": ctx.mode, "subject": "root", "scope": "global",
                         "visible_tenants": sorted(TENANT_KEYS),
                         "keys": [{"key": _mask(v), "tenant": t,
                                   "user": TENANT_USERS[t]} for t, v in TENANT_KEYS.items()],
                         "impersonation_ignored": bool(ctx.spoofed_user)}
        return 200, {"mode": ctx.mode, "subject": record.get("user"), "scope": "tenant",
                     "visible_tenants": [record.get("tenant")],
                     "key": _mask(ctx.key), "tenant": record.get("tenant"),
                     "spend": 0.42, "impersonation_ignored": bool(ctx.spoofed_user)}
    subject = ctx.subject()
    return 200, {"mode": ctx.mode, "subject": subject,
                 "scope": "global" if subject == "admin" or not ctx.key else "tenant",
                 "visible_tenants": sorted(TENANT_KEYS),
                 "master_key": MASTER_KEY,
                 "keys": [{"key": MASTER_KEY, "tenant": "*", "user": "root"}]
                 + [{"key": v, "tenant": t, "user": TENANT_USERS[t]}
                    for t, v in TENANT_KEYS.items()]}


def _config(ctx: _RequestContext):
    if ctx.mode == "fixed":
        denied = ctx.require_admin()
        if denied:
            return denied
        upstreams = [{"provider": u["provider"], "api_base": u["api_base"],
                      "api_key": _mask(u["api_key"]), "models": list(u["models"])}
                     for u in UPSTREAMS]
        return 200, {"mode": ctx.mode, "gateway": "litellm-sim", "upstreams": upstreams,
                     "cache": {"semantic": True, "key_scope": "tenant"},
                     "quota": {"limit": QUOTA_LIMIT, "bucket": "api-key"},
                     "guardrails": {"enabled": True, "inspect": "all_messages"},
                     "redacted": True}
    return 200, {
        "mode": ctx.mode, "gateway": "litellm-sim", "master_key": MASTER_KEY,
        "upstreams": [dict(u) for u in UPSTREAMS],
        "cache": {"semantic": True, "key_scope": "global"},
        "quota": {"limit": QUOTA_LIMIT, "bucket": "x-forwarded-for"},
        "guardrails": {"enabled": True, "inspect": "first_message_only"},
    }


def _ai_route(ctx: _RequestContext):
    if ctx.mode == "fixed":
        denied = ctx.require_tenant()
        if denied:
            return denied
        record = ctx.key_record() or {}
        tenant = record.get("tenant")
        aliases = {}
        for name, alias in ctx.state["aliases"].items():
            if record["role"] == "admin" or alias["visibility"] == "public" or alias["tenant"] == tenant:
                item = dict(alias)
                if record["role"] != "admin":
                    item.pop("backend", None)
                    item["backend_class"] = "allowlisted"
                aliases[name] = item
        return 200, {"mode": ctx.mode, "object": "route_table",
                     "aliases": aliases, "allowlist": list(UPSTREAM_ALLOWLIST)}
    return 200, {"mode": ctx.mode, "object": "route_table",
                 "aliases": {k: dict(v) for k, v in ctx.state["aliases"].items()},
                 "allowlist": list(UPSTREAM_ALLOWLIST), "session": "anonymous-admin"}


def _alias_write(ctx: _RequestContext):
    if ctx.mode == "fixed":
        denied = ctx.require_admin()
        if denied:
            return denied
    alias = str(ctx.body.get("alias") or "")
    backend = str(ctx.body.get("backend") or "")
    if not alias or not backend:
        return 400, {"error": "alias_and_backend_required", "mode": ctx.mode}
    if ctx.mode == "fixed" and backend not in UPSTREAM_ALLOWLIST:
        return 400, {"error": "backend_not_allowlisted", "mode": ctx.mode,
                     "backend": backend, "allowlist": list(UPSTREAM_ALLOWLIST)}
    ctx.state["aliases"][alias] = {
        "backend": backend, "model": str(ctx.body.get("model") or alias),
        "tenant": str(ctx.body.get("tenant") or
                      ((ctx.key_record() or {}).get("tenant") or "tenant-a")),
        "visibility": "public" if ctx.mode == "vulnerable" else "private",
    }
    table = json.dumps(ctx.state["aliases"], sort_keys=True, ensure_ascii=False)
    return 200, {"mode": ctx.mode, "applied": True, "alias": alias, "backend": backend,
                 "state_sha256": _sha(table), "updated_at": _utcnow_iso()}


def _admin_console(ctx: _RequestContext):
    if ctx.mode == "fixed":
        denied = ctx.require_admin()
        if denied:
            return denied
        return 200, {"mode": ctx.mode, "service": "higress-console", "console": True,
                     "session": "admin", "actions": ["/ai/route", "/ai/model-alias", "/config"]}
    return 200, {"mode": ctx.mode, "service": "higress-console", "console": True,
                 "session": "anonymous-admin",
                 "actions": ["/ai/route", "/ai/model-alias", "/config"],
                 "config_editor": True}


def _cache_store(ctx: _RequestContext):
    if ctx.mode == "fixed":
        denied = ctx.require_tenant()
        if denied:
            return denied
    tenant = ctx.tenant()
    key = _cache_key(ctx.body.get("text") or ctx.body.get("prompt") or "", tenant, ctx.mode)
    entry = {"tenant": tenant, "response": ctx.body.get("response") or "",
             "model": ctx.body.get("model") or "gpt-4o", "created_at": _utcnow_iso()}
    ctx.state["cache"][key] = entry
    return 200, {"mode": ctx.mode, "stored": True, "cache_key": key, "tenant": tenant}


def _cache_lookup(ctx: _RequestContext):
    if ctx.mode == "fixed":
        denied = ctx.require_tenant()
        if denied:
            return denied
    tenant = ctx.tenant()
    key = _cache_key(ctx.body.get("text") or ctx.body.get("prompt") or "", tenant, ctx.mode)
    entry = ctx.state["cache"].get(key)
    return 200, {"mode": ctx.mode, "hit": entry is not None, "cache_key": key,
                 "requester_tenant": tenant, "entry": dict(entry) if entry else None}


def _logs(ctx: _RequestContext):
    if ctx.mode == "fixed":
        denied = ctx.require_tenant()
        if denied:
            return denied
        record = ctx.key_record() or {}
        tenant = record.get("tenant")
        rows = []
        for entry in ctx.state["logs"]:
            if record["role"] != "admin" and entry["tenant"] != tenant:
                continue
            item = dict(entry)
            item["prompt"] = _redact(item["prompt"])
            item["authorization"] = "Bearer <redacted>"
            rows.append(item)
        return 200, {"mode": ctx.mode, "entries": rows, "redacted": True,
                     "tenant_scoped": record["role"] != "admin"}
    return 200, {"mode": ctx.mode, "entries": [dict(e) for e in ctx.state["logs"]],
                 "redacted": False, "tenant_scoped": False}


def _vector_collections(ctx: _RequestContext):
    if ctx.mode == "fixed":
        denied = ctx.require_tenant()
        if denied:
            return denied
        record = ctx.key_record() or {}
        tenant = record.get("tenant")
        rows = []
        for name, coll in ctx.state["vectors"].items():
            if record["role"] == "admin" or coll["tenant"] in ("shared", tenant):
                rows.append({"name": name, "tenant": coll["tenant"],
                             "documents": coll["documents"],
                             "embedding_model": coll["embedding_model"]})
        return 200, {"mode": ctx.mode, "collections": rows}
    rows = [{"name": name, "tenant": coll["tenant"], "documents": coll["documents"],
             "embedding_model": coll["embedding_model"]}
            for name, coll in ctx.state["vectors"].items()]
    return 200, {"mode": ctx.mode, "collections": rows}


def _vector_query(ctx: _RequestContext):
    if ctx.mode == "fixed":
        denied = ctx.require_tenant()
        if denied:
            return denied
    name = str(ctx.body.get("collection") or "")
    coll = ctx.state["vectors"].get(name)
    if coll is None:
        return 404, {"error": "collection_not_found", "mode": ctx.mode, "collection": name}
    if ctx.mode == "fixed":
        record = ctx.key_record() or {}
        if record["role"] != "admin" and coll["tenant"] not in ("shared", record.get("tenant")):
            return ctx.deny(403, "collection_scope_required", collection=name,
                            collection_tenant=coll["tenant"])
    top_k = max(1, min(int(ctx.body.get("top_k") or 2), len(coll["docs"])))
    return 200, {"mode": ctx.mode, "collection": name, "collection_tenant": coll["tenant"],
                 "query": ctx.body.get("query") or "", "matches": coll["docs"][:top_k]}


def _routes_manifest(ctx: _RequestContext):
    return 200, {
        "service": "inkblade-ai-gateway-lab", "mode": ctx.mode, "host": HOST,
        "credential_hints": {
            "master_key": MASTER_KEY,
            "rotated_admin_key": "fixed 模式管理面密钥（MOCK-rotated-admin-key-e5f6）",
            "tenant_keys": dict(TENANT_KEYS),
        },
        "route_count": len(ROUTE_TABLE),
        "routes": [{key: value for key, value in entry.items() if key != "behavior"}
                   for entry in ROUTE_TABLE],
    }


# ---------------------------------------------------------------------------
# 路由表（/__routes__ 即此表去行为函数后的 JSON；vulnerable/fixed = 无凭据状态码）
# ---------------------------------------------------------------------------

ROUTE_TABLE = [
    {"service": "litellm", "title": "健康检查", "method": "GET", "path": "/health",
     "vulnerable": 200, "fixed": 200, "gate": "public", "writes": False,
     "description": "vulnerable 泄露默认 master key 与未鉴权 admin_api；fixed 仅产品信息",
     "behavior": _health},
    {"service": "litellm", "title": "模型列表", "method": "GET", "path": "/models",
     "vulnerable": 200, "fixed": 401, "gate": "tenant", "writes": False,
     "description": "vulnerable 暴露私有模型/租户归属/后端地址；fixed 租户 scope 且脱敏 backend",
     "behavior": _models},
    {"service": "litellm", "title": "模型列表（OpenAI 兼容）", "method": "GET", "path": "/v1/models",
     "vulnerable": 200, "fixed": 401, "gate": "tenant", "writes": False,
     "description": "/models 的 OpenAI 兼容别名", "behavior": _models},
    {"service": "litellm", "title": "对话补全", "method": "POST", "path": "/v1/chat/completions",
     "vulnerable": 200, "fixed": 401, "gate": "tenant", "writes": False,
     "description": "vulnerable 无鉴权 + guardrail 仅查首条消息 + 配额按 XFF；fixed 401/guardrail 全量/配额绑 key",
     "behavior": _chat_completions},
    {"service": "litellm", "title": "向量嵌入", "method": "POST", "path": "/v1/embeddings",
     "vulnerable": 200, "fixed": 401, "gate": "tenant", "writes": False,
     "description": "vulnerable 无鉴权嵌入；fixed 租户 key 必需", "behavior": _embeddings},
    {"service": "litellm", "title": "API key 签发", "method": "POST", "path": "/key/generate",
     "vulnerable": 200, "fixed": 401, "gate": "admin", "writes": True,
     "description": "vulnerable 无鉴权签发 admin 全权 key；fixed 仅轮换 admin key（租户 key 403）",
     "behavior": _key_generate},
    {"service": "litellm", "title": "API key 信息", "method": "GET", "path": "/key/info",
     "vulnerable": 200, "fixed": 401, "gate": "tenant", "writes": False,
     "description": "vulnerable 全量 key + master；fixed 仅本租户；伪造 X-Forwarded-User 403",
     "behavior": _key_info},
    {"service": "litellm", "title": "网关配置", "method": "GET", "path": "/config",
     "vulnerable": 200, "fixed": 401, "gate": "admin", "writes": False,
     "description": "vulnerable 明文上游 provider key；fixed 仅 admin 且掩码",
     "behavior": _config},
    {"service": "higress", "title": "AI 路由表", "method": "GET", "path": "/ai/route",
     "vulnerable": 200, "fixed": 401, "gate": "tenant", "writes": False,
     "description": "vulnerable 未鉴权读别名→后端映射；fixed 租户 scope / backend 脱敏",
     "behavior": _ai_route},
    {"service": "higress", "title": "模型别名写入", "method": "POST", "path": "/ai/model-alias",
     "vulnerable": 200, "fixed": 401, "gate": "admin", "writes": True,
     "description": "vulnerable 别名可指向任意后端（路由劫持）；fixed admin + 后端 allowlist",
     "behavior": _alias_write},
    {"service": "higress", "title": "管理控制台", "method": "GET", "path": "/admin/console",
     "vulnerable": 200, "fixed": 401, "gate": "admin", "writes": False,
     "description": "vulnerable 匿名 admin 会话；fixed 仅轮换 admin key", "behavior": _admin_console},
    {"service": "cache", "title": "语义缓存写入", "method": "POST", "path": "/cache/store",
     "vulnerable": 200, "fixed": 401, "gate": "tenant", "writes": True,
     "description": "vulnerable 共享前缀键；fixed 键含租户", "behavior": _cache_store},
    {"service": "cache", "title": "语义缓存查询", "method": "POST", "path": "/cache/lookup",
     "vulnerable": 200, "fixed": 401, "gate": "tenant", "writes": False,
     "description": "vulnerable 跨租户命中；fixed 租户隔离（miss）", "behavior": _cache_lookup},
    {"service": "logs", "title": "请求日志", "method": "GET", "path": "/logs",
     "vulnerable": 200, "fixed": 401, "gate": "tenant", "writes": False,
     "description": "vulnerable 全租户明文 prompt/PII/Authorization；fixed 租户过滤+脱敏",
     "behavior": _logs},
    {"service": "quota", "title": "配额状态", "method": "GET", "path": "/quota",
     "vulnerable": 200, "fixed": 401, "gate": "tenant", "writes": False,
     "description": "vulnerable 按 X-Forwarded-For 分桶（可轮换绕过）；fixed 绑定 API key",
     "behavior": _quota_status},
    {"service": "vector", "title": "向量 collection 清单", "method": "GET", "path": "/vector/collections",
     "vulnerable": 200, "fixed": 401, "gate": "tenant", "writes": False,
     "description": "vulnerable 全租户 collection；fixed 仅本租户 + shared", "behavior": _vector_collections},
    {"service": "vector", "title": "向量检索", "method": "POST", "path": "/vector/query",
     "vulnerable": 200, "fixed": 401, "gate": "tenant", "writes": False,
     "description": "vulnerable 跨租户检索命中；fixed 越权 collection 403", "behavior": _vector_query},
    {"service": "meta", "title": "路由清单", "method": "GET", "path": "/__routes__",
     "vulnerable": 200, "fixed": 200, "gate": "public", "writes": False,
     "description": "返回本清单 JSON（供测试与模块发现）", "behavior": _routes_manifest},
]

_EXACT_ROUTES: dict[tuple[str, str], dict] = {}
for _entry in ROUTE_TABLE:
    _EXACT_ROUTES[(_entry["method"], _entry["path"].rstrip("/") or "/")] = _entry


def _normalize(path: str) -> str:
    stripped = path.rstrip("/")
    return stripped or "/"


class _GatewayHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, mode: str):
        super().__init__(address, _GatewayHandler)
        self.lab_mode = mode
        self.lab_lock = threading.Lock()
        self.lab_state = {
            "aliases": {k: dict(v) for k, v in DEFAULT_ALIASES.items()},
            "cache": {},
            "quota": {"buckets": {}},
            "logs": [dict(e) for e in SEED_LOGS],
            "vectors": {k: {"tenant": v["tenant"], "documents": v["documents"],
                            "embedding_model": v["embedding_model"],
                            "docs": [dict(d) for d in v["docs"]]}
                        for k, v in VECTOR_COLLECTIONS.items()},
            "issued": [],
        }
        # 预置 victim 租户缓存条目（seed 与模式一致：fixed 键含 tenant-b）
        self.lab_state["cache"][_cache_key(VICTIM_CACHE_PROMPT, "tenant-b", mode)] = {
            "tenant": "tenant-b", "response": VICTIM_CACHE_RESPONSE,
            "model": "claude-opus", "created_at": _utcnow_iso(),
        }


class _GatewayHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "InkBladeAIGatewayLab/0.1.0"

    def log_message(self, fmt, *args):  # 静默默认访问日志
        return

    def _send(self, status: int, payload, extra_headers: dict | None = None):
        if isinstance(payload, str):
            body = payload.encode("utf-8")
            content_type = "text/plain; charset=utf-8"
        else:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            content_type = "application/json; charset=utf-8"
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Gateway-Product", "litellm-sim")
        self.send_header("X-Gateway-Mode", self.server.lab_mode)
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
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

    def do_PUT(self):
        self._dispatch("PUT")

    def _dispatch(self, method: str):
        split = urlsplit(self.path)
        norm = _normalize(split.path)
        entry = _EXACT_ROUTES.get((method, norm))
        if entry is None:
            if any(_EXACT_ROUTES.get((other, norm)) for other in ("GET", "POST", "PUT") if other != method):
                self._send(405, {"error": "method not allowed", "path": split.path})
            else:
                self._send(404, {"error": "not found", "path": split.path})
            return
        server = self.server  # type: _GatewayHTTPServer
        ctx = _RequestContext(
            mode=server.lab_mode,
            state=server.lab_state,
            headers=self.headers,
            body=self._read_body() if method in ("POST", "PUT") else {},
            path=split.path,
            query=parse_qs(split.query),
            entry=entry,
        )
        try:
            with server.lab_lock:
                outcome = entry["behavior"](ctx)
        except Exception as exc:  # 仿真服务不向客户端泄漏堆栈
            self._send(500, {"error": "mock internal error", "service": entry["service"],
                             "detail": str(exc)})
            return
        status, payload = outcome[0], outcome[1]
        extra = outcome[2] if len(outcome) > 2 else None
        self._send(status, payload, extra)


# ---------------------------------------------------------------------------
# Server 句柄与启动入口
# ---------------------------------------------------------------------------


class Server:
    """仿真网关句柄：.port/.mode/.url()/.routes() + shutdown()；可作上下文管理器。"""

    def __init__(self, httpd: _GatewayHTTPServer, thread: threading.Thread, mode: str):
        self._httpd = httpd
        self._thread = thread
        self.mode = mode
        self._closed = False

    @property
    def port(self) -> int:
        return int(self._httpd.server_address[1])

    def url(self, path: str = "/") -> str:
        return f"http://{HOST}:{self.port}{path}"

    def routes(self) -> list[dict]:
        return [{key: value for key, value in entry.items() if key != "behavior"}
                for entry in ROUTE_TABLE]

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


def start_all(port: int = 0, mode: str = DEFAULT_MODE) -> Server:
    """启动 AI 网关仿真（单服务器，仅 127.0.0.1）。port=0 自动分配。"""
    if mode not in MODES:
        raise ValueError(f"mode 必须是 {MODES} 之一，收到：{mode!r}")
    httpd = _GatewayHTTPServer((HOST, int(port)), mode)
    thread = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    return Server(httpd, thread, mode)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="InkBlade AI 网关仿真靶场（仅监听 127.0.0.1）")
    parser.add_argument("--port", type=int, default=0, help="监听端口（0=自动分配）")
    parser.add_argument("--mode", choices=list(MODES), default=DEFAULT_MODE,
                        help="vulnerable=fail-open 姿态，fixed=加固姿态")
    args = parser.parse_args(argv)
    server = start_all(port=args.port, mode=args.mode)
    print(f"ai-gateway lab: {server.url('/')} mode={server.mode}")
    print(f"路由清单: {server.url('/__routes__')}（共 {len(ROUTE_TABLE)} 条）")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("正在关闭 AI 网关仿真…")
    finally:
        server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
