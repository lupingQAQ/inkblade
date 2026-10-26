"""lab/longctx_sim.py — OpenAI 兼容长上下文 / PD 分离 KV 推理仿真服务（仅标准库，仅 127.0.0.1）。

两种姿态（与真实框架修复语义同构）：
- vulnerable：窗口上限不校验（超窗请求 200 且排队）、metrics 无鉴权、
  prefix cache 全局共享（无 cache_salt 跨租户复用）、PD KV 通道无鉴权可读写、
  checkpoint 分片无鉴权可写；
- fixed：超窗 400、max_tokens 超限 400、未知租户 401、跨租户无 cache_salt 403、
  metrics/KV 通道/分片写面缺管理密钥 401、带密钥跨租户 KV 写 403。

路由清单（GET /__routes__ 返回同表 JSON）：
- POST /v1/chat/completions
    body: model, messages, context_window=128k|1m（或 131072/1048576）,
          prompt_tokens（可选：确定性计数提示，缺省按内容长度估算）,
          max_tokens, cache_salt（可选）, prompt_prefix（可选）, prefix_tokens（可选）
    resp: choices + usage{prompt_tokens,prefill_tokens,completion_tokens,
          decode_tokens,total_tokens,cached_tokens} + context_window
    头：X-Tenant（必需；fixed 仅接受 tenant-a/b/c）
- GET /metrics
    kv_cache_usage / kv_cache_bytes / queue_depth / prefill_pool / decode_pool /
    prefix_cache / training{world_size,tp,pp,ep,cp,sp,ring_attention,
    hierarchical_all_reduce,collective_ports,nccl_bootstrap_port,kv_transfer_port}
- POST /kv/transfer  {op:"read"|"write", block_id, value?, source_tenant?, dest_tenant?, layer?}
- GET  /kv/transfer?block_id=...
- POST /checkpoint/shards  {shard_id, payload}
- GET  /checkpoint/shards/{shard_id}
- GET  /__routes__

写盘边界：仅 Server.root（默认临时目录并在 shutdown 清理）。
命令行：python lab/longctx_sim.py [--port N] [--mode vulnerable|fixed] [--root DIR]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

HOST = "127.0.0.1"
MODES = ("vulnerable", "fixed")
DEFAULT_MODE = "vulnerable"
ADMIN_TOKEN = "longctx-admin-key"
TENANT_HEADER = "X-Tenant"
ALLOWED_TENANTS = ("tenant-a", "tenant-b", "tenant-c")
CONTEXT_WINDOWS = {"128k": 131072, "1m": 1048576}
DEFAULT_CONTEXT_WINDOW = "128k"
FIXED_MAX_DECODE_TOKENS = 4096
KV_BYTES_PER_TOKEN = 2
KV_CACHE_CAPACITY_BYTES = 1024 * 1024 * 1024  # 1 GiB（指标口径）
PREFILL_CAPACITY = 4
DECODE_CAPACITY = 8
SEED_SHARD = "shard-00000"
TRAINING_PROFILE = {
    "world_size": 512,
    "tp": 8,
    "pp": 4,
    "ep": 32,
    "cp": 4,
    "sp": 2,
    "ring_attention": True,
    "hierarchical_all_reduce": True,
    "collective_ports": [29500, 29501, 29511],
    "nccl_bootstrap_port": 29500,
    "kv_transfer_port": 45678,
    "parallel": ["tp", "pp", "ep", "cp", "sp"],
}


def _utcnow_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _safe_name(value: str, fallback: str = "unnamed") -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value)).strip("._")
    return cleaned or fallback


def _parse_window(value) -> int:
    """context_window 归一：128k→131072，1m→1048576（兼容 128000/1000000 写法）。"""
    if isinstance(value, (int, float)):
        number = int(value)
        if number in (131072, 128000):
            return 131072
        if number in (1048576, 1000000):
            return 1048576
        raise ValueError(f"不支持的 context_window: {value!r}")
    text = str(value or "").strip().lower()
    if text in ("128k", "131072", "128000"):
        return 131072
    if text in ("1m", "1048576", "1000000"):
        return 1048576
    raise ValueError(f"不支持的 context_window: {value!r}")


def _estimate_prompt_tokens(messages) -> int:
    chars = 0
    for message in messages or []:
        if isinstance(message, dict):
            chars += len(str(message.get("content", "")))
        else:
            chars += len(str(message))
    return max(1, chars // 4)


def _as_text(value) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def checkpoint_shard_path(root: Path | str, shard_id: str) -> Path:
    """checkpoint 分片落盘路径（测试/实效验证与仿真器共用同一约定）。"""
    return Path(root) / "checkpoints" / f"{_safe_name(shard_id, 'shard')}.safetensors"


class _RequestContext:
    def __init__(self, mode, root, state, headers, body, path, query, params, entry):
        self.mode = mode
        self.root = root
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
# 路由行为
# ---------------------------------------------------------------------------


def _chat_completions(ctx: _RequestContext):
    state = ctx.state
    tenant = ctx.tenant
    if not tenant:
        return 400, {"error": "missing_tenant_header", "hint": f"需要 {TENANT_HEADER} 请求头"}
    if ctx.mode == "fixed" and tenant not in ALLOWED_TENANTS:
        return 401, {"error": "unknown_tenant", "tenant": tenant}

    try:
        window = _parse_window(ctx.body.get("context_window", DEFAULT_CONTEXT_WINDOW))
    except ValueError:
        return 400, {"error": "unsupported_context_window",
                     "supported": sorted(CONTEXT_WINDOWS.values())}

    try:
        max_tokens = int(ctx.body.get("max_tokens", 256))
    except (TypeError, ValueError):
        return 400, {"error": "invalid_max_tokens"}
    if max_tokens < 1:
        return 400, {"error": "invalid_max_tokens"}

    hint = ctx.body.get("prompt_tokens")
    try:
        hint_tokens = int(hint) if hint is not None else 0
    except (TypeError, ValueError):
        return 400, {"error": "invalid_prompt_tokens"}
    prompt_tokens = max(hint_tokens, _estimate_prompt_tokens(ctx.body.get("messages")))
    if prompt_tokens < 1:
        return 400, {"error": "empty_prompt"}

    if ctx.mode == "fixed":
        if prompt_tokens > window:
            return 400, {
                "error": "context_window_exceeded",
                "context_window": window,
                "prompt_tokens": prompt_tokens,
            }
        if max_tokens > FIXED_MAX_DECODE_TOKENS:
            return 400, {"error": "max_tokens_exceeds_limit",
                         "limit": FIXED_MAX_DECODE_TOKENS, "max_tokens": max_tokens}

    salt = str(ctx.body.get("cache_salt") or "")
    prefix = str(ctx.body.get("prompt_prefix") or "")
    if not prefix:
        prefix = "\n".join(str((m or {}).get("content", "")) for m in (ctx.body.get("messages") or [])
                           if isinstance(m, dict))[:1024]
    try:
        prefix_tokens = int(ctx.body.get("prefix_tokens") or min(prompt_tokens, 4096))
    except (TypeError, ValueError):
        prefix_tokens = min(prompt_tokens, 4096)
    prefix_tokens = max(0, min(prefix_tokens, prompt_tokens))

    request_id = "chatcmpl-" + uuid.uuid4().hex
    with state.lock:
        state.requests += 1
        cached = 0
        if prefix:
            digest = _sha256_text(prefix)[:16]
            if ctx.mode == "vulnerable":
                entry = state.prefix_cache.get(digest)
                if entry is None:
                    state.prefix_cache[digest] = {
                        "tenant": tenant, "salt": salt, "tokens": prefix_tokens,
                    }
                else:
                    cached = min(int(entry.get("tokens") or 0), prompt_tokens)
            else:
                entries = state.prefix_cache.setdefault(digest, [])
                same = next((e for e in entries
                             if e["tenant"] == tenant and e["salt"] and e["salt"] == salt), None)
                foreign = any(e["tenant"] != tenant for e in entries)
                if foreign and not salt:
                    return 403, {
                        "error": "cache_salt_required_for_cross_tenant_prefix",
                        "hint": "跨租户复用 prefix cache 必须携带 cache_salt",
                    }
                if same is not None:
                    cached = min(int(same.get("tokens") or 0), prompt_tokens)
                elif salt:
                    entries.append({"tenant": tenant, "salt": salt, "tokens": prefix_tokens})
        if cached:
            state.cached_tokens_total += cached

        over_window = prompt_tokens > window
        if over_window and ctx.mode == "vulnerable":
            state.queue_depth += 1
            state.over_window_requests += 1

        # vulnerable：按声明窗口预留 KV（上下文越长预留越大）；
        # fixed：仅按实际 prompt + decode 预留。
        reserved_tokens = (max(window, prompt_tokens + max_tokens)
                           if ctx.mode == "vulnerable" else prompt_tokens + max_tokens)
        kv_delta = reserved_tokens * KV_BYTES_PER_TOKEN
        state.kv_bytes += kv_delta
        state.kv_cache_usage = round(min(1.0, state.kv_bytes / KV_CACHE_CAPACITY_BYTES), 6)
        queue_depth = state.queue_depth

    decode_tokens = min(max_tokens, 1024)
    return 200, {
        "id": request_id,
        "object": "chat.completion",
        "created": int(time.time()),
        "model": str(ctx.body.get("model") or "longctx-mock"),
        "context_window": window,
        "tenant": tenant,
        "choices": [{
            "index": 0,
            "finish_reason": "length" if over_window else "stop",
            "message": {"role": "assistant", "content": "mock long-context response"},
        }],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "prefill_tokens": prompt_tokens,
            "completion_tokens": decode_tokens,
            "decode_tokens": decode_tokens,
            "total_tokens": prompt_tokens + decode_tokens,
            "cached_tokens": cached,
        },
        "queue_depth": queue_depth if ctx.mode == "vulnerable" else 0,
    }


def _metrics(ctx: _RequestContext):
    if ctx.mode == "fixed" and not ctx.admin:
        return 401, {"error": "unauthorized", "service": "longctx-infer",
                     "hint": "fixed 模式 metrics 需要管理密钥"}
    state = ctx.state
    with state.lock:
        payload = {
            "service": "longctx-infer",
            "generated_at": _utcnow_iso(),
            "kv_cache_usage": state.kv_cache_usage,
            "kv_cache_bytes": state.kv_bytes,
            "kv_cache_capacity_bytes": KV_CACHE_CAPACITY_BYTES,
            "queue_depth": state.queue_depth,
            "over_window_requests": state.over_window_requests,
            "requests_total": state.requests,
            "prefill_pool": {
                "capacity": PREFILL_CAPACITY,
                "active": min(state.queue_depth, PREFILL_CAPACITY),
                "queued": state.queue_depth,
            },
            "decode_pool": {
                "capacity": DECODE_CAPACITY,
                "active": min(state.requests, DECODE_CAPACITY),
                "completed": state.requests,
            },
            "prefix_cache": {
                "entries": len(state.prefix_cache),
                "cached_tokens_total": state.cached_tokens_total,
            },
            "training": dict(TRAINING_PROFILE),
        }
    return 200, payload


def _kv_transfer(ctx: _RequestContext):
    if ctx.mode == "fixed" and not ctx.admin:
        return 401, {"error": "unauthorized", "service": "longctx-infer",
                     "hint": "fixed 模式 KV 通道需要管理密钥"}
    body = ctx.body
    op = str(body.get("op") or "read").lower()
    block_id = _safe_name(str(body.get("block_id") or ""), "")
    if not block_id:
        return 400, {"error": "missing_block_id"}
    state = ctx.state
    if op == "read":
        with state.lock:
            block = state.kv_blocks.get(block_id)
        return 200, {
            "service": "longctx-infer",
            "op": "read",
            "block_id": block_id,
            "found": block is not None,
            "value": block["value"] if block else None,
            "sha256": block["sha256"] if block else "",
            "layer": block["layer"] if block else None,
        }
    if op == "write":
        if "value" not in body:
            return 400, {"error": "missing_value"}
        source = str(body.get("source_tenant") or ctx.tenant or "")
        dest = str(body.get("dest_tenant") or source or "")
        if ctx.mode == "fixed" and source and dest and source != dest:
            return 403, {"error": "cross_tenant_kv_write_denied",
                         "source_tenant": source, "dest_tenant": dest}
        value = _as_text(body.get("value"))
        with state.lock:
            state.kv_blocks[block_id] = {
                "value": value,
                "sha256": _sha256_text(value),
                "layer": body.get("layer"),
                "source_tenant": source,
                "dest_tenant": dest,
                "updated_at": _utcnow_iso(),
            }
            block = state.kv_blocks[block_id]
        return 200, {
            "service": "longctx-infer",
            "op": "write",
            "block_id": block_id,
            "bytes": len(value.encode("utf-8")),
            "sha256": block["sha256"],
            "source_tenant": source,
            "dest_tenant": dest,
        }
    return 400, {"error": "unsupported_op", "supported": ["read", "write"]}


def _checkpoint_write(ctx: _RequestContext):
    if ctx.mode == "fixed" and not ctx.admin:
        return 401, {"error": "unauthorized", "service": "longctx-infer",
                     "hint": "fixed 模式 checkpoint 分片写面需要管理密钥"}
    shard_id = _safe_name(str(ctx.body.get("shard_id") or ""), "")
    if not shard_id:
        return 400, {"error": "missing_shard_id"}
    payload = ctx.body.get("payload")
    if payload is None:
        return 400, {"error": "missing_payload"}
    text = _as_text(payload)
    path = checkpoint_shard_path(ctx.root, shard_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8"))
    return 200, {
        "service": "longctx-infer",
        "shard_id": shard_id,
        "bytes": len(text.encode("utf-8")),
        "sha256": _sha256_text(text),
        "updated_at": _utcnow_iso(),
    }


def _checkpoint_read(ctx: _RequestContext):
    shard_id = _safe_name(str((ctx.params or {}).get("shard") or ""), "")
    if not shard_id:
        return 400, {"error": "missing_shard_id"}
    path = checkpoint_shard_path(ctx.root, shard_id)
    if not path.is_file():
        return 404, {"error": "shard_not_found", "shard_id": shard_id}
    return 200, path.read_bytes().decode("utf-8", "replace")


def _routes_manifest(ctx: _RequestContext):
    return 200, {
        "service": "inkblade-longctx-lab",
        "mode": ctx.mode,
        "host": HOST,
        "admin_token_hint": f"fixed 模式管理密钥 = Authorization: Bearer {ADMIN_TOKEN}",
        "tenant_header": TENANT_HEADER,
        "route_count": len(ROUTE_TABLE),
        "routes": [{key: value for key, value in entry.items() if key != "behavior"}
                   for entry in ROUTE_TABLE],
    }


# ---------------------------------------------------------------------------
# 路由表（vulnerable/fixed = 基线请求状态码；行为函数内部再做细粒度判定）
# ---------------------------------------------------------------------------

ROUTE_TABLE = [
    {"service": "longctx-infer", "title": "OpenAI 兼容长上下文对话补全", "method": "POST",
     "path": "/v1/chat/completions", "vulnerable": 200, "fixed": 200, "gate": "tenant",
     "writes": False, "description": "窗口内 200；vulnerable 超窗仍 200 并排队；fixed 超窗/超 max_tokens 400、未知租户 401、跨租户无 cache_salt 403",
     "behavior": _chat_completions},
    {"service": "longctx-infer", "title": "推理与训练指标", "method": "GET", "path": "/metrics",
     "vulnerable": 200, "fixed": 401, "gate": "admin", "writes": False,
     "description": "vulnerable 无鉴权开放 kv_cache_usage/queue_depth/prefill_pool/decode_pool/training；fixed 401（管理密钥 200）",
     "behavior": _metrics},
    {"service": "longctx-infer", "title": "PD KV 通道读写", "method": "POST", "path": "/kv/transfer",
     "vulnerable": 200, "fixed": 401, "gate": "admin", "writes": True,
     "description": "vulnerable 无鉴权可读写 KV 块；fixed 401（管理密钥 200，跨租户写 403）",
     "behavior": _kv_transfer},
    {"service": "longctx-infer", "title": "PD KV 通道读回", "method": "GET", "path": "/kv/transfer",
     "vulnerable": 200, "fixed": 401, "gate": "admin", "writes": False,
     "description": "按 block_id 读回 KV 块（value/sha256）；鉴权语义同 POST",
     "behavior": lambda ctx: _kv_read_get(ctx)},
    {"service": "longctx-infer", "title": "checkpoint 分片写入", "method": "POST",
     "path": "/checkpoint/shards", "vulnerable": 200, "fixed": 401, "gate": "admin",
     "writes": True, "description": "vulnerable 无鉴权写分片文件（真实落盘）；fixed 401（管理密钥 200）",
     "behavior": _checkpoint_write},
    {"service": "longctx-infer", "title": "checkpoint 分片读回", "method": "GET",
     "path": "/checkpoint/shards/{shard}", "wildcard": True, "vulnerable": 200,
     "fixed": 200, "gate": "open", "writes": False,
     "description": "两态均允许读回已存在分片（缺失 404）", "behavior": _checkpoint_read},
    {"service": "meta", "title": "路由清单", "method": "GET", "path": "/__routes__",
     "vulnerable": 200, "fixed": 200, "gate": "open", "writes": False,
     "description": "返回本清单 JSON（供测试与模块发现）", "behavior": _routes_manifest},
]


def _kv_read_get(ctx: _RequestContext):
    if ctx.mode == "fixed" and not ctx.admin:
        return 401, {"error": "unauthorized", "service": "longctx-infer",
                     "hint": "fixed 模式 KV 通道需要管理密钥"}
    block_id = _safe_name(str((ctx.query.get("block_id") or [""])[0]), "")
    if not block_id:
        return 400, {"error": "missing_block_id"}
    with ctx.state.lock:
        block = ctx.state.kv_blocks.get(block_id)
    return 200, {
        "service": "longctx-infer",
        "op": "read",
        "block_id": block_id,
        "found": block is not None,
        "value": block["value"] if block else None,
        "sha256": block["sha256"] if block else "",
        "layer": block["layer"] if block else None,
    }


# ---------------------------------------------------------------------------
# 路由索引
# ---------------------------------------------------------------------------


def _normalize(path: str) -> str:
    stripped = path.rstrip("/")
    return stripped or "/"


def _prefix_of(entry: dict) -> str:
    return entry["path"].replace("{shard}", "").rstrip("/")


_EXACT_ROUTES: dict[tuple[str, str], list[dict]] = {}
_PREFIX_ROUTES: list[tuple[str, str, dict]] = []
for _entry in ROUTE_TABLE:
    if _entry.get("wildcard"):
        _PREFIX_ROUTES.append((_entry["method"], _prefix_of(_entry), _entry))
    else:
        _EXACT_ROUTES.setdefault((_entry["method"], _normalize(_entry["path"])), []).append(_entry)


def _entries_for(method: str, norm: str) -> list[dict]:
    found = list(_EXACT_ROUTES.get((method, norm), []))
    for prefix_method, prefix, entry in _PREFIX_ROUTES:
        if prefix_method == method and (norm == prefix or norm.startswith(prefix + "/")):
            found.append(entry)
    return found


def _resolve(method: str, norm: str) -> dict | None:
    entries = _entries_for(method, norm)
    return entries[0] if entries else None


def _path_params(entry: dict, norm: str) -> dict[str, str]:
    prefix = _prefix_of(entry)
    rest = norm[len(prefix):].strip("/")
    return {"shard": rest} if rest else {}


# ---------------------------------------------------------------------------
# HTTP 服务
# ---------------------------------------------------------------------------


class _LongctxState:
    def __init__(self, root: Path):
        self.lock = threading.Lock()
        self.prefix_cache: dict[str, object] = {}
        self.kv_blocks: dict[str, dict] = {}
        self.kv_bytes = 0
        self.kv_cache_usage = 0.0
        self.queue_depth = 0
        self.over_window_requests = 0
        self.requests = 0
        self.cached_tokens_total = 0
        seed = checkpoint_shard_path(root, SEED_SHARD)
        seed.parent.mkdir(parents=True, exist_ok=True)
        if not seed.is_file():
            seed.write_bytes(b"INKBLADE-MOCK-CHECKPOINT-SEED\nshard=00000\n")


class _LongctxHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, mode: str, root: Path):
        super().__init__(address, _LongctxHandler)
        self.lab_mode = mode
        self.lab_root = root
        self.lab_state = _LongctxState(root)


class _LongctxHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "InkBladeLongctxSim/0.1.0"

    def log_message(self, fmt, *args):  # 静默访问日志
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

    def _dispatch(self, method: str):
        split = urlsplit(self.path)
        norm = _normalize(split.path)
        entry = _resolve(method, norm)
        if entry is None:
            if any(_entries_for(other, norm) for other in ("GET", "POST") if other != method):
                self._send(405, {"error": "method not allowed", "path": split.path})
            else:
                self._send(404, {"error": "not found", "path": split.path})
            return
        server = self.server  # type: _LongctxHTTPServer
        ctx = _RequestContext(
            mode=server.lab_mode,
            root=server.lab_root,
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
        status, payload = outcome[0], outcome[1]
        extra = outcome[2] if len(outcome) > 2 else None
        self._send(status, payload, extra)


class Server:
    """仿真服务句柄：.port/.mode/.root + shutdown()；可作为上下文管理器。"""

    def __init__(self, httpd: _LongctxHTTPServer, thread: threading.Thread, mode: str,
                 root: Path, owns_root: bool):
        self._httpd = httpd
        self._thread = thread
        self.mode = mode
        self.root = root
        self._owns_root = owns_root
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
        finally:
            if self._owns_root:
                shutil.rmtree(self.root, ignore_errors=True)

    def __enter__(self) -> "Server":
        return self

    def __exit__(self, *exc_info) -> None:
        self.shutdown()


def start_all(port: int = 0, mode: str = DEFAULT_MODE,
              root: Path | str | None = None) -> Server:
    """启动长上下文仿真服务（单服务器，仅 127.0.0.1）。

    port=0 自动分配；mode ∈ {vulnerable, fixed}；root 缺省临时目录（shutdown 清理），可注入。
    """
    if mode not in MODES:
        raise ValueError(f"mode 必须是 {MODES} 之一，收到：{mode!r}")
    if root is None:
        root_path = Path(tempfile.mkdtemp(prefix="inkblade-longctx-"))
        owns_root = True
    else:
        root_path = Path(root)
        root_path.mkdir(parents=True, exist_ok=True)
        owns_root = False
    httpd = _LongctxHTTPServer((HOST, int(port)), mode, root_path)
    thread = threading.Thread(target=httpd.serve_forever,
                              kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    return Server(httpd, thread, mode, root_path, owns_root)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="InkBlade 长上下文推理仿真（仅 127.0.0.1）")
    parser.add_argument("--port", type=int, default=0, help="监听端口（0=自动分配）")
    parser.add_argument("--mode", choices=list(MODES), default=DEFAULT_MODE,
                        help="vulnerable=fail-open 姿态，fixed=加固姿态")
    parser.add_argument("--root", default=None, help="sandbox 根目录（缺省临时目录，退出清理）")
    args = parser.parse_args(argv)
    server = start_all(port=args.port, mode=args.mode, root=args.root)
    print(f"longctx sim: {server.url('/')} mode={server.mode} root={server.root}")
    print(f"路由清单: {server.url('/__routes__')}（共 {len(ROUTE_TABLE)} 条）")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("正在关闭长上下文仿真…")
    finally:
        server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
