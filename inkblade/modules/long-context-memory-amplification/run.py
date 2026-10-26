# -*- coding: utf-8 -*-
"""长上下文内存放大 — 小 prompt 触发按声明窗口预留的大 KV（真实计数器差分）。

检测口径：
1) GET /metrics 记录 kv_cache_bytes 基线；
2) POST /v1/chat/completions：prompt 仅 1024 token 但声明 1M 窗口；
3) 再次 GET /metrics：kv_cache_bytes 增量 /（prompt×每 token KV 字节）> 64 → high。
fixed 姿态：metrics 401（或无超量预留），无 high finding。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_longctx_common", _PARENT / "_longctx-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

KEY = "long-context-memory-amplification"
WRITES = False
AMPLIFICATION_THRESHOLD = 64
KV_BYTES_PER_TOKEN = 2


def run(ctx: dict, params: dict) -> dict:
    target = _COMMON.target_of(params)
    if not target:
        return _COMMON.no_target()
    marker = _COMMON.marker_of(ctx, params)
    prompt_tokens = _COMMON.int_of(params.get("prompt_tokens"), 1024) or 1024
    t = _COMMON.Trace(ctx, KEY)
    before = t.call("GET", f"{target}/metrics", headers=_COMMON.headers_for(params))
    chat = t.call("POST", f"{target}/v1/chat/completions", {
        "model": "longctx-mock",
        "messages": [{"role": "user", "content": "inkblade kv amplification probe"}],
        "context_window": str(params.get("context_window") or "1m"),
        "prompt_tokens": prompt_tokens,
        "max_tokens": _COMMON.int_of(params.get("max_tokens"), 64) or 64,
        "cache_salt": f"inkblade-{marker}",
    }, _COMMON.headers_for(params))
    after = t.call("GET", f"{target}/metrics")

    before_bytes = _COMMON.int_of(_COMMON.resp(before).get("kv_cache_bytes"))
    after_bytes = _COMMON.int_of(_COMMON.resp(after).get("kv_cache_bytes"))
    delta = after_bytes - before_bytes
    ratio = round(delta / (prompt_tokens * KV_BYTES_PER_TOKEN), 2) if prompt_tokens else 0.0
    detail = {
        "route": "/v1/chat/completions",
        "context_window": str(params.get("context_window") or "1m"),
        "prompt_tokens": prompt_tokens,
        "chat_status": chat.get("status"),
        "metrics_status_before": before.get("status"),
        "metrics_status_after": after.get("status"),
        "kv_cache_bytes_before": before_bytes,
        "kv_cache_bytes_after": after_bytes,
        "kv_cache_bytes_delta": delta,
        "amplification_ratio": ratio,
        "kv_cache_usage_after": _COMMON.resp(after).get("kv_cache_usage"),
        "threshold": AMPLIFICATION_THRESHOLD,
    }
    findings: list[dict] = []
    if (_COMMON.is_ok(before) and _COMMON.is_ok(after) and _COMMON.is_ok(chat)
            and delta > 0 and ratio >= AMPLIFICATION_THRESHOLD):
        findings.append(_COMMON.finding(
            "high", "长上下文内存放大：小 prompt 触发大 KV 预留（窗口声明即分配）", detail))
    else:
        findings.append(_COMMON.finding(
            "info", "未观察到长上下文内存放大（指标受保护或按实际长度分配）", detail))

    artifact = t.dump()
    _COMMON.write_artifact(ctx, "long-context-memory-amplification.json", detail)
    summary = (f"chat={chat.get('status')} metrics={after.get('status')} "
               f"kv_delta={delta} ratio={ratio}")
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
