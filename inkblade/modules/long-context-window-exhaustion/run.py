# -*- coding: utf-8 -*-
"""长上下文窗口耗尽 — 超窗请求被接受且 prefill 队列持续增长（真实 HTTP 差分）。

检测口径（不读仿真器答案）：
1) GET /metrics 取 queue_depth 基线；
2) POST /v1/chat/completions 声明 context_window 但 prompt_tokens 超出窗口；
3) 再次 GET /metrics：200 + usage.prefill_tokens > context_window + queue_depth 增长 → high。
fixed 姿态：超窗 400，metrics 401，无 high finding。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_longctx_common", _PARENT / "_longctx-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

KEY = "long-context-window-exhaustion"
WRITES = False


def run(ctx: dict, params: dict) -> dict:
    target = _COMMON.target_of(params)
    if not target:
        return _COMMON.no_target()
    marker = _COMMON.marker_of(ctx, params)
    window = str(params.get("context_window") or "128k")
    prompt_tokens = _COMMON.int_of(params.get("prompt_tokens"), 200000) or 200000
    t = _COMMON.Trace(ctx, KEY)
    body = {
        "model": "longctx-mock",
        "messages": [{"role": "user", "content": "trident long-context window probe"}],
        "context_window": window,
        "prompt_tokens": prompt_tokens,
        "max_tokens": _COMMON.int_of(params.get("max_tokens"), 32) or 32,
        "cache_salt": f"trident-{marker}",
    }
    before = t.call("GET", f"{target}/metrics")
    chat = t.call("POST", f"{target}/v1/chat/completions", body, _COMMON.headers_for(params))
    after = t.call("GET", f"{target}/metrics")

    usage = _COMMON.resp(chat).get("usage") or {}
    context_window = _COMMON.int_of(_COMMON.resp(chat).get("context_window"))
    prefill = _COMMON.int_of(usage.get("prefill_tokens"))
    queue_before = _COMMON.int_of(_COMMON.resp(before).get("queue_depth"))
    queue_after = _COMMON.int_of(_COMMON.resp(after).get("queue_depth"))
    detail = {
        "route": "/v1/chat/completions",
        "declared_context_window": window,
        "context_window_tokens": context_window,
        "prompt_tokens_requested": prompt_tokens,
        "prefill_tokens": prefill,
        "max_tokens": body["max_tokens"],
        "http_status": chat.get("status"),
        "metrics_status": after.get("status"),
        "queue_depth_before": queue_before,
        "queue_depth_after": queue_after,
        "queue_depth_delta": queue_after - queue_before,
        "tenant": _COMMON.tenant_of(params),
    }
    findings: list[dict] = []
    if _COMMON.is_ok(chat) and prefill > context_window:
        if queue_after > queue_before:
            title = "超窗请求被接受且 prefill 队列增长（长上下文窗口耗尽）"
        else:
            title = "超窗请求被接受（上下文窗口上限未强制执行）"
        findings.append(_COMMON.finding("high", title, detail))
    else:
        findings.append(_COMMON.finding("info", "超窗请求被拒绝：上下文窗口上限生效", detail))

    artifact = t.dump()
    _COMMON.write_artifact(ctx, "long-context-window-exhaustion.json", detail)
    summary = (f"chat={chat.get('status')} metrics={after.get('status')} "
               f"prefill={prefill}/{context_window} queue_delta={detail['queue_depth_delta']}")
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
