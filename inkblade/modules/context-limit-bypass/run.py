# -*- coding: utf-8 -*-
"""上下文上限绕过 — 声明窗口与实际 token 数不一致仍被接受。

检测口径（真实 HTTP 差分 + 计数器）：
1) baseline：128k 窗口 + 1024 token → 200（正对照）；
2) bypass：同一 128k 声明，prompt 实发 900k token → vulnerable 200，
   usage.prefill_tokens > context_window；fixed 400（context_window_exceeded）。
超窗后 /metrics queue_depth 增长作为第二证据。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_longctx_common", _PARENT / "_longctx-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

KEY = "context-limit-bypass"
WRITES = False
BYPASS_PROMPT_TOKENS = 900000


def _chat(trace, target, body, params, tenant):
    return trace.call("POST", f"{target}/v1/chat/completions", body,
                      {_COMMON.TENANT_HEADER: tenant})


def run(ctx: dict, params: dict) -> dict:
    target = _COMMON.target_of(params)
    if not target:
        return _COMMON.no_target()
    marker = _COMMON.marker_of(ctx, params)
    window = str(params.get("context_window") or "128k")
    tenant = _COMMON.tenant_of(params)
    t = _COMMON.Trace(ctx, KEY)
    base_body = {
        "model": "longctx-mock",
        "messages": [{"role": "user", "content": "trident context limit probe"}],
        "context_window": window,
        "prompt_tokens": 1024,
        "max_tokens": 32,
        "cache_salt": f"trident-base-{marker}",
    }
    bypass_body = dict(base_body, prompt_tokens=_COMMON.int_of(
        params.get("prompt_tokens"), BYPASS_PROMPT_TOKENS) or BYPASS_PROMPT_TOKENS,
        cache_salt=f"trident-bypass-{marker}")

    metrics_before = t.call("GET", f"{target}/metrics", headers=_COMMON.headers_for(params))
    baseline = _chat(t, target, base_body, params, tenant)
    bypass = _chat(t, target, bypass_body, params, tenant)
    metrics_after = t.call("GET", f"{target}/metrics", headers=_COMMON.headers_for(params))

    usage = _COMMON.resp(bypass).get("usage") or {}
    context_window = _COMMON.int_of(_COMMON.resp(bypass).get("context_window"))
    prefill = _COMMON.int_of(usage.get("prefill_tokens"))
    queue_before = _COMMON.int_of(_COMMON.resp(metrics_before).get("queue_depth"))
    queue_after = _COMMON.int_of(_COMMON.resp(metrics_after).get("queue_depth"))
    detail = {
        "route": "/v1/chat/completions",
        "declared_context_window": window,
        "context_window_tokens": context_window,
        "baseline_status": baseline.get("status"),
        "bypass_status": bypass.get("status"),
        "prompt_tokens": bypass_body["prompt_tokens"],
        "prefill_tokens": prefill,
        "overshoot_ratio": round(prefill / context_window, 2) if context_window else 0.0,
        "metrics_status": metrics_after.get("status"),
        "queue_depth_before": queue_before,
        "queue_depth_after": queue_after,
        "queue_depth_delta": queue_after - queue_before,
        "tenant": tenant,
    }
    findings: list[dict] = []
    if _COMMON.is_ok(bypass) and prefill > context_window:
        findings.append(_COMMON.finding(
            "high", "上下文上限绕过：声明 128k 实发 900k 仍被接受", detail))
    else:
        findings.append(_COMMON.finding(
            "info", "上下文上限生效：声明窗口与实际 token 不一致时拒绝", detail))

    artifact = t.dump()
    _COMMON.write_artifact(ctx, "context-limit-bypass.json", detail)
    summary = (f"baseline={baseline.get('status')} bypass={bypass.get('status')} "
               f"prefill={prefill}/{context_window}")
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
