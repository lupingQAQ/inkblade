# -*- coding: utf-8 -*-
"""cache-timing-sidechannel — 前缀缓存 TTFT 时序侧信道（成员推断 + 前缀字典提取）。

检测口径（统计显著性，N≥50）：
1) 对「成员前缀」（受害租户已缓存）与「对照前缀」（未缓存）交替各测 N/2 次，
   记录响应 ttft_ms（命中档 vs 未命中档）；
2) Welch t 检验（纯标准库实现不完全 Beta 函数求 p 值）：
   |Δ均值| ≥ min_effect_ms 且 p < alpha → 成员推断成立；
3) 以两档中点为分类阈值逐前缀判定 → 受害前缀字典提取率。

vulnerable：全局前缀键 → 跨租户命中 → 显著差分 → high；
fixed：键含 tenant|salt → 两类皆未命中 → 无显著差分 → info。
"""
from __future__ import annotations

import importlib.util
import math
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_cache_common", _PARENT / "_cache-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

KEY = "cache-timing-sidechannel"
WRITES = False
DEFAULT_PER_CLASS = 30  # 30+30=60 ≥ 50
MIN_TOTAL_SAMPLES = 50


def _betacf(a: float, b: float, x: float) -> float:
    max_it, eps, fpmin = 300, 3e-12, 1e-300
    qab, qap, qam = a + b, a + 1.0, a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < fpmin:
        d = fpmin
    d = 1.0 / d
    h = d
    for m in range(1, max_it + 1):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < fpmin:
            d = fpmin
        c = 1.0 + aa / c
        if abs(c) < fpmin:
            c = fpmin
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < fpmin:
            d = fpmin
        c = 1.0 + aa / c
        if abs(c) < fpmin:
            c = fpmin
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < eps:
            break
    return h


def _betainc(a: float, b: float, x: float) -> float:
    """正则化不完全 Beta 函数 I_x(a,b)（连分式，Numerical Recipes 口径）。"""
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    ln_bt = (math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b)
             + a * math.log(x) + b * math.log(1.0 - x))
    bt = math.exp(ln_bt)
    if x < (a + 1.0) / (a + b + 2.0):
        return bt * _betacf(a, b, x) / a
    return 1.0 - bt * _betacf(b, a, 1.0 - x) / b


def welch_ttest(xs: list[float], ys: list[float]) -> dict:
    """Welch t 检验（双尾 p，不完全 Beta 精确求解，纯标准库）。"""
    n1, n2 = len(xs), len(ys)
    m1 = sum(xs) / n1
    m2 = sum(ys) / n2
    v1 = sum((x - m1) ** 2 for x in xs) / max(1, n1 - 1)
    v2 = sum((y - m2) ** 2 for y in ys) / max(1, n2 - 1)
    se_sq = v1 / n1 + v2 / n2
    se = math.sqrt(se_sq)
    t = ((m1 - m2) / se) if se > 0 else 0.0
    if se_sq > 0 and n1 > 1 and n2 > 1:
        df = se_sq ** 2 / ((v1 / n1) ** 2 / (n1 - 1) + (v2 / n2) ** 2 / (n2 - 1))
    else:
        df = float(n1 + n2 - 2)
    if df <= 0 or se == 0:
        p = 1.0 if abs(t) < 1e-12 else 0.0
    else:
        x = df / (df + t * t)
        p = _betainc(df / 2.0, 0.5, x)  # 双尾 p = I_{df/(df+t²)}(df/2, 1/2)
    return {"t": round(t, 4), "df": round(df, 2), "p": p,
            "mean1": round(m1, 3), "mean2": round(m2, 3)}


def _default_member_prefixes(count: int) -> list[str]:
    return [f"tenant-b member context {i:02d} TRIDENT-BENIGN-TIMING "
            f"corpus analytics monthly summary {i:02d}" for i in range(count)]


def _default_control_prefixes(count: int) -> list[str]:
    return [f"trident-control-corpus {i:02d} unrelated analytics topic "
            f"reference data pack" for i in range(count)]


def run(ctx: dict, params: dict) -> dict:
    target = _COMMON.target_of(params)
    if not target:
        return _COMMON.no_target()
    tenant = _COMMON.tenant_of(params)
    per_class = max(1, _COMMON.int_of(params.get("per_class"), DEFAULT_PER_CLASS))
    members = list(params.get("member_prefixes") or _default_member_prefixes(per_class))
    controls = list(params.get("control_prefixes") or _default_control_prefixes(per_class))
    alpha = _COMMON.float_of(params.get("alpha"), 0.05)
    min_effect = _COMMON.float_of(params.get("min_effect_ms"), 30.0)

    t = _COMMON.Trace(ctx, KEY)
    headers = _COMMON.headers_for(params)
    member_ttft: list[float] = []
    control_ttft: list[float] = []
    # 交替测量（成员/对照交错，消除顺序偏差）
    for i in range(max(len(members), len(controls))):
        if i < len(members):
            entry = t.call("POST", f"{target}/v1/chat/completions", {
                "prompt_prefix": members[i], "prefix_tokens": 2048, "max_tokens": 1,
            }, headers)
            member_ttft.append(float(_COMMON.resp(entry).get("ttft_ms") or 0.0))
        if i < len(controls):
            entry = t.call("POST", f"{target}/v1/chat/completions", {
                "prompt_prefix": controls[i], "prefix_tokens": 2048, "max_tokens": 1,
            }, headers)
            control_ttft.append(float(_COMMON.resp(entry).get("ttft_ms") or 0.0))

    stats = welch_ttest(member_ttft, control_ttft)
    delta = stats["mean2"] - stats["mean1"]  # 对照（未命中）− 成员（命中）
    n_total = len(member_ttft) + len(control_ttft)
    significant = stats["p"] < alpha and delta >= min_effect and n_total >= MIN_TOTAL_SAMPLES
    # 前缀字典提取：两档中点分类器
    midpoint = (stats["mean1"] + stats["mean2"]) / 2.0
    inferred_members = sum(1 for v in member_ttft if v < midpoint)
    inferred_controls = sum(1 for v in control_ttft if v >= midpoint)
    extraction_rate = round(
        (inferred_members + inferred_controls) / max(1, n_total), 4)

    detail = {
        "route": "/v1/chat/completions",
        "channel": "ttft_ms",
        "n_member": len(member_ttft),
        "n_control": len(control_ttft),
        "n_total": n_total,
        "n_total_ge_50": n_total >= MIN_TOTAL_SAMPLES,
        "mean_member_ttft_ms": stats["mean1"],
        "mean_control_ttft_ms": stats["mean2"],
        "delta_ms": round(delta, 3),
        "welch_t": stats["t"],
        "df": stats["df"],
        "p_value": stats["p"],
        "alpha": alpha,
        "significant": significant,
        "classifier_threshold_ms": round(midpoint, 3),
        "inferred_member_prefixes": inferred_members,
        "inferred_control_prefixes": inferred_controls,
        "extraction_rate": extraction_rate,
        "tenant": tenant,
        "victim_tenant": _COMMON.victim_tenant_of(params),
        "note": "成员=受害租户已缓存前缀；对照=未缓存前缀；命中档/未命中档差分即成员推断信号",
    }
    findings: list[dict] = []
    if n_total < MIN_TOTAL_SAMPLES:
        detail["http_status"] = 200
        findings.append(_COMMON.finding(
            "info", f"样本不足（N={n_total}<{MIN_TOTAL_SAMPLES}），显著性断言不成立", detail))
    elif significant:
        detail["http_status"] = 200
        findings.append(_COMMON.finding(
            "high",
            f"前缀缓存时序侧信道：TTFT 差分 {round(delta, 1)}ms（p={stats['p']:.2e}）"
            f"→ 跨租户缓存成员推断/前缀字典提取成立（N={n_total}）",
            detail))
    else:
        detail["http_status"] = 200
        findings.append(_COMMON.finding(
            "info",
            f"未观察到显著 TTFT 差分（Δ={round(delta, 1)}ms，p={stats['p']:.3f}）"
            "——前缀键按租户隔离或命中不可观测", detail))

    artifact = t.dump()
    _COMMON.write_artifact(ctx, "cache-timing-sidechannel.json", detail)
    summary = (f"N={n_total} member={stats['mean1']}ms control={stats['mean2']}ms "
               f"Δ={round(delta, 1)}ms p={stats['p']:.2e} significant={significant}")
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
