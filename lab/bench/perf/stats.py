"""stats — 全分布统计与线性拟合（仅标准库）。

要求：所有时长类测量报 min/median/p95/p99/max + 方差（用户口径④），
禁止只报 median/p95。
"""
from __future__ import annotations

import math


def percentile(sorted_vals: list[float], p: float) -> float:
    """线性插值百分位（输入必须已升序排序）。"""
    if not sorted_vals:
        return float("nan")
    if len(sorted_vals) == 1:
        return float(sorted_vals[0])
    k = (len(sorted_vals) - 1) * p
    lo = math.floor(k)
    hi = math.ceil(k)
    if lo == hi:
        return float(sorted_vals[lo])
    return float(sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (k - lo))


def full_dist(values: list[float], *, unit: str = "ms", n_decimals: int = 3) -> dict:
    """全分布：n/min/median/p95/p99/max/mean/stdev/variance（禁止只报 median/p95）。"""
    vals = sorted(float(v) for v in values)
    n = len(vals)
    if n == 0:
        return {"n": 0, "unit": unit, "note": "no samples"}
    mean = sum(vals) / n
    var = sum((v - mean) ** 2 for v in vals) / n  # 总体方差（全量测量，非抽样）
    out = {
        "n": n,
        "unit": unit,
        "min": round(vals[0], n_decimals),
        "median": round(percentile(vals, 0.50), n_decimals),
        "p95": round(percentile(vals, 0.95), n_decimals),
        "p99": round(percentile(vals, 0.99), n_decimals),
        "max": round(vals[-1], n_decimals),
        "mean": round(mean, n_decimals),
        "variance": round(var, n_decimals),
        "stdev": round(math.sqrt(var), n_decimals),
    }
    return out


def linfit_slope(xs: list[float], ys: list[float]) -> dict:
    """最小二乘线性拟合 y = slope*x + intercept（泄漏判定：RSS-时间斜率）。"""
    n = len(xs)
    if n < 3:
        return {"n": n, "slope": float("nan"), "note": "n<3 无法拟合"}
    mx = sum(xs) / n
    my = sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    if sxx == 0:
        return {"n": n, "slope": 0.0, "intercept": my, "note": "x 无变化"}
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx
    intercept = my - slope * mx
    ss_tot = sum((y - my) ** 2 for y in ys)
    ss_res = sum((y - (slope * x + intercept)) ** 2 for x, y in zip(xs, ys))
    r2 = 1 - ss_res / ss_tot if ss_tot else 1.0
    return {"n": n, "slope": round(slope, 6), "intercept": round(intercept, 6),
            "r2": round(r2, 6)}


def leak_verdict(slope_per_iter: float, unit_per_iter_threshold: float,
                 first: float, last: float, growth_ratio_threshold: float = 0.10) -> dict:
    """泄漏判定：斜率超阈值且首尾增长超比例阈值 → leak-suspected，否则 stable。

    同时给出保守口径：斜率本身 + 拟合优度交给调用方写入 JSON。
    """
    growth = (last - first) / first if first else 0.0
    suspected = (slope_per_iter > unit_per_iter_threshold
                 and growth > growth_ratio_threshold)
    return {
        "slope": slope_per_iter,
        "growth_ratio": round(growth, 4),
        "threshold_slope": unit_per_iter_threshold,
        "threshold_growth": growth_ratio_threshold,
        "verdict": "leak-suspected" if suspected else "stable",
    }


def rate(total: int, seconds: float) -> float:
    return round(total / seconds, 3) if seconds > 0 else 0.0
