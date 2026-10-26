"""CVSS 3.1 基础评分实现（标准公式 + FIRST 官方 roundup 进位规则）与 CNVD/CNNVD 习惯定级。"""

from __future__ import annotations

import math

# CVSS 3.1 权重表（FIRST Specification v3.1 Section 7 / 附录 A）
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

_REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

# 严重度 → CNVD/CNNVD 习惯定级中文（用于报告发现行）
SEVERITY_CN = {
    "critical": "超危",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "提示",
}


def parse(vector: str) -> dict[str, str]:
    """解析 CVSS 3.x 向量（可带 CVSS:3.0/ 或 CVSS:3.1/ 前缀），返回指标字典；非法即抛 ValueError。"""
    v = (vector or "").strip()
    if v.startswith("CVSS:"):
        prefix, _, rest = v.partition("/")
        version = prefix.split(":", 1)[1]
        if version not in ("3.0", "3.1"):
            raise ValueError(f"不支持的 CVSS 版本: {version}")
        v = rest
    metrics: dict[str, str] = {}
    for part in v.split("/"):
        key, sep, val = part.partition(":")
        if not sep or not key or not val:
            raise ValueError(f"非法向量片段: {part!r}")
        if key in metrics:
            raise ValueError(f"重复指标: {key}")
        metrics[key] = val
    missing = [k for k in _REQUIRED if k not in metrics]
    if missing:
        raise ValueError(f"缺少基础指标: {','.join(missing)}")
    if metrics["S"] not in ("U", "C"):
        raise ValueError(f"非法指标值 S:{metrics['S']}")
    tables = (("AV", _AV), ("AC", _AC), ("UI", _UI), ("C", _CIA), ("I", _CIA), ("A", _CIA))
    for key, table in tables:
        if metrics[key] not in table:
            raise ValueError(f"非法指标值 {key}:{metrics[key]}")
    pr = _PR_CHANGED if metrics["S"] == "C" else _PR_UNCHANGED
    if metrics["PR"] not in pr:
        raise ValueError(f"非法指标值 PR:{metrics['PR']}")
    return metrics


def roundup(value: float) -> float:
    """FIRST 官方 roundup（小数进位规则），规避 0.05 边界的浮点尾差。"""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    if int_input % 10000 - 5000 > 0:
        return (math.floor(int_input / 10000) + 1) / 10.0
    return int_input / 100000.0


def base_score(vector: str) -> float:
    """CVSS 3.1 基础评分（ImpactSubscore + Exploitability，Scope 改变时乘 1.08 并封顶 10）。"""
    m = parse(vector)
    iss = 1.0 - (1.0 - _CIA[m["C"]]) * (1.0 - _CIA[m["I"]]) * (1.0 - _CIA[m["A"]])
    if m["S"] == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    pr = _PR_CHANGED if m["S"] == "C" else _PR_UNCHANGED
    exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr[m["PR"]] * _UI[m["UI"]]
    if impact <= 0:
        return 0.0
    if m["S"] == "U":
        return roundup(min(impact + exploitability, 10.0))
    return roundup(min(1.08 * (impact + exploitability), 10.0))


def severity_band(score: float) -> str:
    """评分 → 标准严重度带：none/low/medium/high/critical。"""
    if score <= 0.0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def cn_grade(score: float) -> str:
    """评分 → CNVD/CNNVD 习惯定级（超危/高危/中危/低危）。"""
    band = severity_band(score)
    return {"none": "无风险", "low": "低危", "medium": "中危", "high": "高危", "critical": "超危"}[band]
