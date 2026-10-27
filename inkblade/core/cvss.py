# -*- coding: utf-8 -*-
"""CVSS 3.1 base-score calculator (for validating disclosure metadata).

Only the base metrics are needed: the disclosure packages publish a base
vector and must not claim a score that the vector does not produce.
"""

from __future__ import annotations

import re

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

_PREFIX = "CVSS:3.1/"


def parse_vector(vector: str) -> dict[str, str]:
    if not vector.startswith(_PREFIX):
        raise ValueError(f"not a CVSS 3.1 vector: {vector!r}")
    out: dict[str, str] = {}
    for part in vector[len(_PREFIX):].split("/"):
        if not part:
            continue
        key, _, value = part.partition(":")
        if key in out:
            raise ValueError(f"duplicate metric {key} in {vector!r}")
        out[key] = value
    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    missing = required - set(out)
    if missing:
        raise ValueError(f"missing metrics {sorted(missing)} in {vector!r}")
    return out


def _roundup(value: float) -> float:
    # CVSS 3.1 roundup: smallest one-decimal number >= value (FIRST reference).
    scaled = round(value * 100000)
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (scaled // 10000 + 1) / 10.0


def base_score(vector: str) -> float:
    m = parse_vector(vector)
    scope_changed = m["S"] == "C"
    iss = 1.0 - (1.0 - _CIA[m["C"]]) * (1.0 - _CIA[m["I"]]) * (1.0 - _CIA[m["A"]])
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[m["PR"]]
    exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]
    if impact <= 0:
        return 0.0
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10.0))
    return _roundup(min(impact + exploitability, 10.0))


def severity(score: float) -> str:
    if score == 0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


def check(vector: str, score: float, level: str | None = None) -> None:
    computed = base_score(vector)
    if abs(computed - float(score)) > 0.05:
        raise ValueError(f"score {score} does not match vector {vector} (computed {computed})")
    if level is not None and severity(computed) != level:
        raise ValueError(f"severity {level} does not match score {computed} ({severity(computed)})")


def is_cvss31(vector: str) -> bool:
    try:
        parse_vector(vector)
    except ValueError:
        return False
    return True
