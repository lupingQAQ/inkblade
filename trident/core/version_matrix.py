# -*- coding: utf-8 -*-
"""版本矩阵（武器级弹药库）：指纹 → 受影响版本区间 → 已修复版本 → 绕过变体。

数据源（version-matrix.json 的 sources 字段逐条注明）：
- 本仓库审计轮次（模块探针语义 + lab 两态仿真 + 真 k3s/QEMU 实测）；
- 官方 release notes 抽查（products[].release_notes，2026-10-25 webfetch 核验 ≥10 条）。

诚实性约束（tests 锁定）：未见证官方修复的条目 fixed=null 且 fixed_note 非空；
不臆造修复版本；affected 区间只用可解释的表达式（见 match_version 文法）。
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

MATRIX_PATH = Path(__file__).resolve().parent / "data" / "version-matrix.json"

_SPEC_RE = re.compile(r"^\s*(==|<=|>=|<|>)?\s*(\d+(?:\.\d+)*)\s*$")


class MatrixError(ValueError):
    """矩阵结构/引用非法。"""


@lru_cache(maxsize=1)
def load(path: Path | str | None = None) -> dict:
    p = Path(path) if path else MATRIX_PATH
    data = json.loads(p.read_text(encoding="utf-8"))
    if data.get("schema") != "trident-version-matrix-v1":
        raise MatrixError(f"{p}: 未知 schema {data.get('schema')!r}")
    entries = data.get("entries") or []
    if not entries:
        raise MatrixError(f"{p}: entries 为空")
    seen: set[str] = set()
    for e in entries:
        for field in ("module", "product", "kind", "surface", "fingerprint",
                      "affected", "fixed_note", "variants", "sources", "audit_refs"):
            if field not in e:
                raise MatrixError(f"{e.get('module', '?')}: 缺字段 {field}")
        if e["module"] in seen:
            raise MatrixError(f"重复条目 {e['module']}")
        seen.add(e["module"])
        if not e["sources"]:
            raise MatrixError(f"{e['module']}: sources 为空（必须注明来源）")
        if len(e["variants"]) < 2:
            raise MatrixError(f"{e['module']}: variants < 2（每模块至少 2 探针变体）")
        for v in e["variants"]:
            if not v.get("id") or not v.get("kind") or not v.get("request") or not v.get("transform"):
                raise MatrixError(f"{e['module']}: 变体缺 id/kind/request/transform")
        if e["fixed"] is None and not e["fixed_note"].strip():
            raise MatrixError(f"{e['module']}: fixed=null 但 fixed_note 为空")
        if e["product"] not in (data.get("products") or {}):
            raise MatrixError(f"{e['module']}: 未知产品 {e['product']}")
    return data


def entries() -> list[dict]:
    return list(load()["entries"])


def entry(module_key: str) -> dict | None:
    return next((e for e in entries() if e["module"] == module_key), None)


def products() -> dict[str, dict]:
    return dict(load()["products"])


def variants_for(module_key: str) -> list[dict]:
    e = entry(module_key)
    return list(e["variants"]) if e else []


def modules_for_product(product: str) -> list[str]:
    return [e["module"] for e in entries() if e["product"] == product]


def _version_tuple(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.strip().lstrip("v").split("."))


def match_version(observed: str, spec: str) -> bool:
    """判断 observed 版本是否落入 spec 区间。

    文法（保守白名单）：``*``（全部）；``<=X``/``<X``/``>=X``/``>X``/``X``（精确）；
    ``<2.52（注释）`` 之类带中文注释的先剥注释再判定。其余一律 MatrixError（不静默放行）。
    """
    text = spec.split("（")[0].split("(")[0].strip()
    if text == "*":
        return True
    m = _SPEC_RE.match(text)
    if not m:
        raise MatrixError(f"不可判定的版本区间表达式: {spec!r}")
    op, ver = m.group(1) or "==", m.group(2)
    try:
        obs, ref = _version_tuple(observed), _version_tuple(ver)
    except ValueError as exc:
        raise MatrixError(f"非法版本号（observed={observed!r}, spec={spec!r}）") from exc
    # 补齐位数后比较（0.5 == 0.5.0）
    width = max(len(obs), len(ref))
    obs += (0,) * (width - len(obs))
    ref += (0,) * (width - len(ref))
    return {"<": obs < ref, "<=": obs <= ref, ">": obs > ref, ">=": obs >= ref,
            "==": obs == ref}[op]


def affected(observed_version: str, module_key: str) -> bool:
    """目标版本是否受该模块影响（模块无条目时返回 False 并可由调用方记录）。"""
    e = entry(module_key)
    if e is None:
        return False
    spec = e["affected"]
    if spec.strip() == "*":
        return True
    return match_version(observed_version, spec)


def covered_modules() -> set[str]:
    """矩阵覆盖的全部模块键（供与注册表横向系列对账）。"""
    return {e["module"] for e in entries()}
