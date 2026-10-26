# -*- coding: utf-8 -*-
"""2026-10 合规映射引擎（只读、纯标准库）。

输入发现标题/步骤键/上下文 → 多标签类别 → 七框架条款并集：
OWASP LLM Top 10（2025/2026）、OWASP Agentic AI Top 10（ASI01–ASI10）、
MITRE ATLAS、NIST AI RMF 1.0、ISO/IEC 42001:2023、EU AI Act GPAI（Art. 53/55）、
TC260-003 + 《生成式人工智能服务管理暂行办法》。

Ruling：映射是工程整改追踪口径而非合规认证结论；无法具体归类的发现使用
``fallback``（platform/infrastructure）条款，保证每条发现对每个框架至少 1 条款。
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

_DIR = Path(__file__).resolve().parent
_DATA = json.loads((_DIR / "standards.json").read_text(encoding="utf-8"))
_COMP = _DATA["compliance"]
_FRAMEWORKS: dict[str, dict] = {f["key"]: f for f in _COMP["frameworks"]}
_FRAMEWORK_ORDER: tuple[str, ...] = tuple(_FRAMEWORKS)
_CLAUSE_IDS: dict[str, set[str]] = {
    key: {c["id"] for c in fw["clauses"]} for key, fw in _FRAMEWORKS.items()
}
_CATEGORY_BY_KEY: dict[str, dict] = {c["key"]: c for c in _COMP["categories"]}


def load_standards() -> dict:
    """返回合规标准库（深拷贝，调用方可安全修改）。"""
    return json.loads(json.dumps(_COMP, ensure_ascii=False))


def frameworks() -> dict[str, dict]:
    return _FRAMEWORKS


def framework_order() -> tuple[str, ...]:
    return _FRAMEWORK_ORDER


def fallback_category() -> str:
    return _COMP["fallback"]


def _pick(lang: str, zh: str, en: str) -> str:
    if lang == "zh":
        return zh
    if lang == "en":
        return en
    return f"{zh} / {en}"


def _cell(text: Any) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ").strip()


def _check_lang(lang: str) -> None:
    if lang not in ("bi", "zh", "en"):
        raise ValueError(f"lang 必须为 bi/zh/en: {lang}")


def _haystack(finding: dict) -> str:
    return " ".join(
        str(finding.get(k, "")) for k in ("title", "step_key", "detail", "module", "summary")
    ).lower()


def classify(finding: dict) -> list[str]:
    """多标签分类：按标准库声明顺序返回命中的全部类别；无命中返回兜底类别。"""
    hay = _haystack(finding)
    step_key = str(finding.get("step_key") or finding.get("module") or "").lower()
    hits: list[str] = []
    for cat in _COMP["categories"]:
        if cat["key"] == _COMP["fallback"]:
            continue
        keys = [k.lower() for k in cat.get("keywords", [])]
        if any(k in hay for k in keys) or (step_key and any(k in step_key for k in keys)):
            hits.append(cat["key"])
    if hits:
        return hits
    return [_COMP["fallback"]]


def _ordered(framework: str, ids: Iterable[str]) -> list[str]:
    wanted = set(ids)
    return [c["id"] for c in _FRAMEWORKS[framework]["clauses"] if c["id"] in wanted]


def map_finding(finding: dict) -> dict[str, list[str]]:
    """finding → {framework_key: [clause_id, ...]}（每框架至少 1 条）。"""
    categories = classify(finding)
    mapping = _COMP["mapping"]
    out: dict[str, list[str]] = {}
    for key in _FRAMEWORK_ORDER:
        ids: set[str] = set()
        for cat in categories:
            ids.update(mapping.get(cat, {}).get(key, []))
        if not ids:  # 数据缺口的硬兜底：保持「每发现每框架 ≥1 条款」不变量
            ids.update(mapping[_COMP["fallback"]].get(key, []))
        bad = ids - _CLAUSE_IDS[key]
        if bad:
            raise ValueError(f"标准库引用未知条款 {key}: {sorted(bad)}")
        out[key] = _ordered(key, ids)
    return out


def finding_id(finding: dict) -> str:
    raw = "|".join(str(finding.get(k, "")) for k in ("step_key", "title", "severity"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def matrix_rows(findings: list[dict]) -> list[dict]:
    rows: list[dict] = []
    for finding in findings or []:
        cats = classify(finding)
        rows.append({
            "id": finding_id(finding),
            "title": finding.get("title", ""),
            "step_key": finding.get("step_key", ""),
            "severity": finding.get("severity", ""),
            "categories": cats,
            "clauses": map_finding(finding),
        })
    return rows


def coverage_summary(findings: list[dict]) -> dict:
    rows = matrix_rows(findings)
    per: dict[str, dict] = {}
    for key in _FRAMEWORK_ORDER:
        used: set[str] = set()
        for row in rows:
            used.update(row["clauses"][key])
        per[key] = {
            "name_zh": _FRAMEWORKS[key]["name_zh"],
            "name_en": _FRAMEWORKS[key]["name_en"],
            "ref": _FRAMEWORKS[key]["url"],
            "clauses": len(used),
            "findings": len(rows),
        }
    fallback = _COMP["fallback"]
    return {
        "schema": "inkblade-compliance-coverage/2026-10",
        "findings": len(rows),
        "frameworks": per,
        "fallback": fallback,
        "fallback_used": sum(1 for row in rows if row["categories"] == [fallback]),
        "ok": all(row["clauses"].get(key) for row in rows for key in _FRAMEWORK_ORDER),
    }


def _matrix_table(findings: list[dict], lang: str) -> str:
    head = [_pick(lang, "发现", "Finding")]
    head += [_pick(lang, _FRAMEWORKS[k]["name_zh"], _FRAMEWORKS[k]["name_en"])
             for k in _FRAMEWORK_ORDER]
    lines = ["| " + " | ".join(_cell(h) for h in head) + " |",
             "|" + "---|" * len(head)]
    rows = matrix_rows(findings)
    if not rows:
        lines.append("| " + " | ".join([_pick(lang, "（无发现）", "(no findings)")] + ["—"] * 7) + " |")
    for row in rows:
        cells = [_cell(row["title"])]
        for key in _FRAMEWORK_ORDER:
            cells.append(", ".join(row["clauses"][key]) or "—")
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def _index_table(findings: list[dict], lang: str) -> str:
    used: dict[str, set[str]] = {key: set() for key in _FRAMEWORK_ORDER}
    for row in matrix_rows(findings):
        for key, ids in row["clauses"].items():
            used[key].update(ids)
    head = [_pick(lang, "框架", "Framework"), _pick(lang, "条款", "Clause"),
            _pick(lang, "中文", "Chinese"), _pick(lang, "English", "English")]
    lines = ["| " + " | ".join(head) + " |", "|---|---|---|---|"]
    for key in _FRAMEWORK_ORDER:
        fw = _FRAMEWORKS[key]
        for clause in fw["clauses"]:
            if clause["id"] not in used[key]:
                continue
            legacy = clause.get("legacy_2025")
            label = clause["id"] + (f"（2025: {legacy}）" if legacy and lang != "en"
                                    else (f" (2025: {legacy})" if legacy else ""))
            lines.append(
                f"| {_cell(_pick(lang, fw['name_zh'], fw['name_en']))} | {_cell(label)} "
                f"| {_cell(clause['zh'])} | {_cell(clause['en'])} |"
            )
    return "\n".join(lines)


def _refs(lang: str) -> str:
    label = _pick(lang, "官方来源：", "Official sources:")
    items = [f"[{_pick(lang, fw['name_zh'], fw['name_en'])}]({fw['url']})"
             for fw in _FRAMEWORKS.values()]
    return label + " " + " · ".join(items)


def render_compliance_body(findings: list[dict], lang: str = "bi") -> str:
    """渲染合规映射主体（表格 + 覆盖摘要 + 条款索引 + 免责声明），不含二级标题。"""
    _check_lang(lang)
    summary = coverage_summary(findings)
    lines = [
        _pick(lang, _COMP["intro_zh"], _COMP["intro_en"]),
        "",
        _matrix_table(findings, lang),
        "",
        _pick(
            lang,
            f"覆盖摘要：发现 {summary['findings']} 项；每项均映射七个框架至少 1 条款"
            f"（平台面兜底 {summary['fallback_used']} 项）；条款引用数 "
            + " · ".join(f"{summary['frameworks'][k]['name_zh']} {summary['frameworks'][k]['clauses']}"
                         for k in _FRAMEWORK_ORDER)
            + "。",
            f"Coverage: {summary['findings']} findings; every finding maps to at least one clause "
            f"in all seven frameworks (platform fallback used {summary['fallback_used']} times); "
            "referenced clauses: "
            + " · ".join(f"{summary['frameworks'][k]['name_en']} {summary['frameworks'][k]['clauses']}"
                         for k in _FRAMEWORK_ORDER)
            + ".",
        ),
        "",
        _pick(lang, "条款索引 Clause Index", "Clause Index"),
        "",
        _index_table(findings, lang),
        "",
        _refs(lang),
        "",
        f"> {_pick(lang, _COMP['disclaimer_zh'], _COMP['disclaimer_en'])}",
    ]
    return "\n".join(lines)


def render_compliance_section(findings: list[dict], lang: str = "bi") -> str:
    """完整二级章节（测试与独立导出用；报告中通常复用 body）。"""
    _check_lang(lang)
    title = _pick(lang, "合规映射", "Compliance Mapping")
    return f"## {title}\n\n{render_compliance_body(findings, lang)}"
