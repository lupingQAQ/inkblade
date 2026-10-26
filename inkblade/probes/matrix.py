"""inkblade/probes/matrix.py — 「LLM 探针矩阵」产物与报告节渲染。

- render_matrix_section(matrix, lang)：报告节（双语，嵌入渗透测试报告「LLM 探针矩阵」）；
- render_matrix_doc(matrix)：独立 MD 文档（顶部加标题与对比口径来源）；
- 渲染原则与报告引擎一致：无数据不臆造，逐类别给出 探针数/confirmed/判定分布/规则键/
  OWASP LLM 2026 + ASI 映射，并标注与 garak/PyRIT/promptfoo 的对比口径来源（docs/PROBE-PARITY.md）。
"""
from __future__ import annotations

import json
from pathlib import Path

MATRIX_FILENAME = "llm-probe-matrix.json"

_VERDICT_LABEL = {
    "confirmed": "符合预期差分",
    "not-vulnerable": "两态均未命中",
    "not-differential": "两态均命中（非差分）",
    "unexpected": "反向差分（仅 fixed 命中）",
}


def _pick(lang: str, zh: str, en: str) -> str:
    if lang == "zh":
        return zh
    if lang == "en":
        return en
    return f"{zh} · {en}"


def _cell(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")[:120]


def _category_rows(matrix: dict, lang: str) -> list[str]:
    # 表格是严格列结构：bi 模式不能把中英文表头拼进同一行（列数翻倍错位）；
    # 双语标题放在单元格内（_pick），英文摘要由 render_matrix_section 段落承担。
    header_lang = "zh" if lang == "bi" else lang
    header = _pick(header_lang,
                   "| 类别 | 探针数 | confirmed | 漏报口径（未 confirmed） | OWASP LLM 2026 | ASI | 检测规则 |",
                   "| Category | Probes | Confirmed | Non-confirmed | OWASP LLM 2026 | ASI | Detection rule |")
    lines = [header, "|---|---:|---:|---|---|---|---|"]
    for cat, meta in matrix.get("categories", {}).items():
        probes = [matrix["probes"][k] for k in meta["probes"]]
        confirmed = sum(1 for p in probes if p["verdict"] == "confirmed")
        bad = [k for k in meta["probes"] if matrix["probes"][k]["verdict"] != "confirmed"]
        title = _pick(lang, meta["title"]["zh"], meta["title"]["en"])
        lines.append(
            f"| {_cell(title)} (`{cat}`) | {len(probes)} | {confirmed} "
            f"| {_cell(', '.join(bad) or '—')} "
            f"| {', '.join(meta['owasp'])} | {', '.join(meta['asi'])} "
            f"| `{probes[0]['rule_key']}` |"
        )
    return lines


def render_matrix_section(matrix: dict, lang: str = "bi") -> str:
    """渲染「LLM 探针矩阵」节（供报告嵌入）。"""
    s = matrix.get("summary") or {}
    probes: dict = matrix.get("probes") or {}
    if not probes:
        return _pick(lang, "**无探针矩阵数据**。", "**No probe matrix data.**")
    lines = [
        _pick(lang,
              f"共 **{s.get('total', 0)}** 个探针 / **{s.get('categories', 0)}** 类，"
              f"对 lab 两态靶场（vulnerable/fixed）真实 HTTP 差分："
              f"confirmed={s.get('confirmed', 0)}"
              f"（攻击命中 {s.get('attack_confirmed', 0)} + 对照不误报 {s.get('controls_clean', 0)}），"
              f"判定分布 {json.dumps(s.get('verdicts', {}), ensure_ascii=False)}。"
              "分类映射 OWASP LLM Top 10 2026（LLM01–LLM10）与 OWASP Agentic AI（ASI01–ASI10）；"
              "每类 ≥1 条 SOC 检测规则键（规则包 sigma/llm-probe-*）。",
              f"**{s.get('total', 0)}** probes across **{s.get('categories', 0)}** categories, "
              "differentially executed against the vulnerable/fixed lab faces over real HTTP: "
              f"confirmed={s.get('confirmed', 0)} "
              f"(attack hits {s.get('attack_confirmed', 0)} + clean controls {s.get('controls_clean', 0)}), "
              f"verdicts {json.dumps(s.get('verdicts', {}), ensure_ascii=False)}. "
              "Taxonomy maps OWASP LLM Top 10 2026 (LLM01-LLM10) and OWASP Agentic AI (ASI01-ASI10); "
              "every category links to at least one SOC detection rule (sigma/llm-probe-*)."),
        "",
    ]
    lines.extend(_category_rows(matrix, lang))
    sev = {}
    face_dist = {}
    for p in probes.values():
        sev[p["severity"]] = sev.get(p["severity"], 0) + 1
        face_dist[p["face"]] = face_dist.get(p["face"], 0) + 1
    lines.append("")
    lines.append(_pick(
        lang,
        f"严重度分布 {json.dumps(sev, ensure_ascii=False)}；"
        f"目标面分布 {json.dumps(face_dist, ensure_ascii=False)}；"
        f"关联规则键 {s.get('rules_linked', 0)} 条。"
        "与 garak/PyRIT/promptfoo 的逐类对照（含计数口径与核验日期）见 `docs/PROBE-PARITY.md`。",
        f"Severity distribution {json.dumps(sev, ensure_ascii=False)}; "
        f"face distribution {json.dumps(face_dist, ensure_ascii=False)}; "
        f"{s.get('rules_linked', 0)} linked rule keys. "
        "Per-category parity with garak/PyRIT/promptfoo (counts and verification date) is in `docs/PROBE-PARITY.md`.",
    ))
    return "\n".join(lines)


def render_matrix_doc(matrix: dict, lang: str = "bi") -> str:
    """独立 MD 文档（含标题头）。"""
    head = _pick(lang, "# LLM 探针矩阵（两态差分）", "# LLM Probe Matrix (two-state differential)")
    return head + "\n\n" + render_matrix_section(matrix, lang) + "\n"


def section_for_run(run_dir: Path | str, lang: str = "bi") -> str:
    """报告集成：读 run 目录下的矩阵产物；缺产物时显式占位（不臆造数据）。"""
    path = Path(run_dir) / MATRIX_FILENAME
    if not path.is_file():
        return _pick(
            lang,
            "**本 run 未执行 LLM 探针矩阵**（未运行 `python inkblade/probes/run.py`）。"
            "本节不臆造探针命中结论。",
            "**No LLM probe matrix executed for this run** (`python inkblade/probes/run.py` "
            "was not run). No probe-hit claims are invented here.",
        )
    matrix = json.loads(path.read_text(encoding="utf-8"))
    return render_matrix_section(matrix, lang)


__all__ = ["MATRIX_FILENAME", "render_matrix_section", "render_matrix_doc", "section_for_run"]
