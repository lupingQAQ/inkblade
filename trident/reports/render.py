"""报告引擎：中英双语渗透测试报告与修复报告渲染。

- PTES 七段 + 五个专节（组合层风险 / 训练数据泄露面 / 核心代码问题 / 网络分层威胁模型 / 混合云边界）
- 证据锚 = 步骤 + manifest.sha256 前 16 位（来自 run.findings 的 evidence_path 与 run 归档清单）
- 标准条款映射注入（NIST SP 800-115 计划-执行-后置 / 等保 2.0 GB/T 22239-2019 / GB/T 20984）
- 零日级细节默认展示（公开零日级模块）；redact_zeroday=True 时可选脱敏为
  「影响已验证 + 证据哈希（细节按合同分级）」，供未来真私有发现使用
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from string import Template
from typing import Any, Container

from . import cvss
from . import compliance
from .cvss import SEVERITY_CN

_DIR = Path(__file__).resolve().parent

# 严重度 → 默认修复优先级（无基线命中时的兜底）
_SEV_PRIORITY = {
    "critical": "immediate",
    "high": "immediate",
    "medium": "short",
    "low": "mid",
    "info": "mid",
}

# 风险评级章节中的官方示例向量（渲染时由本引擎现算，作为评分正确性样例）
_LEGEND_VECTORS = [
    "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
]


def _load(name: str) -> dict:
    with (_DIR / name).open(encoding="utf-8") as fh:
        return json.load(fh)


_GLOSSARY = _load("glossary.json")
_STANDARDS = _load("standards.json")
_BASELINE = _load("baseline.json")
_PENTEST_TMPL = Template((_DIR / "templates" / "pentest-cn-en.tmpl").read_text(encoding="utf-8"))
_REMEDIATION_TMPL = Template((_DIR / "templates" / "remediation-cn-en.tmpl").read_text(encoding="utf-8"))


def _pick(lang: str, zh: str, en: str) -> str:
    """按语言选取文案；bi = 中英对照（zh / en）。"""
    if lang == "zh":
        return zh
    if lang == "en":
        return en
    return f"{zh} / {en}"


def _cell(text: Any) -> str:
    """Markdown 表格单元格净化：竖线转义 + 换行折叠。"""
    return str(text).replace("|", "\\|").replace("\n", " ").strip()


def _check_lang(lang: str) -> None:
    if lang not in ("bi", "zh", "en"):
        raise ValueError(f"lang 必须为 bi/zh/en: {lang}")


def _manifest_sha_map(run) -> dict[str, str]:
    """读取 run 归档清单 manifest.sha256 → {相对路径: sha256}。"""
    mpath = run.dir / "manifest.sha256"
    out: dict[str, str] = {}
    if mpath.exists():
        for line in mpath.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            sha, _, rel = line.partition("  ")
            if rel:
                out[rel.strip()] = sha.strip()
    return out


def _sha16(sha_map: dict[str, str], evidence_path: str) -> str:
    sha = sha_map.get(evidence_path or "", "")
    return sha[:16] if sha else ""


def _redacted(lang: str, sha16: str) -> str:
    tag = sha16 or "N/A"
    return _pick(
        lang,
        f"影响已验证 + 证据哈希 {tag}（细节按合同分级）",
        f"Impact verified + evidence hash {tag} (details per contract tier)",
    )


def _is_redacted(finding: dict, disclosed: Container[str] | None, redact_zeroday: bool) -> bool:
    if not redact_zeroday or not finding.get("is_zeroday"):
        return False
    return not (disclosed is not None and finding.get("title") in disclosed)


def _meta_block(store, run, lang: str) -> dict[str, str]:
    ok = store.verify_manifest(run.name)
    zh_status = "通过" if ok else "未通过"
    en_status = "verified" if ok else "FAILED"
    return {
        "meta_run": _pick(lang, "运行 Run", "Run"),
        "meta_workspace": _pick(lang, "工作区 Workspace", "Workspace"),
        "meta_generated": _pick(lang, "生成时间 Generated", "Generated"),
        "meta_lang": _pick(lang, "语言 Lang", "Lang"),
        "run_name": run.name,
        "workspace": store.workspace,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "lang_label": {"bi": "中英对照 / Bilingual (CN/EN)", "zh": "中文 Chinese", "en": "English"}[lang],
        "tamper_decl": _pick(
            lang,
            f"报告不可篡改声明：本报告证据锚引用 run 目录 manifest.sha256 清单，生成时校验结果：{zh_status}。",
            f"Tamper-evident declaration: evidence anchors reference the run's manifest.sha256; verification at generation: {en_status}.",
        ),
        "footer_decl": _pick(
            lang,
            "Trident 双语报告引擎 · 证据三层（上下文摘要 / SQLite / tar+SHA256） · PTES / NIST SP 800-115 / GB/T 22239-2019 / GB/T 20984 / CVSS 3.1 · 合规：OWASP LLM/Agentic · MITRE ATLAS · NIST AI RMF · ISO/IEC 42001 · EU AI Act GPAI · TC260",
            "Trident bilingual report engine - three-layer evidence (context digest / SQLite / tar+SHA256) - PTES / NIST SP 800-115 / GB/T 22239-2019 / GB/T 20984 / CVSS 3.1 - compliance: OWASP LLM/Agentic, MITRE ATLAS, NIST AI RMF, ISO/IEC 42001, EU AI Act GPAI, TC260",
        ),
    }


# ---------- 表格构件 ----------

def _findings_table(run, lang: str, disclosed, sha_map: dict[str, str], redact_zeroday: bool) -> str:
    header = _pick(
        lang,
        "| 发现 | 严重度 | 习惯定级 | 零日 | 细节 | 证据锚 |",
        "| Finding | Severity | CN Grade | 0-day | Detail | Evidence Anchor |",
    )
    lines = [header, "|---|---|---|---|---|---|"]
    rows = run.findings
    if not rows:
        lines.append(_pick(lang, "|（无发现）| | | | | |", "| (no findings) | | | | | |"))
    for f in rows:
        sha16 = _sha16(sha_map, f.get("evidence_path", ""))
        anchor = (
            f"{f['step_key']} · sha256:{sha16}"
            if sha16
            else f"{f['step_key']} · " + _pick(lang, "证据缺失", "no archive")
        )
        detail = _redacted(lang, sha16) if _is_redacted(f, disclosed, redact_zeroday) else f.get("detail", "")
        sev = str(f.get("severity", ""))
        grade = SEVERITY_CN.get(sev, sev) if lang != "en" else sev
        zd = _pick(lang, "是", "Yes") if f.get("is_zeroday") else _pick(lang, "否", "No")
        lines.append(
            f"| {_cell(f['title'])} | {sev} | {grade} | {zd} | {_cell(detail)} | {_cell(anchor)} |"
        )
    return "\n".join(lines)


def _steps_table(run, lang: str) -> str:
    header = _pick(
        lang,
        "| 步骤 | 状态 | 结果摘要 | 归档 |",
        "| Step | Status | Result Summary | Archive |",
    )
    lines = [header, "|---|---|---|---|"]
    rows = run.query(
        "SELECT step_key, status, result_summary, archive FROM steps WHERE run=? ORDER BY id", (run.name,)
    )
    if not rows:
        lines.append(_pick(lang, "|（无步骤）| | | |", "| (no steps) | | | |"))
    for step_key, status, summary, archive in rows:
        lines.append(f"| {_cell(step_key)} | {_cell(status)} | {_cell(summary)} | {_cell(archive)} |")
    return "\n".join(lines)


def _network_layer_section(run, lang: str) -> str:
    """网络分层节的数据驱动部分：消费 graph_nodes/graph_edges（层级 + 判定方式）。

    空图时显式声明「未落图数据」，仅保留七层模型基线叙述，不臆造资产。
    """
    nodes = run.query(
        "SELECT node_id, kind, layer, attrs FROM graph_nodes ORDER BY layer, node_id")
    edges = run.query(
        "SELECT src, dst, verdict, method, chain FROM graph_edges ORDER BY src, dst")
    if not nodes and not edges:
        return _pick(
            lang,
            "**本 run 未落图数据**（`graph_nodes`/`graph_edges` 为空）：上表为七层模型基线，"
            "不对资产归属与可达性作推断；接入侦察模块或可达性图后本节自动填充。",
            "**No graph data recorded for this run** (`graph_nodes`/`graph_edges` empty): the "
            "paragraph above is the seven-layer baseline only; no asset or reachability "
            "inference is made. Populate the graph via recon/reachability modules to fill this section.",
        )

    layer_counts: dict[str, list[str]] = {}
    for node_id, _kind, layer, _attrs in nodes:
        layer_counts.setdefault(layer or _pick(lang, "未分层", "unlayered"), []).append(node_id)

    lines: list[str] = [_pick(lang,
                              "### 分层节点（数据驱动：`graph_nodes.layer`）",
                              "### Layered nodes (data-driven: `graph_nodes.layer`)")]
    lines.append(_pick(lang, "| 层 | 节点数 | 节点样例 |", "| Layer | Nodes | Examples |"))
    lines.append("|---|---:|---|")
    for layer in sorted(layer_counts):
        ids = layer_counts[layer]
        sample = ", ".join(ids[:5]) + (" …" if len(ids) > 5 else "")
        lines.append(f"| {_cell(layer)} | {len(ids)} | {_cell(sample)} |")

    lines.append("")
    lines.append(_pick(lang,
                       "### 跨层边与判定方式（数据驱动：`graph_edges.method`）",
                       "### Cross-layer edges and verdict methods (data-driven: `graph_edges.method`)"))
    lines.append(_pick(lang,
                       "| 源 | 目标 | 判定 | 判定方式 | 链 |",
                       "| Source | Target | Verdict | Method | Chain |"))
    lines.append("|---|---|---|---|---|")
    if not edges:
        lines.append(_pick(lang, "|（无图边）| | | | |", "| (no edges) | | | | |"))
    for src, dst, verdict, method, chain in edges:
        lines.append(f"| {_cell(src)} | {_cell(dst)} | {_cell(verdict)} | "
                     f"{_cell(method)} | {_cell(chain or '—')} |")

    verdict_counts: dict[str, int] = {}
    method_set: set[str] = set()
    for _src, _dst, verdict, method, _chain in edges:
        verdict_counts[verdict or "unknown"] = verdict_counts.get(verdict or "unknown", 0) + 1
        if method:
            method_set.add(method)
    lines.append("")
    lines.append(_pick(lang, "**判定分布**", "**Verdict distribution**"))
    lines.append("")
    lines.append(_pick(lang, "| 判定 | 数量 |", "| Verdict | Count |"))
    lines.append("|---|---:|")
    for verdict in sorted(verdict_counts):
        lines.append(f"| {_cell(verdict)} | {verdict_counts[verdict]} |")
    lines.append("")
    lines.append(_pick(
        lang,
        f"判定方式口径：共 {len(method_set)} 类（{_cell('、'.join(sorted(method_set)) or '—')}）；"
        "`CNI 语义推演`=按 NetworkPolicy/命名空间/端口语义静态推演，"
        "`实测`=运行期 HTTP/连接探测，`静态规则`=清单与策略规则匹配。",
        f"Verdict-method legend: {len(method_set)} kind(s) "
        f"({_cell(', '.join(sorted(method_set)) or '—')}); `CNI 语义推演`=static semantics over "
        "NetworkPolicy/namespace/port, `实测`=runtime probe, `静态规则`=manifest/policy matching.",
    ))
    return "\n".join(lines)


def _combo_table(run, lang: str) -> str:
    header = _pick(lang, "| 组合签名 | 详情 |", "| Combination Signature | Detail |")
    lines = [header, "|---|---|"]
    rows = run.query("SELECT signature, detail FROM combos WHERE run=? ORDER BY id", (run.name,))
    if not rows:
        lines.append(_pick(lang, "|（无组合命中）| |", "| (no combination hits) | |"))
    for signature, detail in rows:
        lines.append(f"| {_cell(signature)} | {_cell(detail)} |")
    return "\n".join(lines)


def _cvss_legend(lang: str) -> str:
    lines = [
        _pick(
            lang,
            "CVSS 3.1 评分示例（官方示例向量，本引擎实时计算）：",
            "CVSS 3.1 scored examples (official example vectors, computed live by this engine):",
        )
    ]
    for vec in _LEGEND_VECTORS:
        score = cvss.base_score(vec)
        grade = _pick(lang, cvss.cn_grade(score), cvss.severity_band(score).capitalize())
        lines.append(f"- `{vec}` → **{score:.1f}**（{grade}）")
    lines.append(
        _pick(
            lang,
            "分级带（CNVD/CNNVD 习惯定级）：低危 0.1–3.9 · 中危 4.0–6.9 · 高危 7.0–8.9 · 超危 9.0–10.0；GB/T 20984 按资产—威胁—脆弱性三要素计算高/中/低。",
            "Bands (CNVD/CNNVD convention): Low 0.1-3.9, Medium 4.0-6.9, High 7.0-8.9, Critical 9.0-10.0; GB/T 20984 computes High/Medium/Low from asset-threat-vulnerability factors.",
        )
    )
    return "\n".join(lines)


def _nist_table(lang: str) -> str:
    header = _pick(lang, "| PTES 段落 | NIST 阶段 | NIST 引用 |", "| PTES Stage | NIST Phase | NIST Reference |")
    lines = [header, "|---|---|---|"]
    for s in _STANDARDS["ptes"]:
        lines.append(
            f"| {_cell(_pick(lang, s['zh'], s['en']))} | "
            f"{_cell(_pick(lang, s['nist_phase_zh'], s['nist_phase_en']))} | {_cell(s['nist_ref'])} |"
        )
    return "\n".join(lines)


def _djbh_table(lang: str) -> str:
    header = _pick(lang, "| 条款 | 条款名称 | 关联发现类别 |", "| Clause | Clause Name | Finding Category |")
    lines = [header, "|---|---|---|"]
    for c in _STANDARDS["djbh"]:
        lines.append(
            f"| {_cell(c['clause'])} | {_cell(_pick(lang, c['zh'], c['en']))} | {_cell(c['maps'])} |"
        )
    return "\n".join(lines)


def _glossary_table(lang: str) -> str:
    header = _pick(lang, "| 中文 | English | 说明 |", "| Chinese | English | Note |")
    lines = [header, "|---|---|---|"]
    for t in _GLOSSARY["terms"]:
        note = _pick(lang, t.get("note_zh", ""), t.get("note_en", ""))
        lines.append(f"| {t['zh']} | {t['en']} | {_cell(note)} |")
    return "\n".join(lines)


# ---------- 渗透测试报告 ----------

def render_pentest(
    store,
    run_name: str,
    lang: str = "bi",
    disclosed: Container[str] | None = None,
    *,
    redact_zeroday: bool = False,
) -> str:
    """渲染双语渗透测试报告（Markdown）。

    默认展示全部发现细节（含已公开零日级模块）。``redact_zeroday=True`` 时对
    is_zeroday 发现启用可选脱敏；``disclosed`` 内的标题视为已披露并恢复细节。
    """
    _check_lang(lang)
    run = store.open_run(run_name)
    sha_map = _manifest_sha_map(run)
    ptes = {s["key"]: s for s in _STANDARDS["ptes"]}
    special = {s["key"]: s for s in _STANDARDS["special"]}
    phases = _STANDARDS["nist"]["phases"]

    mapping: dict[str, str] = {"main_title": _pick(lang, "渗透测试报告（中英双语）", "Penetration Test Report (Bilingual)")}
    mapping.update(_meta_block(store, run, lang))
    for key in ("scope", "intel", "threat-model", "vuln-analysis", "exploitation", "post-exploit", "risk-rating"):
        s = ptes[key]
        mapping[f"title_{key.replace('-', '_')}"] = _pick(lang, s["zh"], s["en"])
        mapping[f"body_{key.replace('-', '_')}"] = _pick(lang, s["zh_body"], s["en_body"])
    for key in ("combo-risk", "training-data-leak", "core-code", "network-threat-model", "hybrid-cloud-boundary"):
        s = special[key]
        safe = key.replace("-", "_")
        mapping[f"title_{safe}"] = _pick(lang, s["zh"], s["en"])
        mapping[f"body_{safe}"] = _pick(lang, s["zh_body"], s["en_body"])
    mapping["title_special_intro"] = _pick(lang, "专节 Special Sections", "Special Sections")
    mapping["body_special_intro"] = _pick(
        lang,
        "以下专节为 ML 训练/推理集群检测焦点（设计基线第 8 节），独立于 PTES 七段成节。",
        "The following sections are ML training/inference cluster detection focus areas (design baseline section 8), kept as standalone sections alongside the PTES stages.",
    )
    # 模板占位符使用短名（combo / data_leak / network_tm / hybrid）
    mapping["title_combo"] = mapping.pop("title_combo_risk")
    mapping["body_combo"] = mapping.pop("body_combo_risk")
    mapping["title_data_leak"] = mapping.pop("title_training_data_leak")
    mapping["body_data_leak"] = mapping.pop("body_training_data_leak")
    mapping["title_network_tm"] = mapping.pop("title_network_threat_model")
    mapping["body_network_tm"] = (
        mapping.pop("body_network_threat_model")
        + "\n\n"
        + _network_layer_section(run, lang)
    )
    mapping["title_hybrid"] = mapping.pop("title_hybrid_cloud_boundary")
    mapping["body_hybrid"] = mapping.pop("body_hybrid_cloud_boundary")
    mapping["findings_table"] = _findings_table(run, lang, disclosed, sha_map, redact_zeroday)
    mapping["steps_table"] = _steps_table(run, lang)
    mapping["combo_table"] = _combo_table(run, lang)
    mapping["cvss_legend"] = _cvss_legend(lang)
    mapping["title_standards"] = _pick(lang, "标准条款映射 Standards Mapping", "Standards Mapping")
    mapping["nist_intro"] = _pick(lang, _STANDARDS["nist"]["intro_zh"], _STANDARDS["nist"]["intro_en"])
    mapping["nist_table"] = _nist_table(lang)
    mapping["djbh_intro"] = _pick(lang, _STANDARDS["djbh_intro_zh"], _STANDARDS["djbh_intro_en"])
    mapping["djbh_table"] = _djbh_table(lang)
    mapping["title_compliance"] = _pick(lang, "合规映射", "Compliance Mapping")
    mapping["body_compliance"] = compliance.render_compliance_body(run.findings, lang)
    mapping["title_glossary"] = _pick(lang, "术语表 Glossary", "Glossary")
    mapping["glossary_table"] = _glossary_table(lang)
    return _PENTEST_TMPL.substitute(mapping)


# ---------- 修复报告 ----------

def _priority_label(key: str, lang: str) -> str:
    p = next(p for p in _BASELINE["priorities"] if p["key"] == key)
    if lang == "bi":
        return f"{p['zh']} · {p['en']}"
    return _pick(lang, p["zh"], p["en"])


def _priority_window(key: str, lang: str) -> str:
    p = next(p for p in _BASELINE["priorities"] if p["key"] == key)
    return _pick(lang, p["window_zh"], p["window_en"])


def _entry_line(e: dict, lang: str) -> str:
    title = _pick(lang, e["title"]["zh"], e["title"]["en"])
    rem = _pick(lang, e["remediation"]["zh"], e["remediation"]["en"])
    refs = ", ".join(e.get("refs", []))
    label = _pick(lang, "规则包参考", "rule pack refs")
    tail = f"（{label}: {refs}）" if refs else ""
    return f"- **{title}**：{rem}{tail}"


def _match_entries(finding: dict) -> list[dict]:
    hay = f"{finding.get('title', '')} {finding.get('step_key', '')}".lower()
    hits = [
        e for e in _BASELINE["entries"]
        if e.get("tags") and any(t.lower() in hay for t in e["tags"])
    ]
    if hits:
        return hits
    prio = _SEV_PRIORITY.get(str(finding.get("severity", "")).lower(), "mid")
    return [e for e in _BASELINE["entries"] if e.get("default_for") == prio]


def _findings_recs(run, lang: str, disclosed, sha_map: dict[str, str], redact_zeroday: bool) -> str:
    header = _pick(
        lang,
        "| 发现 | 严重度 | 优先级 | 细节 | 修复建议（基线命中） |",
        "| Finding | Severity | Priority | Detail | Remediation (baseline hits) |",
    )
    lines = [header, "|---|---|---|---|---|"]
    rows = run.findings
    if not rows:
        lines.append(_pick(lang, "|（无发现）| | | | |", "| (no findings) | | | | |"))
    for f in rows:
        sha16 = _sha16(sha_map, f.get("evidence_path", ""))
        detail = _redacted(lang, sha16) if _is_redacted(f, disclosed, redact_zeroday) else f.get("detail", "")
        hits = _match_entries(f)
        prio = hits[0]["priority"] if hits else "mid"
        recs = "；".join(_pick(lang, h["title"]["zh"], h["title"]["en"]) for h in hits) or "—"
        lines.append(
            f"| {_cell(f['title'])} | {f.get('severity', '')} | {_priority_label(prio, lang)} "
            f"| {_cell(detail)} | {_cell(recs)} |"
        )
    return "\n".join(lines)


def render_remediation(
    store,
    run_name: str,
    lang: str = "bi",
    disclosed: Container[str] | None = None,
    *,
    redact_zeroday: bool = False,
) -> str:
    """渲染双语修复报告（修复基线优先级分组 + 逐发现建议 + 复测计划）。

    默认展示全部发现细节；``redact_zeroday=True`` 时对 is_zeroday 发现启用可选脱敏。
    """
    _check_lang(lang)
    run = store.open_run(run_name)
    sha_map = _manifest_sha_map(run)
    findings = run.findings
    zd_count = sum(1 for f in findings if f.get("is_zeroday"))

    groups: dict[str, list[dict]] = {"immediate": [], "short": [], "mid": []}
    for e in _BASELINE["entries"]:
        if not e.get("default_for"):  # 兜底项不占章节正文，仅在无命中时出现于逐发现建议
            groups[e["priority"]].append(e)

    matched_ids: set[str] = set()
    for f in findings:
        matched_ids.update(e["id"] for e in _match_entries(f))

    mapping: dict[str, str] = {"main_title": _pick(lang, "修复报告（中英双语）", "Remediation Report (Bilingual)")}
    mapping.update(_meta_block(store, run, lang))
    mapping["title_summary"] = _pick(lang, "执行摘要 Executive Summary", "Executive Summary")
    mapping["body_summary"] = _pick(
        lang,
        "本报告与渗透测试报告同批交付，给出按优先级（立即/短期/中期）组织的修复建议、逐发现基线命中与复测计划；防御规则包随本报告一并交付（规则↔攻击映射见规则视图）。",
        "Delivered together with the penetration test report: prioritized remediation (immediate/short-term/mid-term), per-finding baseline hits and a retest plan; the defense rule pack ships alongside (rule-to-attack mapping in the rules view).",
    )
    zd_note_zh = "细节已按合同分级脱敏" if redact_zeroday else "细节默认展示（已公开零日级模块）"
    zd_note_en = (
        "redacted per contract tier"
        if redact_zeroday
        else "details shown by default (public zero-day-class modules)"
    )
    mapping["summary_stats"] = _pick(
        lang,
        f"发现共 {len(findings)} 项（零日级 {zd_count} 项，{zd_note_zh}）；修复基线命中 {len(matched_ids)} 条；建议分布：立即 {len(groups['immediate'])} · 短期 {len(groups['short'])} · 中期 {len(groups['mid'])}。",
        f"{len(findings)} findings ({zd_count} zero-day-class, {zd_note_en}); {len(matched_ids)} baseline entries matched; suggestions: immediate {len(groups['immediate'])}, short-term {len(groups['short'])}, mid-term {len(groups['mid'])}.",
    )
    mapping["title_priorities"] = _pick(lang, "修复建议（按优先级）Remediation by Priority", "Remediation by Priority")
    for key in ("immediate", "short", "mid"):
        label = _priority_label(key, lang)
        window = _priority_window(key, lang)
        safe = {"immediate": "immediate", "short": "short", "mid": "mid"}[key]
        mapping[f"p_{safe}_title"] = f"{label} — {window}"
        body = [ _entry_line(e, lang) for e in groups[key] ] or [
            _pick(lang, "-（本章无条目）", "- (no entries)")
        ]
        if key == "immediate":
            mapping["rem_immediate"] = "\n".join(body)
        elif key == "short":
            mapping["rem_short"] = "\n".join(body)
        else:
            mapping["rem_mid"] = "\n".join(body)
    mapping["title_finding_recs"] = _pick(lang, "逐发现修复建议 Per-Finding Remediation", "Per-Finding Remediation")
    mapping["body_finding_recs"] = _pick(
        lang,
        "每项发现按标题/步骤匹配修复基线库；未命中时按严重度兜底到对应优先级通用建议。",
        "Each finding is matched against the baseline library by title/step; unmatched findings fall back to severity-mapped generic advice.",
    )
    mapping["finding_recs"] = _findings_recs(run, lang, disclosed, sha_map, redact_zeroday)
    mapping["title_retest"] = _pick(lang, "复测计划 Retest Plan", "Retest Plan")
    mapping["body_retest"] = _pick(
        lang,
        "修复完成后按同参数重放对应攻击链（先 dry-run 预览写面），并运行 `trident rules validate` 做紫队验证输出覆盖率矩阵；零日级发现细节默认展示，如启用可选脱敏开关则按合同分级开放细节后在授权窗口内复测。",
        "After fixes, replay the same chains with identical parameters (dry-run first to preview writes) and run `trident rules validate` for purple-team coverage; zero-day-class details are shown by default, and when the optional redaction switch is enabled, retest inside the authorized window once details are released per contract tier.",
    )
    mapping["retest_steps"] = "\n".join([
        _pick(lang, "1. 立即项修复后 72 小时内完成验证（管理面隔离 + RBAC 收敛 + 凭据轮换）。", "1. Verify immediate items within 72 hours of fix (management-plane isolation + RBAC scope-down + credential rotation)."),
        _pick(lang, "2. 规则包部署并紫队验证，输出规则↔攻击覆盖率矩阵。", "2. Deploy the rule pack and validate purple-team style, producing the rule-to-attack coverage matrix."),
        _pick(lang, "3. 短期/中期项在窗口期末统一复测，重出双语报告对比。", "3. Re-test short/mid-term items at the end of each window and regenerate bilingual reports for comparison."),
    ])
    mapping["title_compliance"] = _pick(lang, "合规映射", "Compliance Mapping")
    mapping["body_compliance"] = compliance.render_compliance_body(run.findings, lang)
    mapping["title_glossary"] = _pick(lang, "术语表 Glossary", "Glossary")
    mapping["glossary_table"] = _glossary_table(lang)
    return _REMEDIATION_TMPL.substitute(mapping)
