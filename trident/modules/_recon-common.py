"""_recon_common — 侦察模块族共享库（仅标准库）。

职责：
- 快照装载：params.snapshot = dict（fixture 直传）或 str/Path（lab/fixtures/recon/*.json 路径）
- findings 构造：sev/title/detail + evidence/mapping/fix（与 runner.add_finding 字段对齐）
- 既有 recon 输出 TSV 直通：六列 severity/id/title/evidence/mapping/fix（首行可有可无表头）
- run(ctx, params) 胶水：params.findings_tsv 存在 → 直通转换；否则 snapshot → analyze(snapshot, params)

免 bash 依赖：模块全部为纯 Python 快照分析，测试封闭。
"""
from __future__ import annotations

import json
from pathlib import Path

SEVS = ("critical", "high", "medium", "low", "info")
TSV_COLUMNS = ("severity", "id", "title", "evidence", "mapping", "fix")


def load_snapshot(params: dict) -> dict:
    """params.snapshot 支持 dict 与 JSON 文件路径两种形态。"""
    snap = params.get("snapshot")
    if snap is None:
        raise ValueError("缺少 params.snapshot（fixture dict 或 lab/fixtures/recon/*.json 路径）")
    if isinstance(snap, dict):
        return snap
    return json.loads(Path(str(snap)).read_text(encoding="utf-8"))


def finding(sev: str, title: str, detail: str = "", evidence: str = "", mapping: str = "", fix: str = "", **extra) -> dict:
    if sev not in SEVS:
        sev = "info"
    item = {"sev": sev, "title": title, "detail": detail}
    if evidence:
        item["evidence"] = evidence
    if mapping:
        item["mapping"] = mapping
    if fix:
        item["fix"] = fix
    item.update(extra)
    return item


def findings_from_tsv(text: str) -> list[dict]:
    """既有 recon 工具输出 → findings（severity→sev、evidence→detail；未知 severity 降级 info）。"""
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    if not lines:
        return []
    first_cells = [c.strip() for c in lines[0].lstrip("#").split("\t")]
    if set(first_cells) & set(TSV_COLUMNS):
        header, lines = first_cells, lines[1:]
    else:
        header = list(TSV_COLUMNS)
    out: list[dict] = []
    for line in lines:
        cells = [c.strip() for c in line.split("\t")]
        row = dict(zip(header, cells))
        if not row.get("title"):
            continue
        item = finding(
            row.get("severity") or "info",
            row["title"],
            detail=row.get("evidence") or "",
            evidence=row.get("evidence") or "",
            mapping=row.get("mapping") or "",
            fix=row.get("fix") or "",
        )
        item["id"] = row.get("id") or ""
        out.append(item)
    return out


def run_recon(ctx: dict, params: dict, analyze, family: str = "侦察") -> dict:
    """侦察模块统一入口：TSV 直通优先，否则快照分析。返回 StepResult 形态 dict。"""
    tsv = params.get("findings_tsv")
    if tsv:
        findings = findings_from_tsv(str(tsv))
        return {
            "summary": f"{family} findings_tsv 直通：{len(findings)} 条（severity/id/title/evidence/mapping/fix）",
            "findings": findings,
            "artifacts": [],
        }
    snapshot = load_snapshot(params)
    findings = list(analyze(snapshot, params))
    src = params.get("snapshot")
    src_desc = src if isinstance(src, str) else "<inline snapshot>"
    rank = {s: i for i, s in enumerate(SEVS)}
    top = min((f.get("sev", "info") for f in findings), key=lambda s: rank.get(s, len(rank)), default="info")
    counts = {sev: sum(1 for f in findings if f.get("sev", "info") == sev) for sev in SEVS if any(f.get("sev", "info") == sev for f in findings)}
    return {
        "summary": f"{family}完成：{len(findings)} 条发现（最高 {top}；分布 {counts}；来源 {src_desc}）",
        "findings": findings,
        "artifacts": [],
    }
