# -*- coding: utf-8 -*-
"""2026 agent 架构研究与差距反思：语料完整性 / 文档章节 / 落伍点证据 / 蓝图要点。

锁定四件事：
1. corpus/agent-2026 至少 18 条来源，每条含「来源/核验/架构要素/对我们的启示」；
2. docs/AGENT-ARCHITECTURE-2026.md 含谱系、落伍反思、设计点清单、蓝图、竞品差异五章；
3. 每条落伍点都给出可解析的仓库内证据 `path:line[-line]`，且文件/行号真实存在；
4. 设计点 ≥12 且带 P0/P1/P2 优先级；蓝图覆盖 supervisor/队列/journal/记忆/技能/沙箱/评测/协议。
"""

import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CORPUS = REPO / "corpus" / "agent-2026"
DOC = REPO / "docs" / "AGENT-ARCHITECTURE-2026.md"
PROGRESS = REPO / "progress.md"

CORPUS_SECTIONS = ("## 来源", "## 核验", "## 架构要素", "## 对我们的启示")
DOC_SECTIONS = ("谱系", "为什么落伍", "还没用上的设计点", "升级蓝图", "与 ARTEX", "差异")
BLUEPRINT_TERMS = ("Supervisor", "Worker", "任务队列", "Journal", "三层记忆",
                   "技能库", "Reflexion", "A2A", "MCP", "沙箱", "评测")

# `trident/core/explorer.py:159-200` → (path, start, end)
EVIDENCE_RE = re.compile(r"`([A-Za-z0-9_./-]+\.(?:py|md|json)):(\d+)(?:-(\d+))?`")


def _corpus_files() -> list[Path]:
    if not CORPUS.is_dir():
        return []
    return sorted(p for p in CORPUS.glob("*.md") if p.is_file())


def _doc_text() -> str:
    return DOC.read_text(encoding="utf-8") if DOC.is_file() else ""


def _table_rows(text: str, first_cell_prefix: str) -> list[list[str]]:
    """抓取首列以给定前缀开头的 Markdown 表格行（按 `|` 切分）。"""
    rows: list[list[str]] = []
    for line in text.splitlines():
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if cells and cells[0].startswith(first_cell_prefix):
            rows.append(cells)
    return rows


def _line_count(path: Path) -> int:
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        return sum(1 for _ in fh)


class TestAgentCorpus(unittest.TestCase):
    def test_corpus_has_at_least_18_sources(self):
        files = _corpus_files()
        self.assertGreaterEqual(len(files), 18, f"语料不足: {len(files)}")

    def test_each_source_has_required_sections_and_date(self):
        for path in _corpus_files():
            text = path.read_text(encoding="utf-8")
            for section in CORPUS_SECTIONS:
                self.assertIn(section, text, f"{path.name} 缺章节 {section}")
            self.assertIn("2026-10", text, f"{path.name} 缺核验日期")
            self.assertRegex(text, r"https?://", f"{path.name} 缺来源 URL")
            self.assertIn("核验状态", text, f"{path.name} 缺核验状态")

    def test_blocked_sources_are_marked_not_used(self):
        blocked = [p for p in _corpus_files()
                   if "核验状态：**blocked**" in p.read_text(encoding="utf-8")
                   or "核验状态:**blocked**" in p.read_text(encoding="utf-8")]
        self.assertGreaterEqual(len(blocked), 1)
        for path in blocked:
            self.assertIn("不引用", path.read_text(encoding="utf-8"), path.name)


class TestAgentDoc(unittest.TestCase):
    def test_doc_exists_and_has_five_chapters(self):
        self.assertTrue(DOC.is_file(), "缺少 docs/AGENT-ARCHITECTURE-2026.md")
        text = _doc_text()
        for term in DOC_SECTIONS:
            self.assertIn(term, text, f"文档缺章节关键词: {term}")

    def test_gap_count_and_evidence_refs(self):
        rows = _table_rows(_doc_text(), "**G")
        self.assertGreaterEqual(len(rows), 10, f"落伍点不足: {len(rows)}")
        seen: set[str] = set()
        for cells in rows:
            row_text = " | ".join(cells)
            gap_id = re.search(r"G\d{2}", cells[0])
            self.assertIsNotNone(gap_id, row_text)
            seen.add(gap_id.group(0))
            refs = EVIDENCE_RE.findall(row_text)
            self.assertTrue(refs, f"{gap_id.group(0)} 缺 `path:line` 证据: {row_text}")
            for rel, start, end in refs:
                target = REPO / rel
                self.assertTrue(target.is_file(), f"{gap_id.group(0)} 引用不存在文件: {rel}")
                total = _line_count(target)
                self.assertLessEqual(int(start), total, f"{rel}:{start} 超出文件行数 {total}")
                if end:
                    self.assertLessEqual(int(end), total, f"{rel}:{end} 超出文件行数 {total}")
                    self.assertGreaterEqual(int(end), int(start), f"{rel} 行号区间倒置")
        self.assertGreaterEqual(len(seen), 10, f"落伍点 ID 去重后不足: {seen}")

    def test_design_points_have_priority_and_benefit(self):
        rows = _table_rows(_doc_text(), "**A")
        self.assertGreaterEqual(len(rows), 12, f"设计点不足: {len(rows)}")
        for cells in rows:
            self.assertGreaterEqual(len(cells), 6, f"设计点列数不足: {cells}")
            self.assertRegex(cells[2], r"^\*{0,2}P[012]\*{0,2}$", f"优先级非法: {cells}")
            self.assertTrue(cells[4], f"缺预期收益: {cells}")

    def test_blueprint_covers_required_components(self):
        text = _doc_text()
        for term in BLUEPRINT_TERMS:
            self.assertIn(term, text, f"蓝图缺组件: {term}")
        for phase in ("M0", "M1", "M2", "M3"):
            self.assertIn(phase, text, f"蓝图缺阶段: {phase}")
        self.assertIn("不变量", text)

    def test_doc_cites_at_least_18_corpus_entries(self):
        cited = set(re.findall(r"corpus/agent-2026/([a-z0-9-]+)\.md", _doc_text()))
        self.assertGreaterEqual(len(cited), 18, f"文档引用语料不足: {sorted(cited)}")
        for cid in cited:
            self.assertTrue((CORPUS / f"{cid}.md").is_file(), f"引用了不存在的语料: {cid}")

    def test_progress_logged(self):
        text = PROGRESS.read_text(encoding="utf-8", errors="replace")
        self.assertIn("AGENT-ARCHITECTURE-2026", text)


if __name__ == "__main__":
    unittest.main()
