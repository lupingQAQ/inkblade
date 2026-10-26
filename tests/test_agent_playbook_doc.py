# -*- coding: utf-8 -*-
"""tests/test_agent_playbook_doc.py — 商用 Agent 设计手册的结构与证据断言。

这不是文风测试，而是防止手册退化成“正确但没用”的散文：
- 必须有 10 章，每章都有「概念 / 为什么 / 怎么做 / 反例与坑 / 可复用清单」；
- 每章至少引用 4 个本项目真实代码锚（``path.py::symbol``），且文件与符号必须存在；
- 附录必须有 30 条决策、20 条反模式、术语表、逐章代码索引；
- 关键实测数字必须落文，且不允许 TODO/TBD/待补 之类占位符。
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "HOW-TO-DESIGN-COMMERCIAL-AGENT.md"

CHAPTERS = list("一二三四五六七八九十")
LABELS = ("**概念。**", "**为什么。**", "**怎么做。**", "**反例与坑。**", "**可复用清单。**")
CODE_REF = re.compile(r"(inkblade/[A-Za-z0-9_./-]+\.py)::([A-Za-z_][A-Za-z0-9_.]*)")


class AgentPlaybookDocTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        assert DOC.is_file(), f"缺少商用 Agent 设计手册: {DOC}"
        cls.text = DOC.read_text(encoding="utf-8")

    def section(self, start_marker, end_marker):
        start = self.text.index(start_marker)
        end = self.text.index(end_marker, start)
        return self.text[start:end]

    def chapters(self):
        matches = list(re.finditer(r"^## ([一二三四五六七八九十]+)、(.+)$", self.text, re.M))
        self.assertEqual([m.group(1) for m in matches], CHAPTERS,
                         f"章节不是十个中文数字: {[m.group(1) for m in matches]}")
        out = []
        for i, match in enumerate(matches):
            end = matches[i + 1].start() if i + 1 < len(matches) else self.text.index("## 附录 A")
            out.append((match.group(1), self.text[match.start():end]))
        return out

    def test_exists_and_long_enough(self):
        self.assertGreaterEqual(len(self.text), 12000, "手册不足 12000 字符")
        cjk = len(re.findall(r"[\u4e00-\u9fff]", self.text))
        self.assertGreaterEqual(cjk, 9000, f"中文字符不足 9000（当前 {cjk}）")

    def test_ten_chapters_with_five_sections(self):
        chapters = self.chapters()
        self.assertEqual(len(chapters), 10)
        for number, body in chapters:
            self.assertGreaterEqual(len(body), 1200, f"第 {number} 章过短（{len(body)} 字符）")
            for label in LABELS:
                self.assertEqual(body.count(label), 1, f"第 {number} 章缺少或重复 {label}")

    def test_each_chapter_has_real_code_anchors(self):
        for number, body in self.chapters():
            refs = CODE_REF.findall(body)
            self.assertGreaterEqual(len(refs), 4, f"第 {number} 章代码锚少于 4 个: {refs}")
            for rel, symbol in refs:
                path = ROOT / rel
                self.assertTrue(path.is_file(), f"第 {number} 章引用了不存在的文件: {rel}")
                source = path.read_text(encoding="utf-8")
                leaf = symbol.split(".")[-1]
                self.assertIn(leaf, source, f"{rel} 中找不到符号 {symbol}")

    def test_chapter_code_index(self):
        for number, body in self.chapters():
            self.assertIn("**本章代码索引**", body, f"第 {number} 章缺少本章代码索引")
        index = self.section("## 附录 D", "## 附录 E")
        rows = [line for line in index.splitlines()
                if line.startswith("|") and "---" not in line][1:]
        self.assertEqual(len(rows), 10, f"逐章代码索引应为 10 行，当前 {len(rows)}")
        for number in CHAPTERS:
            self.assertIn(f"第{number}章", index, f"逐章索引缺少第{number}章")

    def test_decision_checklist_has_30_items(self):
        sec = self.section("## 附录 A", "## 附录 B")
        ids = re.findall(r"^\|\s*(D\d{2})\s*\|", sec, re.M)
        self.assertEqual(len(ids), 30, f"决策清单应为 30 条，当前 {len(ids)}")
        self.assertEqual(ids, [f"D{i:02d}" for i in range(1, 31)])

    def test_antipatterns_have_20_items(self):
        sec = self.section("## 附录 B", "## 附录 C")
        ids = re.findall(r"^\|\s*(AP\d{2})\s*\|", sec, re.M)
        self.assertEqual(len(ids), 20, f"反模式应为 20 条，当前 {len(ids)}")
        self.assertEqual(ids, [f"AP{i:02d}" for i in range(1, 21)])

    def test_glossary_has_enough_terms(self):
        sec = self.section("## 附录 C", "## 附录 D")
        rows = [line for line in sec.splitlines()
                if line.startswith("|") and "---" not in line][1:]
        self.assertGreaterEqual(len(rows), 30, f"术语表少于 30 条（当前 {len(rows)}）")
        for term in ("Agent", "ReAct", "Durable", "Journal", "Checkpoint", "幂等",
                     "MCP", "A2A", "AGPL", "Apache-2.0", "证据锚", "ROE",
                     "沙箱", "技能库", "Reflexion"):
            self.assertIn(term, sec, f"术语表缺少 {term}")

    def test_required_metrics_are_present(self):
        for value in ("93.3%", "100.0%", "4,844", "2,899", "12,423", "9,111",
                      "31,500", "19,200", "0.50", "1.00", "32 次"):
            self.assertIn(value, self.text, f"缺少关键实测数字: {value}")

    def test_core_concepts_are_present(self):
        for term in ("L0", "L1", "L2", "L3", "plan-execute", "ReAct",
                     "supervisor-worker", "working", "episodic", "semantic",
                     "durable journal", "checkpoint", "resume", "幂等",
                     "MCP", "A2A", "AGPL", "Apache-2.0", "故障注入",
                     "证据覆盖率", "审批决策点"):
            self.assertIn(term, self.text, f"缺少核心概念: {term}")

    def test_no_placeholders_or_absolute_paths(self):
        upper = self.text.upper()
        for word in ("TODO", "TBD", "XXX", "FIXME", "待补"):
            self.assertNotIn(word, upper, f"手册不允许占位符: {word}")
        self.assertNotRegex(self.text, r"[A-Za-z]:\\\\", "手册不应出现本机绝对路径")

    def test_has_evidence_and_reproduction_section(self):
        sec = self.section("## 附录 E", "## 附录 F")
        self.assertIn("python -m unittest", sec)
        self.assertIn("lab/tencent-compare/run_eval.py", sec)
        self.assertIn("lab/agent-eval/run_eval.py", sec)
        self.assertIn("口径", sec)


if __name__ == "__main__":
    unittest.main()
