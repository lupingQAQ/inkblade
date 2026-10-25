# -*- coding: utf-8 -*-
"""tests/test_docs_master.py — 总报告的结构与底线断言。

这不是“文风测试”，而是防止总报告退化：
- 必须存在且达到最小篇幅（≥8000 字符）；
- 必须有 10 个中文数字章节；
- 术语表至少 20 条，且覆盖核心缩写；
- 指标表必须有“前值/后值/变化%”列；
- 复盘至少 6 条，且每条包含四段式；
- 不允许 TODO/TBD 等占位符。
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "MASTER-REPORT.md"


class MasterReportTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = DOC.read_text(encoding="utf-8")

    def section(self, start_marker, end_marker):
        start = self.text.index(start_marker)
        end = self.text.index(end_marker, start)
        return self.text[start:end]

    def test_exists_and_long_enough(self):
        self.assertTrue(DOC.is_file(), f"缺少总报告: {DOC}")
        self.assertGreaterEqual(len(self.text), 8000, "总报告不足 8000 字符")

    def test_ten_chapters(self):
        chapters = re.findall(r"^## ([一二三四五六七八九十]+)、", self.text, re.M)
        self.assertEqual(len(chapters), 10, f"章节数不是 10: {chapters}")
        self.assertEqual(chapters, list("一二三四五六七八九十"))

    def test_glossary_at_least_20(self):
        sec = self.section("## 九、术语表", "## 十、证据索引")
        rows = [
            line for line in sec.splitlines()
            if line.startswith("|") and "---" not in line
        ][1:]
        self.assertGreaterEqual(len(rows), 20, "术语表少于 20 条")
        for term in (
            "K8s", "RBAC", "SSRR", "IMDS", "IRSA", "NCCL", "RDMA", "SHARP",
            "PFC", "DRA", "IMEX", "EPP", "MCP", "A2A", "OCSF", "SARIF",
            "VEX", "CVSS", "ATT&CK", "ATLAS", "等保", "PTES", "CIS", "TCG",
        ):
            self.assertIn(term, sec, f"术语表缺少 {term}")

    def test_metrics_table_has_before_after(self):
        sec = self.section("## 五、指标总表", "## 六、")
        header = "| 指标 | 前值 | 后值 | 变化% | 原因 | 来源 |"
        self.assertIn(header, sec, "指标表缺少前值/后值/变化%/原因/来源列")
        rows = [
            line for line in sec.splitlines()
            if line.startswith("|") and "---" not in line
        ]
        self.assertGreaterEqual(len(rows) - 1, 12, "指标表数据行少于 12 行")

    def test_retrospective_at_least_six(self):
        sec = self.section("## 八、复盘", "## 九、")
        items = re.findall(r"^### 8\.\d+", sec, re.M)
        self.assertGreaterEqual(len(items), 6, "复盘少于 6 条")
        for label in ("当时怎么想", "错在哪", "如何纠正", "教训"):
            self.assertGreaterEqual(sec.count(label), 6, f"复盘缺少统一字段: {label}")

    def test_no_placeholders(self):
        upper = self.text.upper()
        self.assertNotIn("TODO", upper)
        self.assertNotIn("TBD", upper)

    def test_required_concepts_explained(self):
        sec = self.section("## 一、", "## 二、")
        for term in (
            "K8s", "Pod", "RBAC", "Service", "NetworkPolicy", "GPU 训练",
            "NCCL", "KV cache", "prefill", "AI 网关", "租户", "证据链",
        ):
            self.assertIn(term, sec, f"前置知识缺少 {term}")

    def test_evidence_links_are_relative(self):
        sec = self.section("## 十、证据索引", "*本报告由")
        self.assertIn("](../", sec, "证据索引缺少相对路径链接")


if __name__ == "__main__":
    unittest.main()
