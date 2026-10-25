# -*- coding: utf-8 -*-
"""SOTA-2026-10 能力矩阵测试：表结构 / 状态枚举 / 诚实未达成项 / README 链接。"""

import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DOC = REPO / "docs" / "SOTA-2026-10.md"
README = REPO / "README.md"

STATUSES = {"已达成", "部分", "未达成"}
# 矩阵 27 行：15 已达成 / 6 部分 / 6 未达成（与文档「计数」节一致；2026-10-25 新增「K8s 审计轨迹分析」已达成行）
EXPECTED = {"已达成": 15, "部分": 6, "未达成": 6}


def _rows() -> list[dict[str, str]]:
    text = DOC.read_text(encoding="utf-8")
    rows: list[dict[str, str]] = []
    header_seen = False
    for line in text.splitlines():
        if not line.startswith("|"):
            header_seen = False
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if not header_seen:
            if "能力" in cells[0] and "状态" in cells[-1]:
                header_seen = True
            continue
        if set(cells[0]) <= set("-: "):
            continue
        rows.append({"capability": cells[0], "implementation": cells[1],
                     "reference": cells[2], "status": cells[3]})
    return rows


class TestSotaDoc(unittest.TestCase):
    def test_doc_exists_and_readme_links(self):
        self.assertTrue(DOC.is_file(), "缺少 docs/SOTA-2026-10.md")
        readme = README.read_text(encoding="utf-8")
        self.assertIn("docs/SOTA-2026-10.md", readme)

    def test_matrix_shape(self):
        rows = _rows()
        self.assertGreaterEqual(len(rows), 24, f"矩阵行数不足: {len(rows)}")
        for row in rows:
            self.assertEqual(set(row), {"capability", "implementation", "reference", "status"})
            self.assertIn(row["status"], STATUSES, row)
            self.assertTrue(row["implementation"], row)
            self.assertTrue(row["reference"], row)
            self.assertTrue(any(tok in row["reference"] for tok in ("http", "arch-intel/corpus")),
                            f"公开参照未给出来源: {row}")

    def test_status_counts(self):
        counts = {s: 0 for s in STATUSES}
        for row in _rows():
            counts[row["status"]] += 1
        self.assertEqual(counts, EXPECTED)

    def test_honest_gaps_present(self):
        text = DOC.read_text(encoding="utf-8")
        for topic, needle in (("万卡实测", "万卡"), ("真实 ARTEX 对比数据", "真实 ARTEX 对比数据"),
                              ("硬件 TEE 实测", "硬件 TEE")):
            line = next((l for l in text.splitlines() if needle in l and l.startswith("|")), None)
            self.assertIsNotNone(line, f"缺少未达成项: {topic}")
            self.assertIn("未达成", line, f"{topic} 未诚实标注未达成: {line}")
        self.assertIn("追赶路径", text)
        self.assertIn("未达成", text)

    def test_corpus_citations_exist(self):
        rows = _rows()
        cited = set()
        for row in rows:
            cited.update(re.findall(r"arch-intel/corpus/([a-z0-9-]+)\.md", row["reference"]))
        self.assertGreaterEqual(len(cited), 8, cited)
        for cid in cited:
            self.assertTrue((REPO / "trident" / "arch-intel" / "corpus" / f"{cid}.md").is_file(),
                            f"引用了不存在的 corpus 条目: {cid}")

    def test_documented_counts_match_matrix(self):
        text = DOC.read_text(encoding="utf-8")
        m = re.search(r"已达成\s*(\d+)\s*[·/、,，]\s*部分\s*(\d+)\s*[·/、,，]\s*未达成\s*(\d+)", text)
        self.assertIsNotNone(m, "文档缺少计数行：已达成 N · 部分 N · 未达成 N")
        self.assertEqual(
            {"已达成": int(m.group(1)), "部分": int(m.group(2)), "未达成": int(m.group(3))},
            EXPECTED,
        )


if __name__ == "__main__":
    unittest.main()
