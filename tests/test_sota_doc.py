# -*- coding: utf-8 -*-
"""SOTA-2026-10 能力矩阵测试：表结构 / 状态枚举 / 诚实未达成项 / README 链接。"""

import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DOC = REPO / "docs" / "SOTA-2026-10.md"
README = REPO / "README.md"

STATUSES = {"已达成", "部分", "未达成"}
# 矩阵 38 行：26 已达成 / 7 部分 / 5 未达成（与文档「计数」节一致）。
# 2026-10-25 收尾：新增输出确定性/执行审计轨迹/单机多租户隔离（已达成）；
# Live K8s 部分→已达成；真实 ARTEX 对比 未达成→部分（QEMU TCG 实测，非裸机）。
EXPECTED = {"已达成": 26, "部分": 7, "未达成": 5}


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
        for topic, needle in (("万卡实测", "万卡"), ("硬件 TEE 实测", "硬件 TEE"),
                              ("生产级模型签名", "cosign keyless"),
                              ("六云商真实环境", "六云商"),
                              ("分布式调度", "分布式调度")):
            line = next((l for l in text.splitlines() if needle in l and l.startswith("|")), None)
            self.assertIsNotNone(line, f"缺少未达成项: {topic}")
            self.assertIn("未达成", line, f"{topic} 未诚实标注未达成: {line}")
        self.assertIn("追赶路径", text)
        self.assertIn("未达成", text)

    def test_artex_comparison_is_partial_with_tcg_caveat(self):
        """真实 ARTEX 对比：已有实测数据（同靶场 + 全端点网格），但仍为 QEMU TCG，故标部分。"""
        line = next(l for l in DOC.read_text(encoding="utf-8").splitlines()
                    if l.startswith("|") and "真实 ARTEX 对比数据" in l)
        self.assertIn("部分", line)
        self.assertIn("QEMU TCG", line)
        self.assertIn("跨副本", DOC.read_text(encoding="utf-8"), "缺分布式调度未达成行")

    def test_closure_rows_present(self):
        rows = {r["capability"]: r for r in _rows()}
        for cap in ("输出确定性（归档/报告/样张可复现）",
                    "执行审计轨迹（平台侧 who-did-what）",
                    "多租户工作区隔离与有界并发（单机）",
                    "API-first REST + MCP 同步暴露"):
            self.assertIn(cap, rows, f"缺能力行 {cap}")
            self.assertEqual(rows[cap]["status"], "已达成", cap)

    def test_corpus_citations_exist(self):
        rows = _rows()
        cited = set()
        for row in rows:
            cited.update(re.findall(
                r"arch-intel/corpus/(?:official-cn/|official-en/|paper/)?"
                r"([a-z0-9-]+)\.md", row["reference"]))
        self.assertGreaterEqual(len(cited), 8, cited)
        for cid in cited:
            base = REPO / "trident" / "arch-intel" / "corpus"
            self.assertTrue(
                any((base / cls / f"{cid}.md").is_file()
                    for cls in ("official-cn", "official-en", "paper")),
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
