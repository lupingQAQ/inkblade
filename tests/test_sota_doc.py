# -*- coding: utf-8 -*-
"""SOTA-2026-10 三态矩阵：表结构/状态枚举/计数/证据路径/五个补齐项。"""

import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DOC = REPO / "docs" / "SOTA-2026-10.md"
README = REPO / "README.md"

STATUSES = {"真实验证", "模拟验证", "仍未达成"}
# 38 行：25 真实验证 / 10 模拟验证 / 3 仍未达成。
EXPECTED = {"真实验证": 25, "模拟验证": 10, "仍未达成": 3}


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
            if "能力" in cells[0] and any("状态" in c for c in cells):
                header_seen = True
            continue
        if set(cells[0]) <= set("-: "):
            continue
        if len(cells) != 5:
            continue
        rows.append({"capability": cells[0], "implementation": cells[1],
                     "reference": cells[2], "status": cells[3], "evidence": cells[4]})
    return rows


class TestSotaDoc(unittest.TestCase):
    def test_doc_exists_and_readme_links(self):
        self.assertTrue(DOC.is_file(), "缺少 docs/SOTA-2026-10.md")
        readme = README.read_text(encoding="utf-8")
        self.assertIn("docs/SOTA-2026-10.md", readme)

    def test_matrix_shape_and_three_state(self):
        rows = _rows()
        self.assertEqual(len(rows), 38, f"矩阵行数不匹配: {len(rows)}")
        for row in rows:
            self.assertEqual(set(row), {"capability", "implementation", "reference",
                                        "status", "evidence"})
            self.assertIn(row["status"], STATUSES, row)
            self.assertTrue(row["implementation"], row)
            self.assertTrue(row["reference"], row)
            self.assertTrue(row["evidence"], row)
            self.assertTrue(any(tok in row["reference"] for tok in ("http", "arch-intel/corpus")),
                            f"公开参照未给出来源: {row}")

    def test_status_counts(self):
        counts = {s: 0 for s in STATUSES}
        for row in _rows():
            counts[row["status"]] += 1
        self.assertEqual(counts, EXPECTED)

    def test_honest_gaps_present(self):
        rows = {r["capability"]: r for r in _rows()}
        self.assertEqual(rows["硬件 TEE 实测（TDX/SEV-SNP/NVIDIA CC）"]["status"], "仍未达成")
        self.assertEqual(rows["模型注册中心 / 权重仓库直连"]["status"], "仍未达成")
        self.assertEqual(rows["SIEM/SOAR 连接器"]["status"], "仍未达成")
        text = DOC.read_text(encoding="utf-8")
        self.assertIn("免费资源补齐（2026-10-25）", text)
        self.assertIn("剩余硬缺口", text)
        self.assertIn("模拟验证", text)

    def test_gap_closure_section_statuses(self):
        text = DOC.read_text(encoding="utf-8")
        start = text.index("## 免费资源补齐")
        end = text.index("## 剩余硬缺口", start)
        section = text[start:end]
        checks = {
            "cosign keyless": "模拟验证",
            "TEE 公共证书链": "真实验证",
            "六云免费/模拟": "模拟验证",
            "万卡网络仿真": "模拟验证",
            "SaaS 多租户压测": "模拟验证",
        }
        for topic, status in checks.items():
            line = next(l for l in section.splitlines() if l.startswith("|") and topic in l)
            self.assertIn(status, line, f"{topic} 状态不符: {line}")
        self.assertIn("硬件 TEE", section)

    def test_artex_comparison_is_simulated_with_tcg_caveat(self):
        line = next(l for l in DOC.read_text(encoding="utf-8").splitlines()
                    if l.startswith("|") and "真实 ARTEX 对比数据" in l)
        self.assertIn("模拟验证", line)
        self.assertIn("QEMU TCG", line)
        self.assertIn("跨副本", DOC.read_text(encoding="utf-8"))

    def test_closure_rows_present(self):
        rows = {r["capability"]: r for r in _rows()}
        for cap in ("输出确定性（归档/报告/样张可复现）",
                    "执行审计轨迹（平台侧 who-did-what）",
                    "多租户工作区隔离与有界并发（单机）",
                    "API-first REST + MCP 同步暴露"):
            self.assertIn(cap, rows, f"缺能力行 {cap}")
            self.assertEqual(rows[cap]["status"], "真实验证", cap)

    def test_evidence_paths_exist(self):
        for row in _rows():
            for raw in row["evidence"].split(";"):
                path = raw.strip()
                if not path:
                    continue
                self.assertTrue((REPO / path).exists(),
                                f"{row['capability']} 证据路径不存在: {path}")

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
        m = re.search(r"真实验证\s*(\d+)\s*[·/、,，]\s*模拟验证\s*(\d+)\s*[·/、,，]\s*仍未达成\s*(\d+)", text)
        self.assertIsNotNone(m, "文档缺少计数行：真实验证 N · 模拟验证 N · 仍未达成 N")
        self.assertEqual(
            {"真实验证": int(m.group(1)), "模拟验证": int(m.group(2)),
             "仍未达成": int(m.group(3))},
            EXPECTED,
        )


if __name__ == "__main__":
    unittest.main()
