# -*- coding: utf-8 -*-
"""企业就绪文档的诚实性校验：六类差距、四阶段闸门、≥50 项三态清单。"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DOC = REPO / "docs" / "ENTERPRISE-READINESS.md"
LAB = REPO / "docs" / "ENTERPRISE-LAB-RESULTS.md"
OPS = REPO / "docs" / "OPERATIONS.md"
README = REPO / "README.md"


class TestEnterpriseReadinessDoc(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = DOC.read_text(encoding="utf-8")

    def test_six_gap_categories(self):
        for cat in ("真实环境差异", "规模", "数据敏感与变更窗口", "误报漏报与调优",
                    "系统集成", "合规与运营"):
            self.assertIn(cat, self.text, f"缺差距类别: {cat}")
        self.assertGreaterEqual(self.text.count("demo 证明什么"), 6)
        self.assertGreaterEqual(self.text.count("企业还差什么"), 6)
        self.assertGreaterEqual(self.text.count("本地可测"), 6)
        self.assertGreaterEqual(self.text.count("必须客户环境测"), 6)

    def test_four_phase_gates_and_metrics(self):
        for phase in ("POC", "Lab", "Pilot", "Production"):
            self.assertIn(f"| {phase} |", self.text, f"缺阶段 {phase}")
        for metric in ("只读通过率", "误报率", "漏报率", "扫描窗口", "回滚成功率", "报告签核"):
            self.assertIn(metric, self.text, f"缺量化指标 {metric}")
        self.assertIn("准入", self.text)
        self.assertIn("退出", self.text)

    def test_checklist_at_least_50_and_three_states(self):
        rows = []
        for line in self.text.splitlines():
            if not line.startswith("| ER-"):
                continue
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            self.assertEqual(len(cells), 5, line)
            rows.append(cells)
        self.assertGreaterEqual(len(rows), 50, f"清单不足 50 项: {len(rows)}")
        states = {"🟢": 0, "🟡": 0, "🔴": 0}
        for cells in rows:
            state = cells[3][:1]
            self.assertIn(state, states, cells)
            states[state] += 1
            self.assertTrue(cells[2], f"缺类别: {cells}")
            self.assertTrue(cells[4], f"缺证据/缺口: {cells}")
        self.assertGreater(states["🟢"], 0)
        self.assertGreater(states["🟡"], 0)
        self.assertGreater(states["🔴"], 0)
        self.assertNotEqual(states["🟢"], len(rows), "不允许全绿粉饰")
        m = re.search(r"绿\s*(\d+)\s*[·/]\s*黄\s*(\d+)\s*[·/]\s*红\s*(\d+).*?共\s*(\d+)\s*项",
                      self.text)
        self.assertIsNotNone(m, "缺计数行：绿 N · 黄 N · 红 N（共 N 项）")
        self.assertEqual(int(m.group(1)), states["🟢"])
        self.assertEqual(int(m.group(2)), states["🟡"])
        self.assertEqual(int(m.group(3)), states["🔴"])
        self.assertEqual(int(m.group(4)), len(rows))

    def test_lab_doc_labels_real_and_fixture_lanes(self):
        text = LAB.read_text(encoding="utf-8")
        self.assertIn("fixture", text)
        self.assertIn("真实集群", text)
        self.assertIn("FP", text)
        self.assertIn("FN", text)
        for scenario in ("platform-baseline-noise", "rbac-intent-noise", "audit-flood-noise"):
            self.assertIn(scenario, text)
        self.assertIn("不计算 FP/FN", text)

    def test_operations_and_readme_tiers(self):
        ops = OPS.read_text(encoding="utf-8")
        for needle in ("HA", "升级", "备份", "回滚", "许可证", "交付边界", "多租户", "压测"):
            self.assertIn(needle, ops)
        readme = README.read_text(encoding="utf-8")
        for needle in ("demo", "试点", "生产", "禁止宣称"):
            self.assertIn(needle, readme)


if __name__ == "__main__":
    unittest.main()
