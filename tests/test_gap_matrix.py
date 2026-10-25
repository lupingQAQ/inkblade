import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools import render_gap_docs  # noqa: E402

MATRIX = ROOT / "docs" / "gap-matrix.json"
DOCS = {
    "features": ROOT / "docs" / "GAP-FEATURES.md",
    "surfaces": ROOT / "docs" / "GAP-ATTACK-SURFACE.md",
    "payloads": ROOT / "docs" / "GAP-PAYLOADS.md",
}


class TestGapMatrix(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(MATRIX.read_text(encoding="utf-8"))

    def test_tool_coverage(self):
        tools = self.data["tools"]
        self.assertGreaterEqual(len(tools), 30)
        for name, block in tools.items():
            self.assertTrue(block.get("verification"), name)
            self.assertIn("completeness", block["verification"], name)
            total_items = sum(len(block.get(k, [])) for k in ("features", "surfaces", "payloads"))
            self.assertGreater(total_items, 0, name)

    def test_every_item_has_source_and_status(self):
        valid = {"we-have", "partial", "missing", "N/A", "n/a", "covered", "not-applicable"}
        for name, block in self.data["tools"].items():
            for key in ("features", "surfaces", "payloads"):
                for item in block.get(key, []):
                    self.assertTrue(item.get("name"), f"{name}/{key} no name")
                    self.assertTrue(item.get("source"), f"{name}/{key}/{item.get('name')} no source")
                    self.assertIn(str(item.get("status")), valid,
                                  f"{name}/{key}/{item.get('name')} bad status {item.get('status')}")

    def test_render_docs_cover_every_item(self):
        render_gap_docs.main()
        for key, path in DOCS.items():
            text = path.read_text(encoding="utf-8")
            expected = sum(len(b.get(key, [])) for b in self.data["tools"].values())
            rows = [l for l in text.splitlines() if l.startswith("| ") and "---" not in l]
            # 表头占 1 行
            self.assertEqual(len(rows) - 1, expected, f"{path.name}: {len(rows)-1} != {expected}")
            self.assertIn("完备性声明", text)

    def test_skipped_tools_documented(self):
        self.assertGreaterEqual(len(self.data.get("skipped", [])), 1)
        text = DOCS["features"].read_text(encoding="utf-8")
        for s in self.data["skipped"]:
            self.assertIn(s["tool"], text)


if __name__ == "__main__":
    unittest.main()
