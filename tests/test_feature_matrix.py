import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "docs" / "feature-matrix.json"


def _rows(tool_block):
    rows = []
    for sec in tool_block.get("sections", []):
        rows.extend(sec.get("rows", []))
    return rows


class TestFeatureMatrix(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m = json.loads(MATRIX.read_text(encoding="utf-8"))

    def test_source_counts_are_source_derived(self):
        c = self.m["source_counts"]
        self.assertGreaterEqual(c["artex_routes"], 200)
        self.assertGreaterEqual(c["artex_tables"], 40)
        self.assertGreaterEqual(c["artex_views"], 20)
        self.assertGreaterEqual(c["kubetrail_collectors"], 15)
        self.assertGreaterEqual(c["kubetrail_desktop_methods"], 50)

    def test_matrix_rows_complete(self):
        rows = self.m["matrix_rows"]
        self.assertGreaterEqual(rows["total"], 700)
        self.assertEqual(rows["total"], rows["artex"] + rows["kubetrail"])

    def test_every_row_has_status_and_anchor(self):
        valid = {"we-have", "partial", "missing", "N/A", "n/a"}
        for tool in ("artex", "kubetrail"):
            rows = _rows(self.m[tool])
            self.assertGreaterEqual(len(rows), self.m["matrix_rows"][tool], tool)
            for row in rows:
                status = row.get("inkblade_status", row.get("status"))
                self.assertIn(str(status), valid, f"{tool} bad status: {row}")
                self.assertTrue(row.get("anchor") or row.get("id"), f"{tool} row missing anchor: {row}")

    def test_status_counts_sum_to_rows(self):
        for tool in ("artex", "kubetrail"):
            counts = self.m["status_counts"][tool]
            self.assertEqual(sum(counts.values()), self.m["matrix_rows"][tool], tool)
            rows = _rows(self.m[tool])
            self.assertEqual(len(rows), self.m["matrix_rows"][tool], tool)

    def test_docs_exist_and_are_substantial(self):
        k = (ROOT / "docs" / "FEATURE-BY-FEATURE-KUBETRAIL.md").read_text(encoding="utf-8")
        self.assertGreater(len(k), 15000)
        self.assertIn("来源", k)


if __name__ == "__main__":
    unittest.main()
