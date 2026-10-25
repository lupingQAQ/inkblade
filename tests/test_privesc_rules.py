"""提权检测规则包：每向量 ≥1 条 Sigma/Falco 规则、准入策略、紫队重放覆盖。"""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from trident.core.privesc import load_matrix
from trident.rules.privesc import (
    ADMISSION_RULE_IDS,
    ADMISSION_VECTORS,
    purple_replay,
    render_rule_pack,
    write_rule_pack,
)

REPO = Path(__file__).resolve().parents[1]


class TestPrivescRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.matrix = load_matrix()
        cls.pack = render_rule_pack(cls.matrix)

    def test_every_vector_has_a_rule(self):
        by_vector = {d["vector"]: d for d in self.pack["documents"]}
        for v in self.matrix["vectors"]:
            self.assertIn(v["id"], by_vector, f"{v['id']} 无检测规则")
            doc = by_vector[v["id"]]
            self.assertIn(doc["engine"], ("sigma", "falco"))
            self.assertTrue(doc["rule_id"].strip())
            self.assertTrue(doc["text"].strip())

    def test_rules_are_valid_yaml_ish_and_unique(self):
        ids = [d["rule_id"] for d in self.pack["documents"]]
        self.assertEqual(len(ids), len(set(ids)), "规则 id 必须唯一")
        for doc in self.pack["documents"]:
            if doc["engine"] == "sigma":
                self.assertIn("kind: SigmaRule", doc["text"])
                self.assertIn("metadata:", doc["text"])
            self.assertIn("trident.io/vector:", doc["text"])

    def test_admission_policies_cover_high_risk_vectors(self):
        self.assertGreaterEqual(len(ADMISSION_RULE_IDS), 4)
        self.assertTrue(set(ADMISSION_VECTORS) <= {v["id"] for v in self.matrix["vectors"]})
        self.pack = render_rule_pack(self.matrix)
        admission = self.pack["admission"]
        self.assertEqual(len(admission), len(ADMISSION_RULE_IDS))
        for doc in admission:
            self.assertIn("ClusterPolicy", doc["text"])
            self.assertIn("validationFailureAction: Audit", doc["text"])

    def test_purple_replay_hits_all(self):
        result = purple_replay(self.matrix)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["missed"], [])
        engines = {item["engine"] for item in result["items"]}
        self.assertEqual(engines, {"sigma", "falco"})

    def test_write_pack_artifacts(self):
        with TemporaryDirectory() as tmp:
            summary = write_rule_pack(self.matrix, tmp)
            self.assertTrue(summary["ok"], summary)
            root = Path(tmp)
            for rel in ("coverage.json", "README.md", "coverage.md"):
                self.assertTrue((root / rel).is_file(), rel)
            self.assertTrue((root / "sigma").is_dir())
            self.assertTrue((root / "falco").is_dir())
            self.assertTrue((root / "kyverno").is_dir())
            coverage = json.loads((root / "coverage.json").read_text(encoding="utf-8"))
            self.assertEqual(coverage["summary"]["vectors"], len(self.matrix["vectors"]))
            self.assertTrue(coverage["summary"]["ok"])


if __name__ == "__main__":
    unittest.main()
