# -*- coding: utf-8 -*-
"""规划器（agent_planner）只读提议路径接入策略/成本测试。"""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from trident.agent_planner import plan_workspace
from trident.core.evidence import EvidenceStore

ROOT = Path(__file__).resolve().parents[1]


class PlannerPolicyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.store = EvidenceStore(Path(self.tmp.name), workspace="local-lab")

    def tearDown(self):
        self.tmp.cleanup()

    def test_policy_on_annotates_candidates_without_executing(self):
        doc = plan_workspace(self.store, chains_dir=ROOT / "trident" / "chains",
                             modules_dir=ROOT / "trident" / "modules", policy=True)
        self.assertTrue(doc["read_only"])
        self.assertEqual(doc["writes"], {"actions": 0, "runs": 0, "backups": 0})
        self.assertTrue(doc["agent_policy"]["enabled"])
        self.assertTrue(doc["candidates"])
        for cand in doc["candidates"]:
            self.assertIn(cand["policy"]["level"], ("L1", "L2", "L3"))
            self.assertGreaterEqual(cand["policy"]["approval_count"], 1)
            self.assertGreater(cand["cost"]["tokens"], 0)
            self.assertFalse(cand["execution"]["performed"])

    def test_policy_off_matches_head_shape(self):
        doc = plan_workspace(self.store, chains_dir=ROOT / "trident" / "chains",
                             modules_dir=ROOT / "trident" / "modules", policy=False)
        self.assertNotIn("agent_policy", doc)
        for cand in doc["candidates"]:
            self.assertNotIn("policy", cand)
            self.assertNotIn("cost", cand)

    def test_irreversible_chain_requires_per_write_confirmation(self):
        doc = plan_workspace(self.store, chains_dir=ROOT / "trident" / "chains",
                             modules_dir=ROOT / "trident" / "modules", policy=True)
        gated = [c for c in doc["candidates"]
                 if c["policy"]["level"] == "L1" and c["writes"] > 0]
        self.assertTrue(gated, "expected at least one irreversible-write chain")
        for cand in gated:
            self.assertTrue(cand["policy"]["requires_human"])
            irreversible = [s for s in cand["steps"]
                            if s.get("writes") and not s.get("backup_targets")]
            self.assertTrue(irreversible)
            self.assertEqual(cand["policy"]["approval_count"], 1 + len(irreversible))


if __name__ == "__main__":
    unittest.main()
