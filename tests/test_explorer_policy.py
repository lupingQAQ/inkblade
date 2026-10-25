# -*- coding: utf-8 -*-
"""Explorer 只读提议路径接入策略/观察/成本（OFF = HEAD 行为）测试。"""

import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from trident.core.discovery import AssetInventory
from trident.core.evidence import EvidenceStore
from trident.core.explorer import Explorer
from trident.core.roe import init_roe
from trident.core.users import Session

MODULES_DIR = Path(__file__).resolve().parents[1] / "trident" / "modules"
SEEDS = {"services": [
    {"name": "sglang-admin", "namespace": "ml", "addr": "10.96.0.11", "port": 30000,
     "labels": {"app": "sglang"}},
    {"name": "litellm-proxy", "namespace": "ml", "addr": "10.96.0.12", "port": 4000,
     "labels": {"app": "litellm"}},
]}


def _session(role="lead"):
    return Session(None, f"s-{role}", role, ["local-lab"], "t")


class TestExplorerPolicyWiring(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.store = EvidenceStore(Path(self.tmp.name), workspace="local-lab")
        init_roe(self.store, {"level": "利用验证", "namespaces": ["ml"],
                              "cidrs": ["10.0.0.0/8"]})
        AssetInventory(self.store).ingest(SEEDS, source="seed")
        self.ex = Explorer(self.store, modules_dir=MODULES_DIR)

    def tearDown(self):
        self.tmp.cleanup()

    def test_on_adds_policy_observation_and_cost(self):
        p = self.ex.propose(_session())
        self.assertEqual(p["status"], "pending_approval")
        self.assertIn("policy", p)
        self.assertIn("decomposition", p)
        self.assertIn("observations", p)
        self.assertIn("cost", p)
        self.assertIn(p["policy"]["level"], ("L1", "L2", "L3"))
        self.assertGreaterEqual(p["policy"]["approval_count"], 1)
        self.assertLessEqual(p["policy"]["approval_count"], len(p["actions"]))
        self.assertGreaterEqual(p["decomposition"]["stages"], 1)
        self.assertEqual(len(p["observations"]), len(p["actions"]))
        for obs in p["observations"]:
            self.assertIn(obs["claim"], ("confirmed", "planned"))
            self.assertTrue(obs["evidence"])
            self.assertIn("next", obs)
        self.assertGreater(p["cost"]["tokens"], 0)

    def test_on_still_readonly_never_executes(self):
        p = self.ex.propose(_session())
        self.assertFalse(any((x / "evidence.db").exists()
                             for x in self.store.ws_dir.iterdir() if x.is_dir()))
        self.assertFalse(p["execution"]["performed"])

    def test_off_matches_head_shape(self):
        p = self.ex.propose(_session(), policy=False)
        for key in ("policy", "decomposition", "observations", "cost"):
            self.assertNotIn(key, p)
        self.assertIn("actions", p)
        self.assertEqual(p["approval"]["required"], True)

    def test_env_switch_off(self):
        with mock.patch.dict(os.environ, {"TRIDENT_AGENT_POLICY": "off"}):
            p = self.ex.propose(_session())
        self.assertNotIn("policy", p)

    def test_explicit_override_beats_env(self):
        with mock.patch.dict(os.environ, {"TRIDENT_AGENT_POLICY": "off"}):
            p = self.ex.propose(_session(), policy=True)
        self.assertIn("policy", p)

    def test_observations_are_persisted_for_view(self):
        p = self.ex.propose(_session())
        path = Path(self.store.ws_dir) / "agent" / "observations.jsonl"
        self.assertTrue(path.exists())
        lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        self.assertEqual(len(lines), len(p["actions"]))


if __name__ == "__main__":
    unittest.main()
