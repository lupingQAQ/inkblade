# -*- coding: utf-8 -*-
"""任务模板：链子集/参数预设/dry-run 计划/从 run 反推（只读）/角色闸门。"""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from trident.core.evidence import EvidenceStore
from trident.core.templates import TemplateError, TemplateStore
from trident.core.users import Session

MODULES_DIR = Path(__file__).resolve().parents[1] / "trident" / "modules"
CHAINS_DIR = Path(__file__).resolve().parents[1] / "trident" / "chains"


def _session(role="lead"):
    return Session(None, f"s-{role}", role, ["local-lab"], "t")


class TestTemplates(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.store = EvidenceStore(Path(self.tmp.name), workspace="local-lab")
        self.run = self.store.create_run("run-src")
        self.run.add_step("sglang-admin-failopen", "{'probe': 'auth-bypass'}",
                          {"env": "lab"}, "sglang ok")
        self.run.add_step("slime-weight-pull-poison",
                          "{'mode': 'backup-write', 'api_key': 'sk-123456'}",
                          {"env": "lab"}, "weight write")
        self.ts = TemplateStore(self.store, chains_dir=CHAINS_DIR, modules_dir=MODULES_DIR)

    def tearDown(self):
        self.tmp.cleanup()

    def test_create_requires_approve(self):
        with self.assertRaises(PermissionError):
            self.ts.add(_session("tester"), name="t", chains=["flat-network-admin-plane-weight-poison"])
        t = self.ts.add(_session(), name="t", chains=["flat-network-admin-plane-weight-poison"],
                        params={"sglang-admin-failopen": {"probe": "auth-bypass"}})
        self.assertEqual(t["id"], "tmpl-001")
        self.assertEqual(len(self.ts.list()), 1)

    def test_invalid_chain_and_duplicate(self):
        with self.assertRaises(TemplateError):
            self.ts.add(_session(), name="t", chains=["no-such-chain"])
        self.ts.add(_session(), name="t", chains=["flat-network-admin-plane-weight-poison"],
                    template_id="x")
        with self.assertRaises(TemplateError):
            self.ts.add(_session(), name="t2", chains=["flat-network-admin-plane-weight-poison"],
                        template_id="x")

    def test_from_run_is_read_only_and_derives(self):
        runs_before = sorted(p.name for p in self.store.ws_dir.iterdir()
                             if p.is_dir() and (p / "evidence.db").is_file())
        actions_before = self.run.query("SELECT COUNT(*) FROM actions")[0][0]
        t = self.ts.from_run(_session(), "run-src", name="derived")
        self.assertEqual(t["source"]["run"], "run-src")
        self.assertIn("sglang-admin-failopen", t["modules"])
        self.assertIn("slime-weight-pull-poison", t["modules"])
        self.assertTrue(t["params"])
        self.assertEqual(t["params"]["slime-weight-pull-poison"]["api_key"], "***")
        runs_after = sorted(p.name for p in self.store.ws_dir.iterdir()
                            if p.is_dir() and (p / "evidence.db").is_file())
        self.assertEqual(runs_before, runs_after)
        self.assertEqual(self.run.query("SELECT COUNT(*) FROM actions")[0][0], actions_before)
        self.assertFalse(any(x["action"] == "execute" for x in
                             self.run.query("SELECT action FROM actions")))

    def test_instantiate_plan_no_execution(self):
        t = self.ts.add(_session(), name="t", chains=["flat-network-admin-plane-weight-poison"],
                        params={"slime-weight-pull-poison": {"mode": "backup-write"}})
        runs_before = len([p for p in self.store.ws_dir.iterdir() if (p / "evidence.db").is_file()])
        plan = self.ts.instantiate(t["id"])
        modules = [s["module"] for s in plan["steps"]]
        self.assertIn("sglang-admin-failopen", modules)
        self.assertIn("slime-weight-pull-poison", modules)
        writes = [s for s in plan["steps"] if s["writes"]]
        self.assertTrue(writes)
        self.assertTrue(writes[0]["backup_required"])
        self.assertFalse(plan["execution"]["performed"])
        runs_after = len([p for p in self.store.ws_dir.iterdir() if (p / "evidence.db").is_file()])
        self.assertEqual(runs_before, runs_after)

    def test_update_delete_permissions(self):
        t = self.ts.add(_session(), name="t", chains=["flat-network-admin-plane-weight-poison"])
        with self.assertRaises(PermissionError):
            self.ts.update(_session("tester"), t["id"], name="x")
        with self.assertRaises(PermissionError):
            self.ts.delete(_session("auditor"), t["id"])
        up = self.ts.update(_session(), t["id"], name="renamed")
        self.assertEqual(up["name"], "renamed")
        self.ts.delete(_session(), t["id"])
        with self.assertRaises(TemplateError):
            self.ts.get(t["id"])


if __name__ == "__main__":
    unittest.main()
