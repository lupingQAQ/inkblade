# -*- coding: utf-8 -*-
"""跨 run 黑板：固定/读取/注入 explorer（只读）/角色闸门。"""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.core.blackboard import Blackboard, BlackboardError
from inkblade.core.discovery import AssetInventory
from inkblade.core.evidence import EvidenceStore
from inkblade.core.explorer import Explorer
from inkblade.core.roe import init_roe
from inkblade.core.users import Session

MODULES_DIR = Path(__file__).resolve().parents[1] / "inkblade" / "modules"


def _session(role="lead"):
    return Session(None, f"s-{role}", role, ["local-lab"], "t")


class TestBlackboard(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.store = EvidenceStore(Path(self.tmp.name), workspace="local-lab")
        init_roe(self.store, {"level": "利用验证", "namespaces": ["ml"],
                              "cidrs": ["10.0.0.0/8"]})
        AssetInventory(self.store).ingest({"services": [
            {"name": "sglang-admin", "namespace": "ml", "addr": "10.96.0.11",
             "port": 30000, "labels": {"app": "sglang"}}]})
        self.run = self.store.create_run("run-bb")
        self.run.add_step("sglang-admin-failopen", "cmd", {}, "ok")
        self.run.add_finding("sglang-admin-failopen", "high", "admin unauth", "secret=abc",
                             evidence_path="steps/a.tar.gz")
        self.bb = Blackboard(self.store, clock=lambda: 1000.0)

    def tearDown(self):
        self.tmp.cleanup()

    def test_pin_and_context_summaries(self):
        e = self.bb.pin_finding(_session(), "run-bb", "admin unauth", note="prioritize")
        self.assertEqual(e["kind"], "finding")
        self.assertNotIn("detail", e)
        self.bb.pin_assets(_session(), limit=5)
        self.bb.pin_note(_session(), "focus sglang", ref="note:focus")
        ctx = self.bb.context()
        self.assertEqual(ctx["count"], 3)
        self.assertTrue(ctx["readonly"])
        self.assertEqual(ctx["findings"][0]["note"], "prioritize")
        self.assertIn("sglang", ctx["notes"][0]["summary"])

    def test_role_gate_and_unpin(self):
        with self.assertRaises(PermissionError):
            self.bb.pin_note(_session("tester"), "x")
        e = self.bb.pin_note(_session(), "x", ref="n1")
        with self.assertRaises(PermissionError):
            self.bb.unpin(_session("auditor"), "n1")
        with self.assertRaises(BlackboardError):
            self.bb.unpin(_session(), "ghost")
        self.assertEqual(self.bb.unpin(_session(), "n1"), {"removed": "n1"})
        self.assertEqual(self.bb.list(), [])

    def test_idempotent_ref_updates(self):
        a = self.bb.pin_note(_session(), "v1", ref="same")
        b = self.bb.pin_note(_session(), "v2", ref="same")
        self.assertEqual(a["id"], b["id"])
        self.assertEqual(b["summary"], "v2")
        self.assertEqual(len(self.bb.list()), 1)

    def test_explorer_injection_is_read_only(self):
        self.bb.pin_note(_session(), "previous run showed sglang exposed", ref="prior")
        before = (self.store.ws_dir / "blackboard.json").read_bytes()
        runs_before = len([p for p in self.store.ws_dir.iterdir()
                           if (p / "evidence.db").is_file()])
        ex = Explorer(self.store, modules_dir=MODULES_DIR)
        p = ex.propose(_session("tester"))
        self.assertGreaterEqual(p["context"]["blackboard"]["count"], 1)
        self.assertIn("previous run", p["context"]["blackboard"]["notes"][0]["summary"])
        self.assertEqual((self.store.ws_dir / "blackboard.json").read_bytes(), before)
        runs_after = len([p for p in self.store.ws_dir.iterdir()
                          if (p / "evidence.db").is_file()])
        self.assertEqual(runs_before, runs_after)


if __name__ == "__main__":
    unittest.main()
