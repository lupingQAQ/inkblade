# -*- coding: utf-8 -*-
"""资产/攻击图快照与跨 run 差异：只读重建、diff、UI 数据。"""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from trident.core.discovery import AssetInventory
from trident.core.evidence import EvidenceStore
from trident.core.graphsnap import GraphSnapError, GraphSnapshots, build
from trident.core.users import Session


def _session(role="lead"):
    return Session(None, f"s-{role}", role, ["local-lab"], "t")


class TestGraphSnap(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.store = EvidenceStore(Path(self.tmp.name), workspace="local-lab")
        AssetInventory(self.store).ingest({"services": [
            {"name": "sglang-admin", "namespace": "ml", "addr": "10.96.0.11",
             "port": 30000, "labels": {"app": "sglang"}}]})
        self.run = self.store.create_run("run-g1")
        self.run.add_step("sglang-admin-failopen", "cmd", {}, "ok")
        self.run.add_finding("sglang-admin-failopen", "high", "admin unauth", "x",
                             evidence_path="steps/a.tar.gz")
        self.run.upsert_node("pod/ml/trainer", "pod", "主机网络层", {"label": "trainer"})
        self.run.upsert_node("svc/ml/sglang", "service", "服务与网关层", {"label": "sglang"})
        self.run.add_edge("pod/ml/trainer", "svc/ml/sglang", "可达", "配置证据", "flat")
        self.gs = GraphSnapshots(self.store, clock=lambda: 1000.0)

    def tearDown(self):
        self.tmp.cleanup()

    def test_build_and_snapshot(self):
        doc = build(self.store, run="run-g1")
        self.assertTrue(doc["cold"])
        self.assertGreaterEqual(doc["stats"]["nodes"], 3)
        self.assertGreaterEqual(doc["stats"]["edges"], 2)
        self.assertEqual(doc["stats"]["findings"], 1)
        steps = self.run.query("SELECT COUNT(*) FROM steps")[0][0]
        actions = self.run.query("SELECT COUNT(*) FROM actions")[0][0]
        snap = self.gs.snapshot(_session(), run="run-g1", label="first")
        self.assertEqual(snap["label"], "first")
        self.assertEqual(self.run.query("SELECT COUNT(*) FROM steps")[0][0], steps)
        self.assertEqual(self.run.query("SELECT COUNT(*) FROM actions")[0][0], actions)
        self.assertEqual(len(self.gs.list()), 1)

    def test_diff_nodes_edges_findings(self):
        s1 = self.gs.snapshot(_session(), run="run-g1")
        self.run.upsert_node("pod/ml/trainer", "pod", "主机网络层",
                             {"label": "trainer-v2"})
        self.run.add_edge("svc/ml/sglang", "pod/ml/trainer", "可达", "主动实测", "flat")
        self.run.add_finding("sglang-admin-failopen", "critical", "new crit", "y")
        s2 = self.gs.snapshot(_session(), run="run-g1")
        diff = self.gs.diff(s1["id"], s2["id"])
        self.assertEqual(diff["nodes"]["counts"]["changed"], 1)
        self.assertEqual(diff["edges"]["counts"]["added"], 1)
        self.assertEqual(diff["findings"]["counts"]["new"], 1)

    def test_ui_and_neighbors(self):
        s = self.gs.snapshot(_session(), run="run-g1")
        ui = self.gs.ui_data(s["id"])
        self.assertTrue(ui["cold"])
        self.assertTrue(all("id" in n and "group" in n for n in ui["nodes"]))
        self.assertTrue(all("source" in e and "target" in e for e in ui["edges"]))
        nb = self.gs.neighbors(s["id"], "pod/ml/trainer")
        self.assertEqual(len(nb["out"]), 1)
        self.assertEqual(len(nb["in"]), 0)

    def test_errors_and_permissions(self):
        with self.assertRaises(GraphSnapError):
            self.gs.load("")
        with self.assertRaises(PermissionError):
            self.gs.snapshot(Session(None, "x", "bogus", ["local-lab"], "t"))
        s = self.gs.snapshot(_session(), run="run-g1")
        with self.assertRaises(GraphSnapError):
            self.gs.load("gs-nope")


if __name__ == "__main__":
    unittest.main()
