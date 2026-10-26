"""提权图：真实快照推断主体、最短路径、加权/跳数、解释与人话报告、evidence 联动。"""

from __future__ import annotations

import json
import shutil
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.core.discovery import AssetInventory
from inkblade.core.evidence import EvidenceStore
from inkblade.core.privesc import (
    PrivescGraph,
    UnknownPrincipal,
    explain,
    infer_principals,
    load_matrix,
    load_snapshot,
    load_snapshot_from_evidence,
    paths_from_evidence,
    render_privesc_section,
)

REPO = Path(__file__).resolve().parents[1]
FIXTURES = REPO / "lab" / "fixtures" / "privesc"


class TestPrivescGraph(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.matrix = load_matrix()
        cls.snapshot = load_snapshot(FIXTURES / "rbac.json")
        cls.graph = PrivescGraph(cls.matrix, snapshot=cls.snapshot)

    def test_principals_inferred_from_rbac_fixture(self):
        principals = infer_principals(self.snapshot)
        ids = {p.id for p in principals}
        for subject in (
            "system:serviceaccount:privesc-lab:esc-sa",
            "system:serviceaccount:privesc-lab:bind-sa",
            "system:serviceaccount:privesc-lab:imp-sa",
            "system:serviceaccount:privesc-lab:token-sa",
            "user:privesc-superuser",
        ):
            self.assertIn(subject, ids, f"未从快照推断出 {subject}")
        esc = next(p for p in principals if p.id.endswith(":esc-sa"))
        self.assertTrue(any("rbac-escalate" in c for c in esc.capabilities), esc.capabilities)
        admin = next(p for p in principals if p.id.endswith("privesc-superuser"))
        self.assertTrue(admin.cluster_admin, admin)

    def test_paths_to_cluster_admin_for_four_primitives(self):
        cases = {
            "system:serviceaccount:privesc-lab:esc-sa": "rbac-escalate-verb",
            "system:serviceaccount:privesc-lab:bind-sa": "rbac-bind-verb",
            "system:serviceaccount:privesc-lab:imp-sa": "rbac-impersonate",
            "system:serviceaccount:privesc-lab:token-sa": "rbac-sa-token-request",
        }
        for subject, vector in cases.items():
            with self.subTest(subject=subject):
                paths = self.graph.paths(subject, to="cluster-admin", limit=5)
                self.assertTrue(paths, f"{subject} 没有到 cluster-admin 的路径")
                self.assertIn(vector, paths[0].vector_ids, paths[0].vector_ids)
                text = explain(paths[0])
                self.assertIn(vector, text)
                self.assertIn("检测", text)
                self.assertIn("cluster-admin", text)

    def test_shortest_weight_and_hops_are_stable(self):
        subject = "system:serviceaccount:privesc-lab:token-sa"
        weighted = self.graph.paths(subject, limit=5, mode="weight")
        hops = self.graph.paths(subject, limit=5, mode="hops")
        self.assertEqual(weighted[0].vector_ids, self.graph.paths(subject, limit=5)[0].vector_ids)
        self.assertLessEqual(hops[0].hops, weighted[0].hops)
        self.assertEqual(hops[0].to_dict(), self.graph.paths(subject, limit=5, mode="hops")[0].to_dict())

    def test_direct_admin_is_zero_hop(self):
        paths = self.graph.paths("user:privesc-superuser", to="cluster-admin")
        self.assertTrue(paths)
        self.assertEqual(paths[0].hops, 0)
        self.assertIn("已具备", explain(paths[0]))

    def test_cloud_target_path(self):
        snap = {
            "cani": [
                {"subject": "system:serviceaccount:train:pod-sa", "allowed": ["get 169.254.169.254", "imds"]},
            ]
        }
        graph = PrivescGraph(self.matrix, snapshot=snap)
        paths = graph.paths("system:serviceaccount:train:pod-sa", to="cloud-admin")
        self.assertTrue(paths, "IMDS 主体应能到达 cloud-admin")
        self.assertIn("cred-cloud-imds", paths[0].vector_ids)

    def test_unknown_principal_has_suggestions(self):
        with self.assertRaises(UnknownPrincipal) as cm:
            self.graph.paths("system:serviceaccount:nope:ghost")
        self.assertIn("esc-sa", str(cm.exception))

    def test_section_and_mermaid(self):
        path = self.graph.paths("system:serviceaccount:privesc-lab:esc-sa")[0]
        section = render_privesc_section(self.matrix, [path], principal=path.nodes[0].id)
        joined = "\n".join(section)
        self.assertIn("提权面", joined)
        self.assertIn("提权路径图", joined)
        self.assertIn("选择依据", joined)
        self.assertIn("flowchart", joined)
        self.assertIn("rbac-escalate-verb", joined)


class TestEvidenceLink(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = EvidenceStore(self.root, workspace="privesc-lab")

    def tearDown(self):
        self.tmp.cleanup()

    def test_snapshot_loaded_from_evidence_artifacts(self):
        run = self.store.create_run("privesc-evidence")
        art = self.root / "snapshot.json"
        shutil.copyfile(FIXTURES / "rbac.json", art)
        run.add_step("snapshot", "kubectl get -o json", {}, "snapshot", artifacts=[art])
        run.finalize_run()
        snapshot = load_snapshot_from_evidence(self.store, run.name)
        self.assertIn("clusterroles", snapshot)
        graph = PrivescGraph(load_matrix(), snapshot=snapshot)
        paths = paths_from_evidence(
            self.store, run.name, "system:serviceaccount:privesc-lab:bind-sa")
        self.assertTrue(paths)
        self.assertIn("rbac-bind-verb", paths[0].vector_ids)
        self.assertIn(graph.nodes["target:cluster-admin"].kind, ("target", "cloud"))

    def test_asset_inventory_is_attached(self):
        inv = AssetInventory(self.store)
        inv.ingest({
            "services": [{"product": "ray", "name": "ray-dashboard",
                          "namespace": "ray-system", "addr": "10.0.0.5", "port": 8265}],
        })
        run = self.store.create_run("privesc-assets")
        art = self.root / "snapshot.json"
        shutil.copyfile(FIXTURES / "rbac.json", art)
        run.add_step("snapshot", "kubectl get -o json", {}, "snapshot", artifacts=[art])
        run.finalize_run()
        snapshot = load_snapshot_from_evidence(self.store, run.name)
        self.assertEqual(len(snapshot["assets"]), 1)
        self.assertEqual(snapshot["assets"][0]["product"], "ray")
        self.assertEqual(AssetInventory(self.store).count(), 1)


if __name__ == "__main__":
    unittest.main()
