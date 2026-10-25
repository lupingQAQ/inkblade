# -*- coding: utf-8 -*-
"""Kill-chain deliverables: chain shape, per-stage rules, docs and real PROOF."""

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from trident.core.objective import CHAIN_ID, load_objective
from trident.rules.generate import generate_all
from trident.rules.validate import rule_fires, validate

REPO = Path(__file__).resolve().parents[1]
CHAINS = REPO / "trident" / "chains"
SAMPLES = REPO / "reports" / "samples" / "kill-chain"
DOC = REPO / "docs" / "KILL-CHAIN.md"
LAB = REPO / "lab" / "qemu-k3s"


class KillChainDefinitionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.chain = load_objective(CHAINS)
        cls.stages = cls.chain["objective"]["stages"]

    def test_stage_matrix_and_hardware_gate(self):
        self.assertEqual(len(self.stages), 7)
        for stage in self.stages:
            self.assertTrue(stage["detection_rules"], stage["id"])
            self.assertTrue(stage["preconditions"])
            self.assertTrue(stage["success_evidence"])
            self.assertTrue(stage["fallback"])
            if stage["writes"]:
                self.assertTrue(stage["backup_targets"], stage["id"])
        self.assertTrue(any(t["kind"] == "kube" for t in self.stages[2]["backup_targets"]))
        self.assertTrue(any(t["kind"] == "node-file" for t in self.stages[4]["backup_targets"]))
        gates = self.chain["objective"]["hardware_gates"]
        self.assertTrue(gates and all(g["max_action"] == "只读" for g in gates))

    def test_lab_fixture_and_runner_exist(self):
        for rel in ("manifests/40-killchain-operator.yaml",
                    "manifests/41-killchain-entry.yaml",
                    "kill_chain_lab.py",
                    "run-kill-chain.ps1"):
            path = LAB / rel
            self.assertTrue(path.is_file(), f"missing lab artifact {rel}")
            self.assertGreater(path.stat().st_size, 200, f"{rel} looks like a stub")
        fixture = (LAB / "manifests" / "40-killchain-operator.yaml").read_text(encoding="utf-8")
        self.assertIn("trident-operator", fixture)
        self.assertIn("rbac.authorization.k8s.io", fixture)
        self.assertIn("ClusterRoleBinding", fixture)


class KillChainRulesTest(unittest.TestCase):
    def test_each_stage_rule_has_purple_hit(self):
        with TemporaryDirectory() as tmp:
            pack = generate_all(CHAINS, out_dir=tmp)
            root = Path(pack.out_dir)
            mapping = json.loads((root / "mapping.json").read_text(encoding="utf-8"))
            probes = json.loads((REPO / "trident/rules/templates/probes.json").read_text(
                encoding="utf-8"))["chains"][CHAIN_ID]
            fixtures = probes["fixtures"]
            self.assertGreaterEqual(len(fixtures), 7)
            rule_by_id = {r["id"]: r for r in mapping["rules"]}
            chain_rules = set(mapping["chains"][CHAIN_ID]["rules"])
            self.assertIn("sigma-cluster-takeover-entry", chain_rules)
            self.assertIn("falco-node-root-marker-write", chain_rules)
            self.assertIn("deny-privileged-pod", chain_rules)
            for stage in load_objective(CHAINS)["objective"]["stages"]:
                for rid in stage["detection_rules"]:
                    self.assertIn(rid, rule_by_id, f"{stage['id']} rule {rid} missing")
                self.assertTrue(any(rid in chain_rules for rid in stage["detection_rules"]),
                                stage["id"])
            # Sigma/Falco stage rules actually fire on the replay fixtures.
            for rid in ("sigma-cluster-takeover-entry", "sigma-cluster-token-harvest",
                        "sigma-cluster-rbac-takeover", "sigma-cluster-privileged-pod",
                        "sigma-cluster-proof-actions", "sigma-cluster-cleanup-trail",
                        "falco-node-root-marker-write"):
                self.assertTrue(rule_fires(rule_by_id[rid]["match"], fixtures),
                                f"{rid} did not fire on purple fixtures")
            # Full validator: this chain must have zero missed rules.
            matrix = validate(root, mock_base="http://127.0.0.1:9")
            row = matrix["chains"][CHAIN_ID]
            self.assertTrue(row["rules"])
            missed = [c for c in row["rules"] if c["status"] == "漏过"]
            self.assertEqual(missed, [], missed)
            states = {c["status"] for c in row["rules"]}
            self.assertIn("检测", states)
            self.assertIn("拦截", states)


class KillChainDocsAndProofTest(unittest.TestCase):
    def test_docs_cover_every_stage_and_boundary(self):
        self.assertTrue(DOC.is_file())
        text = DOC.read_text(encoding="utf-8")
        for stage in load_objective(CHAINS)["objective"]["stages"]:
            self.assertIn(stage["id"], text)
        for token in ("三闸门", "逐阶段", "阶段超时", "已清理", "硬件", "交换机", "fake-kubectl",
                      "proof_sha256", "边界"):
            self.assertIn(token, text)

    def test_real_proof_shape_and_cleanup(self):
        proof_path = SAMPLES / "proof.json"
        self.assertTrue(proof_path.is_file(), "real PROOF sample missing")
        proof = json.loads(proof_path.read_text(encoding="utf-8"))
        self.assertEqual(proof["chain"], CHAIN_ID)
        self.assertEqual(proof["backend"]["kind"], "kubectl")
        self.assertTrue(proof["backend"]["real_cluster"])
        self.assertTrue(proof["complete"])
        self.assertTrue(proof["cleanup"]["verified"])
        self.assertEqual(proof["cleanup"]["residue"], [])
        self.assertTrue(proof["cleanup"]["fixture_cleanup"])
        wrapper = json.loads((SAMPLES / "lab-wrapper.json").read_text(encoding="utf-8"))
        self.assertEqual(wrapper["fixture_namespace_absent"], True)
        hp = proof["highest_privilege"]
        self.assertEqual(hp["rbac"]["role"], "cluster-admin")
        self.assertTrue(hp["rbac"]["can_i"]["all"])
        self.assertTrue(hp["node_root"]["verified"])
        self.assertTrue(hp["node_root"]["sha256"])
        self.assertGreaterEqual(hp["cluster_secrets"]["count"], 1)
        self.assertTrue(hp["test_namespace"]["created"])
        self.assertTrue(hp["test_configmap"]["read_back"])
        actions = proof["cluster_actions"]
        self.assertTrue(any(a["verb"] == "create" and a["resource"] == "clusterrolebinding"
                            for a in actions))
        self.assertTrue(any(a["verb"] == "delete" and a["resource"] == "namespace"
                            for a in actions))
        self.assertEqual(proof["hashes"]["proof_sha256"],
                         hashlib.sha256(json.dumps(
                             {k: v for k, v in proof.items() if k != "hashes"}
                             | {"hashes": {k: v for k, v in proof["hashes"].items()
                                           if k != "proof_sha256"}},
                             ensure_ascii=False, sort_keys=True,
                             separators=(",", ":")).encode("utf-8")).hexdigest())
        # clean up stage artifacts were archived
        for stage in proof["stages"]:
            self.assertTrue(stage["artifact_sha256"], stage["id"])

    def test_bilingual_report_and_screenshot(self):
        report = (SAMPLES / "report.md").read_text(encoding="utf-8")
        for token in ("最高权限证明", "Highest-Privilege Proof", "已清理",
                      "Cleanup confirmed", "proof_sha256", "cluster-admin",
                      "集群级动作清单", "Screenshot"):
            self.assertIn(token, report)
        self.assertNotIn("fake-token-", report)
        png = SAMPLES / "proof.png"
        self.assertTrue(png.is_file(), "proof screenshot missing")
        sha = hashlib.sha256(png.read_bytes()).hexdigest()
        self.assertIn(sha, report)


if __name__ == "__main__":
    unittest.main()
