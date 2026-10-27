# -*- coding: utf-8 -*-
"""Objective orchestrator tests: three gates, staged confirmation, timeout,
emergency stop, evidence layers, PROOF hashes and cleanup verification.

The cluster backend used here is the explicit ``fake-kubectl`` fixture
(``FakeKubectlBackend``); the real QEMU k3s run is covered by
``lab/qemu-k3s/kill_chain_lab.py`` and the recorded sample artifacts.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.core.abort import request_abort
from inkblade.core.evidence import EvidenceStore
from inkblade.core.objective import (
    CHAIN_ID,
    FakeKubectlBackend,
    GateRefused,
    check_gates,
    load_objective,
    render_report,
    run_objective,
)
from inkblade.core.roe import init_roe
from inkblade.core.users import Session

REPO = Path(__file__).resolve().parents[1]
CHAINS = REPO / "inkblade" / "chains"


def _session(role: str = "lead") -> Session:
    return Session(None, f"{role}-user", role, ["local-lab"], "test-token")


def _canonical(doc: dict) -> str:
    body = {k: v for k, v in doc.items() if k != "hashes"}
    body["hashes"] = {k: v for k, v in doc["hashes"].items() if k != "proof_sha256"}
    return json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


CI_SLOW_WINDOWS = os.name == "nt" and bool(os.environ.get("CI"))


class ObjectiveBase(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.store = EvidenceStore(self.home, workspace="local-lab")
        init_roe(self.store, {
            "level": "全影响演示",
            "namespaces": ["inkblade-killchain"],
            "cidrs": ["127.0.0.1/32", "10.0.0.0/8"],
            "window": "2026-01-01 – 2026-12-31",
        })
        self.session = _session()
        self.chain = load_objective(CHAINS)

    def tearDown(self):
        self.tmp.cleanup()


class TestObjectiveDefinition(ObjectiveBase):
    def test_seven_stages_with_required_fields(self):
        stages = self.chain["objective"]["stages"]
        self.assertEqual(len(stages), 7)
        self.assertEqual([s["index"] for s in stages], list(range(1, 8)))
        for stage in stages:
            for key in ("id", "module", "title", "primitive", "preconditions",
                        "backup_targets", "success_evidence", "fallback",
                        "timeout_s", "detection_rules"):
                self.assertIn(key, stage, f"{stage.get('id')} missing {key}")
            self.assertTrue(stage["preconditions"])
            self.assertTrue(stage["success_evidence"])
            self.assertTrue(stage["fallback"])
            self.assertTrue(stage["detection_rules"])
            self.assertGreater(stage["timeout_s"], 0)
        # write stages must declare backups; cleanup must snapshot every created class
        for stage in stages:
            if stage["writes"]:
                self.assertTrue(stage["backup_targets"], f"{stage['id']} write without backup")
        self.assertTrue(stages[4]["backup_targets"][0]["kind"] == "node-file")
        self.assertTrue(any(t["kind"] == "node-file" for t in stages[6]["backup_targets"]))
        # hardware/switch planes are explicitly version-gated read-only
        gates = self.chain["objective"]["hardware_gates"]
        self.assertTrue(gates)
        for gate in gates:
            self.assertEqual(gate["max_action"], "只读")
            self.assertIn("read-only", gate["status"])

    def test_chain_catalog_still_valid(self):
        from inkblade.core.chains import load_chains

        chains = load_chains(CHAINS)
        self.assertIn(CHAIN_ID, chains)
        self.assertEqual(len(chains[CHAIN_ID]["steps"]), 7)


class TestGates(ObjectiveBase):
    def test_missing_consent_refused(self):
        store = EvidenceStore(self.home, workspace="no-consent")
        with self.assertRaises(GateRefused) as ctx:
            check_gates(store, self.session, self.chain, "inkblade-killchain")
        self.assertEqual(ctx.exception.exit_code, 91)
        self.assertIn("授权", str(ctx.exception))

    def test_level_below_full_impact_refused(self):
        store = EvidenceStore(self.home, workspace="low-level")
        init_roe(store, {"level": "利用验证", "namespaces": ["inkblade-killchain"],
                         "cidrs": ["127.0.0.1/32"]})
        with self.assertRaises(GateRefused) as ctx:
            check_gates(store, self.session, self.chain, "inkblade-killchain")
        self.assertIn("全影响演示", str(ctx.exception))

    def test_namespace_out_of_scope_refused(self):
        with self.assertRaises(GateRefused) as ctx:
            check_gates(self.store, self.session, self.chain, "kube-system")
        self.assertIn("范围", str(ctx.exception))

    def test_auto_approve_only_for_lead_full_impact(self):
        with self.assertRaises(GateRefused):
            check_gates(self.store, _session("tester"), self.chain, "inkblade-killchain",
                        auto_approve=True)
        gates = check_gates(self.store, self.session, self.chain, "inkblade-killchain",
                            auto_approve=True)
        self.assertTrue(gates["auto_approve_allowed"])
        self.assertTrue(all(g["status"] == "pass" for g in gates["gates"]))

    def test_missing_backup_targets_refused(self):
        chain = json.loads(json.dumps(self.chain))
        for stage in chain["objective"]["stages"]:
            if stage["index"] == 3:
                stage["backup_targets"] = []
        with self.assertRaises(GateRefused) as ctx:
            check_gates(self.store, self.session, chain, "inkblade-killchain")
        self.assertIn("备份", str(ctx.exception))

    def test_emergency_stop_refused(self):
        request_abort(self.store, "lead-user", "test stop")
        with self.assertRaises(GateRefused) as ctx:
            check_gates(self.store, self.session, self.chain, "inkblade-killchain")
        self.assertIn("紧急停止", str(ctx.exception))


class TestExecution(ObjectiveBase):
    def test_full_chain_proof_and_cleanup(self):
        backend = FakeKubectlBackend()
        before_pods = len(backend.state["pods"])
        out = self.home / "out"
        started = time.time()
        result = run_objective(
            self.store, self.session, self.chain, backend,
            proof_marker="unit-full", namespace="inkblade-killchain",
            auto_approve=True, out_dir=out,
        )
        self.assertTrue(result["ok"], json.dumps(result, ensure_ascii=False)[:2000])
        self.assertTrue(result["complete"])
        self.assertGreaterEqual(len(result["stages"]), 7)
        self.assertEqual([s["index"] for s in result["stages"] if s["status"] == "success"],
                         list(range(1, 8)))
        proof = result["proof"]
        self.assertEqual(proof["marker"], "unit-full")
        self.assertEqual(proof["highest_privilege"]["rbac"]["role"], "cluster-admin")
        self.assertTrue(proof["highest_privilege"]["node_root"]["verified"])
        self.assertGreater(proof["highest_privilege"]["cluster_secrets"]["count"], 0)
        self.assertTrue(proof["highest_privilege"]["test_namespace"]["created"])
        self.assertTrue(proof["highest_privilege"]["test_configmap"]["read_back"])
        self.assertTrue(proof["cleanup"]["verified"])
        self.assertEqual(proof["cleanup"]["residue"], [])
        # cluster-level action list + hashes
        verbs = {(a["verb"], a["resource"]) for a in proof["cluster_actions"]}
        self.assertIn(("create", "clusterrolebinding"), verbs)
        self.assertIn(("create", "namespace"), verbs)
        self.assertIn(("delete", "namespace"), verbs)
        self.assertTrue(proof["hashes"]["proof_sha256"])
        self.assertEqual(hashlib.sha256(_canonical(proof).encode("utf-8")).hexdigest(),
                         proof["hashes"]["proof_sha256"])
        # proof file + three evidence layers
        saved = json.loads((out / "proof.json").read_text(encoding="utf-8"))
        self.assertEqual(saved["hashes"]["proof_sha256"], proof["hashes"]["proof_sha256"])
        run = self.store.open_run(result["run"])
        self.assertGreaterEqual(len(run.query("SELECT * FROM steps")), 8)
        self.assertTrue((run.dir / "context.jsonl.gz").is_file())
        self.assertTrue((run.dir / "manifest.sha256").is_file())
        self.assertTrue((run.dir / "objective-proof.json").is_file())
        self.assertGreaterEqual(len(run.findings), 5)
        # idempotent cleanup: no test ns, no pwn objects, no node file
        self.assertNotIn("inkblade-proof-unit-full", backend.state["namespaces"])
        self.assertFalse(any("inkblade-pwn" in k for k in backend.state["clusterrolebindings"]))
        self.assertFalse(any("inkblade-pwn" in k for k in backend.state["rolebindings"]))
        self.assertEqual(backend.node_files, {})
        # entry service was pre-existing and must not be deleted
        self.assertIn("inkblade-proof/mock-target", backend.state["services"])
        self.assertLess(time.time() - started, 20)

    def test_partial_run_forces_cleanup(self):
        backend = FakeKubectlBackend()
        result = run_objective(
            self.store, self.session, self.chain, backend,
            proof_marker="unit-partial", auto_approve=True, max_stage=2,
        )
        self.assertTrue(result["ok"])
        self.assertFalse(result["complete"])
        self.assertEqual([s["index"] for s in result["stages"]
                          if s["status"] == "success" and s["index"] < 7], [1, 2])
        self.assertEqual(result["stages"][-1]["index"], 7)
        self.assertTrue(result["proof"]["cleanup"]["verified"])
        self.assertEqual(result["proof"]["cleanup"]["residue"], [])
        self.assertEqual(backend.node_files, {})

    def test_stage_confirmation_refusal_cancels_and_cleans(self):
        backend = FakeKubectlBackend()
        seen: list[int] = []

        def confirm(stage: dict) -> bool:
            seen.append(stage["index"])
            return stage["index"] != 3

        result = run_objective(
            self.store, self.session, self.chain, backend,
            proof_marker="unit-cancel", auto_approve=False, confirm=confirm,
        )
        self.assertTrue(result["cancelled"])
        self.assertFalse(result["ok"])
        self.assertEqual(seen, [1, 2, 3])
        self.assertTrue(result["proof"]["cleanup"]["verified"])
        self.assertEqual(result["proof"]["cleanup"]["residue"], [])

    @unittest.skipIf(CI_SLOW_WINDOWS, "wall-clock scheduling assertions are unreliable on shared Windows CI")
    def test_stage_timeout_fails_and_cleans(self):
        backend = FakeKubectlBackend(slow_stages={"stage-4-privileged-pod": 0.25})
        result = run_objective(
            self.store, self.session, self.chain, backend,
            proof_marker="unit-timeout", auto_approve=True, stage_timeout=0.15,
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["failed_stage"], "stage-4-privileged-pod")
        self.assertIn("timeout", (result.get("error") or "").lower())
        self.assertTrue(result["proof"]["cleanup"]["verified"])
        self.assertEqual(backend.node_files, {})

    def test_dry_run_has_no_mutation(self):
        backend = FakeKubectlBackend()
        pods_before = len(backend.state["pods"])
        result = run_objective(
            self.store, self.session, self.chain, backend,
            proof_marker="unit-dry", auto_approve=False, dry_run=True,
        )
        self.assertTrue(result["dry_run"])
        self.assertEqual(len(result["stages"]), 7)
        self.assertEqual(result["gates"]["auto_approve_allowed"], True)
        self.assertEqual(len(backend.state["pods"]), pods_before)
        self.assertEqual(backend.calls, [])

    def test_report_bilingual_and_cleanup_statement(self):
        result = run_objective(
            self.store, self.session, self.chain, FakeKubectlBackend(),
            proof_marker="unit-report", auto_approve=True,
        )
        text = render_report(result["proof"], lang="bi")
        for token in ("最高权限证明", "Highest-Privilege Proof", "已清理",
                      "Cleanup", "proof_sha256", "cluster-admin"):
            self.assertIn(token, text)
        self.assertNotIn("fake-token-", text)


class TestObjectiveCli(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.home = Path(self.tmp.name)
        store = EvidenceStore(self.home, workspace="local-lab")
        init_roe(store, {"level": "全影响演示",
                         "namespaces": ["inkblade-killchain"],
                         "cidrs": ["127.0.0.1/32"]})

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, *args: str):
        import subprocess
        import sys
        return subprocess.run([sys.executable, "-m", "inkblade", "--home", str(self.home), *args],
                              cwd=str(REPO), capture_output=True, timeout=120)

    def test_cli_dry_run_then_fake_run(self):
        out = self.home / "out"
        r = self._run("objective", "cluster-takeover", "--workspace", "local-lab",
                      "--proof-marker", "cli-dry", "--dry-run", "--backend", "fake")
        self.assertEqual(r.returncode, 0, r.stderr.decode("utf-8", "replace"))
        dry = json.loads(r.stdout.decode("utf-8"))
        self.assertTrue(dry["dry_run"])
        self.assertEqual(len(dry["stages"]), 7)
        r = self._run("objective", "cluster-takeover", "--workspace", "local-lab",
                      "--proof-marker", "cli-full", "--auto-approve", "--backend", "fake",
                      "--out", str(out))
        self.assertEqual(r.returncode, 0, r.stderr.decode("utf-8", "replace"))
        body = json.loads(r.stdout.decode("utf-8"))
        self.assertTrue(body["ok"])
        self.assertTrue(body["proof"]["cleanup"]["verified"])
        self.assertTrue((out / "proof.json").is_file())

    def test_cli_auto_approve_tester_refused(self):
        r = self._run("objective", "cluster-takeover", "--workspace", "local-lab",
                      "--proof-marker", "cli-refuse", "--auto-approve",
                      "--backend", "fake", "--role", "tester")
        self.assertEqual(r.returncode, 91)
        self.assertIn("auto-approve", r.stderr.decode("utf-8", "replace"))


if __name__ == "__main__":
    unittest.main()
