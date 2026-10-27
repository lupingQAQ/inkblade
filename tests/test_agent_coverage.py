# -*- coding: utf-8 -*-
"""Coverage graph, closure criteria, proof and scheduler/objective integration."""
from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tests.agent_fixture import ROOT  # noqa: F401 - path setup
from inkblade.agent.coverage import (CoverageEvidenceRequired, CoverageGraph,
                                     CoverageLoopError, CoverageScheduler,
                                     CoverageSupervisor, attach_coverage,
                                     render_markdown)
from inkblade.agent.graph import PlanGraph
from inkblade.agent.objectives import get_objective
from inkblade.agent.runtime import Budget
from inkblade.agent.scheduler import TaskScheduler


def sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def covered_graph() -> tuple[CoverageGraph, PlanGraph, dict]:
    cov = CoverageGraph(objective="read-only-recon")
    graph = PlanGraph(objective="read-only-recon")
    cov.add_asset("asset:prod/api", cluster_id="prod", kind="workload",
                  name="api", namespace="train", address="10.0.0.5:8080")
    cov.add_service("svc:prod/api", cluster_id="prod", asset_id="asset:prod/api",
                    name="api", namespace="train", port=8080,
                    address="10.0.0.5:8080")
    cov.add_identity("sa:prod/agent", cluster_id="prod", name="agent",
                     namespace="train")
    cov.add_permission("sa:prod/agent", "asset:prod/api", verb="get",
                       resource="secrets", scope="train")
    cov.register_probe("probe-a", cluster_id="prod")
    cov.mark_baseline("probe-a", ok=True, evidence=sha("baseline"))
    cov.mark_check("asset:prod/api", probe_id="probe-a", module="recon",
                   mode="probe", ok=True, evidence=sha("check-asset"),
                   template="recon")
    cov.mark_check("svc:prod/api", probe_id="probe-a", module="exposure",
                   mode="probe", ok=True, evidence=sha("check-service"),
                   template="exposure")
    edge = [e for e in cov.edges() if e["relation"] == "can"][0]
    return cov, graph, edge


class CoverageClosureTest(unittest.TestCase):
    def test_four_criteria_and_closure(self):
        cov, graph, edge = covered_graph()
        initial = cov.evaluate(graph=graph)
        self.assertEqual(len(initial["criteria"]), 4)
        self.assertTrue(initial["criteria"][0]["ok"])
        self.assertFalse(initial["criteria"][1]["ok"])
        self.assertTrue(initial["criteria"][2]["ok"])
        self.assertTrue(initial["criteria"][3]["ok"])
        self.assertFalse(initial["closed"])
        self.assertEqual(initial["stop_reason"], "frontier-open")
        self.assertTrue(any(g["reason"] == "unattempted-exploitable-edge"
                            for g in initial["gaps"]))

        cov.mark_permission_attempt(edge["id"], outcome="blocked",
                                    reason="RBAC denies secrets in train")
        closed = cov.evaluate(graph=graph)
        self.assertTrue(closed["closed"], closed)
        self.assertTrue(closed["success"])
        self.assertEqual(closed["stop_reason"], "closed")
        self.assertEqual(closed["gaps"], [])

        intent = graph.add_intent("recon", "more", priority=5)
        open_graph = cov.evaluate(graph=graph)
        self.assertFalse(open_graph["criteria"][3]["ok"])
        self.assertFalse(open_graph["closed"])
        self.assertTrue(any(g["kind"] == "intent" for g in open_graph["gaps"]))
        graph.block(intent["id"], "operator accepted the residual risk")
        self.assertTrue(cov.evaluate(graph=graph)["closed"])

    def test_check_and_attempt_evidence_rules(self):
        cov = CoverageGraph()
        cov.add_asset("asset:a", cluster_id="c1")
        cov.register_probe("p1", cluster_id="c1")
        with self.assertRaises(CoverageEvidenceRequired):
            cov.mark_check("asset:a", probe_id="p1", ok=True, evidence="")
        with self.assertRaises(CoverageEvidenceRequired):
            cov.mark_check("asset:a", probe_id="p1", ok=False)
        failed = cov.mark_check("asset:a", probe_id="p1", ok=False,
                                detail="connection refused", template="recon")
        self.assertFalse(failed["ok"])
        cov.add_identity("sa:c1/agent", cluster_id="c1")
        cov.add_permission("sa:c1/agent", "asset:a", verb="create",
                           resource="pods", scope="c1")
        edge = [e for e in cov.edges() if e["relation"] == "can"][0]
        with self.assertRaises(CoverageEvidenceRequired):
            cov.mark_permission_attempt(edge["id"], outcome="success")
        with self.assertRaises(CoverageEvidenceRequired):
            cov.mark_permission_attempt(edge["id"], outcome="failed")
        rec = cov.mark_permission_attempt(edge["id"], outcome="failed",
                                          reason="403 Forbidden")
        self.assertEqual(rec["outcome"], "failed")
        self.assertTrue(cov.edges(relation="can")[0]["attempted"])

    def test_probe_registration_baseline_and_parent_loop(self):
        cov = CoverageGraph()
        cov.add_asset("asset:a", cluster_id="c1")
        cov.register_probe("p1", cluster_id="c1", registered=False)
        gaps = cov.frontier(include_unknown_frontier=False)
        self.assertTrue(any(g["reason"] == "probe-not-registered" for g in gaps))
        cov.register_probe("p1", cluster_id="c1")
        gaps = cov.frontier(include_unknown_frontier=False)
        self.assertTrue(any(g["reason"] == "baseline-collect-missing" for g in gaps))
        cov.register_probe("p2", cluster_id="c1", parent_id="p1")
        with self.assertRaises(CoverageLoopError):
            cov.register_probe("p1", cluster_id="c1", parent_id="p2")
        with self.assertRaises(CoverageEvidenceRequired):
            cov.mark_baseline("p1", ok=True, evidence="")
        cov.mark_baseline("p1", ok=True, evidence=sha("baseline-1"))
        cov.mark_baseline("p2", ok=True, evidence=sha("baseline-2"))
        gaps = [g for g in cov.frontier(include_unknown_frontier=False)
                if g["kind"] == "probe"]
        self.assertEqual(gaps, [])
        self.assertEqual(cov.coverage()["baselined_probes"], 2)

    def test_proof_json_and_markdown(self):
        cov, graph, edge = covered_graph()
        cov.mark_permission_attempt(edge["id"], outcome="blocked",
                                    reason="RBAC denies secrets in train")
        budget = Budget(tokens=1000, steps=10, actions=10)
        proof = cov.proof(graph=graph, budget=budget, run_id="run-demo")
        self.assertEqual(proof["schema"], "inkblade-coverage-proof/1")
        self.assertTrue(proof["closed"])
        self.assertEqual(len(proof["criteria"]), 4)
        self.assertIn("state", proof)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "coverage-proof.json"
            cov.write_proof(path, proof=proof)
            loaded = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(loaded["run_id"], "run-demo")
            self.assertEqual(loaded["coverage"]["checked_assets"], 2)
            restored = CoverageGraph.from_proof(loaded)
            self.assertTrue(restored.evaluate(graph=graph)["closed"])
            md = render_markdown(loaded)
            self.assertIn("四条闭包判据", md)
            self.assertIn("证据 / 限制", md)
            self.assertIn("coverage:assets", md)

    def test_budget_exhaustion_keeps_gap_list(self):
        cov = CoverageGraph()
        cov.add_asset("asset:a", cluster_id="c1")
        cov.add_identity("sa:c1/agent", cluster_id="c1")
        cov.add_permission("sa:c1/agent", "asset:a", verb="get",
                           resource="secrets")
        budget = Budget(steps=1)
        budget.consume("steps", 1)
        evaluation = cov.evaluate(graph=PlanGraph(), budget=budget)
        self.assertEqual(evaluation["stop_reason"], "budget-exhausted")
        self.assertFalse(evaluation["closed"])
        reasons = {g["reason"] for g in evaluation["gaps"]}
        self.assertIn("unchecked-reachable-asset", reasons)
        self.assertIn("unattempted-exploitable-edge", reasons)
        proof = cov.proof(graph=PlanGraph(), budget=budget)
        self.assertEqual(proof["stop_reason"], "budget-exhausted")
        self.assertTrue(proof["gaps"])
        self.assertEqual(proof["gap_counts"]["unchecked-reachable-asset"], 1)


class CoverageIntegrationTest(unittest.TestCase):
    def test_objective_refuses_success_until_closed(self):
        objective = get_objective("read-only-recon")
        graph = PlanGraph(objective="read-only-recon")
        evidence = graph.add_evidence(sha("fact"))
        graph.add_fact("asset", status="confirmed", kind="asset",
                       evidence=[evidence["id"]], severity="info")
        graph.add_fact("exposure", status="confirmed", kind="exposure",
                       evidence=[evidence["id"]], severity="medium")
        graph.add_fact("rbac", status="confirmed", kind="rbac",
                       evidence=[evidence["id"]], severity="medium")
        report = graph.add_intent("report", "agent-report", probe=False)
        graph.complete(report["id"], evidence=[])

        cov = CoverageGraph()
        cov.add_asset("asset:prod/api", cluster_id="prod", kind="workload")
        result = objective.evaluate(graph, coverage=cov)
        self.assertFalse(result["success"])
        self.assertIn("coverage:closure", result["missing"])
        cov.mark_check("asset:prod/api", mode="read-only", ok=True,
                       evidence=sha("read-only-check"), template="recon")
        result = objective.evaluate(graph, coverage=cov)
        self.assertTrue(result["success"], result)

    def test_scheduler_prioritises_uncovered_refs(self):
        cov = CoverageGraph()
        cov.add_asset("asset:prod/api", cluster_id="prod", kind="workload")
        graph = PlanGraph()
        graph.add_intent("recon", "plain", priority=9)
        graph.add_intent("recon", "cover", priority=1,
                         tags=["coverage:asset:prod/api"])
        scheduler = CoverageScheduler(graph, Budget(steps=5), coverage=cov)
        first = scheduler.claim_next("w1")
        self.assertEqual(first["module"], "cover")
        cov.mark_check("asset:prod/api", mode="read-only", ok=True,
                       evidence=sha("covered"))
        second = scheduler.claim_next("w2")
        self.assertEqual(second["module"], "plain")
        # Plain TaskScheduler still prefers the higher priority intent.
        plain_graph = PlanGraph()
        plain_graph.add_intent("recon", "plain", priority=9)
        plain_graph.add_intent("recon", "cover", priority=1)
        plain = TaskScheduler(plain_graph, Budget(steps=5))
        self.assertEqual(plain.claim_next("w1")["module"], "plain")

    def test_attach_coverage_wraps_existing_supervisor(self):
        # A minimal duck-typed supervisor is enough to prove the adapter keeps
        # the base objective and rebuilds the scheduler with coverage priority.
        from inkblade.agent.objectives import get_objective as get_obj

        objective = get_obj("read-only-recon")
        graph = PlanGraph(objective="read-only-recon")
        cov = CoverageGraph(objective="read-only-recon")

        class Dummy:
            pass

        dummy = Dummy()
        dummy.objective = objective
        dummy.graph = graph
        dummy.coverage = None
        dummy.scheduler = TaskScheduler(graph, Budget(steps=5))
        dummy.runtime = Dummy()
        dummy.runtime.run_id = "dummy-run"
        attach_coverage(dummy, cov)
        self.assertIs(dummy._base_objective, objective)
        self.assertIsInstance(dummy.scheduler, CoverageScheduler)
        self.assertIs(dummy.scheduler.coverage, cov)
        self.assertFalse(dummy.objective.success(graph))

    def test_supervisor_never_claims_unclosed_success(self):
        from tests.agent_fixture import (golden_script, make_lab,
                                         supervisor_kwargs)

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            store, session, modules, rng, k8s = make_lab(tmp_path)
            cov = CoverageGraph(objective="cluster-takeover")
            cov.add_asset("asset:uncovered", cluster_id="lab", kind="workload",
                          name="uncovered", namespace="train")
            try:
                sup = CoverageSupervisor.create(
                    store, session, coverage=cov,
                    **supervisor_kwargs(tmp_path, modules, rng, k8s,
                                        script=golden_script(rng.url())))
                result = sup.run()
            finally:
                rng.stop()
            self.assertEqual(result["status"], "coverage-gap", result)
            self.assertFalse(result["success"])
            self.assertTrue(result["gaps"])
            self.assertTrue(any(g["reason"] == "unchecked-reachable-asset"
                                for g in result["gaps"]))
            proof_path = Path(sup.runtime.dir) / "coverage-proof.json"
            self.assertTrue(proof_path.is_file())
            proof = json.loads(proof_path.read_text(encoding="utf-8"))
            self.assertFalse(proof["closed"])
            self.assertEqual(proof["stop_reason"], "frontier-open")
            self.assertIn("coverage.proof",
                          [e["kind"] for e in sup.runtime.events()])
            # the base objective did succeed; only closure blocked success
            self.assertTrue(result["objective_eval"]["success"] is False)
            self.assertTrue(result["objective_eval"]["missing"])

            import contextlib
            import io

            from inkblade.cli import main

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                code = main(["--home", str(tmp_path), "agent", "coverage",
                             "status", "--workspace", "lab",
                             "--run-id", sup.runtime.run_id])
            self.assertEqual(code, 0, buf.getvalue())
            cli_doc = json.loads(buf.getvalue())
            self.assertFalse(cli_doc["closed"])
            self.assertTrue(cli_doc["gaps"])

    def test_supervisor_budget_exhaustion_emits_gaps(self):
        from tests.agent_fixture import (golden_script, make_lab,
                                         supervisor_kwargs)

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            store, session, modules, rng, k8s = make_lab(tmp_path)
            cov = CoverageGraph(objective="cluster-takeover")
            cov.add_asset("asset:uncovered", cluster_id="lab", kind="workload",
                          name="uncovered", namespace="train")
            try:
                sup = CoverageSupervisor.create(
                    store, session, coverage=cov,
                    **supervisor_kwargs(tmp_path, modules, rng, k8s,
                                        script=golden_script(rng.url()),
                                        budgets={"tokens": 2000, "steps": 2,
                                                 "actions": 2,
                                                 "duration_ms": 120000}))
                result = sup.run()
            finally:
                rng.stop()
            self.assertEqual(result["status"], "budget-exceeded", result)
            self.assertTrue(result["coverage_gaps"])
            self.assertTrue(any(g["reason"] == "unchecked-reachable-asset"
                                for g in result["coverage_gaps"]))


if __name__ == "__main__":
    unittest.main()
