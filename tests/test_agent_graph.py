# -*- coding: utf-8 -*-
"""Graph/evidence-gate/objective unit tests."""
from __future__ import annotations

import unittest

from tests.agent_fixture import ROOT  # noqa: F401 - path setup
from inkblade.agent.graph import EvidenceRequired, GraphError, PlanGraph, replay_graph
from inkblade.agent.objectives import get_objective

SHA = "a" * 64
SHA2 = "b" * 64


class GraphTest(unittest.TestCase):
    def setUp(self):
        self.g = PlanGraph(objective="cluster-takeover")

    def test_confirmed_requires_probe_evidence(self):
        with self.assertRaises(EvidenceRequired):
            self.g.add_fact("no evidence", status="confirmed", kind="exposure")
        ev = self.g.add_evidence(SHA, run="r", step="m", source="probe",
                                 runtime="reference")
        fact = self.g.add_fact("exposure", status="confirmed", evidence=[ev["id"]],
                               kind="exposure", severity="high")
        self.assertEqual(fact["status"], "confirmed")
        self.assertEqual(self.g.evidence_coverage(), 1.0)

    def test_evidence_must_come_from_probe(self):
        with self.assertRaises(EvidenceRequired):
            self.g.add_evidence(SHA, source="llm")
        with self.assertRaises(EvidenceRequired):
            self.g.add_evidence("short", source="probe")

    def test_frontier_priority_cost_and_requires(self):
        fact = self.g.add_fact("exposure", status="hypothesis", kind="exposure",
                               severity="high")
        ev = self.g.add_evidence(SHA, run="r", step="m")
        self.g.confirm_fact(fact["id"], [ev["id"]])
        low = self.g.add_intent("recon", "low", priority=1, cost_tokens=10)
        high = self.g.add_intent("recon", "high", priority=9, cost_tokens=50)
        cheap = self.g.add_intent("recon", "cheap", priority=9, cost_tokens=5)
        with self.assertRaises(GraphError):
            self.g.add_intent("exploit", "blocked", priority=10,
                              requires=["missing"])
        # missing dependencies are rejected at add time
        self.assertFalse(any(i["id"] == "intent-4" for i in self.g.intents()))
        frontier = self.g.frontier()
        self.assertEqual(frontier[0]["module"], "cheap")
        self.assertEqual(frontier[1]["module"], "high")
        self.assertIn(low["id"], [i["id"] for i in frontier])

    def test_requires_fact_gate(self):
        fact = self.g.add_fact("rbac", status="hypothesis", kind="rbac")
        intent = self.g.add_intent("exploit", "escalate", requires=[fact["id"]])
        self.assertEqual(self.g.frontier(), [])
        ev = self.g.add_evidence(SHA, run="r", step="m")
        self.g.confirm_fact(fact["id"], [ev["id"]])
        self.assertEqual([i["id"] for i in self.g.frontier()], [intent["id"]])

    def test_lease_heartbeat_reclaim(self):
        intent = self.g.add_intent("recon", "probe", max_attempts=2)
        claimed = self.g.claim(intent["id"], "w1", lease_seconds=5, now=100)
        self.assertEqual(claimed["status"], "claimed")
        with self.assertRaises(GraphError):
            self.g.claim(intent["id"], "w2", lease_seconds=5, now=101)
        self.g.heartbeat(intent["id"], lease_seconds=10, now=101)
        self.assertEqual(self.g.reclaim_expired(now=105), [])
        reclaimed = self.g.reclaim_expired(now=112)
        self.assertEqual(len(reclaimed), 1)
        self.assertEqual(reclaimed[0]["status"], "open")

    def test_complete_probe_intent_needs_evidence(self):
        intent = self.g.add_intent("recon", "probe")
        self.g.claim(intent["id"], "w1", now=1)
        with self.assertRaises(EvidenceRequired):
            self.g.complete(intent["id"])
        ev = self.g.add_evidence(SHA, run="r", step="m")
        done = self.g.complete(intent["id"], evidence=[ev["id"]], result={"ok": True})
        self.assertEqual(done["status"], "done")

    def test_report_intent_can_complete_without_probe_evidence(self):
        intent = self.g.add_intent("report", "agent-report", probe=False)
        self.g.claim(intent["id"], "w1", now=1)
        done = self.g.complete(intent["id"], result={"report": "x"})
        self.assertEqual(done["status"], "done")

    def test_fail_retry_and_dead_letter(self):
        intent = self.g.add_intent("recon", "probe", max_attempts=2)
        self.g.claim(intent["id"], "w1", now=1)
        retry = self.g.fail(intent["id"], "transient", retryable=True, now=2,
                            backoff_seconds=0)
        self.assertEqual(retry["status"], "open")
        self.g.claim(intent["id"], "w1", now=3)
        failed = self.g.fail(intent["id"], "permanent", retryable=False, now=4)
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(failed["attempts"], 2)

    def test_graph_replay_roundtrip(self):
        ev = self.g.add_evidence(SHA, run="r", step="m")
        fact = self.g.add_fact("x", status="confirmed", evidence=[ev["id"]],
                               kind="exposure", severity="high")
        intent = self.g.add_intent("exploit", "m", requires=[fact["id"]])
        doc = self.g.to_dict()
        restored = PlanGraph.from_dict(doc)
        self.assertEqual(restored.summary()["edges"], self.g.summary()["edges"])
        self.assertEqual([i["id"] for i in restored.intents()], [intent["id"]])

    def test_event_folding(self):
        events = [
            {"kind": "graph.evidence.added", "payload": {"evidence": {
                "id": "ev-1", "sha256": SHA, "run": "r", "step": "m",
                "source": "probe", "runtime": "reference"}}},
            {"kind": "graph.fact.added", "payload": {"fact": {
                "id": "fact-1", "claim": "x", "status": "confirmed",
                "evidence": ["ev-1"], "fact_kind": "exposure", "severity": "high"}}},
            {"kind": "graph.intent.added", "payload": {"intent": {
                "id": "intent-1", "role": "exploit", "module": "m",
                "params": {}, "priority": 5, "requires": ["fact-1"]}}},
            {"kind": "intent.claimed", "payload": {"intent": "intent-1",
                                                   "owner": "w", "lease_until": 100}},
            {"kind": "intent.completed", "payload": {"intent": "intent-1",
                                                     "evidence": ["ev-1"], "result": {}}},
        ]
        graph = replay_graph(events)
        self.assertEqual(len(graph.confirmed_facts()), 1)
        self.assertEqual(graph.intents()[0]["status"], "done")


class ObjectiveTest(unittest.TestCase):
    def _graph(self, *, with_proof=True, with_cleanup=True, with_report=True):
        g = PlanGraph(objective="cluster-takeover")
        ev = g.add_evidence(SHA, run="r", step="m")
        for kind, sev in (("exposure", "high"), ("foothold", "high"),
                          ("privesc", "critical")):
            g.add_fact(kind, status="confirmed", evidence=[ev["id"]], kind=kind,
                       severity=sev)
        if with_proof:
            g.add_fact("takeover", status="confirmed", evidence=[ev["id"]],
                       kind="takeover-proof", severity="critical")
        if with_report:
            i = g.add_intent("report", "agent-report", probe=False)
            g.claim(i["id"], "w", now=1)
            g.complete(i["id"], result={"report": "x"})
        if with_cleanup:
            i = g.add_intent("exploit", "cleanup", writes=True, cleanup=True)
            g.claim(i["id"], "w", now=1)
            g.complete(i["id"], evidence=[ev["id"]], result={"ok": True})
        return g

    def test_cluster_takeover_success(self):
        result = get_objective("cluster-takeover").evaluate(self._graph())
        self.assertTrue(result["success"], result)

    def test_missing_proof_fails(self):
        result = get_objective("cluster-takeover").evaluate(
            self._graph(with_proof=False))
        self.assertFalse(result["success"])
        self.assertIn("fact:takeover-proof", result["missing"])

    def test_missing_cleanup_fails(self):
        result = get_objective("cluster-takeover").evaluate(
            self._graph(with_cleanup=False))
        self.assertIn("intent:cleanup", result["missing"])

    def test_read_only_objective_rejects_writes(self):
        g = self._graph()
        g.add_intent("exploit", "w", writes=True)
        result = get_objective("read-only-recon").evaluate(g)
        self.assertFalse(result["success"])
        self.assertIn("policy:read-only", result["missing"])

    def test_deterministic_stage_order(self):
        obj = get_objective("cluster-takeover")
        g = PlanGraph(objective="cluster-takeover")
        stage = obj.next_stage(g, module_map={"recon": "lab-recon"})
        self.assertEqual(stage["stage"], "recon")
        self.assertEqual(stage["module"], "lab-recon")
        ev = g.add_evidence(SHA, run="r", step="m")
        g.add_fact("asset", status="confirmed", evidence=[ev["id"]], kind="asset")
        stage = obj.next_stage(g, module_map={"exposure": "lab-exposure"})
        self.assertEqual(stage["stage"], "exposure")


if __name__ == "__main__":
    unittest.main()
