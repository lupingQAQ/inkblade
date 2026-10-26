# -*- coding: utf-8 -*-
"""Event log / checkpoint / resume / budget tests."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tests.agent_fixture import ROOT  # noqa: F401 - path setup
from inkblade.core.evidence import EvidenceStore
from inkblade.agent.runtime import (AgentRuntime, AgentRuntimeError, Budget,
                                    BudgetExceeded, EventLog)


class RuntimeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = EvidenceStore(Path(self.tmp.name), workspace="lab")

    def tearDown(self):
        self.tmp.cleanup()

    def test_event_hash_chain_and_tamper(self):
        runtime = AgentRuntime.create(
            self.store, objective="cluster-takeover", mode="graph-swarm",
            probe_id="p", llm="mock", budgets={"tokens": 10, "steps": 3},
            authorization={"actor": "lead"})
        runtime.emit("plan.proposed", {"rationale": "r"})
        runtime.emit("intent.claimed", {"intent": "intent-1"})
        self.assertTrue(runtime.log.verify()["ok"])
        lines = runtime.log.path.read_text(encoding="utf-8").splitlines()
        lines[1] = lines[1].replace('"rationale":"r"', '"rationale":"tampered"')
        runtime.log.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        verdict = runtime.log.verify()
        self.assertFalse(verdict["ok"])
        self.assertEqual(verdict["broken_at"], 2)
        with self.assertRaises(AgentRuntimeError):
            runtime.events()

    def test_checkpoint_replay_time_travel(self):
        runtime = AgentRuntime.create(
            self.store, objective="read-only-recon", mode="deterministic",
            budgets={"steps": 10}, authorization={})
        runtime.emit("graph.evidence.added", {"evidence": {
            "id": "ev-1", "sha256": "a" * 64, "run": "r", "step": "m",
            "source": "probe", "runtime": "reference"}})
        seq = runtime.emit("graph.fact.added", {"fact": {
            "id": "fact-1", "claim": "asset", "status": "confirmed",
            "evidence": ["ev-1"], "fact_kind": "asset", "severity": "info"}})["seq"]
        runtime.checkpoint("mid", {"graph": {"schema": "inkblade-agent-graph/1",
                                             "nodes": [], "edges": []}})
        runtime.emit("graph.intent.added", {"intent": {
            "id": "intent-1", "role": "recon", "module": "m", "params": {},
            "priority": 5, "requires": []}})
        early = runtime.state_at(seq - 1)
        self.assertEqual(early["facts"], 0)
        late = runtime.state_at(seq)
        self.assertEqual(late["facts"], 1)
        self.assertEqual(runtime.log.latest_checkpoint()["label"], "mid")

    def test_budget_hard_caps(self):
        budget = Budget(tokens=10, steps=2, actions=1, duration_ms=5000)
        self.assertEqual(budget.consume("tokens", 4), 4)
        self.assertFalse(budget.would_exceed("tokens", 6))
        self.assertTrue(budget.would_exceed("tokens", 7))
        self.assertEqual(budget.consume("steps", 2), 2)
        with self.assertRaises(BudgetExceeded):
            budget.consume("steps", 1)
        with self.assertRaises(BudgetExceeded):
            budget.consume("actions", 2)
        self.assertEqual(budget.limits["tokens"], 10)
        self.assertEqual(budget.remaining("tokens"), 6)

    def test_stop_marker_and_status(self):
        runtime = AgentRuntime.create(
            self.store, objective="cluster-takeover", mode="graph-swarm")
        self.assertFalse(runtime.is_stopped())
        runtime.request_stop("operator", actor="test")
        self.assertTrue(runtime.is_stopped())
        status = runtime.status()
        self.assertTrue(status["stopped"])
        self.assertTrue(status["journal"]["ok"])
        runtime.clear_stop()
        # the run.stopped event remains authoritative
        self.assertTrue(runtime.is_stopped())

    def test_last_run_pointer_and_load(self):
        runtime = AgentRuntime.create(
            self.store, objective="data-exfiltration", mode="graph-swarm")
        loaded = AgentRuntime.load(self.store)
        self.assertEqual(loaded.run_id, runtime.run_id)
        self.assertEqual(loaded.meta["objective"], "data-exfiltration")

    def test_trace_contains_decision_and_reason(self):
        runtime = AgentRuntime.create(
            self.store, objective="cluster-takeover", mode="graph-swarm")
        runtime.emit("decision.made", {"rationale": "because evidence",
                                       "chosen": "intent-1"})
        runtime.emit("policy.refused", {"reason": "out of scope",
                                        "intent": "intent-2"})
        trace = runtime.trace()
        self.assertEqual(trace[-2]["kind"], "decision.made")
        self.assertIn("because evidence", trace[-2]["summary"])
        self.assertEqual(trace[-1]["kind"], "policy.refused")


if __name__ == "__main__":
    unittest.main()
