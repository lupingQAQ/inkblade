# -*- coding: utf-8 -*-
"""Scheduler frontier/lease/retry/budget tests."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tests.agent_fixture import ROOT  # noqa: F401 - path setup
from inkblade.core.evidence import EvidenceStore
from inkblade.agent.graph import PlanGraph
from inkblade.agent.memory import AgentMemory
from inkblade.agent.policy import PolicyDecision
from inkblade.agent.runtime import AgentRuntime, Budget, BudgetExceeded
from inkblade.agent.scheduler import TaskScheduler


class FakePolicy:
    def __init__(self, allow=True, reason="scope"):
        self.allow = allow
        self.reason = reason

    def check_intent(self, intent, graph=None):
        return PolicyDecision(self.allow, "" if self.allow else self.reason,
                              "" if self.allow else "ScopeViolation")


class SchedulerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = EvidenceStore(Path(self.tmp.name), workspace="lab")
        self.runtime = AgentRuntime.create(
            self.store, objective="cluster-takeover", mode="graph-swarm")
        self.graph = PlanGraph(objective="cluster-takeover")
        self.budget = Budget(steps=10, actions=10, tokens=100)

    def tearDown(self):
        self.tmp.cleanup()

    def _scheduler(self, **kwargs):
        return TaskScheduler(self.graph, self.budget, self.runtime,
                             mode=kwargs.pop("mode", "graph-swarm"), **kwargs)

    def test_priority_and_memory_ranking(self):
        memory = AgentMemory(self.store)
        for _ in range(2):
            memory.episodic.record(run_id="r", objective="x", success=True,
                                   modules=["good"], role="recon")
            memory.episodic.record(run_id="r", objective="x", success=False,
                                   modules=["bad"], role="recon")
        self.graph.add_intent("recon", "bad", priority=5)
        self.graph.add_intent("recon", "good", priority=5)
        scheduler = self._scheduler(memory=memory)
        first = scheduler.claim_next("w1")
        self.assertEqual(first["module"], "good")
        self.assertIn("episodic", first.get("priority_reason", ""))

    def test_fifo_supervisor_mode(self):
        first = self.graph.add_intent("recon", "a", priority=1)
        second = self.graph.add_intent("recon", "b", priority=10)
        scheduler = self._scheduler(mode="supervisor")
        claimed = scheduler.claim_next("w1")
        self.assertEqual(claimed["id"], first["id"])
        self.assertEqual(self.graph.intents(status="done"), [])

    def test_lease_reclaim_and_retry_dead_letter(self):
        intent = self.graph.add_intent("recon", "probe", max_attempts=2)
        scheduler = self._scheduler(lease_seconds=5)
        claimed = scheduler.claim_next("w1")
        self.assertEqual(claimed["id"], intent["id"])
        self.assertIsNone(scheduler.claim_next("w2"))
        scheduler.heartbeat(intent["id"])
        first = scheduler.fail(intent["id"], "transient", retryable=True)
        self.assertEqual(first["status"], "open")
        claimed = scheduler.claim_next("w1")
        self.assertEqual(claimed["status"], "claimed")
        failed = scheduler.fail(intent["id"], "permanent", retryable=False)
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(scheduler.status.dead_letter[0]["intent"], intent["id"])

    def test_budget_stop_before_extra_step(self):
        self.budget = Budget(steps=1)
        self.graph.add_intent("recon", "a")
        self.graph.add_intent("recon", "b")
        scheduler = self._scheduler()
        self.assertIsNotNone(scheduler.claim_next("w1"))
        with self.assertRaises(BudgetExceeded):
            scheduler.claim_next("w2")
        self.assertTrue(scheduler.tripped)
        kinds = [e["kind"] for e in self.runtime.events()]
        self.assertIn("budget.exceeded", kinds)
        self.assertIn("budget.spent", kinds)

    def test_policy_refusal_blocks_intent(self):
        self.graph.add_intent("recon", "out-of-scope")
        scheduler = self._scheduler(policy=FakePolicy(allow=False))
        self.assertIsNone(scheduler.claim_next("w1"))
        self.assertEqual(self.graph.intents()[0]["status"], "blocked")
        kinds = [e["kind"] for e in self.runtime.events()]
        self.assertIn("policy.refused", kinds)
        self.assertEqual(self.budget.spent["steps"], 0)

    def test_complete_consumes_actions_and_emits(self):
        intent = self.graph.add_intent("report", "agent-report", probe=False)
        scheduler = self._scheduler()
        scheduler.claim_next("w1")
        scheduler.complete(intent["id"], result={"report": "x"})
        self.assertEqual(self.budget.spent["actions"], 1)
        self.assertEqual(self.graph.intents()[0]["status"], "done")


if __name__ == "__main__":
    unittest.main()
