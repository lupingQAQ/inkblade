# -*- coding: utf-8 -*-
"""Three-layer memory, reflexion, skill library tests."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tests.agent_fixture import ROOT  # noqa: F401 - path setup
from inkblade.core.evidence import EvidenceStore
from inkblade.core.users import Session
from inkblade.agent.graph import PlanGraph
from inkblade.agent.memory import AgentMemory, MemoryWriteRefused
from inkblade.agent.objectives import get_objective
from inkblade.agent.runtime import AgentRuntime
from inkblade.agent.skills import SkillLibrary


class MemoryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = EvidenceStore(Path(self.tmp.name), workspace="lab")
        self.memory = AgentMemory(self.store)

    def tearDown(self):
        self.tmp.cleanup()

    def test_working_memory_compaction_keeps_refs(self):
        for i in range(40):
            self.memory.working.add(f"item {i}", ref=f"ref-{i}")
        result = self.memory.working.compact()
        self.assertGreater(result["dropped"], 0)
        text = " ".join(i["text"] for i in self.memory.working.items())
        self.assertIn("compacted", text)

    def test_episodic_records_and_ranking(self):
        for _ in range(2):
            self.memory.episodic.record(run_id="r1", objective="cluster-takeover",
                                        success=True, modules=["good"], role="recon")
            self.memory.episodic.record(run_id="r2", objective="cluster-takeover",
                                        success=False, modules=["bad"], role="recon")
        rate, count = self.memory.episodic.success_rate(module="good")
        self.assertEqual((rate, count), (1.0, 2))
        graph = PlanGraph(objective="cluster-takeover")
        good = graph.add_intent("recon", "good", priority=5)
        bad = graph.add_intent("recon", "bad", priority=5)
        ranked = self.memory.rank_intents([bad, good], graph)
        self.assertEqual(ranked[0]["module"], "good")
        self.assertIn("episodic", ranked[0]["priority_reason"])

    def test_semantic_requires_provenance_and_approval(self):
        with self.assertRaises(MemoryWriteRefused):
            self.memory.semantic.upsert("asset:1", "asset", {}, source_ref="")
        with self.assertRaises(MemoryWriteRefused):
            self.memory.semantic.upsert("skill:1", "skill", {}, source_ref="skill:1",
                                        trust="skill")
        record = self.memory.semantic.upsert(
            "asset:1", "asset", {"product": "vllm"}, source_ref="probe:run:step",
            trust="probe")
        self.assertEqual(record["version"], 1)
        second = self.memory.semantic.upsert(
            "asset:1", "asset", {"product": "vllm-2"}, source_ref="probe:run:step2",
            trust="probe")
        self.assertEqual(second["version"], 2)
        self.assertEqual(len(self.memory.semantic.get("asset:1")), 1)
        rolled = self.memory.semantic.rollback("asset:1", reason="bad source")
        self.assertTrue(rolled["active"])
        self.assertEqual(self.memory.semantic.get("asset:1")[0]["attrs"]["product"], "vllm")

    def test_semantic_expiry(self):
        self.memory.semantic.upsert("asset:x", "asset", {"a": 1}, source_ref="probe:x",
                                    trust="probe", ttl_seconds=1)
        self.assertEqual(len(self.memory.semantic.search("asset:x")), 1)

    def test_reflection_is_zero_execution(self):
        runtime = AgentRuntime.create(self.store, objective="cluster-takeover",
                                      mode="graph-swarm")
        graph = PlanGraph(objective="cluster-takeover")
        intent = graph.add_intent("recon", "m", max_attempts=1)
        graph.claim(intent["id"], "w", now=1)
        graph.fail(intent["id"], "scope violation", retryable=False, now=2)
        report = self.memory.reflect(runtime, graph, get_objective("cluster-takeover"))
        self.assertFalse(report["executed"])
        self.assertTrue(Path(report["path"]).is_file())
        self.assertIn("scope", " ".join(report["next_avoid"]))


class SkillLibraryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = EvidenceStore(Path(self.tmp.name), workspace="lab")
        self.lead = Session(None, "lead", "lead", ["lab"], "x")
        self.tester = Session(None, "tester", "tester", ["lab"], "x")
        self.library = SkillLibrary(self.store)

    def tearDown(self):
        self.tmp.cleanup()

    def _graph(self):
        graph = PlanGraph(objective="cluster-takeover")
        ev = graph.add_evidence("a" * 64, run="r", step="recon")
        graph.add_fact("asset", status="confirmed", evidence=[ev["id"]],
                       kind="asset")
        intent = graph.add_intent("recon", "recon")
        graph.claim(intent["id"], "w", now=1)
        graph.complete(intent["id"], evidence=[ev["id"]], result={})
        return graph

    def test_propose_submit_approve_and_search(self):
        draft = self.library.propose_from_graph(self._graph(), objective="cluster-takeover")
        self.assertEqual(draft["status"], "draft")
        pending = self.library.submit(self.tester, draft)
        self.assertEqual(pending["status"], "pending")
        self.assertEqual(self.library.search(draft["id"]), [])
        with self.assertRaises(PermissionError):
            self.library.approve(self.tester, pending["id"])
        approved = self.library.approve(self.lead, pending["id"], note="reviewed")
        self.assertEqual(approved["status"], "approved")
        self.assertEqual(len(self.library.search("cluster-takeover")), 1)
        self.library.record_outcome(approved["id"], True)
        self.library.record_outcome(approved["id"], False)
        record = self.library.get(approved["id"])
        self.assertEqual(record["stats"]["uses"], 2)
        self.assertEqual(record["stats"]["success_rate"], 0.5)

    def test_versioning_and_promotion(self):
        draft = self.library.propose_from_graph(self._graph(), objective="x")
        first = self.library.submit(self.lead, draft)
        second = self.library.submit(self.lead, {**draft, "playbook": [
            {"module": "recon", "role": "recon", "params": {}}]})
        self.assertEqual(second["version"], 2)
        self.assertEqual(len(second["history"]), 2)
        promoted = self.library.promote(self.lead, second["id"], eval_score=0.8)
        self.assertEqual(promoted["status"], "approved")
        low = self.library.promote(self.lead, second["id"], eval_score=0.2)
        self.assertEqual(low["status"], "pending")

    def test_index_into_semantic_memory(self):
        memory = AgentMemory(self.store)
        draft = self.library.propose_from_graph(self._graph(), objective="x")
        pending = self.library.submit(self.lead, draft)
        self.library.approve(self.lead, pending["id"])
        count = self.library.index_into(memory)
        self.assertEqual(count, 1)
        self.assertEqual(len(memory.semantic.get(pending["id"])), 1)


if __name__ == "__main__":
    unittest.main()
