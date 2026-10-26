# -*- coding: utf-8 -*-
"""Evaluation harness comparison: deterministic / supervisor / graph-swarm."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tests.agent_fixture import ROOT  # noqa: F401 - path setup
from inkblade.agent.eval import EvalHarness, golden_task


class AgentEval2026Test(unittest.TestCase):
    def test_three_modes_run_and_report_metrics(self):
        with tempfile.TemporaryDirectory() as tmp:
            harness = EvalHarness(Path(tmp))
            report = harness.compare([golden_task(workers=2)])
            self.assertEqual(set(report["per_mode"]),
                             {"deterministic", "supervisor", "graph-swarm"})
            for mode, block in report["per_mode"].items():
                self.assertEqual(block["tasks"], 1, mode)
                self.assertGreaterEqual(block["successes"], 1, mode)
                for field in ("success_rate", "mean_steps", "mean_tokens",
                              "mean_evidence_coverage", "interventions"):
                    self.assertIn(field, block, mode)
            graph = [r for r in report["results"] if r["mode"] == "graph-swarm"][0]
            self.assertTrue(graph["metrics"]["success"])
            self.assertEqual(graph["metrics"]["steps"], 8)
            self.assertGreaterEqual(graph["metrics"]["probe_calls"], 7)
            self.assertEqual(len(report["results"]), 3)

    def test_eval_result_has_task_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            harness = EvalHarness(Path(tmp))
            row = harness.run_task("deterministic", golden_task())
            self.assertEqual(row["task"]["id"], "golden-cluster-takeover")
            self.assertIn("expected_success", row["task"])
            self.assertEqual(row["run_id"], row["summary"]["run_id"])
            self.assertTrue(row["metrics"]["success"])


if __name__ == "__main__":
    unittest.main()
