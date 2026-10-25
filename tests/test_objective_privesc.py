"""cluster-takeover objective：阶段③前自动选择最短提权路径、失败回退、报告含提权路径图与选择依据。"""

from __future__ import annotations

import unittest
from pathlib import Path

from trident.core.objective import (
    OBJECTIVES,
    NoPathError,
    execute_objective,
    plan_objective,
    render_objective_report,
)
from trident.core.privesc import load_matrix, load_snapshot

REPO = Path(__file__).resolve().parents[1]
FIXTURES = REPO / "lab" / "fixtures" / "privesc"


class TestObjectivePrivesc(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.matrix = load_matrix()
        cls.snapshot = load_snapshot(FIXTURES / "rbac.json")
        cls.principal = "system:serviceaccount:privesc-lab:esc-sa"

    def test_objective_defined_with_four_phases(self):
        obj = OBJECTIVES["cluster-takeover"]
        self.assertEqual(obj["target"], "cluster-admin")
        self.assertEqual(len(obj["phases"]), 4)
        self.assertEqual(obj["phases"][2]["id"], "privesc")
        self.assertEqual(obj["phases"][2]["index"], 3)

    def test_plan_selects_shortest_and_records_alternates(self):
        plan = plan_objective("cluster-takeover", snapshot=self.snapshot,
                              from_principal=self.principal, limit=4)
        phase3 = plan["phases"][2]
        self.assertEqual(phase3["status"], "ready")
        selection = phase3["selection"]
        self.assertIn("rbac-escalate-verb", selection["chosen"]["vector_ids"])
        self.assertTrue(selection["rationale"])
        self.assertIn("weight", selection["rationale"].lower())
        self.assertGreaterEqual(len(selection["alternates"]), 1)
        self.assertIn("提权", plan["summary"])
        self.assertTrue(plan["graph"]["nodes"])
        self.assertTrue(plan["graph"]["edges"])

    def test_execute_falls_back_to_next_path(self):
        plan = plan_objective("cluster-takeover", snapshot=self.snapshot,
                              from_principal=self.principal, limit=4)
        calls: list[str] = []

        def executor(step, phase):
            calls.append(step["vector"])
            if len(calls) == 1:
                raise RuntimeError("injected failure on first primitive")
            return {"status": "success", "evidence": f"module:{step['module']}"}

        result = execute_objective(plan, executor=executor)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["selected_path"], result["attempts"][-1]["path"])
        self.assertIn("failed", result["attempts"][0]["status"])
        self.assertGreaterEqual(len(result["attempts"]), 2)
        self.assertTrue(result["fallback_used"])
        report = render_objective_report(result)
        self.assertIn("提权面", report)
        self.assertIn("提权路径图", report)
        self.assertIn("选择依据", report)
        self.assertIn("flowchart", report)
        self.assertIn("回退", report)

    def test_all_paths_failed(self):
        plan = plan_objective("cluster-takeover", snapshot=self.snapshot,
                              from_principal=self.principal, limit=2)

        def executor(step, phase):
            raise RuntimeError("all fail")

        result = execute_objective(plan, executor=executor)
        self.assertFalse(result["ok"])
        self.assertFalse(result["fallback_used"])
        self.assertTrue(result["attempts"])

    def test_no_path_raises_with_diagnostics(self):
        with self.assertRaises(NoPathError) as cm:
            plan_objective("cluster-takeover",
                           snapshot={"cani": [{"subject": "system:serviceaccount:x:y",
                                               "allowed": ["get pods"]}]},
                           from_principal="system:serviceaccount:x:y")
        self.assertIn("没有", str(cm.exception))

    def test_report_contains_graph_and_rationale(self):
        plan = plan_objective("cluster-takeover", snapshot=self.snapshot,
                              from_principal="system:serviceaccount:privesc-lab:bind-sa")
        report = render_objective_report(plan)
        self.assertIn("bind-verb", report)
        self.assertIn("备选", report)
        self.assertIn("检测", report)


if __name__ == "__main__":
    unittest.main()
