# -*- coding: utf-8 -*-
"""Swarm 评测脚本测试：15 任务、1 vs 4 worker、成功率/时延/审批口径。"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from lab.swarm_eval import DOC, OUT_DIR, build_tasks, run_eval

REPO = Path(__file__).resolve().parents[1]


class TestSwarmEval(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results = run_eval(reps=1, write=False)

    def test_task_set_is_15_and_role_balanced(self):
        tasks = build_tasks()
        self.assertEqual(len(tasks), 15)
        roles = {}
        for t in tasks:
            roles[t["role"]] = roles.get(t["role"], 0) + 1
            self.assertEqual(t["approval"]["status"], "approved")
        self.assertEqual(roles, {"recon": 5, "exploit": 4, "verify": 4, "report": 2})
        self.assertEqual([t["id"] for t in tasks if t.get("fail")], ["exploit-03"])
        self.assertEqual([t["id"] for t in tasks if t.get("fail_times")], ["verify-02"])

    def test_success_rate_and_approvals_do_not_regress(self):
        one, four = self.results["configs"]["1w"], self.results["configs"]["4w"]
        self.assertEqual(one["total_tasks"], 15)
        self.assertEqual(four["total_tasks"], 15)
        self.assertEqual(one["success"], 14)
        self.assertEqual(four["success"], 14)
        self.assertEqual(one["success_rate"], four["success_rate"])
        self.assertEqual(one["approvals"], 15)
        self.assertEqual(four["approvals"], 15)
        self.assertGreaterEqual(four["pids"], 2, "4 worker 必须是真实多进程")

    def test_parallel_is_faster_and_approval_wall_shrinks(self):
        cmp_ = self.results["comparison"]
        self.assertGreater(cmp_["speedup_wall"], 1.0)
        self.assertGreater(cmp_["approval_wall_speedup"], 1.0)
        self.assertGreaterEqual(self.results["configs"]["4w"]["peak_concurrency"], 2)

    def test_results_and_docs_exist(self):
        self.assertTrue((OUT_DIR / "results.json").is_file())
        self.assertTrue((OUT_DIR / "results.md").is_file())
        self.assertTrue(DOC.is_file())
        text = DOC.read_text(encoding="utf-8")
        for needle in ("1 worker", "4 worker", "成功率", "审批墙钟", "simulate", "复现"):
            self.assertIn(needle, text)
        doc = json.loads((OUT_DIR / "results.json").read_text(encoding="utf-8"))
        self.assertEqual(doc["schema"], "inkblade-swarm-eval/1")
        self.assertEqual(doc["task_set"]["total"], 15)


if __name__ == "__main__":
    unittest.main()
