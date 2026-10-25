# -*- coding: utf-8 -*-
"""第三节微评测（lab/tencent-compare）契约与阈值测试。"""

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVAL_DIR = ROOT / "lab" / "tencent-compare"


def _load():
    spec = importlib.util.spec_from_file_location("tencent_compare", EVAL_DIR / "run_eval.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TencentCompareTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load()
        cls.tasks = cls.mod.load_tasks()
        cls.report = cls.mod.evaluate(cls.tasks, write=False)

    def test_task_set_contract(self):
        self.assertGreaterEqual(len(self.tasks), 6)
        self.assertGreaterEqual(len({t["zone"] for t in self.tasks}), 3)
        for task in self.tasks:
            self.assertTrue(task["actions"])
            self.assertIn("min_findings", task["expect"])

    def test_both_modes_cover_all_tasks(self):
        for mode in ("off", "on"):
            block = self.report["modes"][mode]
            self.assertEqual(len(block["tasks"]), len(self.tasks))
            self.assertEqual(block["summary"]["tasks"], len(self.tasks))
            for record in block["tasks"]:
                for field in ("id", "zone", "success", "tokens", "latency_ms",
                              "approvals", "approval_items", "human_interventions",
                              "evidence_ratio"):
                    self.assertIn(field, record, f"{mode}/{record.get('id')}")

    def test_thresholds_met(self):
        off = self.report["modes"]["off"]["summary"]
        on = self.report["modes"]["on"]["summary"]
        self.assertGreaterEqual(on["success_rate"], off["success_rate"] + 0.25)
        self.assertLessEqual(on["approval_items"], off["approval_items"] * 0.85)
        self.assertLessEqual(on["approvals"], off["approvals"] + 1)
        self.assertLessEqual(on["latency_ms"], off["latency_ms"] * 0.8)
        self.assertLessEqual(on["tokens"], off["tokens"] * 0.85)
        self.assertEqual(on["human_interventions"], 0)
        self.assertGreaterEqual(on["evidence_ratio"], 0.9)
        self.assertGreater(on["evidence_ratio"], off["evidence_ratio"])
        self.assertTrue(self.report["comparison"]["pass"])
        self.assertGreaterEqual(self.report["comparison"]["significant"], 2)

    def test_guardrail_irreversible_write_stays_l1(self):
        on = {t["id"]: t for t in self.report["modes"]["on"]["tasks"]}
        task = on["irreversible-write"]
        self.assertEqual(task["level"], "L1")
        self.assertEqual(task["approval_mode"], "per-action")
        self.assertTrue(task["requires_human"])
        self.assertEqual(task["approvals"], 2)

    def test_wiring_readonly(self):
        wiring = self.report["wiring"]
        self.assertTrue(wiring.get("ok"), wiring)
        self.assertFalse(wiring.get("executed"))
        self.assertGreaterEqual(wiring.get("observations", 0), 1)

    def test_markdown_render_contains_thresholds(self):
        text = self.mod.render_markdown(self.report)
        self.assertIn("OFF（HEAD）", text)
        self.assertIn("success_rate", text)
        self.assertIn("PASS", text)
        self.assertIn("策略级", text)

    def test_deterministic_summaries(self):
        again = self.mod.evaluate(self.tasks, write=False)
        for mode in ("off", "on"):
            first = self.report["modes"][mode]["summary"]
            second = again["modes"][mode]["summary"]
            for key in ("success_rate", "tokens", "latency_ms", "approvals",
                        "human_interventions"):
                self.assertEqual(first[key], second[key], f"{mode}/{key}")


if __name__ == "__main__":
    unittest.main()
