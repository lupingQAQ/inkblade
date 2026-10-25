# -*- coding: utf-8 -*-
"""成本预算（token / 时延 / 审批 / 人工干预）与超支降级测试。"""

import unittest

from trident.core import cost


def _act(module, tokens, latency, *, writes=False, optional=False):
    return {"module": module, "writes": writes, "optional": optional,
            "tokens": tokens, "latency_ms": latency}


class TestEstimate(unittest.TestCase):
    def test_estimate_monotonic(self):
        small = cost.estimate_tokens("abc")
        big = cost.estimate_tokens("abc" * 100)
        self.assertGreaterEqual(small, 1)
        self.assertGreater(big, small)

    def test_plan_cost_sums(self):
        plan = cost.plan_cost([_act("a", 100, 10), _act("b", 250, 30)])
        self.assertEqual(plan["tokens"], 350)
        self.assertEqual(plan["latency_ms"], 40)
        self.assertEqual(len(plan["per_action"]), 2)


class TestBudget(unittest.TestCase):
    def test_status_thresholds(self):
        b = cost.Budget(tokens=1000, latency_ms=1000, approvals=4, interventions=1)
        self.assertEqual(b.status()["state"], "ok")
        b.record(tokens=820, latency_ms=100)
        self.assertEqual(b.status()["state"], "warn")
        b.record(tokens=200, latency_ms=100)
        self.assertEqual(b.status()["state"], "over")
        self.assertEqual(b.status()["remaining"]["tokens"], 0)

    def test_record_approvals_and_interventions(self):
        b = cost.Budget(tokens=100, latency_ms=100, approvals=2, interventions=1)
        b.record(tokens=1, latency_ms=1, approvals=1, interventions=1)
        st = b.status()
        self.assertEqual(st["used"]["approvals"], 1)
        self.assertEqual(st["used"]["interventions"], 1)
        self.assertEqual(st["state"], "over")  # interventions 1/1 已用尽


class TestDegrade(unittest.TestCase):
    def test_degrades_optional_first(self):
        actions = [_act("read", 100, 10),
                   _act("expensive-optional", 5000, 4000, optional=True),
                   _act("write", 200, 20, writes=True)]
        out = cost.degrade(actions, budget=cost.Budget(tokens=2000, latency_ms=5000,
                                                      approvals=2, interventions=0))
        self.assertTrue(out["degraded"])
        self.assertIn("expensive-optional", [a["module"] for a in out["dropped"]])
        self.assertIn("read", [a["module"] for a in out["actions"]])
        self.assertGreater(out["saved"]["tokens"], 0)

    def test_never_degrades_to_empty(self):
        actions = [_act("only", 999999, 999999)]
        out = cost.degrade(actions, budget=cost.Budget(tokens=10, latency_ms=10,
                                                      approvals=1, interventions=0))
        self.assertEqual([a["module"] for a in out["actions"]], ["only"])
        self.assertTrue(out["over_budget"])

    def test_no_degrade_within_budget(self):
        actions = [_act("read", 100, 10)]
        out = cost.degrade(actions, budget=cost.Budget(tokens=1000, latency_ms=1000,
                                                      approvals=1, interventions=0))
        self.assertFalse(out["degraded"])
        self.assertEqual(out["dropped"], [])

    def test_degrade_is_deterministic(self):
        actions = [_act("a", 100, 10, optional=True), _act("b", 100, 10),
                   _act("c", 100, 10, optional=True)]
        b = lambda: cost.Budget(tokens=150, latency_ms=1000, approvals=1, interventions=0)
        first = cost.degrade(actions, budget=b())
        second = cost.degrade(actions, budget=b())
        self.assertEqual([a["module"] for a in first["actions"]],
                         [a["module"] for a in second["actions"]])


class TestTracker(unittest.TestCase):
    def test_tracker_summary(self):
        tracker = cost.CostTracker(cost.Budget(tokens=1000, latency_ms=1000,
                                               approvals=2, interventions=0))
        tracker.record("s1", tokens=100, latency_ms=50, approvals=1, cached=False)
        tracker.record("s2", tokens=0, latency_ms=0, cached=True)
        summary = tracker.summary()
        self.assertEqual(summary["steps"], 2)
        self.assertEqual(summary["tokens"], 100)
        self.assertEqual(summary["cached_steps"], 1)
        self.assertEqual(summary["state"], "ok")

    def test_apply_budget_marks_reason(self):
        actions = [_act("a", 100, 10), _act("b", 100, 10)]
        out = cost.apply_budget(actions, budget=cost.Budget(tokens=150, latency_ms=1000,
                                                           approvals=2, interventions=0))
        self.assertTrue(out["degraded"])
        self.assertIn("预算", out["reason"])


if __name__ == "__main__":
    unittest.main()
