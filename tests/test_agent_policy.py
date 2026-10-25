# -*- coding: utf-8 -*-
"""自主度分级 / 任务分解 / 重试回退策略测试（TDD，第三节改进项）。

设计边界：
- L0-L3 四档，档位是「动作能力」而不是「模型自由度」；
- 混合动作取最弱链路（不可逆写动作把整批降到 L1）；
- 重试只对瞬时错误生效，闸门类错误必须立即停止（不浪费预算）。
"""

import unittest

from trident.core import agent_policy as ap


READ = {"module": "sglang-admin-failopen", "writes": False, "params": {"use_assets": True}}
WRITE_BACKED = {"module": "model-weight-poison", "writes": True,
                "dry_run": {"backup_targets": ["s3://models/weights"]}}
WRITE_IRREVERSIBLE = {"module": "evidence-destroy", "writes": True, "dry_run": {"backup_targets": []}}


class TestAutonomyLevels(unittest.TestCase):
    def test_levels_ordered_and_documented(self):
        self.assertEqual(ap.LEVELS, ("L0", "L1", "L2", "L3"))
        for key in ap.LEVELS:
            item = ap.AUTONOMY[key]
            self.assertEqual(item["key"], key)
            self.assertTrue(item["label"])
            self.assertTrue(item["summary"])
            self.assertIn(item["approval"], ("none", "batch", "per-action"))
        self.assertEqual(ap.AUTONOMY["L0"]["max_actions"], 0)
        self.assertTrue(ap.AUTONOMY["L3"]["auto_readonly"])

    def test_classify_action_capability(self):
        self.assertEqual(ap.classify_action(READ)["level"], "L3")
        self.assertTrue(ap.classify_action(READ)["auto"])
        self.assertEqual(ap.classify_action(WRITE_BACKED)["level"], "L2")
        self.assertFalse(ap.classify_action(WRITE_BACKED)["auto"])
        self.assertEqual(ap.classify_action(WRITE_IRREVERSIBLE)["level"], "L1")
        self.assertTrue(ap.classify_action(WRITE_IRREVERSIBLE)["requires_human"])

    def test_decide_weakest_link(self):
        batch = ap.decide([READ, {"module": "kubectl-auth-probe", "writes": False}])
        self.assertEqual(batch["level"], "L3")
        self.assertEqual(batch["approval_mode"], "batch")
        self.assertEqual(batch["approval_count"], 1)
        self.assertFalse(batch["requires_human"])

        mixed = ap.decide([READ, WRITE_IRREVERSIBLE])
        self.assertEqual(mixed["level"], "L1")
        self.assertEqual(mixed["approval_mode"], "per-action")
        self.assertEqual(mixed["approval_count"], 2)
        self.assertTrue(mixed["requires_human"])

    def test_decide_empty_and_l0(self):
        self.assertEqual(ap.decide([])["level"], "L0")
        self.assertEqual(ap.decide([], requested="L0")["approval_count"], 0)
        with self.assertRaises(ap.PolicyError):
            ap.decide([READ], requested="L9")


class TestDecomposition(unittest.TestCase):
    def test_phase_strategy_orders_readonly_first(self):
        actions = [READ, WRITE_BACKED, {"module": "sglang-metrics-read", "writes": False},
                   WRITE_IRREVERSIBLE]
        plan = ap.decompose(actions, strategy="phase")
        self.assertEqual(plan["strategy"], "phase")
        self.assertGreaterEqual(len(plan["phases"]), 2)
        self.assertTrue(plan["phases"][0]["auto"])
        self.assertFalse(plan["phases"][0]["gate"])
        self.assertTrue(any(p["gate"] for p in plan["phases"][1:]))
        covered = [i for phase in plan["phases"] for i in phase["actions"]]
        self.assertEqual(sorted(covered), [0, 1, 2, 3])

    def test_dependency_strategy_isolates_writes(self):
        actions = [READ, WRITE_BACKED, WRITE_IRREVERSIBLE]
        plan = ap.decompose(actions, strategy="dependency")
        write_phases = [p for p in plan["phases"] if p["gate"]]
        self.assertEqual(len(write_phases), 2)
        self.assertEqual(plan["stages"], 3)

    def test_decompose_bad_strategy(self):
        with self.assertRaises(ap.PolicyError):
            ap.decompose([READ], strategy="chaos")


class TestRetryFallback(unittest.TestCase):
    def test_transient_is_bounded_retry(self):
        for err in (TimeoutError("upstream timeout"), "HTTP 429 rate limit",
                    "502 bad gateway", ConnectionError("reset")):
            plan = ap.retry_plan(err)
            self.assertEqual(plan["class"], "transient", err)
            self.assertEqual(plan["attempts"], 2)
            self.assertGreater(plan["backoff_ms"], 0)
            self.assertEqual(plan["fallback"], "same-action")

    def test_permanent_never_retries(self):
        for err in ("exit 91: backup gate", "403 forbidden", "consent missing",
                    "scope denied"):
            plan = ap.retry_plan(err)
            self.assertEqual(plan["class"], "permanent", err)
            self.assertEqual(plan["attempts"], 1)
            self.assertTrue(plan["escalate"])

    def test_invalid_output_replans_without_retry(self):
        plan = ap.retry_plan(ValueError("schema invalid"))
        self.assertEqual(plan["class"], "invalid")
        self.assertEqual(plan["fallback"], "replan")
        self.assertEqual(plan["attempts"], 1)

    def test_budget_error_degrades(self):
        plan = ap.retry_plan("token budget exceeded")
        self.assertEqual(plan["class"], "budget")
        self.assertEqual(plan["fallback"], "degrade")

    def test_fallback_action_selected_from_declared_alternatives(self):
        action = {"module": "a", "fallback": ["b", "c"]}
        plan = ap.retry_plan(TimeoutError("x"), action=action, attempted={"b"})
        self.assertEqual(plan["class"], "transient")
        self.assertEqual(plan["fallback"], "c")


if __name__ == "__main__":
    unittest.main()
