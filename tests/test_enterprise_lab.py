# -*- coding: utf-8 -*-
"""企业真实感实验室（fixture 车道）测试。

判定口径（与 docs/ENTERPRISE-LAB-RESULTS.md 一致）：
- FP 率 = FP / (TP + FP)（发现级误报占比）；
- FN 率 = FN / (TP + FN)（标注风险漏报率）；
- benign/risk 标签由 ground-truth.json 固化，不允许实现里临时改标签。
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from lab.enterprise_lab import (
    FIXTURE_DIR,
    load_fixture,
    evaluate_labels,
    run_suite,
)

REPO = Path(__file__).resolve().parents[1]


class TestEnterpriseLab(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = load_fixture()
        cls.results = run_suite(write=False)

    def test_fixture_shape(self):
        self.assertGreaterEqual(len(self.fixture["snapshot"]["pods"]), 20)
        self.assertGreaterEqual(len(self.fixture["snapshot"]["networkpolicies"]), 4)
        self.assertGreaterEqual(len(self.fixture["audit_events"]), 300)
        self.assertGreaterEqual(len(self.fixture["ground_truth"]), 12)
        self.assertIn("kyverno", self.fixture["defenses"])
        self.assertIn("falco", self.fixture["defenses"])
        names = {p["namespace"] for p in self.fixture["snapshot"]["pods"]}
        for ns in ("kube-system", "monitoring", "ml-training", "ml-inference", "tenant-a", "tenant-b"):
            self.assertIn(ns, names)

    def test_three_noise_scenarios_and_rates(self):
        scenarios = self.results["scenarios"]
        self.assertEqual([s["id"] for s in scenarios],
                         ["platform-baseline-noise", "rbac-intent-noise", "audit-flood-noise"])
        for s in scenarios:
            for key in ("tp", "fp", "fn", "fp_rate", "fn_rate", "findings_total", "risk_items"):
                self.assertIn(key, s)
            self.assertGreater(s["findings_total"], 0)
            self.assertGreaterEqual(s["fp"], 0)
            expect_fp = round(s["fp"] / max(1, s["findings_total"]), 4)
            expect_fn = round(s["fn"] / max(1, s["risk_items"]), 4)
            self.assertAlmostEqual(s["fp_rate"], expect_fp, places=4)
            self.assertAlmostEqual(s["fn_rate"], expect_fn, places=4)
        self.assertGreater(self.results["overall"]["fp"], 0, "不允许粉饰为 0 误报")
        self.assertGreater(self.results["overall"]["fn"], 0, "至少保留 1 个未覆盖风险（诚实漏报）")

    def test_defense_state_effective_rates(self):
        defenses = self.results["defenses"]
        kyverno = defenses["kyverno"]
        self.assertEqual(kyverno["total"], len(self.fixture["defenses"]["kyverno"]["policies"]))
        self.assertGreater(kyverno["enforced"], 0)
        self.assertGreater(kyverno["audit"] + kyverno["missing"], 0, "不得全绿")
        self.assertLess(kyverno["enforced_rate"], 1.0)
        falco = defenses["falco"]
        self.assertEqual(falco["total"], len(self.fixture["defenses"]["falco"]["rules"]))
        self.assertGreater(falco["missing"], 0, "Falco 规则有缺口才符合真实实验室")
        self.assertLess(falco["loaded_rate"], 1.0)
        netpol = defenses["network_policy"]
        self.assertGreater(netpol["namespaces"], 0)
        self.assertLess(netpol["coverage_rate"], 1.0, "混合命名空间必须存在未隔离分区")

    def test_real_cluster_lane_is_separate_and_unlabeled(self):
        real = self.results["real_cluster"]
        self.assertEqual(real["source"], "real-cluster-k3s")
        self.assertEqual(real["modules_ok"], 6)
        self.assertEqual(real["findings"], 16)
        self.assertFalse(real["fp_fn_available"])
        self.assertIn("无客户标注", real["note"])

    def test_results_are_deterministic_and_written(self):
        out = REPO / "reports" / "samples" / "enterprise-lab"
        self.assertTrue((out / "results.json").is_file())
        self.assertTrue((out / "results.md").is_file())
        import importlib
        lab = importlib.import_module("lab.enterprise_lab")
        again = lab.run_suite(write=False)
        self.assertEqual(again["scenarios"], self.results["scenarios"])
        self.assertEqual(again["overall"], self.results["overall"])

    def test_evaluate_labels_rejects_unlabeled_match(self):
        findings = [
            {"step_key": "rbac-mapping", "severity": "critical", "title": "wildcard role",
             "detail": "x", "evidence": "x"},
            {"step_key": "rbac-mapping", "severity": "high", "title": "other", "detail": "y"},
        ]
        labels = [{"id": "benign-1", "scenario": "s", "label": "benign",
                   "module": "rbac-mapping", "contains": "wildcard"}]
        metrics = evaluate_labels(findings, labels, scenario="s")
        self.assertEqual(metrics["tp"], 0)
        self.assertEqual(metrics["fp"], 2)
        self.assertEqual(metrics["fn"], 0)
        self.assertEqual(metrics["fp_rate"], 1.0)


if __name__ == "__main__":
    unittest.main()
