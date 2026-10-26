# -*- coding: utf-8 -*-
"""混沌编排（inkblade/chaos）测试：目录完整性 + 稳态-注入-中止-回滚-恢复闭环。"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from inkblade.chaos import (  # noqa: E402
    EXPERIMENTS,
    ChaosOrchestrator,
    abort_active_run,
    experiment_by_id,
    list_experiments,
)
from inkblade.chaos.orchestrator import active_abort_file, clear_abort  # noqa: E402


REQUIRED_EXPERIMENTS = {
    # 任务口径的 15 类必选实验（id → 语义）
    "net-latency-step-degradation": "网络延迟",
    "net-disconnect-workers": "断连",
    "net-partition-rail-groups": "分区",
    "net-packet-loss": "丢包",
    "dns-resolution-failure": "DNS 故障",
    "fabric-pfc-storm": "PFC 风暴（fabric-sim 联动）",
    "gpu-xid-driver-reset": "GPU 故障注入（mock NVML Xid）",
    "node-drain-gang-hold": "节点驱逐",
    "io-throttle-checkpoint": "IO 限速",
    "memory-pressure-kv-oom": "内存压力",
    "apiserver-request-flood": "api-server 洪泛",
    "kv-eviction-storm": "KV 驱逐风暴",
    "checkpoint-write-conflict": "checkpoint 写冲突",
    "nccl-slow-rank-straggler": "慢 rank（训练步时退化）",
    "trainer-master-loss": "管理者失联",
}


class CatalogTest(unittest.TestCase):
    def test_at_least_15_experiments_and_unique_ids(self):
        ids = [e.id for e in EXPERIMENTS]
        self.assertGreaterEqual(len(ids), 15)
        self.assertEqual(len(ids), len(set(ids)))

    def test_required_experiment_families_present(self):
        for exp_id in REQUIRED_EXPERIMENTS:
            self.assertIsNotNone(experiment_by_id(exp_id), f"缺少必选实验: {exp_id}")

    def test_every_experiment_has_full_lifecycle(self):
        for e in EXPERIMENTS:
            self.assertTrue(e.steady, f"{e.id} 缺稳态定义")
            self.assertTrue(e.measure, f"{e.id} 缺 SLO 度量")
            self.assertTrue(e.abort_when, f"{e.id} 缺中止条件")
            self.assertTrue(e.recovery or e.steady, f"{e.id} 缺恢复断言")
            self.assertTrue(e.rollback and e.rollback.kind, f"{e.id} 缺回滚动作")
            self.assertTrue(e.slo.strip(), f"{e.id} 缺 SLO 描述")
            self.assertTrue(e.parity.strip(), f"{e.id} 缺三大工具对照注记")
            self.assertTrue(e.probes_complete())

    def test_ml_specific_experiments_beyond_generic_chaos_tools(self):
        ml = [e.id for e in EXPERIMENTS if e.ml_specific]
        # 三大工具没有的 ML 面：训练步时退化 / KV 命中率·驱逐 / 梯度噪声阈值（至少各一）
        self.assertIn("nccl-slow-rank-straggler", ml)
        self.assertIn("kv-hit-rate-degradation", ml)
        self.assertIn("gradient-noise-threshold", ml)
        self.assertGreaterEqual(len(ml), 8)

    def test_list_experiments_shape(self):
        items = list_experiments()
        self.assertEqual(len(items), len(EXPERIMENTS))
        for it in items:
            self.assertIn("id", it)
            self.assertGreaterEqual(it["probes"]["steady"], 1)
            self.assertGreaterEqual(it["probes"]["measure"], 1)
            self.assertGreaterEqual(it["probes"]["abort_when"], 1)
            self.assertGreaterEqual(it["probes"]["recovery"], 1)

    def test_unknown_id_raises_keyerror(self):
        with self.assertRaises(KeyError):
            experiment_by_id("no-such-experiment")


class LiveChaosTest(unittest.TestCase):
    """对本地仿真靶场实跑：稳态破坏 + 自动回滚 + 恢复断言。"""

    def _run(self, ids, **kw):
        with tempfile.TemporaryDirectory() as tmp:
            orch = ChaosOrchestrator(tmp)
            return orch.run(ids, **kw)

    def _by_id(self, report, exp_id):
        rows = [r for r in report["results"] if r.get("id") == exp_id]
        self.assertTrue(rows, f"结果缺 {exp_id}")
        return rows[0]

    def test_latency_breaks_slo_then_recovers(self):
        report = self._run(["net-latency-step-degradation"])
        row = self._by_id(report, "net-latency-step-degradation")
        self.assertEqual(row["outcome"], "completed")
        impact = row["slo_impact"]
        self.assertTrue(impact["degraded"])
        self.assertTrue(impact["recovered"])
        baseline = impact["baseline"]["step-latency-baseline"]
        during = impact["during"]["step-latency-degraded"]
        self.assertLess(baseline, 250)
        self.assertGreaterEqual(during, 350)
        self.assertGreaterEqual(during / max(baseline, 1e-6), 2.0)

    def test_disconnect_triggers_abort_condition_and_rolls_back(self):
        report = self._run(["net-disconnect-workers"])
        row = self._by_id(report, "net-disconnect-workers")
        self.assertEqual(row["outcome"], "aborted_by_condition")
        self.assertTrue(row["slo_impact"]["degraded"])
        self.assertTrue(row["slo_impact"]["recovered"])
        self.assertIn("中止条件", row["slo_impact"]["abort_reason"])

    def test_partition_blocks_only_target_group(self):
        report = self._run(["net-partition-rail-groups"])
        row = self._by_id(report, "net-partition-rail-groups")
        self.assertEqual(row["outcome"], "completed")
        self.assertTrue(row["slo_impact"]["recovered"])

    def test_pfc_storm_fabric_sim_break_and_recover(self):
        report = self._run(["fabric-pfc-storm"])
        row = self._by_id(report, "fabric-pfc-storm")
        self.assertEqual(row["outcome"], "completed")
        impact = row["slo_impact"]
        self.assertTrue(impact["degraded"])
        self.assertTrue(impact["recovered"])
        self.assertGreaterEqual(impact["during"]["pfc-delta"], 25000)
        # 回滚后风暴标志复位（计数器允许保持单调）
        recovery = {r["name"]: r for r in row["phases"]["recovery"]}
        self.assertTrue(recovery["storm-cleared"]["ok"])

    def test_ml_specific_training_experiments(self):
        report = self._run(["nccl-slow-rank-straggler", "gradient-noise-threshold",
                            "kv-hit-rate-degradation"])
        slow = self._by_id(report, "nccl-slow-rank-straggler")
        grad = self._by_id(report, "gradient-noise-threshold")
        kv = self._by_id(report, "kv-hit-rate-degradation")
        self.assertEqual(slow["outcome"], "completed")
        self.assertGreaterEqual(slow["slo_impact"]["during"]["step-ratio-degraded"], 2.0)
        self.assertLess(slow["slo_impact"]["baseline"]["step-ratio-baseline"], 1.5)
        self.assertEqual(grad["outcome"], "completed")
        self.assertGreaterEqual(
            grad["slo_impact"]["during"]["loss-diverged"], 1.5)
        self.assertEqual(kv["outcome"], "completed")
        self.assertEqual(kv["slo_impact"]["during"]["cold-miss"], 0)

    def test_full_catalog_run_all_green(self):
        """全套目录逐一实跑：不允许回滚失败/稳态失败。"""
        report = self._run([e.id for e in EXPERIMENTS])
        bad = [r for r in report["results"]
               if r.get("outcome") in ("rollback_failed", "steady_state_failed")]
        self.assertEqual(bad, [], f"存在失败实验: {[(b['id'], b['outcome']) for b in bad]}")
        completed = [r for r in report["results"] if r["outcome"] == "completed"]
        self.assertGreaterEqual(len(completed), 14)
        for r in completed:
            self.assertTrue(r["slo_impact"]["degraded"], f"{r['id']} 未观测到 SLO 破坏")
            self.assertTrue(r["slo_impact"]["recovered"], f"{r['id']} 回滚后未恢复稳态")

    def test_dead_target_refuses_injection(self):
        with tempfile.TemporaryDirectory() as tmp:
            orch = ChaosOrchestrator(
                tmp, targets={"fabric-dos": "http://127.0.0.1:9"},
                auto_start=False)
            report = orch.run(["net-disconnect-workers"])
        row = self._by_id(report, "net-disconnect-workers")
        self.assertEqual(row["outcome"], "steady_state_failed")
        self.assertNotIn("inject", row["phases"], "稳态失败必须拒绝注入")


class OrchestrationModeTest(unittest.TestCase):
    def test_parallel_mode_runs_all(self):
        with tempfile.TemporaryDirectory() as tmp:
            orch = ChaosOrchestrator(tmp)
            report = orch.run(["net-packet-loss", "gpu-xid-driver-reset",
                               "apiserver-request-flood"],
                              mode="parallel", max_parallel=3)
        self.assertEqual(len(report["results"]), 3)
        for r in report["results"]:
            self.assertEqual(r["outcome"], "completed")
            self.assertTrue(r["slo_impact"]["recovered"])

    def test_scheduled_cycles(self):
        with tempfile.TemporaryDirectory() as tmp:
            orch = ChaosOrchestrator(tmp)
            report = orch.run(["fabric-pfc-storm"], every_s=0, cycles=2)
        self.assertEqual(len(report["results"]), 2)
        self.assertEqual([r["cycle"] for r in report["results"]], [0, 1])
        self.assertTrue(all(r["slo_impact"]["recovered"] for r in report["results"]))

    def test_external_abort_file_blocks_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            abort_active_run(tmp, "test-abort")
            self.assertTrue(active_abort_file(tmp).is_file())
            orch = ChaosOrchestrator(tmp)
            report = orch.run(["net-packet-loss"])
            clear_abort(tmp)
        row = [r for r in report["results"] if r["id"] == "net-packet-loss"][0]
        self.assertEqual(row["outcome"], "aborted_external")

    def test_report_written_to_chaos_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            orch = ChaosOrchestrator(tmp)
            orch.run(["fabric-pfc-storm"])
            latest = Path(tmp) / "chaos-runs" / "latest.json"
            self.assertTrue(latest.is_file())
            doc = json.loads(latest.read_text(encoding="utf-8"))
        self.assertEqual(doc["schema"], "inkblade-chaos-run/1")
        self.assertIn("boundary", doc)


class ChaosCliTest(unittest.TestCase):
    def _main(self, *argv):
        from inkblade.cli import main

        return main(list(argv))

    def test_list_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            import contextlib
            import io

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = self._main("--home", tmp, "chaos", "list", "--json")
            self.assertEqual(rc, 0)
            doc = json.loads(buf.getvalue())
        self.assertGreaterEqual(doc["count"], 15)

    def test_run_single_experiment_and_abort_cmd(self):
        with tempfile.TemporaryDirectory() as tmp:
            import contextlib
            import io

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = self._main("--home", tmp, "chaos", "run", "fabric-pfc-storm",
                                "--json-out", str(Path(tmp) / "chaos.json"))
            self.assertEqual(rc, 0)
            self.assertTrue((Path(tmp) / "chaos.json").is_file())
            with contextlib.redirect_stdout(buf):
                rc = self._main("--home", tmp, "chaos", "abort", "--reason", "cli-test")
            self.assertEqual(rc, 0)
            self.assertTrue(active_abort_file(tmp).is_file())
            clear_abort(tmp)


if __name__ == "__main__":
    unittest.main()
