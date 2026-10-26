# -*- coding: utf-8 -*-
"""挖掘流水线闭环（弹药 B③）测试：模板验证/差异复核/登记册候选（不自动入库）。"""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade import mining

REPO = Path(__file__).resolve().parents[1]


class TestTemplates(unittest.TestCase):
    def test_all_rules_anchor_validated(self):
        v = mining.validate_templates()
        self.assertTrue(v["ok"], v["invalid_rules"])
        self.assertGreaterEqual(v["rules"], 14)
        self.assertGreater(v["sample_hits"], 0)

    def test_missing_sample_tree_raises(self):
        with self.assertRaises(mining.MiningError):
            mining.validate_templates(sample_tree=REPO / "no-such-tree")


class TestExtract(unittest.TestCase):
    def test_targets_covered(self):
        # 2026-10-26 push-2: transformers 加入推理栈挖掘目标（reproenv-d 实装 4.57.1）
        self.assertEqual(set(mining.TARGETS),
                         {"vllm", "sglang", "kuberay", "hami", "litellm", "transformers"})

    def test_extract_latest_hits(self):
        for t in mining.TARGETS:
            ex = mining.extract_latest(t)
            self.assertEqual(ex["target"], t)
            self.assertTrue(ex["files"], t)
        # litellm 快照必然含 dynamic-import/auth-fail-open 类命中（2026-10-25 抓取）
        lit = mining.extract_latest("litellm")
        rules = {h["rule"] for h in lit["hits"]}
        self.assertIn("dynamic-import", rules)
        # hami Go 通道命中（pprof 调试路由）
        hami = mining.extract_latest("hami")
        self.assertIn("pprof-exposed-go", {h["rule"] for h in hami["hits"]})

    def test_unknown_target(self):
        with self.assertRaises(mining.MiningError):
            mining.extract_latest("open-webui")

    def test_tags_are_latest_release_snapshots(self):
        """五经典目标 tag 与版本矩阵 products 一致（2026-10-25 webfetch GitHub 核验）。

        transformers（2026-10-26 push-2 扩展）以 reproenv-d 实装 wheel 4.57.1 为 pin，
        不进入版本矩阵 products。
        """
        from inkblade.core.version_matrix import products

        mx = products()
        for t in ("vllm", "sglang", "kuberay", "hami", "litellm"):
            self.assertEqual(mining.TARGETS[t]["tag"], mx[t]["latest_tag_checked"], t)
        self.assertEqual(mining.TARGETS["transformers"]["tag"], "v4.57.1")


class TestPipelineClosedLoop(unittest.TestCase):
    def test_run_pipeline_candidates_then_deterministic(self):
        with TemporaryDirectory() as td:
            out = Path(td) / "mining"
            baseline = Path(td) / "baseline.json"
            r1 = mining.run_pipeline(out, baseline_path=baseline)
            self.assertTrue(r1["validation"]["ok"])
            self.assertGreaterEqual(r1["candidates_total"], 5)
            # 登记册候选：pending-manual-review + 文件存在 + 唯一 id
            cand_dir = out / "zeroday" / "registry" / "candidates"
            files = sorted(cand_dir.glob("*.json"))
            self.assertEqual(len(files), r1["candidates_total"])
            docs = [json.loads(p.read_text(encoding="utf-8")) for p in files]
            self.assertTrue(all(d["status"] == "pending-manual-review" for d in docs))
            self.assertTrue(all("不自动入库" in d["note"] for d in docs))
            ids = [d["id"] for d in docs]
            self.assertEqual(len(ids), len(set(ids)))
            # 报告落盘
            self.assertTrue((out / "mining-report.json").is_file())
            # 第二轮（同 fixtures）：0 新候选（闭环=差异复核）
            r2 = mining.run_pipeline(out, baseline_path=baseline)
            self.assertEqual(r2["candidates_total"], 0)

    def test_repo_committed_report_exists(self):
        """仓库样张（首轮 9 候选）在库：reports/samples/mining/。"""
        report = REPO / "reports" / "samples" / "mining" / "mining-report.json"
        if not report.is_file():  # 允许后续轮次重生成，但文件必须存在
            self.fail("缺 reports/samples/mining/mining-report.json（跑 inkblade mine 生成）")
        doc = json.loads(report.read_text(encoding="utf-8"))
        self.assertGreaterEqual(doc["candidates_total"], 5)
        self.assertTrue(all(c["status"] == "pending-manual-review"
                            for c in doc["candidates"]))

    def test_baseline_committed(self):
        self.assertTrue(mining.BASELINE_PATH.is_file(), "缺 core/data/mining-baseline.json")
        base = json.loads(mining.BASELINE_PATH.read_text(encoding="utf-8"))
        for t in mining.TARGETS:
            self.assertIn(t, base)

    def test_no_auto_registration(self):
        """候选绝不进模块注册表（不自动入库）。"""
        from inkblade.core.registry import load_modules

        mods = load_modules(REPO / "inkblade" / "modules")
        report = REPO / "reports" / "samples" / "mining" / "mining-report.json"
        doc = json.loads(report.read_text(encoding="utf-8"))
        for c in doc["candidates"]:
            self.assertNotIn(c["id"], mods)


if __name__ == "__main__":
    unittest.main()
