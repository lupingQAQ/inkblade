# -*- coding: utf-8 -*-
"""tests/test_trainstack_mining.py — 训练栈五目标 0day 挖掘流水线（候选待人工复核）。

锁定：
- 五目标 tag = 2026-10-26 GitHub releases/latest 核验值（Megatron/DeepSpeed/
  LLaMA-Factory/ms-swift/TRL）；
- 每个目标 fixture 文件可提取到预期 sink（torch.load / optimizer state /
  apply_chat_template / load_dataset / trust_remote_code / subprocess）；
- 首轮候选 ≥5 且全部 pending-manual-review，候选 repo/tag/文件必须可回溯到 fixture；
- 第二轮同 fixtures → 0 新候选（差异复核闭环）；
- 候选绝不进模块注册表（不自动入库）；
- 仓库样张与训练栈独立基线在库。
"""
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade import mining
from inkblade.core.registry import load_modules

REPO = Path(__file__).resolve().parents[1]
MODULES_DIR = REPO / "inkblade" / "modules"
ARTIFACT = REPO / "reports" / "samples" / "mining-trainstack"
FIXTURE = REPO / "lab" / "mining-fixture"

EXPECTED_TAGS = {
    "megatron": "core_v0.19.2",
    "deepspeed": "v0.19.8",
    "llamafactory": "v0.9.5",
    "msswift": "v4.6.0",
    "trl": "v1.16.0",
}

EXPECTED_RULES = {
    "megatron": {"torch-load-any", "wandb-checkpoint-hook"},
    "deepspeed": {"torch-load-any", "torch-load-unsafe", "subprocess-popen",
                  "env-rank-read"},
    "llamafactory": {"apply-chat-template-dynamic", "trust-remote-code-propagated",
                     "bind-all-interfaces"},
    "msswift": {"apply-chat-template-dynamic", "load-dataset-any"},
    "trl": {"apply-chat-template-dynamic", "load-dataset-any",
            "trust-remote-code-propagated"},
}


class TestTrainstackTargets(unittest.TestCase):
    def test_five_targets_and_latest_tags(self):
        self.assertEqual(set(mining.TRAINSTACK_TARGETS), set(EXPECTED_TAGS))
        for target, tag in EXPECTED_TAGS.items():
            self.assertEqual(mining.TRAINSTACK_TARGETS[target]["tag"], tag, target)
            self.assertTrue(mining.TRAINSTACK_TARGETS[target]["repo"], target)

    def test_extract_each_target_hits_expected_rules(self):
        for target, wanted in EXPECTED_RULES.items():
            with self.subTest(target=target):
                ex = mining.extract_latest(target)
                self.assertEqual(ex["tag"], EXPECTED_TAGS[target])
                self.assertGreaterEqual(len(ex["files"]), 3, target)
                rules = {h["rule"] for h in ex["hits"]}
                missing = wanted - rules
                self.assertFalse(missing, f"{target} 缺规则命中: {sorted(missing)}")
                self.assertTrue(all(h["file"] for h in ex["hits"]), target)

    def test_unknown_target_rejected(self):
        with self.assertRaises(mining.MiningError):
            mining.extract_latest("no-such-trainstack")

    def test_classic_targets_unchanged(self):
        # 2026-10-26 push-2: 推理栈目标新增 transformers（其余五经典目标不变）
        self.assertEqual(set(mining.TARGETS),
                         {"vllm", "sglang", "kuberay", "hami", "litellm", "transformers"})


class TestTrainstackPipeline(unittest.TestCase):
    def test_candidates_then_deterministic(self):
        with TemporaryDirectory() as td:
            out = Path(td) / "mining"
            baseline = Path(td) / "baseline.json"
            r1 = mining.run_trainstack_pipeline(out, baseline_path=baseline)
            self.assertTrue(r1["validation"]["ok"], r1["validation"])
            self.assertGreaterEqual(r1["candidates_total"], 5)
            self.assertEqual(set(r1["targets"]), set(EXPECTED_TAGS))
            cand_dir = out / "zeroday" / "registry" / "candidates"
            files = sorted(cand_dir.glob("*.json"))
            self.assertEqual(len(files), r1["candidates_total"])
            docs = [json.loads(p.read_text(encoding="utf-8")) for p in files]
            self.assertTrue(all(d["status"] == "pending-manual-review" for d in docs))
            self.assertTrue(all("不自动入库" in d["note"] for d in docs))
            self.assertEqual(len({d["id"] for d in docs}), len(docs), "候选 id 重复")
            for doc in docs:
                self.assertEqual(doc["tag"], EXPECTED_TAGS[doc["target"]], doc["id"])
                self.assertEqual(doc["repo"],
                                 mining.TRAINSTACK_TARGETS[doc["target"]]["repo"])
                fixture_files = {p.name for p in (FIXTURE / doc["target"]).iterdir()
                                 if p.is_file()}
                self.assertIn(doc["file"], fixture_files, f"候选文件不可回溯: {doc['id']}")
                self.assertGreaterEqual(int(doc["line"]), 1)
            self.assertTrue((out / "mining-report.json").is_file())
            # 第二轮同 fixtures：0 新候选
            r2 = mining.run_trainstack_pipeline(out, baseline_path=baseline)
            self.assertEqual(r2["candidates_total"], 0)

    def test_no_auto_registration(self):
        docs = [json.loads(p.read_text(encoding="utf-8"))
                for p in (ARTIFACT / "zeroday" / "registry" / "candidates").glob("*.json")]
        mods = load_modules(MODULES_DIR)
        for doc in docs:
            self.assertNotIn(doc["id"], mods)
            self.assertNotIn(doc["rule"], mods)


class TestRepoArtifacts(unittest.TestCase):
    def test_report_committed_and_pending(self):
        report = ARTIFACT / "mining-report.json"
        self.assertTrue(report.is_file(), "缺 reports/samples/mining-trainstack/mining-report.json")
        doc = json.loads(report.read_text(encoding="utf-8"))
        self.assertEqual(doc["schema"], "inkblade-mining-report-v1")
        self.assertGreaterEqual(doc["candidates_total"], 5)
        self.assertEqual(set(doc["targets"]), set(EXPECTED_TAGS))
        self.assertTrue(all(c["status"] == "pending-manual-review"
                            for c in doc["candidates"]))
        for target, tag in EXPECTED_TAGS.items():
            self.assertEqual(doc["targets"][target]["tag"], tag)

    def test_independent_baseline_committed(self):
        path = mining.TRAINSTACK_BASELINE_PATH
        self.assertTrue(path.is_file(), "缺训练栈独立基线")
        base = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(set(base), set(EXPECTED_TAGS))
        for target, keys in base.items():
            self.assertTrue(keys, target)
            self.assertTrue(all(isinstance(k, str) and ":" in k for k in keys), target)

    def test_shared_rules_cover_trainstack_and_anchors(self):
        report = json.loads((ARTIFACT / "mining-report.json").read_text(encoding="utf-8"))
        self.assertTrue(report["validation"]["ok"], report["validation"])
        rule_ids = {r["id"] for r in mining.load_rules()["rules"]}
        self.assertGreaterEqual(len(rule_ids), 23)
        for rule in ("torch-load-any", "yaml-unsafe-load", "apply-chat-template-dynamic",
                     "subprocess-popen", "load-dataset-any", "env-rank-read",
                     "trust-remote-code-propagated", "wandb-checkpoint-hook",
                     "elevated-pod-spec"):
            self.assertIn(rule, rule_ids)


if __name__ == "__main__":
    unittest.main()
