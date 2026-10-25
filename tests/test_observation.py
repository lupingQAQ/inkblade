# -*- coding: utf-8 -*-
"""结构化观察（动作/结果/证据指针/下一步候选）测试。

核心不变量（对齐 TCH 参赛项目的「证据优先」）：
- 声称 confirmed 的观察必须带至少一个证据指针，否则降级为 hypothesis 或直接拒绝；
- 下一步候选必须来自候选目录，且自动剔除已成功动作与死胡同；
- 压缩保留高信号（confirmed 优先），并给出省下的 token 估算。
"""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from trident.core import observation as ob
from trident.core.evidence import EvidenceStore


def _action(module="sglang-admin-failopen", **kw):
    base = {"module": module, "writes": False, "params": {"use_assets": True}}
    base.update(kw)
    return base


class TestBuild(unittest.TestCase):
    def test_confirmed_requires_evidence(self):
        with self.assertRaises(ob.ObservationError):
            ob.build(1, _action(), status="ok", result_summary="admin fail-open",
                     evidence=[])

    def test_failed_becomes_hypothesis(self):
        obs = ob.build(2, _action(), status="failed", result_summary="connection refused",
                       evidence=[])
        self.assertEqual(obs["claim"], "hypothesis")
        self.assertEqual(obs["result"]["status"], "failed")
        self.assertEqual(obs["schema"], ob.SCHEMA)

    def test_confirmed_with_evidence_pointer(self):
        obs = ob.build(3, _action(), status="ok", result_summary="verify ok",
                       evidence=[{"kind": "finding", "ref": "finding:12",
                                  "detail": "sglang admin without auth"}])
        self.assertEqual(obs["claim"], "confirmed")
        self.assertEqual(obs["evidence"][0]["ref"], "finding:12")
        self.assertTrue(obs["key"])
        self.assertEqual(obs["action"]["module"], "sglang-admin-failopen")

    def test_result_summary_bounded(self):
        obs = ob.build(4, _action(), status="ok", result_summary="x" * 2000,
                       evidence=[{"kind": "run", "ref": "run:r1"}])
        self.assertLessEqual(len(obs["result"]["summary"]), ob.MAX_SUMMARY + 1)

    def test_next_candidates_validated(self):
        obs = ob.build(5, _action(), status="ok", result_summary="done",
                       evidence=[{"kind": "run", "ref": "run:r1"}],
                       candidates=[{"module": "m2", "reason": "same product",
                                    "confidence": 0.7},
                                   {"module": "m3", "reason": "chain", "confidence": 1.9}])
        self.assertEqual(obs["next"][0]["module"], "m2")
        self.assertTrue(obs["next"][0]["requires_approval"])
        self.assertEqual(obs["next"][1]["confidence"], 1.0)

    def test_bad_evidence_kind_rejected(self):
        with self.assertRaises(ob.ObservationError):
            ob.build(6, _action(), status="ok", result_summary="x",
                     evidence=[{"kind": "vibes", "ref": "?"}])


class TestCandidatesAndDedupe(unittest.TestCase):
    def test_candidate_ranking_excludes_executed_and_dead_ends(self):
        catalog = [
            {"module": "write-mod", "writes": True, "reason": "write"},
            {"module": "read-mod", "writes": False, "reason": "read"},
            {"module": "dead-mod", "writes": False, "reason": "dead"},
            {"module": "done-mod", "writes": False, "reason": "done"},
        ]
        observations = [
            ob.build(1, _action("done-mod"), status="ok", result_summary="ok",
                     evidence=[{"kind": "run", "ref": "run:1"}]),
        ]
        dead = [ob.build(2, _action("dead-mod"), status="failed", result_summary="x"),
                ob.build(3, _action("dead-mod"), status="failed", result_summary="y")]
        picks = ob.next_candidates(catalog, observations + dead, limit=2)
        self.assertEqual([p["module"] for p in picks], ["read-mod", "write-mod"])
        self.assertEqual(picks[1]["requires_approval"], True)

    def test_dedupe_keeps_latest_success(self):
        a = ob.build(1, _action("m1"), status="failed", result_summary="x")
        b = ob.build(2, _action("m1"), status="ok", result_summary="ok",
                     evidence=[{"kind": "run", "ref": "run:1"}])
        kept = ob.dedupe([a, b])
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0]["result"]["status"], "ok")

    def test_compress_prioritizes_confirmed(self):
        rows = [ob.build(i, _action(f"m{i}"), status="failed", result_summary="x" * 100)
                for i in range(1, 8)]
        rows.append(ob.build(9, _action("key"), status="ok", result_summary="key finding",
                             evidence=[{"kind": "finding", "ref": "finding:1"}]))
        packed = ob.compress(rows, max_items=3)
        self.assertEqual(len(packed["items"]), 3)
        self.assertEqual(packed["items"][0]["module"], "key")
        self.assertGreater(packed["dropped"], 0)
        self.assertGreaterEqual(packed["tokens_saved"], 0)


class TestPersistence(unittest.TestCase):
    def test_append_read_roundtrip(self):
        with TemporaryDirectory() as td:
            store = EvidenceStore(Path(td), workspace="local-lab")
            obs = ob.build(1, _action(), status="ok", result_summary="ok",
                           evidence=[{"kind": "run", "ref": "run:r1"}])
            path = ob.append(store, obs)
            self.assertTrue(path.exists())
            rows = ob.read(path)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["result"]["summary"], "ok")
            raw = path.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(json.loads(raw[0])["key"], obs["key"])

    def test_coverage_counts_confirmed_with_evidence(self):
        rows = [
            ob.build(1, _action("a"), status="ok", result_summary="ok",
                     evidence=[{"kind": "run", "ref": "run:1"}]),
            ob.build(2, _action("b"), status="failed", result_summary="no"),
        ]
        cov = ob.coverage(rows)
        self.assertEqual(cov["total"], 2)
        self.assertEqual(cov["confirmed"], 1)
        self.assertEqual(cov["ratio"], 0.5)


if __name__ == "__main__":
    unittest.main()
