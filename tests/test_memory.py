"""tests/test_memory.py — 三层记忆（working/episodic/semantic）检索 API 与压缩策略。

断言：
- working 有界、超限压缩保留头尾并输出摘要（不丢引用）；
- episodic 从 evidence DB 跨 run 检索 findings/steps；
- semantic 从资产/技能/模块图谱检索；
- retrieve 分层返回并按分数排序；空查询可用；
- 压缩前后条数/摘要/保留引用结构完整。
"""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from trident.core.evidence import EvidenceStore
from trident.core.memory import LAYERS, Memory, WorkingMemory

REPO = Path(__file__).resolve().parents[1]


class WorkingMemoryTest(unittest.TestCase):
    def test_bounded_and_compacted(self):
        wm = WorkingMemory(capacity=6)
        for i in range(10):
            wm.add(f"note-{i}", ref=f"ref-{i}")
        self.assertEqual(len(wm.items()), 6)
        self.assertEqual([i["text"] for i in wm.items()], [f"note-{i}" for i in range(4, 10)])
        result = wm.compact(max_items=3, keep_tail=2)
        self.assertLessEqual(result["after"], 3)
        self.assertGreaterEqual(result["dropped"], 1)
        ctx = wm.context()
        self.assertTrue(any("compacted" in item.get("kind", "") for item in ctx))
        refs = {item.get("ref") for item in ctx}
        self.assertIn("ref-9", refs)

    def test_context_is_json_safe(self):
        wm = WorkingMemory()
        wm.add("a", kind="note", ref="r1")
        payload = wm.context()
        self.assertEqual(payload[0]["kind"], "note")
        self.assertEqual(payload[0]["ref"], "r1")


class MemoryLayersTest(unittest.TestCase):
    def setUp(self):
        self.td = TemporaryDirectory()
        self.store = EvidenceStore(Path(self.td.name), workspace="local-lab")
        run = self.store.create_run("run-memory")
        run.add_step("exposure-mapping", "snapshot", {"actor": "tester"}, "暴露面 12 条")
        run.add_finding("exposure-mapping", "critical", "Ray Dashboard LoadBalancer 暴露", "auth=none")
        run.add_finding("escape-primitives", "high", "特权 Pod 宿主逃逸原语", "privileged=true")
        self.memory = Memory(self.store, modules_dir=REPO / "trident" / "modules")

    def tearDown(self):
        self.td.cleanup()

    def episodic(self, q, k=5):
        return self.memory.retrieve(q, k=k, layers=("episodic",))

    def test_episodic_retrieves_findings_across_runs(self):
        hits = self.episodic("宿主逃逸")
        self.assertTrue(hits)
        self.assertEqual(hits[0]["layer"], "episodic")
        self.assertIn("逃逸", hits[0]["text"])
        self.assertIn("run-memory", hits[0]["ref"])

    def test_semantic_retrieves_module_graph(self):
        hits = self.memory.retrieve("ray", k=5, layers=("semantic",))
        self.assertTrue(hits)
        self.assertTrue(any("ray" in h["text"].lower() for h in hits))
        self.assertTrue(all(h["layer"] == "semantic" for h in hits))

    def test_retrieve_fuses_layers_and_sorts(self):
        self.memory.working.add("宿主逃逸 现场笔记", ref="run-memory/step-1")
        hits = self.memory.retrieve("宿主逃逸", k=6)
        self.assertTrue({"working", "episodic"} <= {h["layer"] for h in hits} & set(LAYERS))
        scores = [h["score"] for h in hits]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_compaction_reports(self):
        for i in range(8):
            self.memory.working.add(f"step-{i}", ref=f"r{i}")
        result = self.memory.compact()
        self.assertEqual(result["strategy"], "head-tail-digest")
        self.assertLess(result["after"], result["before"])
        self.assertTrue(result["digest"])

    def test_unknown_layer_rejected(self):
        with self.assertRaises(ValueError):
            self.memory.retrieve("x", layers=("bogus",))


if __name__ == "__main__":
    unittest.main()
