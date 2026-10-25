"""终审 Minor#12：报告「网络分层威胁模型」节改数据驱动（消费 graph_nodes/graph_edges）。

断言：
- 节点按 ``layer`` 聚合，报告中出现每层计数与节点样例；
- 边按 ``verdict``/``method`` 列示，标注「判定方式」（CNI 语义推演 / 实测 / 静态规则）；
- 空图 run 仍保留七层叙述 + 明确的「本 run 未落图数据」声明（不臆造节点）。
"""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from trident.core.evidence import EvidenceStore
from trident.reports.render import render_pentest


class TestNetworkThreatModelSection(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = EvidenceStore(self.root, workspace="local-lab")

    def tearDown(self):
        self.tmp.cleanup()

    def _seed(self, name: str):
        run = self.store.create_run(name)
        run.add_step("s1", "probe", {"actor": "tester"}, "summary")
        run.upsert_node("ns/train", "namespace", "命名空间层", {"ns": "train"})
        run.upsert_node("svc/sglang", "service", "工作负载层", {"ns": "train", "port": 30000})
        run.upsert_node("pod/ray-head", "pod", "工作负载层", {"ns": "ray-system"})
        run.upsert_node("node/gpu-0", "node", "主机网络层", {"ip": "10.1.2.3"})
        run.add_edge("ns/train", "svc/sglang", "reachable", "CNI 语义推演", "admin-plane")
        run.add_edge("svc/sglang", "pod/ray-head", "reachable", "实测（HTTP 200）", "admin-plane")
        run.add_edge("pod/ray-head", "node/gpu-0", "blocked", "静态规则（NetworkPolicy）", "lateral")
        return run

    def test_layers_and_verdict_methods_rendered(self):
        run = self._seed("net-layers")
        text = render_pentest(self.store, run.name, lang="zh")
        # 层名与计数（数据驱动）
        self.assertIn("命名空间层", text)
        self.assertIn("工作负载层", text)
        self.assertIn("主机网络层", text)
        self.assertIn("| 工作负载层 | 2 |", text)
        self.assertIn("| 主机网络层 | 1 |", text)
        # 节点样例
        for node in ("ns/train", "svc/sglang", "pod/ray-head", "node/gpu-0"):
            self.assertIn(node, text)
        # 判定方式（边）
        self.assertIn("CNI 语义推演", text)
        self.assertIn("实测（HTTP 200）", text)
        self.assertIn("静态规则（NetworkPolicy）", text)
        self.assertIn("判定方式", text)
        # 边计数：reachable 2 / blocked 1
        self.assertIn("| reachable | 2 |", text)
        self.assertIn("| blocked | 1 |", text)
        self.assertNotIn("本 run 未落图数据", text)

    def test_english_variant_has_same_data(self):
        run = self._seed("net-layers-en")
        text = render_pentest(self.store, run.name, lang="en")
        self.assertIn("Layered Network Threat Model", text)
        self.assertIn("svc/sglang", text)
        self.assertIn("CNI 语义推演", text)  # 判定方式为数据原值，不做翻译
        self.assertIn("Layer", text)

    def test_empty_graph_falls_back_without_fabrication(self):
        run = self.store.create_run("net-empty")
        run.add_step("s1", "probe", {"actor": "tester"}, "summary")
        text = render_pentest(self.store, run.name, lang="zh")
        self.assertIn("网络分层威胁模型", text)
        self.assertIn("未落图数据", text)
        # 七层模型叙述仍在（standards 基线）
        self.assertIn("物理 fabric", text)
        self.assertIn("集合通信", text)

    def test_section_is_deterministic(self):
        run = self._seed("net-det")
        a = render_pentest(self.store, run.name, lang="zh")
        b = render_pentest(self.store, run.name, lang="zh")
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
