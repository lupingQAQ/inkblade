import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from trident.core.evidence import EvidenceStore
from trident.core.graph import Graph, LAYERS, METHODS
from trident.core.reachability import MATRIX_DIMENSIONS, infer


class TestGraphModel(unittest.TestCase):
    def test_layer_and_method_validated(self):
        g = Graph()
        g.add_node("pod-a", "pod", "CNI 与 Overlay 层")
        g.add_node("host-b", "宿主", "主机网络层")
        with self.assertRaises(ValueError):
            g.add_node("bad", "pod", "不存在的层")
        with self.assertRaises(ValueError):
            g.add_edge("pod-a", "host-b", "可达", "拍脑袋")
        g.add_edge("pod-a", "host-b", "可达", "配置证据")
        edge = g.reachable("pod-a", "host-b")
        self.assertIsNotNone(edge)
        self.assertEqual(edge.method, "配置证据")
        self.assertIsNone(g.reachable("host-b", "pod-a"))

    def test_edge_requires_nodes(self):
        g = Graph()
        g.add_node("pod-a", "pod", "CNI 与 Overlay 层")
        with self.assertRaises(ValueError):
            g.add_edge("pod-a", "ghost", "可达", "配置证据")


class TestInfer(unittest.TestCase):
    def test_hostnetwork_bypass_inferred(self):
        g = infer({"hostnetwork-pod": True})
        edge = g.reachable("workload-pod", "node-plane")
        self.assertIsNotNone(edge)
        self.assertEqual(edge.verdict, "可达")
        self.assertEqual(edge.method, "配置证据")

    def test_sriov_bypass_despite_policy(self):
        g = infer({"sriov-attachment": True, "network-policy-coverage": True})
        edge = g.reachable("workload-pod", "sriov-network")
        self.assertIsNotNone(edge)
        self.assertEqual(edge.verdict, "旁路")
        self.assertEqual(edge.method, "配置证据")

    def test_vpc_native_sg_gap(self):
        g = infer({"vpc-native-cni": True, "security-group-gap": True})
        edge = g.reachable("workload-pod", "cloud-intranet")
        self.assertIsNotNone(edge)
        self.assertEqual(edge.verdict, "可达")
        self.assertEqual(edge.method, "静态策略推演")

    def test_ib_no_partition_collective(self):
        g = infer({"ib-fabric": True, "ib-partition": False})
        edge = g.reachable("workload-pod", "collective-endpoint")
        self.assertIsNotNone(edge)
        self.assertEqual(edge.verdict, "可达")
        self.assertEqual(edge.method, "静态策略推演")

    def test_no_false_edges(self):
        g = infer({"network-policy-coverage": True})
        self.assertEqual(g.edges, [])


class TestMatrix(unittest.TestCase):
    def test_matrix_dimensions(self):
        g = infer({"hostnetwork-pod": True})
        m = g.render_matrix()
        self.assertEqual(set(m.keys()), set(MATRIX_DIMENSIONS))
        self.assertTrue(any(e["src"] == "workload-pod" for e in m["pod 到宿主"]))
        # 空维度也必须以键存在
        for dim in MATRIX_DIMENSIONS:
            self.assertIsInstance(m[dim], list)

    def test_verdict_method_recorded(self):
        g = infer({"hostnetwork-pod": True, "ib-fabric": True, "ib-partition": False})
        m = g.render_matrix()
        flat = [e for dim in m.values() for e in dim]
        self.assertTrue(flat)
        for e in flat:
            self.assertIn(e["method"], METHODS)
            self.assertTrue(e["verdict"])


class TestPersistence(unittest.TestCase):
    def test_persisted_to_graph_tables(self):
        with TemporaryDirectory() as tmp:
            store = EvidenceStore(Path(tmp), "local-lab")
            run = store.create_run("graph-run")
            g = infer(
                {"hostnetwork-pod": True, "vpc-native-cni": True, "security-group-gap": True},
                run=run,
            )
            nodes = run.query("SELECT node_id, layer FROM graph_nodes")
            edges = run.query("SELECT src, dst, verdict, method FROM graph_edges")
            self.assertGreaterEqual(len(nodes), 2)
            self.assertGreaterEqual(len(edges), 2)
            self.assertIn("主机网络层", [n[1] for n in nodes])
            self.assertIn(("workload-pod", "cloud-intranet", "可达", "静态策略推演"),
                          [(e[0], e[1], e[2], e[3]) for e in edges])


if __name__ == "__main__":
    unittest.main()
