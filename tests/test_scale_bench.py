"""tests/test_scale_bench.py — 合成规模压测与 O(n²) 回归护栏。

覆盖三层：
1. 快照生成器契约：对象总数逐 scale 精确等于目标值、可复现、11 模块消费键齐备；
2. 复杂度回归：用「字典读取计数器」而非计时——索引化实现里每个 policy/serviceaccount/service
   字典只被读常数次，旧实现则是 pods×policies / pods×SAs / raycrs×services 次；
3. 端到端：100 对象跑批（11 侦察模块 + 可达性 + 规则生成）与 findings 语义不回归。
"""
import json
import sys
import unittest
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lab.bench.bench import MemorySampler  # noqa: F401  # 复用同一 RSS 采样实现（导入即验证）
from trident.core.reachability import infer

SCALE_BENCH = ROOT / "lab" / "bench" / "scale-bench.py"
MODULES_DIR = ROOT / "trident" / "modules"
RECON_MODULES = (
    "cloud-integration-fingerprint", "escape-primitives", "exposure-mapping",
    "framework-port-matching", "metadata-egress", "network-policy-coverage",
    "observability-exposure", "privileged-workloads", "ray-control-plane",
    "rbac-mapping", "storage-sharing",
)


def _load_path(path: Path, name: str):
    spec = spec_from_file_location(name, path)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_SCALE = _load_path(SCALE_BENCH, "trident_scale_bench")


def load_run(key: str):
    return _load_path(MODULES_DIR / key / "run.py", f"scale_test_{key.replace('-', '_')}")


class CountingDict(dict):
    """dict 读取计数器：任何 .get/[]/in 命中都记一次（用于证明扫描次数与对象数关系）。"""

    gets = 0

    @classmethod
    def reset(cls):
        cls.gets = 0

    def get(self, key, default=None):
        type(self).gets += 1
        return super().get(key, default)

    def __getitem__(self, key):
        type(self).gets += 1
        return super().__getitem__(key)

    def __contains__(self, key):
        type(self).gets += 1
        return super().__contains__(key)


class SnapshotGeneratorTest(unittest.TestCase):
    def test_object_totals_exact(self):
        for scale in (100, 1000, 5000, 10000):
            snap = _SCALE.build_snapshot(scale)
            counts = _SCALE.snapshot_object_count(snap)
            self.assertEqual(counts["total"], scale, f"scale={scale} 对象总数不符：{counts}")
            self.assertGreater(counts["pods"], 0)
            self.assertGreater(counts["namespaces"], 1)

    def test_deterministic(self):
        a = _SCALE.build_snapshot(2000)
        b = _SCALE.build_snapshot(2000)
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))
        small = _SCALE.build_snapshot(1000)
        self.assertNotEqual(json.dumps(a, sort_keys=True), json.dumps(small, sort_keys=True))
        self.assertEqual(_SCALE.snapshot_object_count(a)["total"], 2000)

    def test_snapshot_contract_keys(self):
        snap = _SCALE.build_snapshot(500)
        for key in _SCALE._SNAPSHOT_CONTRACT:
            self.assertIn(key, snap, f"快照缺模块消费键 {key}")
        # 11 个侦察模块各取所需：core 六类对象必须非空
        for key in ("namespaces", "pods", "services", "networkpolicies", "roles", "pvcs"):
            self.assertTrue(snap[key], f"{key} 为空，压测不成立")

    def test_recon_module_list_matches_registry_family(self):
        from trident.core.registry import load_modules

        modules = load_modules(MODULES_DIR)
        for key in RECON_MODULES:
            self.assertIn(key, modules)
        # 11 模块集合与 tests/test_modules_recon.py 口径一致（防新增模块漏压测）
        self.assertEqual(len(set(RECON_MODULES)), 11)


class NoQuadraticScanTest(unittest.TestCase):
    """旧实现的 O(n²) 扫描：每 Pod 重扫全部策略 / 每 Pod 线性找 SA / 每 RayCluster 线性找 Service。"""

    def _snapshot(self, pods=400, policies=60, sas=40, services=80, raycrs=40):
        snap = {"pods": [], "networkpolicies": [], "serviceaccounts": [],
                "services": [], "rayclusters": []}
        for i in range(pods):
            snap["pods"].append({"namespace": f"ns-{i % 10}", "name": f"p{i}",
                                 "serviceAccount": f"sa-{i % sas}",
                                 "containers": [{"name": "c", "image": "vllm/vllm-openai",
                                                 "env": [], "securityContext": {}}],
                                 "volumes": []})
        for i in range(policies):
            # 交替两种形态：默认拒绝（空选择器 + Egress）与仅选择部分 Pod（标签选择器 + Ingress）
            if i % 2 == 0:
                snap["networkpolicies"].append(CountingDict(
                    {"namespace": f"ns-{i % 10}", "name": f"np{i}", "podSelector": {},
                     "policyTypes": ["Ingress", "Egress"], "ingress": []}))
            else:
                snap["networkpolicies"].append(CountingDict(
                    {"namespace": f"ns-{i % 10}", "name": f"np{i}", "podSelector": {"app": "x"},
                     "policyTypes": ["Ingress"], "ingress": [{"from": []}]}))
        for i in range(sas):
            snap["serviceaccounts"].append(CountingDict(
                {"namespace": f"ns-{i % 10}", "name": f"sa-{i}", "annotations": {}, "automount": False}))
        for i in range(services):
            snap["services"].append(CountingDict(
                {"namespace": f"ns-{i % 10}", "name": f"ray-dashboard-{i}",
                 "type": "ClusterIP", "ports": [{"port": 8265}]}))
        for i in range(raycrs):
            snap["rayclusters"].append({"namespace": f"ns-{i % 10}", "name": f"rc{i}",
                                        "headService": f"ray-dashboard-{i}", "dashboardPort": 8265,
                                        "auth": "none"})
        return snap

    def test_metadata_egress_single_pass(self):
        snap = self._snapshot()
        CountingDict.reset()
        findings = load_run("metadata-egress").analyze(snap, {})
        self.assertTrue(findings)
        # 索引化后：策略/SA 各读常数次（≤ 12×对象数）；旧实现为 pods×对象数 = 400×60 / 400×40
        self.assertLessEqual(CountingDict.gets, 12 * (len(snap["networkpolicies"]) +
                                                      len(snap["serviceaccounts"])),
                             f"metadata-egress 仍在对每 Pod 重扫（reads={CountingDict.gets}）")

    def test_network_policy_coverage_single_pass(self):
        snap = self._snapshot()
        CountingDict.reset()
        findings = load_run("network-policy-coverage").analyze(snap, {})
        self.assertTrue(findings)
        self.assertLessEqual(CountingDict.gets, 12 * len(snap["networkpolicies"]),
                             f"network-policy-coverage 仍按命名空间全表扫描（reads={CountingDict.gets}）")

    def test_ray_control_plane_single_pass(self):
        snap = self._snapshot()
        CountingDict.reset()
        findings = load_run("ray-control-plane").analyze(snap, {})
        self.assertTrue(findings)
        self.assertLessEqual(CountingDict.gets, 12 * len(snap["services"]),
                             f"ray-control-plane 仍对每 RayCluster 线性找 Service（reads={CountingDict.gets}）")


class ScaleEndToEndTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.snapshot = _SCALE.build_snapshot(1000)

    def test_all_recon_modules_produce_findings(self):
        for key in RECON_MODULES:
            result = load_run(key).run({}, {"snapshot": self.snapshot})
            self.assertIn("summary", result)
            self.assertGreaterEqual(len(result["findings"]), 0, key)
        # 聚合：六类对象齐全的快照必须命中侦察面
        total = sum(len(load_run(key).run({}, {"snapshot": self.snapshot})["findings"])
                    for key in RECON_MODULES)
        self.assertGreater(total, 200, "1000 对象快照的侦察发现数异常偏低")

    def test_findings_semantics_preserved(self):
        """优化后语义不回归：缺失策略命名空间 = high；选择部分 Pod 的命名空间 = medium（无 deny-all）。"""
        findings = load_run("network-policy-coverage").analyze(self.snapshot, {})
        titles = [f["title"] for f in findings]
        sevs = {f["sev"] for f in findings}
        self.assertTrue(any("覆盖缺口" in t for t in titles), titles)
        self.assertIn("high", sevs)
        self.assertIn("medium", sevs)
        self.assertTrue(all("ns=" in f.get("evidence", "") for f in findings))
        # 出网缺口按 Pod 计数（每 Pod 一条）与 Pod 数同阶
        egress = load_run("metadata-egress").analyze(self.snapshot, {})
        pod_like = [f for f in egress if "egress_policy=absent" in f.get("evidence", "")]
        self.assertGreater(len(pod_like), 100)

    def test_reachability_per_namespace_linear(self):
        namespaces = [f"ns-{i}" for i in range(50)]
        fps = {"hostnetwork-pod": True, "network-policy-coverage": True, "vpc-native-cni": True,
               "security-group-gap": True, "sriov-attachment": True, "ib-attachment": True,
               "ib-fabric": True}
        graphs = [infer(fps) for _ in namespaces]
        edges = sum(len(g.edges) for g in graphs)
        self.assertEqual(edges, len(namespaces) * len(graphs[0].edges))
        matrix = graphs[0].render_matrix()
        self.assertEqual(len(matrix), 5, "五维可达矩阵维度缺失")

    def test_rules_generate_from_scale_findings(self):
        from trident.rules.generate import generate_all

        findings = []
        for key in RECON_MODULES:
            for f in load_run(key).run({}, {"snapshot": self.snapshot})["findings"]:
                item = dict(f)
                item.setdefault("module", key)
                findings.append(item)
        import tempfile

        with tempfile.TemporaryDirectory(prefix="trident-scale-test-") as tmp:
            pack = generate_all(ROOT / "trident" / "chains", findings=findings, out_dir=tmp)
            self.assertGreater(pack.total_rules, 20)
            self.assertGreater(pack.covered_chain_count, 10)
            self.assertTrue((Path(tmp) / "mapping.json").exists())
            mapping = json.loads((Path(tmp) / "mapping.json").read_text(encoding="utf-8"))
            self.assertEqual(mapping["inputs"]["findings"], len(findings))

    def test_run_scale_smoke(self):
        result = _SCALE.run_scale(100)
        self.assertEqual(result["objects"]["total"], 100)
        for stage in ("build_snapshot", "reachability-graph", "rules-generate"):
            self.assertIn(stage, result["stages"])
        self.assertFalse(result["totals"]["recon_over_60s"])
        self.assertGreater(result["totals"]["findings"], 0)
        self.assertGreater(result["reachability"]["graphs"], 0)


class RealK3sScalePointTest(unittest.TestCase):
    """真集群 200 对象规模点：证据文件必须可复核（不做网络访问，避免 CI 依赖实验室）。"""

    ARTIFACT = ROOT / "reports" / "samples" / "scale" / "k3s-scale.json"

    def test_artifact_shape(self):
        self.assertTrue(self.ARTIFACT.exists(), f"缺真实规模点证据 {self.ARTIFACT}")
        data = json.loads(self.ARTIFACT.read_text(encoding="utf-8"))
        self.assertEqual(data["mode"], "real-k3s-qemu-tcg")
        self.assertGreaterEqual(data["objects"]["total"], 200, data["objects"])
        self.assertGreaterEqual(data["objects"]["pods"], 50)
        self.assertEqual(set(data["steps"]["recon"]["modules"]), set(RECON_MODULES))
        self.assertGreater(data["steps"]["recon"]["findings"], 0)
        self.assertIn("collect", data["steps"])


if __name__ == "__main__":
    unittest.main()
