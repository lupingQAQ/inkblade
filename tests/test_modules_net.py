"""网络架构模块族测试：fixture 检测命中 + 指纹/combo 线索 + 五维可达矩阵聚合落库。

- 前九个模块：params.snapshot（目录路径或 dict）→ 指纹 → findings（detail 尾部
  ||fingerprints= 机器标记 + combo 线索字段）。
- cni-aware-reachability-graph：聚合其余九个模块的指纹 findings，调
  core.reachability.infer 推演，graph 落 run（graph_nodes/graph_edges），
  输出五维矩阵 finding 与 artifact。
"""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.core.combo import match as combo_match
from inkblade.core.evidence import EvidenceStore
from inkblade.core.reachability import MATRIX_DIMENSIONS
from inkblade.core.registry import load_modules
from inkblade.core.roe import init_roe
from inkblade.core.runner import run_module
from inkblade.core.users import UserStore

REPO = Path(__file__).resolve().parents[1]
MODULES_DIR = REPO / "inkblade" / "modules"
FIXTURES = REPO / "lab" / "fixtures" / "network"

NET_KEYS = [
    "fabric-topology-isolation",
    "cni-stack-capability",
    "multus-sriov-rdma-bypass",
    "collective-communication-surface",
    "gpu-network-operator-posture",
    "inference-gateway-pd",
    "storage-protocol-csi",
    "dns-service-discovery",
    "cni-aware-reachability-graph",
    "scheduler-network-semantics",
]
DETECT_KEYS = [k for k in NET_KEYS if k != "cni-aware-reachability-graph"]

EXPECTED_COMBOS = [
    "multus-sriov-rdma-bypass",
    "ib-flatnet-no-partition",
    "pd-split-nixl-rdma-kv-channel",
    "vpc-cni-dual-controlplane-mismatch",
    "inferencepool-failopen-gateway",
    "nvl-dra-imex-domain",
]


def fingerprints_of(finding: dict) -> dict:
    detail = finding.get("detail", "")
    if " ||fingerprints=" not in detail:
        return {}
    tail = detail.rsplit(" ||fingerprints=", 1)[1].split(" ||combo=", 1)[0]
    try:
        return json.loads(tail)
    except json.JSONDecodeError:
        return {}


class TestNetModules(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = EvidenceStore(self.root, workspace="local-lab")
        users = UserStore(self.root / "users.json")
        users.create_user("tester", "x", "tester", ["local-lab"])
        self.session = users.verify("tester", "x")
        init_roe(self.store, fields={
            "level": "只读侦察", "namespaces": ["train", "infer"],
            "cidrs": ["10.0.0.0/8", "127.0.0.0/8"],
        })

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, key, params, run=None):
        return run_module(self.store, self.session, key, params,
                          modules_dir=MODULES_DIR, run=run)

    def _findings(self, run, key):
        return [f for f in run.findings if f["step_key"] == key]

    # ---------- 注册与契约 ----------

    def test_net_modules_registered(self):
        mods = load_modules(MODULES_DIR)
        for key in NET_KEYS:
            self.assertIn(key, mods, f"缺少网络架构模块 {key}")
            self.assertEqual(mods[key].series, "网络架构")
            self.assertEqual(mods[key].min_level, "只读侦察")
            self.assertFalse(mods[key].writes, "静态测绘模块必须 writes=false")

    def test_missing_snapshot_rejected(self):
        with self.assertRaises(ValueError):
            self._run("fabric-topology-isolation", {})

    def test_snapshot_dict_input(self):
        snap = json.loads((FIXTURES / "cluster-fabric.json").read_text(encoding="utf-8"))
        result = self._run("fabric-topology-isolation", {"snapshot": snap})
        run = self.store.open_run(result["run"])
        self.assertGreaterEqual(len(self._findings(run, "fabric-topology-isolation")), 1)

    # ---------- 检测命中（前九模块） ----------

    def test_detection_hits_on_fixtures(self):
        for key in DETECT_KEYS:
            with self.subTest(module=key):
                result = self._run(key, {"snapshot": str(FIXTURES)})
                run = self.store.open_run(result["run"])
                rows = self._findings(run, key)
                self.assertGreaterEqual(len(rows), 1, f"{key} 未产出 finding")
                self.assertTrue(rows[0]["title"])
                self.assertIn(rows[0]["severity"], ("high", "medium", "low", "info"))
                has_fp = any(fingerprints_of(f) for f in rows)
                self.assertTrue(has_fp, f"{key} findings 缺指纹标记（combo 线索字段）")

    def test_multus_uncovered_paths_listed(self):
        result = self._run("multus-sriov-rdma-bypass", {"snapshot": str(FIXTURES)})
        run = self.store.open_run(result["run"])
        rows = self._findings(run, "multus-sriov-rdma-bypass")
        target = [f for f in rows if "NetworkPolicy 不覆盖" in f["title"]]
        self.assertTrue(target, "必须输出「NetworkPolicy 不覆盖路径」清单 finding")
        detail = target[0]["detail"]
        self.assertIn("llm-train-worker", detail, "未覆盖路径清单应包含 SR-IOV 附件 Pod")
        self.assertIn("sriov-rdma-net", detail)
        self.assertIn("ib-sriov-net", detail)
        fps = fingerprints_of(target[0])
        for k in ("multus", "sriov", "rdma", "sriov-attachment", "ib-attachment"):
            self.assertTrue(fps.get(k), f"旁路 finding 缺指纹 {k}")

    def test_cni_capability_matrix_artifact(self):
        result = self._run("cni-stack-capability", {"snapshot": str(FIXTURES)})
        run = self.store.open_run(result["run"])
        matrix_path = run.dir / "artifacts" / "cni-capability-matrix.json"
        self.assertTrue(matrix_path.exists(), "per-CNI 能力矩阵必须落 artifact 文件")
        matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
        cnis = {row["cni"] for row in matrix["cni"]}
        self.assertTrue({"calico", "cilium", "terway"} <= cnis, f"矩阵应含检测到的 CNI: {cnis}")
        for row in matrix["cni"]:
            for cap in ("network-policy", "host-network-policy", "sriov-enforcement", "vpc-native"):
                self.assertIn(cap, row, f"CNI 行缺能力键 {cap}")
        fps_all = {}
        for f in self._findings(run, "cni-stack-capability"):
            fps_all.update(fingerprints_of(f))
        for k in ("hostnetwork-pod", "vpc-native-cni", "security-group-gap", "terway"):
            self.assertTrue(fps_all.get(k), f"CNI 模块缺指纹 {k}")

    def test_fabric_ib_no_partition_fingerprint(self):
        result = self._run("fabric-topology-isolation", {"snapshot": str(FIXTURES)})
        run = self.store.open_run(result["run"])
        fps_all = {}
        for f in self._findings(run, "fabric-topology-isolation"):
            fps_all.update(fingerprints_of(f))
        for k in ("ib-fabric", "ib-no-partition", "nvl-host", "dra", "computedomain"):
            self.assertTrue(fps_all.get(k), f"Fabric 模块缺指纹 {k}")

    def test_gateway_failopen_fingerprint(self):
        result = self._run("inference-gateway-pd", {"snapshot": str(FIXTURES)})
        run = self.store.open_run(result["run"])
        rows = self._findings(run, "inference-gateway-pd")
        self.assertTrue(any("FailOpen" in f["title"] for f in rows), "应有 FailOpen finding")
        fps_all = {}
        for f in rows:
            fps_all.update(fingerprints_of(f))
        for k in ("inferencepool", "failopen", "pd-split", "gateway-api"):
            self.assertTrue(fps_all.get(k), f"推理网关模块缺指纹 {k}")

    def test_storage_nfs_authsys_fingerprint(self):
        result = self._run("storage-protocol-csi", {"snapshot": str(FIXTURES)})
        run = self.store.open_run(result["run"])
        rows = self._findings(run, "storage-protocol-csi")
        self.assertTrue(any("AUTH_SYS" in f["detail"] for f in rows), "应有 NFS AUTH_SYS finding")
        fps_all = {}
        for f in rows:
            fps_all.update(fingerprints_of(f))
        for k in ("nfs-authsys", "rwx-shared-pvc", "csi-node-privileged"):
            self.assertTrue(fps_all.get(k), f"存储模块缺指纹 {k}")

    def test_dns_coredns_fingerprints(self):
        result = self._run("dns-service-discovery", {"snapshot": str(FIXTURES)})
        run = self.store.open_run(result["run"])
        fps_all = {}
        for f in self._findings(run, "dns-service-discovery"):
            fps_all.update(fingerprints_of(f))
        for k in ("coredns-forward-open", "dns-poison-surface", "ray-gcs-discoverable",
                  "cross-cluster-dns"):
            self.assertTrue(fps_all.get(k), f"DNS 模块缺指纹 {k}")

    def test_collective_fingerprints(self):
        result = self._run("collective-communication-surface", {"snapshot": str(FIXTURES)})
        run = self.store.open_run(result["run"])
        fps_all = {}
        for f in self._findings(run, "collective-communication-surface"):
            fps_all.update(fingerprints_of(f))
        for k in ("nccl", "tcpstore-unauth", "nixl-rdma", "areal", "sglang"):
            self.assertTrue(fps_all.get(k), f"集合通信模块缺指纹 {k}")

    def test_operator_posture_fingerprints(self):
        result = self._run("gpu-network-operator-posture", {"snapshot": str(FIXTURES)})
        run = self.store.open_run(result["run"])
        fps_all = {}
        for f in self._findings(run, "gpu-network-operator-posture"):
            fps_all.update(fingerprints_of(f))
        for k in ("ofed-driver-privileged", "sriov-operator", "rdma-device-plugin",
                  "ib-kubernetes", "dra-kubelet-plugin", "computedomain-controller"):
            self.assertTrue(fps_all.get(k), f"Operator 姿态模块缺指纹 {k}")

    def test_scheduler_fingerprints(self):
        result = self._run("scheduler-network-semantics", {"snapshot": str(FIXTURES)})
        run = self.store.open_run(result["run"])
        fps_all = {}
        for f in self._findings(run, "scheduler-network-semantics"):
            fps_all.update(fingerprints_of(f))
        for k in ("gang-dos-surface", "cross-namespace-submit", "topology-mismatch"):
            self.assertTrue(fps_all.get(k), f"调度语义模块缺指纹 {k}")

    # ---------- 组合矩阵联动 + 可达性图聚合 ----------

    def test_combo_matrix_hits_from_family_fingerprints(self):
        run = self.store.create_run("net-combo-run")
        fps: dict = {}
        for key in DETECT_KEYS:
            self._run(key, {"snapshot": str(FIXTURES)}, run=run)
            for f in self._findings(run, key):
                fps.update(fingerprints_of(f))
        sigs = [h.signature for h in combo_match(fps)]
        for sig in EXPECTED_COMBOS:
            self.assertIn(sig, sigs, f"家族指纹应命中组合签名 {sig}")

    def test_reachability_graph_aggregates_and_persists(self):
        run = self.store.create_run("net-graph-run")
        for key in DETECT_KEYS:
            self._run(key, {"snapshot": str(FIXTURES)}, run=run)
        self._run("cni-aware-reachability-graph", {"snapshot": str(FIXTURES)}, run=run)

        # graph 落库（ctx['run'].upsert_node / add_edge）
        nodes = run.query("SELECT node_id, kind, layer FROM graph_nodes")
        edges = run.query("SELECT src, dst, verdict, method FROM graph_edges")
        self.assertGreaterEqual(len(nodes), 3, "可达性图节点应落 graph_nodes")
        self.assertGreaterEqual(len(edges), 3, "可达性图边应落 graph_edges")
        self.assertTrue(any(e[1] == "node-plane" for e in edges), "hostNetwork 旁路边应存在")
        self.assertTrue(any(e[2] in ("旁路", "可达") for e in edges))

        # 五维矩阵 finding + artifact
        rows = self._findings(run, "cni-aware-reachability-graph")
        matrix_finding = [f for f in rows if "五维" in f["title"]]
        self.assertTrue(matrix_finding, "应输出五维可达矩阵 finding")
        matrix_path = run.dir / "artifacts" / "reachability-matrix.json"
        self.assertTrue(matrix_path.exists(), "五维矩阵应落 artifact 文件")
        matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
        self.assertEqual(set(matrix["matrix"].keys()), set(MATRIX_DIMENSIONS))
        for dim in MATRIX_DIMENSIONS:
            self.assertIsInstance(matrix["matrix"][dim], list)
        self.assertTrue(matrix["matrix"]["pod 到宿主"], "hostNetwork 维度应有边")
        self.assertTrue(matrix["matrix"]["pod 到 IB"], "IB 旁路维度应有边")
        self.assertTrue(matrix["matrix"]["跨集群"], "VPC 安全组缺口维度应有边")


if __name__ == "__main__":
    unittest.main()
