# -*- coding: utf-8 -*-
"""资产自动发现（XBow 对标 ①）测试：增量差异/产品推断/资产图/模块消费。"""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.core.discovery import AssetInventory, DiscoveryError, discover, infer_product
from inkblade.core.evidence import EvidenceStore

SEEDS_V1 = {
    "namespaces": ["ml-train"],
    "services": [
        {"name": "sglang-admin", "namespace": "ml-train", "addr": "10.0.0.11", "port": 30000},
        {"name": "ray-head", "namespace": "ml-train", "addr": "10.0.0.12", "port": 8265},
        {"name": "litellm-gw", "namespace": "ml-train", "addr": "10.0.0.13", "port": 8081},
    ],
}
SEEDS_V2 = {
    "namespaces": ["ml-train"],
    "services": [
        {"name": "sglang-admin", "namespace": "ml-train", "addr": "10.0.0.11", "port": 30000},
        {"name": "ray-head", "namespace": "ml-train", "addr": "10.0.0.99", "port": 8265},  # addr 变更
        {"name": "vllm-main", "namespace": "ml-train", "addr": "10.0.0.14", "port": 8000},  # 新增
        # litellm-gw 消失 → removed
    ],
}


class TestInferProduct(unittest.TestCase):
    def test_names_labels_ports(self):
        self.assertEqual(infer_product("sglang-admin"), "sglang")
        self.assertEqual(infer_product("x", labels={"app": "vllm"}), "vllm")
        self.assertEqual(infer_product("svc", port=8265), "kuberay")
        self.assertEqual(infer_product("random"), "")


class TestInventory(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.store = EvidenceStore(Path(self.tmp.name), workspace="local-lab")

    def tearDown(self):
        self.tmp.cleanup()

    def test_ingest_incremental_diff(self):
        inv = AssetInventory(self.store)
        d1 = inv.ingest(SEEDS_V1, source="seed")
        self.assertEqual(len(d1["added"]), 4)  # 1 ns + 3 svc
        self.assertEqual(d1["removed"], [])
        d2 = inv.ingest(SEEDS_V2, source="seed")
        self.assertEqual(len(d2["added"]), 1)  # vllm-main
        self.assertIn("service/ml-train/litellm-gw", d2["removed"])
        updated_keys = [u["asset_key"] for u in d2["updated"]]
        self.assertIn("service/ml-train/ray-head", updated_keys)

    def test_soft_delete_keeps_audit_trail(self):
        inv = AssetInventory(self.store)
        inv.ingest(SEEDS_V1, source="seed")
        inv.ingest(SEEDS_V2, source="seed")
        live = inv.list(kind="service")
        self.assertNotIn("service/ml-train/litellm-gw", {a["asset_key"] for a in live})
        all_assets = inv.list(kind="service", include_missing=True)
        gone = next(a for a in all_assets if a["asset_key"] == "service/ml-train/litellm-gw")
        self.assertTrue(gone["missing"])
        self.assertIsNotNone(gone["missing_since"])

    def test_other_source_not_removed(self):
        inv = AssetInventory(self.store)
        inv.ingest(SEEDS_V1, source="seed")
        d = inv.ingest({"namespaces": ["other"]}, source="another")
        self.assertEqual(d["removed"], [])  # 不同源不互删

    def test_invalid_seeds(self):
        inv = AssetInventory(self.store)
        with self.assertRaises(DiscoveryError):
            inv.ingest({})
        with self.assertRaises(DiscoveryError):
            inv.ingest({"services": [{"no-name": 1}]})

    def test_kubeconfig_snapshot_seed(self):
        inv = AssetInventory(self.store)
        d = inv.ingest({"kubeconfig_snapshot": {
            "contexts": ["lab"], "clusters": ["lab"], "users": [1, 2], "namespaces": ["ns-a"]}},
            source="kube")
        self.assertEqual(len(d["added"]), 2)  # kubeconfig + ns-a
        kinds = {a["kind"] for a in inv.list()}
        self.assertIn("kubeconfig", kinds)

    def test_graph_shape(self):
        inv = AssetInventory(self.store)
        inv.ingest(SEEDS_V1, source="seed")
        g = inv.graph()
        self.assertEqual(len(g["nodes"]), 4)
        self.assertEqual(len(g["edges"]), 3)  # 3 service→namespace contains

    def test_resolve_targets_and_bind(self):
        inv = AssetInventory(self.store)
        inv.ingest(SEEDS_V1, source="seed")
        hits = inv.resolve_targets("sglang-admin-failopen")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["port"], 30000)
        params = inv.bind_params("sglang-admin-failopen", {"use_assets": True})
        self.assertEqual(params["target"], "http://10.0.0.11:30000")
        self.assertEqual(params["asset_key"], "service/ml-train/sglang-admin")
        # 显式 target 优先
        keep = inv.bind_params("sglang-admin-failopen",
                               {"use_assets": True, "target": "http://manual:1"})
        self.assertEqual(keep["target"], "http://manual:1")
        # 未开 use_assets 不动 params
        raw = inv.bind_params("sglang-admin-failopen", {})
        self.assertEqual(raw, {})

    def test_discover_helper(self):
        diff = discover(self.store, SEEDS_V1)
        self.assertEqual(len(diff["added"]), 4)


if __name__ == "__main__":
    unittest.main()
