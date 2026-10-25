# -*- coding: utf-8 -*-
"""payload 变体库（弹药 B②）测试：物化/白名单/每模块≥2变体/参数面。"""

import unittest

from trident.core.payloads import (
    PayloadError, http_variants, materialize, param_variants, variants,
)

BASE = {"method": "POST", "path": "/pause", "body": {}, "headers": {}}


class TestMaterialize(unittest.TestCase):
    def test_path_suffix(self):
        out = materialize(BASE, {"op": "path_suffix", "arg": "/"})
        self.assertEqual(out["path"], "/pause/")
        self.assertEqual(out["method"], "POST")

    def test_path_case(self):
        out = materialize(BASE, {"op": "path_case"})
        self.assertEqual(out["path"], "/Pause")

    def test_path_dotseg(self):
        out = materialize({"method": "GET", "path": "/plugins/list"}, {"op": "path_dotseg"})
        self.assertEqual(out["path"], "/plugins/./list")

    def test_pct_and_double_pct(self):
        out = materialize(BASE, {"op": "pct_encode"})
        self.assertEqual(out["path"], "/%70ause")
        out2 = materialize(BASE, {"op": "double_pct_encode"})
        self.assertEqual(out2["path"], "/%2570ause")

    def test_method_whitelist(self):
        out = materialize(BASE, {"op": "method", "arg": "PUT"})
        self.assertEqual(out["method"], "PUT")
        with self.assertRaises(PayloadError):
            materialize(BASE, {"op": "method", "arg": "DELETE"})

    def test_header_override(self):
        out = materialize(BASE, {"op": "header", "arg": ["Authorization", "Bearer "]})
        self.assertEqual(out["headers"]["Authorization"], "Bearer ")

    def test_query_and_body_merge(self):
        out = materialize(BASE, {"op": "query", "arg": ["probe", "cve"]})
        self.assertEqual(out["path"], "/pause?probe=cve")
        merged = materialize({"method": "POST", "path": "/x", "body": {"a": 1}},
                             {"op": "body_merge", "arg": {"b": 2}})
        self.assertEqual(merged["body"], {"a": 1, "b": 2})
        with self.assertRaises(PayloadError):
            materialize({"method": "POST", "path": "/x", "body": "raw"},
                        {"op": "body_merge", "arg": {"b": 2}})

    def test_unknown_op_rejected(self):
        with self.assertRaises(PayloadError):
            materialize(BASE, {"op": "evil", "arg": "x"})
        with self.assertRaises(PayloadError):
            materialize(BASE, {})

    def test_pct_no_letter_raises(self):
        with self.assertRaises(PayloadError):
            materialize({"method": "GET", "path": "/123"}, {"op": "pct_encode"})


class TestHttpVariants(unittest.TestCase):
    def test_sglang_two_plus_distinct(self):
        vs = http_variants("sglang-admin-failopen", BASE)
        self.assertGreaterEqual(len(vs), 2)
        self.assertGreater(len({v["path"] for v in vs}), 1)
        # 每个变体必须与原始探针（POST /pause）至少差一处
        for v in vs:
            differs = v["path"] != "/pause" or v["method"] != "POST" or v.get("headers")
            self.assertTrue(differs, f"变体 {v['variant']} 与原始探针无差异")

    def test_limit(self):
        vs = http_variants("sglang-admin-failopen", BASE, limit=1)
        self.assertEqual(len(vs), 1)

    def test_unknown_module_raises(self):
        with self.assertRaises(PayloadError):
            http_variants("no-such-module", BASE)

    def test_surface_mismatch_raises(self):
        with self.assertRaises(PayloadError):
            http_variants("areal-awex-nccl-injection", BASE)  # surface=params


class TestParamVariants(unittest.TestCase):
    def test_param_surface(self):
        vs = param_variants("areal-awex-nccl-injection", {"transport": "tcp"})
        self.assertGreaterEqual(len(vs), 2)
        kinds = {v["params"].get("transport"): v["params"] for v in vs}
        self.assertIn("rdma", kinds)  # v1 覆盖 transport
        others = [v["params"] for v in vs if v["params"].get("transport") == "tcp"]
        self.assertTrue(others and others[0].get("use_group") == "1")  # v2 增参数变体

    def test_http_module_param_variant_rejected(self):
        with self.assertRaises(PayloadError):
            param_variants("sglang-admin-failopen", {})


class TestDispatch(unittest.TestCase):
    def test_variants_dispatch_by_surface(self):
        self.assertTrue(variants("sglang-admin-failopen", BASE))
        self.assertTrue(variants("areal-awex-nccl-injection", {"transport": "tcp"}))


if __name__ == "__main__":
    unittest.main()
