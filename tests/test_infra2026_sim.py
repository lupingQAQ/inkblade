"""tests/test_infra2026_sim.py — 2026 infra 议题仿真靶场双态。

覆盖至少 6 个新面：CoCo 证明、SPIRE、webhook TLS、ambient mesh、WASM 权限、PQ TLS；
并覆盖 DPU/IPU、IOMMU、TPM、GitOps、多集群、模型水印、RAG、联邦学习、来源证明。
只读：所有 POST/PUT/PATCH/DELETE 返回 405。
"""

import json
import unittest
import urllib.error
import urllib.request

from lab.infra2026_sim import start_all


def _get(url):
    with urllib.request.urlopen(url, timeout=5) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


class Infra2026SimTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vuln = start_all(mode="vulnerable")
        cls.fixed = start_all(mode="fixed")

    @classmethod
    def tearDownClass(cls):
        cls.vuln.shutdown()
        cls.fixed.shutdown()

    def test_routes_manifest_covers_all_faces(self):
        status, payload = _get(self.vuln.url("/__routes__"))
        self.assertEqual(status, 200)
        paths = {row["path"] for row in payload["routes"]}
        for path in (
            "/coco/attestation", "/coco/policy", "/sandbox/runtime",
            "/spire/entries", "/webhook/tls", "/mesh/policies",
            "/wasm/modules", "/gitops/secrets", "/multicluster/federation",
            "/dpu/offload", "/iommu/groups", "/tpm/eventlog",
            "/tls/posture", "/model/watermark", "/rag/documents",
            "/fl/round", "/provenance/attestation",
        ):
            self.assertIn(path, paths, path)

    def test_coco_attestation_vulnerable_and_fixed(self):
        _, bad = _get(self.vuln.url("/coco/attestation"))
        _, good = _get(self.fixed.url("/coco/attestation"))
        self.assertNotEqual(bad["measurement"], bad["expected_measurement"])
        self.assertTrue(bad["snp_policy"]["debug"])
        self.assertFalse(bad["report_data_binding"])
        self.assertEqual(good["measurement"], good["expected_measurement"])
        self.assertFalse(good["snp_policy"]["debug"])
        self.assertTrue(good["report_data_binding"])

    def test_spire_wildcard_vulnerable_and_fixed(self):
        _, bad = _get(self.vuln.url("/spire/entries"))
        _, good = _get(self.fixed.url("/spire/entries"))
        self.assertTrue(any("*" in e["spiffe_id"] for e in bad["entries"]))
        self.assertTrue(any(not e["selectors"] for e in bad["entries"]))
        self.assertFalse(bad["server"]["admin_acl"])
        self.assertFalse(any("*" in e["spiffe_id"] for e in good["entries"]))
        self.assertTrue(all(e["selectors"] for e in good["entries"]))
        self.assertTrue(good["server"]["admin_acl"])

    def test_webhook_tls_expired_vulnerable_and_fixed(self):
        _, bad = _get(self.vuln.url("/webhook/tls"))
        _, good = _get(self.fixed.url("/webhook/tls"))
        self.assertLess(bad["not_after"], bad["now"])
        self.assertFalse(bad["ca_bundle_matches"])
        self.assertGreater(good["not_after"], good["now"])
        self.assertTrue(good["ca_bundle_matches"])
        self.assertEqual(good["san"], good["expected_san"])

    def test_ambient_mesh_policy_gap_vulnerable_and_fixed(self):
        _, bad = _get(self.vuln.url("/mesh/policies"))
        _, good = _get(self.fixed.url("/mesh/policies"))
        self.assertFalse(bad["waypoint"]["authz_enforced"])
        self.assertEqual(bad["peer_auth"]["mtls"], "permissive")
        self.assertTrue(good["waypoint"]["authz_enforced"])
        self.assertEqual(good["peer_auth"]["mtls"], "strict")

    def test_wasm_permissions_vulnerable_and_fixed(self):
        _, bad = _get(self.vuln.url("/wasm/modules"))
        _, good = _get(self.fixed.url("/wasm/modules"))
        caps = bad["modules"][0]["capabilities"]
        self.assertIn("/", caps["filesystem"])
        self.assertIn("*", caps["network"])
        self.assertFalse(bad["modules"][0]["signed"])
        good_caps = good["modules"][0]["capabilities"]
        self.assertEqual(good_caps["filesystem"], [])
        self.assertEqual(good_caps["network"], [])
        self.assertTrue(good["modules"][0]["signed"])

    def test_pq_tls_posture_vulnerable_and_fixed(self):
        _, bad = _get(self.vuln.url("/tls/posture"))
        _, good = _get(self.fixed.url("/tls/posture"))
        self.assertEqual(bad["min_version"], "TLS1.2")
        self.assertEqual(bad["key_exchange"], "rsa")
        self.assertIsNone(bad["hybrid_group"])
        self.assertEqual(good["min_version"], "TLS1.3")
        self.assertEqual(good["hybrid_group"], "X25519MLKEM768")
        self.assertTrue(good["hndl_safe"])

    def test_other_faces_two_state(self):
        pairs = {
            "/sandbox/runtime": ("runtime", "runc", "runsc"),
            "/gitops/secrets": ("plaintext_secrets", 3, 0),
            "/multicluster/federation": ("propagation", None, None),
            "/dpu/offload": ("dpu", None, None),
            "/iommu/groups": ("iommu_enabled", False, True),
            "/tpm/eventlog": ("measured_boot", False, True),
            "/model/watermark": ("watermark", None, None),
            "/rag/documents": ("retrieval", None, None),
            "/fl/round": ("secure_aggregation", False, True),
            "/provenance/attestation": ("attestation", None, None),
        }
        for path in pairs:
            with self.subTest(path=path):
                _, bad = _get(self.vuln.url(path))
                _, good = _get(self.fixed.url(path))
                self.assertNotEqual(bad, good, path)
        _, bad_gitops = _get(self.vuln.url("/gitops/secrets"))
        _, good_gitops = _get(self.fixed.url("/gitops/secrets"))
        self.assertGreater(bad_gitops["plaintext_secrets"], 0)
        self.assertEqual(good_gitops["plaintext_secrets"], 0)
        _, bad_sb = _get(self.vuln.url("/sandbox/runtime"))
        _, good_sb = _get(self.fixed.url("/sandbox/runtime"))
        self.assertFalse(bad_sb["pods"][0]["sandboxed"])
        self.assertTrue(good_sb["pods"][0]["sandboxed"])

    def test_read_only_methods_rejected(self):
        req = urllib.request.Request(self.vuln.url("/coco/policy"), method="POST", data=b"{}")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=5)
        self.assertEqual(ctx.exception.code, 405)


if __name__ == "__main__":
    unittest.main()
