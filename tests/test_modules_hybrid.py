"""tests/test_modules_hybrid.py — 混合云模块族（3 模块）表驱动自测。

Ruling：
- 三模块均打靶场 /mock-imds/* 五云元数据面（AWS IMDSv1/v2、Azure Managed Identity、阿里 RAM、腾讯 CAM、GCP）；
- 检测差分 = 攻击姿态请求（无 token/无 Metadata 头）在 vulnerable 得 200、在 fixed 得 401/400/404；
  GCP 两模式一致（要求 Metadata-Flavor 头，任何内网方可伪造）→ 仅记 trace 可达性，不构成 finding；
- cloud-role-overprivilege 输入 params.role_snapshot（dict fixture）枚举权重面过权 finding，
  不真实调用云 API；过权分析以「角色凭据可达」为闸（fixed 下凭据不可得 → 0 finding）；
- hybrid-cloud-egress-pivot 输出私网→云面 pivot 边图；DNS 泄露通道在 HTTP 靶场不可仿真，仅备注不判定。
"""
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from lab.mock_targets import start_all

from tests.test_modules_lateral import load_run, make_ctx, run_direct

HYBRID_CASES = [
    {"key": "multi-cloud-imds-credentials", "mode": "probe-only", "writes": False,
     "min_level": "利用验证"},
    {"key": "cloud-role-overprivilege", "mode": "probe-only", "writes": False,
     "min_level": "主动探测"},
    {"key": "hybrid-cloud-egress-pivot", "mode": "probe-only", "writes": False,
     "min_level": "主动探测"},
]

OVERPRIV_SNAPSHOT = {
    "provider": "aws",
    "role_name": "mock-node-role",
    "permissions": [
        {"action": "s3:PutObject", "resource": "arn:aws:s3:::train-checkpoints/weights/*"},
        {"action": "s3:DeleteObject", "resource": "arn:aws:s3:::train-checkpoints/*"},
        {"action": "kms:Decrypt", "resource": "*"},
        {"action": "sts:AssumeRole", "resource": "arn:aws:iam::999999999999:role/other-account"},
    ],
}

LEAST_PRIV_SNAPSHOT = {
    "provider": "aws",
    "role_name": "auditor",
    "permissions": [
        {"action": "s3:GetObject", "resource": "arn:aws:s3:::public-docs/*"},
    ],
}

CLOUD_SECRETS = ("MOCKAKIAINKBLADELAB", "MOCKSECRETINKBLADELAB", "MOCKSESSIONINKBLADELAB",
                 "MOCKLTAIINKBLADELAB", "MOCKSTSINKBLADELAB", "MOCKAKIDINKBLADELAB",
                 "MOCK-AZURE-IDENTITY-TOKEN")


class HybridCatalogTest(unittest.TestCase):
    def test_catalog_registered_and_contract(self):
        from inkblade.core.registry import load_modules
        mods = load_modules(Path(__file__).resolve().parents[1] / "inkblade" / "modules")
        for case in HYBRID_CASES:
            key = case["key"]
            self.assertIn(key, mods, f"缺少模块 {key}")
            m = mods[key]
            self.assertRegex(m.key, r"^[a-z][a-z-]*$")
            self.assertEqual(m.series, "混合云", key)
            self.assertEqual(m.writes, case["writes"], key)
            self.assertEqual(m.min_level, case["min_level"], key)
            self.assertEqual(m.key, m.path.name, key)


class HybridVulnerableTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lab = start_all(mode="vulnerable")

    @classmethod
    def tearDownClass(cls):
        cls.lab.shutdown()

    def test_vulnerable_detects_at_least_one_finding(self):
        with TemporaryDirectory() as tmp:
            for case in HYBRID_CASES:
                with self.subTest(key=case["key"]):
                    params = {"target": self.lab.url(""), "mode": case["mode"]}
                    if case["key"] == "cloud-role-overprivilege":
                        params["role_snapshot"] = OVERPRIV_SNAPSHOT
                    result = run_direct(case["key"], params, Path(tmp))
                    self.assertTrue(result["findings"], "vulnerable 必须检出 ≥1 finding")
                    for f in result["findings"]:
                        self.assertIsInstance(f["detail"], str)
                    for art in result["artifacts"]:
                        self.assertTrue(Path(art).is_file())
                    doc = json.loads(Path(result["artifacts"][0]).read_text(encoding="utf-8"))
                    self.assertEqual(doc["module"], case["key"])
                    self.assertTrue(doc["entries"])


class HybridFixedTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lab = start_all(mode="fixed")

    @classmethod
    def tearDownClass(cls):
        cls.lab.shutdown()

    def test_fixed_reports_zero_findings(self):
        with TemporaryDirectory() as tmp:
            for case in HYBRID_CASES:
                with self.subTest(key=case["key"]):
                    params = {"target": self.lab.url(""), "mode": case["mode"]}
                    if case["key"] == "cloud-role-overprivilege":
                        params["role_snapshot"] = OVERPRIV_SNAPSHOT
                    result = run_direct(case["key"], params, Path(tmp))
                    self.assertEqual(result["findings"], [], "fixed 必须为 0 finding")


class RoleSnapshotTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lab = start_all(mode="vulnerable")

    @classmethod
    def tearDownClass(cls):
        cls.lab.shutdown()

    def test_overprivileged_snapshot_expands_findings(self):
        """凭据可达 + 过权快照 → 可达性 finding + 权重桶写/KMS/跨账户过权 finding。"""
        with TemporaryDirectory() as tmp:
            result = run_direct("cloud-role-overprivilege", {
                "target": self.lab.url(""), "mode": "probe-only",
                "role_snapshot": OVERPRIV_SNAPSHOT,
            }, Path(tmp))
        titles = " ".join(f["title"] for f in result["findings"])
        self.assertGreaterEqual(len(result["findings"]), 3)
        self.assertIn("可达", titles)
        self.assertIn("权重", titles, "必须产出权重/checkpoint 桶写过权 finding")
        text = json.dumps(result["findings"], ensure_ascii=False)
        self.assertIn("train-checkpoints", text, "过权 finding 需列出证据权限")

    def test_least_privilege_snapshot_no_overprivilege(self):
        """最小权限快照 → 仅凭据可达性 finding，无过权 finding。"""
        with TemporaryDirectory() as tmp:
            result = run_direct("cloud-role-overprivilege", {
                "target": self.lab.url(""), "mode": "probe-only",
                "role_snapshot": LEAST_PRIV_SNAPSHOT,
            }, Path(tmp))
        self.assertEqual(len(result["findings"]), 1, "只应有可达性 finding")

    def test_reachability_only_without_snapshot(self):
        """无快照：仍产出角色凭据面可达 finding（快照缺失在 summary 注明）。"""
        with TemporaryDirectory() as tmp:
            result = run_direct("cloud-role-overprivilege", {
                "target": self.lab.url(""), "mode": "probe-only",
            }, Path(tmp))
        self.assertEqual(len(result["findings"]), 1)
        self.assertIn("可达", result["findings"][0]["title"])
        self.assertIn("快照", result["summary"])

    def test_fixed_with_snapshot_still_zero(self):
        """fixed：即便提供过权快照，凭据不可得 → 角色无法假定 → 0 finding。"""
        with start_all(mode="fixed") as lab:
            with TemporaryDirectory() as tmp:
                result = run_direct("cloud-role-overprivilege", {
                    "target": lab.url(""), "mode": "probe-only",
                    "role_snapshot": OVERPRIV_SNAPSHOT,
                }, Path(tmp))
        self.assertEqual(result["findings"], [])


class MultiCloudMaskTest(unittest.TestCase):
    def test_masked_outputs_and_gcp_not_a_finding(self):
        """五云凭据全脱敏（MOCK**** + 尾 4 位）；GCP 两模式一致 → 不构成 finding 仅入 trace。"""
        with TemporaryDirectory() as tmp:
            with start_all(mode="vulnerable") as lab:
                result = run_direct("multi-cloud-imds-credentials",
                                    {"target": lab.url(""), "mode": "probe-only"}, Path(tmp))
                doc = json.loads(Path(result["artifacts"][0]).read_text(encoding="utf-8"))
        text = result["summary"] + json.dumps(result["findings"], ensure_ascii=False)
        self.assertIn("MOCK****", text)
        for secret in CLOUD_SECRETS:
            self.assertNotIn(secret, text, "凭据全文不得出现在输出")
        findings_text = json.dumps(result["findings"], ensure_ascii=False)
        self.assertNotIn("gcp", findings_text.lower(), "GCP 非差分面不得进入 findings")
        gcp_entries = [e for e in doc["entries"] if "gcp" in e["url"]]
        self.assertTrue(gcp_entries, "GCP 可达性仍应记入 trace")
        self.assertGreaterEqual(len(result["findings"]), 4, "aws/azure/aliyun/tencent 四面均可达")


class EgressPivotTest(unittest.TestCase):
    def test_pivot_edges_and_dns_note(self):
        """pivot 边图进入 finding；DNS 泄露通道显式标注不可仿真（不作为判定）。"""
        with TemporaryDirectory() as tmp:
            with start_all(mode="vulnerable") as lab:
                result = run_direct("hybrid-cloud-egress-pivot",
                                    {"target": lab.url(""), "mode": "probe-only"}, Path(tmp))
        self.assertTrue(result["findings"])
        detail = json.dumps(result["findings"], ensure_ascii=False)
        self.assertIn("edges", detail)
        blob = result["summary"] + detail
        self.assertIn("dns", blob.lower())


if __name__ == "__main__":
    unittest.main()
