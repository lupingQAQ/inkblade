"""tests/test_six_cloud_sim.py — 六云契约级仿真（身份/桶/快照/网络策略）。

断言分三层：
1. 契约覆盖：6 云 × 7 类能力（identity/assume-role/bucket-policy/bucket-list/snapshot/
   snapshot-share/security-group）+ 总矩阵路由；
2. 厂商形状：每云 payload 带该云公开 API 的判别字段（AWS Principal / Azure publicAccess /
   阿里 Grant / 腾讯 SecurityGroupPolicySet / GCP allUsers / 华为 remote_ip_prefix）；
3. 跨租户场景：4 场景 × 6 云，vulnerable 全部可达、fixed 全部拒绝（401/403），
   并断言「契约级仿真，非真实环境」的边界文案在响应里。

边界：仿真器不是云账号，不调用任何云 API；测试只证明「同一类跨租户风险可以用六云各自的
字段形状表达并被检测」，不证明真实环境配置。
"""
import unittest
import urllib.error
import urllib.request
import json

from lab import cloud_six_sim as sim

TENANT = "tenant-b"
TOKEN = sim.TENANT_TOKENS[TENANT]


def call(server, path, method="GET", body=None, anonymous=False):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(server.url(path), data=data, method=method)
    if not anonymous:
        req.add_header("X-Tenant", TENANT)
        req.add_header("Authorization", f"Bearer {TOKEN}")
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8") or "{}")


class RouteCoverageTest(unittest.TestCase):
    def test_six_clouds_and_seven_capabilities(self):
        self.assertEqual(len(sim.CLOUDS), 6)
        self.assertEqual(set(sim.CLOUDS), {"aws", "azure", "aliyun", "tencent", "gcp", "huawei"})
        for cloud in sim.CLOUDS:
            paths = {entry["path"] for entry in sim.ROUTE_TABLE if entry["cloud"] == cloud}
            for suffix in ("/identity", "/assume-role", "/bucket/policy", "/bucket/list",
                           "/snapshot", "/snapshot/share", "/security-group"):
                self.assertIn(f"/api/{cloud}{suffix}", paths, f"{cloud} 缺 {suffix}")

    def test_no_route_writes_files(self):
        for entry in sim.ROUTE_TABLE:
            self.assertFalse(entry["writes"], entry["path"])

    def test_matrix_endpoint(self):
        with sim.start_all(mode="vulnerable") as server:
            status, payload = call(server, "/api/__matrix__")
        self.assertEqual(status, 200)
        self.assertEqual(len(payload["clouds"]), 6)
        self.assertIn("契约级仿真", payload["note"])
        for row in payload["clouds"]:
            self.assertEqual(len(row["capabilities"]), 7)
            self.assertTrue(row["apis"]["identity_api"])


class VendorShapeTest(unittest.TestCase):
    """每云响应必须是该云的字段形状，而不是统一抽象层。"""

    def setUp(self):
        self.server = sim.start_all(mode="vulnerable")
        self.addCleanup(self.server.shutdown)

    def test_aws(self):
        _, ident = call(self.server, "/api/aws/identity")
        self.assertIn("Principal", json.dumps(ident["trust_policy"]))
        self.assertIn("Federated", json.dumps(ident["trust_policy"]))
        _, bucket = call(self.server, "/api/aws/bucket/policy")
        self.assertEqual(bucket["policy"]["Statement"][0]["Principal"], "*")
        _, sg = call(self.server, "/api/aws/security-group")
        self.assertEqual(sg["security_group"]["MetadataOptions"]["HttpTokens"], "optional")

    def test_azure(self):
        _, ident = call(self.server, "/api/azure/identity")
        self.assertIn("federatedIdentityCredentials", ident["api"])
        self.assertEqual(ident["trust_policy"]["properties"]["subject"], "*")
        _, bucket = call(self.server, "/api/azure/bucket/policy")
        self.assertEqual(bucket["policy"]["properties"]["publicAccess"], "Blob")
        _, sg = call(self.server, "/api/azure/security-group")
        self.assertEqual(sg["security_group"]["securityRules"][0]["properties"]["sourceAddressPrefix"], "*")

    def test_aliyun(self):
        _, ident = call(self.server, "/api/aliyun/identity")
        self.assertIn("RAM", json.dumps(ident["trust_policy"]))
        _, bucket = call(self.server, "/api/aliyun/bucket/policy")
        self.assertEqual(bucket["policy"]["AccessControlPolicy"]["AccessControlList"]["Grant"], "public-read")
        _, sg = call(self.server, "/api/aliyun/security-group")
        self.assertEqual(sg["security_group"]["Permissions"][0]["SourceCidrIp"], "0.0.0.0/0")

    def test_tencent(self):
        _, ident = call(self.server, "/api/tencent/identity")
        self.assertIn("qcs", json.dumps(ident["trust_policy"]))
        _, bucket = call(self.server, "/api/tencent/bucket/policy")
        self.assertEqual(bucket["policy"]["ACL"], "public-read-write")
        _, sg = call(self.server, "/api/tencent/security-group")
        self.assertEqual(sg["security_group"]["SecurityGroupPolicySet"]["Ingress"][0]["CidrBlock"],
                         "0.0.0.0/0")

    def test_gcp(self):
        _, ident = call(self.server, "/api/gcp/identity")
        self.assertIn("workloadIdentityUser", json.dumps(ident["trust_policy"]))
        self.assertIn("*", json.dumps(ident["trust_policy"]))
        _, bucket = call(self.server, "/api/gcp/bucket/policy")
        self.assertIn("allUsers", json.dumps(bucket["policy"]))
        _, sg = call(self.server, "/api/gcp/security-group")
        self.assertEqual(sg["security_group"]["sourceRanges"], ["0.0.0.0/0"])

    def test_huawei(self):
        _, ident = call(self.server, "/api/huawei/identity")
        self.assertEqual(ident["trust_policy"]["trust_domain"], "*")
        _, bucket = call(self.server, "/api/huawei/bucket/policy")
        self.assertEqual(bucket["policy"]["Acl"]["Grant"], "public-read")
        _, sg = call(self.server, "/api/huawei/security-group")
        self.assertEqual(sg["security_group"]["rules"][0]["remote_ip_prefix"], "0.0.0.0/0")


class CrossTenantScenarioTest(unittest.TestCase):
    """4 场景 × 6 云：vulnerable 可达、fixed 拒绝。"""

    @classmethod
    def setUpClass(cls):
        cls.vuln = sim.run_scenarios("vulnerable")
        cls.fixed = sim.run_scenarios("fixed")

    def test_vulnerable_all_reachable(self):
        self.assertTrue(self.vuln["all_as_expected"], [
            (r["scenario"], r["cloud"]) for r in self.vuln["scenarios"] if not r["as_expected"]])
        self.assertEqual(len(self.vuln["scenarios"]), 24)
        self.assertTrue(all(r["cross_tenant_ok"] for r in self.vuln["scenarios"]))

    def test_fixed_all_denied(self):
        self.assertTrue(self.fixed["all_as_expected"], [
            (r["scenario"], r["cloud"]) for r in self.fixed["scenarios"] if not r["as_expected"]])
        self.assertFalse(any(r["cross_tenant_ok"] for r in self.fixed["scenarios"]))
        # 跨租户动作必须是 401/403，不能是静默 200
        denied = {"assume-role": {403}, "bucket-list": {401}, "snapshot-share": {403},
                  "authorize": {403}}
        for row in self.fixed["scenarios"]:
            for step in row["steps"]:
                for key, allowed in denied.items():
                    if key in step["path"]:
                        self.assertIn(step["status"], allowed, (row["cloud"], step["path"]))

    def test_irsa_wildcard_evidence(self):
        rows = [r for r in self.vuln["scenarios"] if r["scenario"] == "irsa-wildcard"]
        self.assertEqual(len(rows), 6)
        for row in rows:
            self.assertIn("wildcard=True", row["steps"][0]["evidence"])
            self.assertIn("cross_account=True", row["steps"][1]["evidence"])
            fixed = [r for r in self.fixed["scenarios"]
                     if r["scenario"] == "irsa-wildcard" and r["cloud"] == row["cloud"]][0]
            self.assertIn("wildcard=False", fixed["steps"][0]["evidence"])

    def test_bucket_snapshot_sg_evidence(self):
        for scenario, needle in (("bucket-public", "cross_tenant=True"),
                                 ("snapshot-share", "shared_with"),
                                 ("sg-imds", "imds_open=True")):
            rows = [r for r in self.vuln["scenarios"] if r["scenario"] == scenario]
            self.assertEqual(len(rows), 6)
            for row in rows:
                joined = " ".join(step["evidence"] for step in row["steps"])
                self.assertIn(needle, joined, (scenario, row["cloud"], joined))

    def test_boundary_note_present(self):
        with sim.start_all(mode="fixed") as server:
            _, payload = call(server, "/api/__matrix__")
        self.assertIn("契约级仿真", payload["note"])
        self.assertIn("非真实环境", payload["note"])

    def test_anonymous_listing(self):
        with sim.start_all(mode="vulnerable") as vuln:
            status, payload = call(vuln, "/api/aws/bucket/list?bucket=b", anonymous=True)
        self.assertEqual(status, 200)
        self.assertTrue(payload["cross_tenant"])
        with sim.start_all(mode="fixed") as fixed:
            status, payload = call(fixed, "/api/aws/bucket/list?bucket=b", anonymous=True)
        self.assertEqual(status, 401)


if __name__ == "__main__":
    unittest.main()
