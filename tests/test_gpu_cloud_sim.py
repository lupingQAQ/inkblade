"""tests/test_gpu_cloud_sim.py — GPU 池化/云租户仿真靶场两态断言（表驱动）。

覆盖：
- 每组路由在 vulnerable / fixed 两模式下的匿名请求状态码；
- 跨租户分配/迁移、释放后残留 marker 读回与 sha256、fixed 清理后 404；
- MIG profile 请求/生效不一致与重配闸门；
- MPS 共享 context、DCGM 指标跨租户进程名泄露与 fixed 租户过滤；
- IRSA/RRSA 通配 trust policy 与跨账户 AssumeRole（fixed 403）；
- 桶策略 public / 跨租户列目录、快照任意账户共享、KMS grants、安全组 IMDS；
- 路由清单自描述与写盘边界（仅 Server.root）。
自测仅连接 127.0.0.1。
"""
import hashlib
import json
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from tempfile import TemporaryDirectory

from lab.gpu_cloud_sim import (
    ADMIN_TOKEN,
    ROUTE_TABLE,
    TENANT_TOKENS,
    start_all,
)


def request(method, url, body=None, headers=None):
    """发一次 HTTP 请求，返回 (status, payload)；payload 能解析 JSON 就解析。"""
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method.upper())
    if data is not None:
        req.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read()
            status = resp.status
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        status = exc.code
    text = raw.decode("utf-8", "replace")
    try:
        payload = json.loads(text)
    except ValueError:
        payload = text
    return status, payload


def tenant(token: str, headers: dict | None = None) -> dict:
    name = "tenant-a" if "tenant-a" in token else "tenant-b"
    out = {"X-Tenant": name, "Authorization": f"Bearer {token}"}
    out.update(headers or {})
    return out


TENANT_A = tenant(TENANT_TOKENS["tenant-a"])
TENANT_B = tenant(TENANT_TOKENS["tenant-b"])
ADMIN_A = {"X-Tenant": "tenant-a", "Authorization": f"Bearer {ADMIN_TOKEN}"}

# 表驱动：name/service/method/path/body/headers + 两模式匿名期望状态码。
CASES = [
    {"name": "GPU 池清单", "service": "gpu-pooling", "method": "GET", "path": "/gpu/pools", "body": None, "vulnerable_status": 200, "fixed_status": 401},
    {"name": "GPU 跨租户分配", "service": "gpu-pooling", "method": "POST", "path": "/gpu/allocate", "body": {"tenant": "tenant-a", "device": "gpu-b-0", "namespace": "ns-a-infer"}, "vulnerable_status": 200, "fixed_status": 401},
    {"name": "GPU 释放", "service": "gpu-pooling", "method": "POST", "path": "/gpu/release", "body": {"tenant": "tenant-a", "allocation_id": "alloc-missing"}, "vulnerable_status": 404, "fixed_status": 401},
    {"name": "MIG profile 清单", "service": "gpu-pooling", "method": "GET", "path": "/gpu/mig/profiles?device=gpu-b-1", "body": None, "vulnerable_status": 200, "fixed_status": 401},
    {"name": "MIG profile 重配", "service": "gpu-pooling", "method": "POST", "path": "/gpu/mig/profiles", "body": {"tenant": "tenant-a", "device": "gpu-b-1", "profile": "1g.10gb"}, "vulnerable_status": 200, "fixed_status": 401},
    {"name": "DCGM 指标", "service": "gpu-pooling", "method": "GET", "path": "/gpu/metrics", "body": None, "vulnerable_status": 200, "fixed_status": 401},
    {"name": "MPS 状态", "service": "gpu-pooling", "method": "GET", "path": "/gpu/mps/status", "body": None, "vulnerable_status": 200, "fixed_status": 401},
    {"name": "残留显存快照", "service": "gpu-pooling", "method": "GET", "path": "/gpu/residue?device=gpu-b-0", "body": None, "vulnerable_status": 200, "fixed_status": 401},
    {"name": "云身份与 trust policy", "service": "cloud-identity", "method": "GET", "path": "/cloud/identity?role=weight-reader", "body": None, "vulnerable_status": 200, "fixed_status": 401},
    {"name": "跨账户 AssumeRole", "service": "cloud-identity", "method": "POST", "path": "/cloud/identity/assume-role", "body": {"role": "weight-reader", "source_account": "999999999999"}, "vulnerable_status": 200, "fixed_status": 403},
    {"name": "桶策略", "service": "cloud-storage", "method": "GET", "path": "/cloud/bucket/policy?bucket=weights-b", "body": None, "vulnerable_status": 200, "fixed_status": 401},
    {"name": "跨租户列目录", "service": "cloud-storage", "method": "GET", "path": "/cloud/bucket/list?bucket=weights-b", "body": None, "vulnerable_status": 200, "fixed_status": 401},
    {"name": "快照共享清单", "service": "cloud-storage", "method": "GET", "path": "/cloud/snapshot/share?snapshot=snap-weights-b", "body": None, "vulnerable_status": 200, "fixed_status": 401},
    {"name": "快照共享给任意账户", "service": "cloud-storage", "method": "POST", "path": "/cloud/snapshot/share", "body": {"snapshot": "snap-weights-b", "target_account": "999999999999"}, "vulnerable_status": 200, "fixed_status": 401},
    {"name": "KMS grants", "service": "cloud-kms", "method": "GET", "path": "/cloud/kms/grants?key=weights-key", "body": None, "vulnerable_status": 200, "fixed_status": 401},
    {"name": "安全组与 IMDS 选项", "service": "cloud-network", "method": "GET", "path": "/cloud/security-group?group=sg-gpu-nodes", "body": None, "vulnerable_status": 200, "fixed_status": 401},
    {"name": "路由清单", "service": "meta", "method": "GET", "path": "/__routes__", "body": None, "vulnerable_status": 200, "fixed_status": 200},
]


class TwoStatePerRouteTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vulnerable = start_all(mode="vulnerable")
        cls.fixed = start_all(mode="fixed")

    @classmethod
    def tearDownClass(cls):
        cls.vulnerable.shutdown()
        cls.fixed.shutdown()

    def test_vulnerable_status_per_route(self):
        for case in CASES:
            with self.subTest(case=case["name"]):
                status, payload = request(case["method"], self.vulnerable.url(case["path"]),
                                          case.get("body"), case.get("headers"))
                self.assertEqual(status, case["vulnerable_status"], f"{case['name']} -> {payload}")

    def test_fixed_status_per_route(self):
        for case in CASES:
            with self.subTest(case=case["name"]):
                status, payload = request(case["method"], self.fixed.url(case["path"]),
                                          case.get("body"), case.get("headers"))
                self.assertEqual(status, case["fixed_status"], f"{case['name']} -> {payload}")


class RoutesManifestTest(unittest.TestCase):
    def test_manifest_covers_every_table_case(self):
        with start_all(mode="vulnerable") as server:
            status, payload = request("GET", server.url("/__routes__"))
        self.assertEqual(status, 200)
        self.assertEqual(payload["mode"], "vulnerable")
        entries = payload["routes"]
        self.assertEqual(len(entries), len(ROUTE_TABLE))
        for case in CASES:
            base = case["path"].split("?", 1)[0].rstrip("/")
            matches = [
                e for e in entries
                if e["service"] == case["service"]
                and e["method"] == case["method"]
                and e["path"].rstrip("/") == base
            ]
            self.assertEqual(len(matches), 1, case["name"])
            entry = matches[0]
            self.assertEqual(entry["vulnerable"], case["vulnerable_status"], case["name"])
            self.assertEqual(entry["fixed"], case["fixed_status"], case["name"])


class GpuAllocationResidueTest(unittest.TestCase):
    def test_cross_tenant_allocate_previous_tenant_and_residue_readback(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            marker = "TRIDENT-BENIGN-VRAM-PROBE-ALPHA"
            with start_all(mode="vulnerable", root=root) as server:
                status, allocated = request("POST", server.url("/gpu/allocate"), {
                    "tenant": "tenant-a", "device": "gpu-b-0",
                    "namespace": "ns-a-infer", "marker": marker,
                })
                self.assertEqual(status, 200, allocated)
                self.assertTrue(allocated["cross_tenant"])
                self.assertEqual(allocated["previous_tenant"], "tenant-b")
                self.assertEqual(allocated["marker_sha256"], hashlib.sha256(marker.encode()).hexdigest())
                alloc_id = allocated["allocation_id"]
                status, released = request("POST", server.url("/gpu/release"), {
                    "tenant": "tenant-a", "allocation_id": alloc_id,
                })
                self.assertEqual(status, 200, released)
                self.assertTrue(released["residue_retained"])
                status, residue = request("GET", server.url(f"/gpu/residue?device=gpu-b-0&allocation={alloc_id}"))
                self.assertEqual(status, 200, residue)
                entry = residue["residue"][0]
                self.assertTrue(entry["readable_after_release"])
                self.assertEqual(entry["marker"], marker)
                self.assertEqual(entry["marker_sha256"], hashlib.sha256(marker.encode()).hexdigest())
                file_path = root / entry["residue_file"]
                self.assertTrue(file_path.is_file())
                self.assertEqual(hashlib.sha256(file_path.read_bytes()).hexdigest(), entry["file_sha256"])
            self.assertTrue(list(root.glob("gpu/residue/gpu-b-0/*.json")))

    def test_fixed_allocates_own_and_cleans_residue(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            with start_all(mode="fixed", root=root) as server:
                status, denied = request("POST", server.url("/gpu/allocate"), {
                    "tenant": "tenant-a", "device": "gpu-b-0",
                }, ADMIN_A)
                self.assertEqual(status, 403, denied)
                status, allocated = request("POST", server.url("/gpu/allocate"), {
                    "tenant": "tenant-a", "device": "gpu-a-1",
                    "namespace": "ns-a-infer", "marker": "TRIDENT-BENIGN-FIXED",
                }, ADMIN_A)
                self.assertEqual(status, 200, allocated)
                alloc_id = allocated["allocation_id"]
                status, released = request("POST", server.url("/gpu/release"), {
                    "tenant": "tenant-a", "allocation_id": alloc_id,
                }, ADMIN_A)
                self.assertEqual(status, 200, released)
                self.assertFalse(released["residue_retained"])
                status, residue = request("GET", server.url(f"/gpu/residue?device=gpu-a-1&allocation={alloc_id}"),
                                          None, TENANT_A)
                self.assertEqual(status, 404, residue)
            self.assertFalse(list(root.glob("gpu/residue/gpu-a-1/*.json")))

    def test_fixed_tenant_token_cannot_cross_tenant(self):
        with start_all(mode="fixed") as server:
            status, payload = request("GET", server.url("/gpu/pools"), None, TENANT_A)
            self.assertEqual(status, 200, payload)
            tenants = {d["tenant"] for d in payload["devices"]}
            self.assertEqual(tenants, {"tenant-a"})
            status, denied = request("GET", server.url("/gpu/residue?device=gpu-b-0"), None, TENANT_A)
            self.assertEqual(status, 403, denied)


class MigAndMpsTest(unittest.TestCase):
    def test_mig_mismatch_and_unauth_reconfigure(self):
        with start_all(mode="vulnerable") as server:
            status, profiles = request("GET", server.url("/gpu/mig/profiles?device=gpu-b-1"))
            self.assertEqual(status, 200)
            device = profiles["devices"][0]
            self.assertTrue(device["mismatch"])
            self.assertEqual(device["active"], "3g.40gb")
            self.assertEqual(device["requested"], "1g.10gb")
            status, reconfigured = request("POST", server.url("/gpu/mig/profiles"), {
                "tenant": "tenant-a", "device": "gpu-b-1", "profile": "1g.10gb",
            })
            self.assertEqual(status, 200, reconfigured)
            self.assertTrue(reconfigured["applied"])
            self.assertTrue(reconfigured["isolation_downgraded"])

    def test_mps_shared_context_and_fixed_filtering(self):
        with start_all(mode="vulnerable") as server:
            status, payload = request("GET", server.url("/gpu/mps/status"))
            self.assertEqual(status, 200)
            self.assertTrue(payload["shared_context"])
            tenants = {c["tenant"] for c in payload["contexts"]}
            self.assertEqual(tenants, {"tenant-a", "tenant-b"})
        with start_all(mode="fixed") as server:
            status, payload = request("GET", server.url("/gpu/mps/status"), None, TENANT_A)
            self.assertEqual(status, 200)
            self.assertFalse(payload["shared_context"])
            self.assertEqual({c["tenant"] for c in payload["contexts"]}, {"tenant-a"})

    def test_metrics_leak_and_fixed_filtering(self):
        with start_all(mode="vulnerable") as server:
            status, payload = request("GET", server.url("/gpu/metrics"))
            self.assertEqual(status, 200)
            tenants = {p["tenant"] for g in payload["gpus"] for p in g["processes"]}
            self.assertEqual(tenants, {"tenant-a", "tenant-b"})
        with start_all(mode="fixed") as server:
            status, payload = request("GET", server.url("/gpu/metrics"), None, TENANT_A)
            self.assertEqual(status, 200)
            tenants = {p["tenant"] for g in payload["gpus"] for p in g["processes"]}
            self.assertEqual(tenants, {"tenant-a"})


class CloudTenantTest(unittest.TestCase):
    def test_trust_policy_wildcard_and_cross_account_assume(self):
        with start_all(mode="vulnerable") as server:
            status, identity = request("GET", server.url("/cloud/identity?role=weight-reader"))
            self.assertEqual(status, 200)
            self.assertTrue(identity["wildcard_principal"])
            self.assertTrue(identity["cross_account_allowed"])
            self.assertEqual(identity["trust_policy"]["Statement"][0]["Principal"], "*")
            status, assumed = request("POST", server.url("/cloud/identity/assume-role"), {
                "role": "weight-reader", "source_account": "999999999999",
            })
            self.assertEqual(status, 200, assumed)
            self.assertTrue(assumed["assumed"])
            self.assertTrue(assumed["cross_account"])
            self.assertTrue(str(assumed["credentials"]["AccessKeyId"]).startswith("MOCK"))
        with start_all(mode="fixed") as server:
            status, denied = request("POST", server.url("/cloud/identity/assume-role"), {
                "role": "weight-reader", "source_account": "999999999999",
            })
            self.assertEqual(status, 403, denied)

    def test_bucket_policy_and_cross_tenant_listing(self):
        with start_all(mode="vulnerable") as server:
            status, policy = request("GET", server.url("/cloud/bucket/policy?bucket=weights-b"))
            self.assertEqual(status, 200)
            self.assertTrue(policy["public"])
            self.assertTrue(policy["cross_tenant_read"])
            status, listing = request("GET", server.url("/cloud/bucket/list?bucket=weights-b&prefix=tenant-b/"))
            self.assertEqual(status, 200, listing)
            self.assertTrue(listing["cross_tenant"])
            keys = [o["key"] for o in listing["objects"]]
            self.assertIn("tenant-b/model.safetensors", keys)
        with start_all(mode="fixed") as server:
            status, denied = request("GET", server.url("/cloud/bucket/list?bucket=weights-b"), None, TENANT_A)
            self.assertEqual(status, 403, denied)
            status, own = request("GET", server.url("/cloud/bucket/list?bucket=weights-b"), None, TENANT_B)
            self.assertEqual(status, 200, own)

    def test_snapshot_share_kms_and_sg_hardening(self):
        with start_all(mode="vulnerable") as server:
            status, shared = request("POST", server.url("/cloud/snapshot/share"), {
                "snapshot": "snap-weights-b", "target_account": "999999999999",
            })
            self.assertEqual(status, 200)
            self.assertTrue(shared["cross_account"])
            self.assertIn("999999999999", shared["shared_with"])
            status, grants = request("GET", server.url("/cloud/kms/grants?key=weights-key"))
            self.assertEqual(status, 200)
            self.assertTrue(grants["wildcard"])
            self.assertTrue(grants["cross_account"])
            status, sg = request("GET", server.url("/cloud/security-group?group=sg-gpu-nodes"))
            self.assertEqual(status, 200)
            self.assertTrue(sg["public_ingress"])
            self.assertEqual(sg["metadata_options"]["http_tokens"], "optional")
            self.assertGreater(sg["metadata_options"]["http_put_response_hop_limit"], 1)
        with start_all(mode="fixed") as server:
            status, denied = request("POST", server.url("/cloud/snapshot/share"), {
                "snapshot": "snap-weights-b", "target_account": "999999999999",
            }, ADMIN_A)
            self.assertEqual(status, 403, denied)
            status, grants = request("GET", server.url("/cloud/kms/grants?key=weights-key"), None, TENANT_B)
            self.assertEqual(status, 200)
            self.assertFalse(grants["wildcard"])
            status, sg = request("GET", server.url("/cloud/security-group?group=sg-gpu-nodes"), None, TENANT_B)
            self.assertEqual(status, 200)
            self.assertFalse(sg["public_ingress"])
            self.assertEqual(sg["metadata_options"]["http_tokens"], "required")
            self.assertEqual(sg["metadata_options"]["http_put_response_hop_limit"], 1)


class ServerLifecycleTest(unittest.TestCase):
    def test_default_root_temp_and_cleanup(self):
        server = start_all()
        root = server.root
        try:
            self.assertTrue(root.is_dir())
            status, _ = request("POST", server.url("/gpu/allocate"), {"tenant": "tenant-a", "device": "gpu-a-1"})
            self.assertEqual(status, 200)
            self.assertTrue(list(root.glob("gpu/residue/*/*.json")))
        finally:
            server.shutdown()
        self.assertFalse(root.exists())

    def test_invalid_mode_rejected(self):
        with self.assertRaises(ValueError):
            start_all(mode="bogus")


if __name__ == "__main__":
    unittest.main()
