"""tests/test_chipsec_sim.py — 芯片/加速器姿态仿真靶场（vulnerable/fixed 双态）。

覆盖：
- 路由表：仅两条 POST（allocate/release）写路由，其余 GET；其他方法 405；
- GPU CC：fixed 给出可验证 NRAS 风格 JWT，vulnerable 给出篡改 JWT（同一 JWKS）；
- SPDM：fixed 证书链有效/测量摘要一致，vulnerable 证书过期/摘要不一致；
- IOMMU：fixed 严格翻译，vulnerable `iommu=pt` 直通；
- 安全启动：fixed PCR 与 golden 基线一致，vulnerable PCR 偏移 + UKI 签名无效；
- 固件签名：fixed 全链有效，vulnerable 一组件签名无效；
- IMEX/CXL：fixed 租户隔离/IDE+TSP，vulnerable 跨租户/明文；
- 显存残留：vulnerable 释放后读回 200 + marker sha256 一致，fixed 404；
- 上下文管理器与非法 mode。
"""

import json
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from lab.chipsec_sim import ROUTE_TABLE, start_all


def _get(url: str):
    req = Request(url, headers={}, method="GET")
    try:
        with urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except HTTPError as exc:
        raw = exc.read()
        return exc.code, json.loads(raw.decode("utf-8")) if raw else {}


def _post(url: str, body: dict):
    data = json.dumps(body).encode("utf-8")
    req = Request(url, data=data, method="POST",
                  headers={"Content-Type": "application/json"})
    try:
        with urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except HTTPError as exc:
        raw = exc.read()
        return exc.code, json.loads(raw.decode("utf-8")) if raw else {}


class ChipsecSimTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vulnerable = start_all(mode="vulnerable")
        cls.fixed = start_all(mode="fixed")

    @classmethod
    def tearDownClass(cls):
        cls.vulnerable.shutdown()
        cls.fixed.shutdown()

    def test_route_table_read_only_except_residue_writes(self):
        self.assertGreaterEqual(len(ROUTE_TABLE), 10)
        writes = [e for e in ROUTE_TABLE if e["writes"]]
        self.assertEqual({e["path"] for e in writes},
                         {"/chip/gpu/allocate", "/chip/gpu/release"})
        for entry in writes:
            self.assertEqual(entry["method"], "POST")
        for entry in ROUTE_TABLE:
            if not entry["writes"]:
                self.assertEqual(entry["method"], "GET")
        status, doc = _get(self.vulnerable.url("/__routes__"))
        self.assertEqual(status, 200)
        self.assertEqual(doc["route_count"], len(ROUTE_TABLE))
        self.assertEqual(doc["mode"], "vulnerable")

    def test_gpu_cc_fixed_valid_vulnerable_tampered(self):
        status, fixed = _get(self.fixed.url("/chip/gpu-cc"))
        self.assertEqual(status, 200)
        self.assertTrue(fixed["valid_reference"])
        self.assertEqual(fixed["token"], fixed["valid_reference"])
        self.assertTrue(fixed["jwks"]["keys"])
        status, risky = _get(self.vulnerable.url("/chip/gpu-cc"))
        self.assertEqual(status, 200)
        self.assertTrue(risky["tampered"])
        self.assertNotEqual(risky["token"], risky["valid_reference"])
        self.assertEqual(risky["token"].split(".")[0], risky["valid_reference"].split(".")[0])
        self.assertNotEqual(risky["token"].split(".")[1], risky["valid_reference"].split(".")[1])
        self.assertEqual(risky["token"].split(".")[2], risky["valid_reference"].split(".")[2])

    def test_spdm_posture(self):
        _, fixed = _get(self.fixed.url("/chip/spdm"))
        self.assertTrue(fixed["spdm"]["session"])
        self.assertGreaterEqual(fixed["spdm"]["version"], "1.3")
        self.assertEqual(fixed["spdm"]["measurement_summary"],
                         fixed["spdm"]["expected_measurement_summary"])
        self.assertTrue(fixed["pcie"]["doe"])
        _, risky = _get(self.vulnerable.url("/chip/spdm"))
        self.assertFalse(risky["spdm"]["session"])
        self.assertEqual(risky["spdm"]["version"], "1.0.0")
        self.assertNotEqual(risky["spdm"]["measurement_summary"],
                            risky["spdm"]["expected_measurement_summary"])
        self.assertFalse(risky["pcie"]["doe"])

    def test_iommu_posture(self):
        _, fixed = _get(self.fixed.url("/chip/iommu"))
        self.assertTrue(fixed["iommu"]["enabled"])
        self.assertFalse(fixed["iommu"]["passthrough"])
        self.assertTrue(fixed["iommu"]["strict"])
        _, risky = _get(self.vulnerable.url("/chip/iommu"))
        self.assertIn("iommu=pt", risky["kernel_cmdline"])
        self.assertTrue(risky["iommu"]["passthrough"])
        self.assertTrue(any(g.get("identity") for g in risky["groups"]))

    def test_boot_pcr_baseline(self):
        _, fixed = _get(self.fixed.url("/chip/boot"))
        self.assertTrue(fixed["secure_boot"])
        self.assertFalse(fixed["setup_mode"])
        for key, value in fixed["baseline"].items():
            self.assertEqual(fixed["pcrs"][key], value)
        _, risky = _get(self.vulnerable.url("/chip/boot"))
        diff = [k for k, v in risky["baseline"].items() if risky["pcrs"].get(k) != v]
        self.assertIn("0", diff)
        self.assertIn("4", diff)
        self.assertFalse(risky["uki"]["signature_expected_valid"])

    def test_firmware_signature_invalid_in_vulnerable(self):
        _, fixed = _get(self.fixed.url("/chip/firmware"))
        self.assertTrue(all(c["signature_expected_valid"] for c in fixed["components"]))
        _, risky = _get(self.vulnerable.url("/chip/firmware"))
        invalid = [c for c in risky["components"] if not c["signature_expected_valid"]]
        self.assertEqual(len(invalid), 1)
        self.assertEqual(invalid[0]["name"], "bmc-fw")

    def test_imex_and_cxl_posture(self):
        _, fixed = _get(self.fixed.url("/chip/imex"))
        owners = {}
        for domain in fixed["domains"]:
            for member in domain["members"]:
                owners.setdefault(member["gpu"], set()).add(member["tenant"])
        self.assertTrue(all(len(v) == 1 for v in owners.values()), owners)
        _, risky = _get(self.vulnerable.url("/chip/imex"))
        self.assertTrue(any(d["permissions"]["export"] == ["*"]
                            for d in risky["domains"]))
        _, fixed_cxl = _get(self.fixed.url("/chip/cxl"))
        self.assertTrue(all(d["ide"]["enabled"] for d in fixed_cxl["devices"]))
        self.assertTrue(all(d["tsp"]["enabled"] for d in fixed_cxl["devices"]))
        _, risky_cxl = _get(self.vulnerable.url("/chip/cxl"))
        self.assertFalse(any(d["ide"]["enabled"] for d in risky_cxl["devices"]))

    def test_gpu_residue_active_differential(self):
        status, alloc = _post(self.vulnerable.url("/chip/gpu/allocate"), {
            "tenant": "tenant-a", "device": "gpu-a-1", "marker": "MARKER-SIM",
        })
        self.assertEqual(status, 200)
        allocation_id = alloc["allocation_id"]
        status, release = _post(self.vulnerable.url("/chip/gpu/release"), {
            "allocation_id": allocation_id,
        })
        self.assertEqual(status, 200)
        self.assertFalse(release["zeroized"])
        status, residue = _get(
            self.vulnerable.url(f"/chip/gpu/residue?allocation={allocation_id}"))
        self.assertEqual(status, 200)
        self.assertEqual(residue["residue"][0]["marker"], "MARKER-SIM")
        self.assertTrue(residue["residue"][0]["readable_after_release"])

        status, alloc = _post(self.fixed.url("/chip/gpu/allocate"), {
            "tenant": "tenant-a", "device": "gpu-a-1", "marker": "MARKER-SIM",
        })
        self.assertEqual(status, 200)
        status, release = _post(self.fixed.url("/chip/gpu/release"), {
            "allocation_id": alloc["allocation_id"],
        })
        self.assertEqual(status, 200)
        self.assertTrue(release["zeroized"])
        status, _ = _get(
            self.fixed.url(f"/chip/gpu/residue?allocation={alloc['allocation_id']}"))
        self.assertEqual(status, 404)

    def test_post_not_allowed_and_invalid_mode(self):
        req = Request(self.vulnerable.url("/chip/gpu-cc"), data=b"{}", method="POST")
        with self.assertRaises(HTTPError) as ctx:
            urlopen(req, timeout=10)
        self.assertEqual(ctx.exception.code, 405)
        with self.assertRaises(ValueError):
            start_all(mode="unsafe")

    def test_context_manager_and_stats(self):
        with start_all(mode="fixed") as server:
            self.assertEqual(_get(server.url("/health"))[0], 200)
            before = _get(server.url("/__stats__"))[1]["requests"]
            _get(server.url("/chip/iommu"))
            after = _get(server.url("/__stats__"))[1]["requests"]
            self.assertGreater(after, before)
        self.assertTrue(server._closed)


if __name__ == "__main__":
    unittest.main()
