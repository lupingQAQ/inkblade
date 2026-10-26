"""tests/test_hardware_sim.py — 硬件/交换机只读仿真靶场（配置面 + 遥测面 × 两态）。

覆盖：
- 路由表全部 GET / writes=false（仿真不提供写面）；
- Redfish/BMC：vulnerable 匿名管理详情 + 默认凭据可登录；fixed 401；
- SONiC 配置导出：vulnerable PFC watchdog 关闭 / fixed 开启；
- NVSwitch 拓扑：vulnerable 跨租户分区 / fixed 租户隔离；
- DPU：vulnerable 服务未鉴权 + 凭据暴露；fixed 全鉴权 + 404；
- telemetry/gNMI/SNMP：vulnerable 明文/弱团体名/跨租户标签；fixed TLS+鉴权；
- 固件清单与签名 fixture 可读；
- POST 一律 405；非法 mode 拒绝；上下文管理器关闭。
"""

import base64
import json
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from lab.hardware_sim import (
    ADMIN_PASSWORD,
    ADMIN_USER,
    DEFAULT_BMC_PASSWORD,
    DEFAULT_BMC_USER,
    FIXTURES,
    ROUTE_TABLE,
    start_all,
)


def _get(url: str, headers: dict | None = None):
    req = Request(url, headers=headers or {}, method="GET")
    try:
        with urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except HTTPError as exc:
        raw = exc.read()
        return exc.code, json.loads(raw.decode("utf-8")) if raw else {}


def _basic(user: str, password: str) -> dict:
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


class HardwareSimTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vulnerable = start_all(mode="vulnerable")
        cls.fixed = start_all(mode="fixed")

    @classmethod
    def tearDownClass(cls):
        cls.vulnerable.shutdown()
        cls.fixed.shutdown()

    def test_route_table_is_read_only(self):
        self.assertGreaterEqual(len(ROUTE_TABLE), 14)
        for entry in ROUTE_TABLE:
            self.assertEqual(entry["method"], "GET", entry["path"])
            self.assertFalse(entry["writes"], entry["path"])
            self.assertIn(entry["plane"], {"redfish", "config", "dpu", "telemetry", "firmware"})
    def test_routes_manifest_and_stats(self):
        status, doc = _get(self.vulnerable.url("/__routes__"))
        self.assertEqual(status, 200)
        self.assertEqual(doc["mode"], "vulnerable")
        self.assertEqual(doc["route_count"], len(ROUTE_TABLE))
        self.assertTrue(all(not r["writes"] for r in doc["routes"]))
        _, before = _get(self.vulnerable.url("/__stats__"))
        _get(self.vulnerable.url("/redfish/v1/"))
        _, after = _get(self.vulnerable.url("/__stats__"))
        self.assertGreater(after["requests"], before["requests"])
        self.assertGreaterEqual(after["by_path"].get("/redfish/v1/", 0), 1)

    def test_redfish_vulnerable_anonymous_and_default_login(self):
        status, root = _get(self.vulnerable.url("/redfish/v1/"))
        self.assertEqual(status, 200)
        self.assertIn("RedfishVersion", root)
        self.assertEqual(_get(self.vulnerable.url("/redfish/v1/Managers/BMC"))[0], 200)
        status, protocol = _get(self.vulnerable.url("/redfish/v1/Managers/BMC/NetworkProtocol"))
        self.assertEqual(status, 200)
        self.assertTrue(protocol["IPMI"]["ProtocolEnabled"])
        self.assertEqual(protocol["IPMI"]["Port"], 623)
        status, accounts = _get(self.vulnerable.url("/redfish/v1/Managers/BMC/Accounts"))
        self.assertEqual(status, 200)
        self.assertTrue(any(a.get("DefaultCredential") for a in accounts["Members"]))
        status, _ = _get(self.vulnerable.url("/redfish/v1/Systems/1"),
                         _basic(DEFAULT_BMC_USER, DEFAULT_BMC_PASSWORD))
        self.assertEqual(status, 200)
        status, _ = _get(self.vulnerable.url("/redfish/v1/Systems/1"),
                         _basic(DEFAULT_BMC_USER, "wrong-password"))
        self.assertEqual(status, 401)

    def test_redfish_fixed_rejects_anonymous_and_default(self):
        self.assertEqual(_get(self.fixed.url("/redfish/v1/Managers/BMC"))[0], 401)
        self.assertEqual(_get(self.fixed.url("/redfish/v1/Managers/BMC/NetworkProtocol"))[0], 401)
        self.assertEqual(_get(self.fixed.url("/redfish/v1/Managers/BMC/Accounts"))[0], 401)
        self.assertEqual(
            _get(self.fixed.url("/redfish/v1/Systems/1"),
                 _basic(DEFAULT_BMC_USER, DEFAULT_BMC_PASSWORD))[0],
            401,
        )
        self.assertEqual(
            _get(self.fixed.url("/redfish/v1/Systems/1"),
                 _basic(ADMIN_USER, ADMIN_PASSWORD))[0],
            200,
        )

    def test_sonic_config_export_posture(self):
        status, risky = _get(self.vulnerable.url("/sonic/config"))
        self.assertEqual(status, 200)
        self.assertEqual(risky["PFC_WATCHDOG"]["GLOBAL"]["mode"], "disable")
        self.assertIn("public", risky["SNMP"]["COMMUNITY"])
        status, hardened = _get(self.fixed.url("/sonic/config"))
        self.assertEqual(status, 200)
        self.assertEqual(hardened["PFC_WATCHDOG"]["GLOBAL"]["mode"], "detect")
        self.assertTrue(hardened["WRED_PROFILE"]["AZURE_LOSSLESS"]["wred_enabled"])
        self.assertNotIn("COMMUNITY", hardened["SNMP"])

    def test_nvswitch_topology_posture(self):
        status, risky = _get(self.vulnerable.url("/nvswitch/topology"))
        self.assertEqual(status, 200)
        partitions = {p["id"]: p for p in risky["partitions"]}
        self.assertIn("gpu-0", partitions[1]["gpus"])
        self.assertIn("gpu-0", partitions[3]["gpus"])
        self.assertEqual(partitions[1]["tenant"], "tenant-a")
        self.assertEqual(partitions[3]["tenant"], "tenant-b")
        status, clean = _get(self.fixed.url("/nvswitch/topology"))
        self.assertEqual(status, 200)
        owners = {}
        for part in clean["partitions"]:
            for gpu in part["gpus"]:
                owners.setdefault(gpu, set()).add(part["tenant"])
        self.assertTrue(all(len(tenants) == 1 for tenants in owners.values()), owners)

    def test_dpu_services_and_credentials(self):
        status, services = _get(self.vulnerable.url("/dpu/services"))
        self.assertEqual(status, 200)
        self.assertTrue(any(not s["auth_required"] for s in services["services"]))
        status, creds = _get(self.vulnerable.url("/dpu/credentials"))
        self.assertEqual(status, 200)
        self.assertIn("password", creds)
        status, fixed_services = _get(self.fixed.url("/dpu/services"))
        self.assertEqual(status, 200)
        self.assertTrue(all(s["auth_required"] for s in fixed_services["services"]))
        self.assertEqual(_get(self.fixed.url("/dpu/credentials"))[0], 404)

    def test_telemetry_posture(self):
        status, cfg = _get(self.vulnerable.url("/telemetry/v1/config"))
        self.assertEqual(status, 200)
        self.assertFalse(cfg["gnmi"]["tls"])
        self.assertFalse(cfg["gnmi"]["auth"])
        self.assertEqual(cfg["snmp"]["version"], "2c")
        self.assertEqual(cfg["snmp"]["community"], "public")
        status, metrics = _get(self.vulnerable.url("/telemetry/v1/metrics"))
        self.assertEqual(status, 200)
        labels = [m["labels"] for m in metrics["metrics"]]
        self.assertTrue(any("tenant" in x for x in labels))
        self.assertTrue(any("serial" in x for x in labels))
        status, fixed_cfg = _get(self.fixed.url("/telemetry/v1/config"))
        self.assertEqual(status, 200)
        self.assertTrue(fixed_cfg["gnmi"]["tls"])
        self.assertTrue(fixed_cfg["gnmi"]["auth"])
        self.assertEqual(fixed_cfg["snmp"]["version"], "3")
        self.assertEqual(_get(self.fixed.url("/telemetry/v1/metrics"))[0], 401)

    def test_firmware_manifest_and_signature_fixture(self):
        status, manifest = _get(self.vulnerable.url("/firmware/manifest"))
        self.assertEqual(status, 200)
        self.assertGreaterEqual(len(manifest["components"]), 4)
        self.assertEqual(len(manifest["signature"]), 64)
        status, sig = _get(self.vulnerable.url("/firmware/manifest.sig"))
        self.assertEqual(status, 200)
        self.assertEqual(sig["signature"], manifest["signature"])
        key_file = FIXTURES / "firmware" / "fixture-signing-key.txt"
        self.assertTrue(key_file.is_file())
        for component in manifest["components"]:
            self.assertTrue((FIXTURES / "firmware" / component["file"]).is_file(),
                            component["file"])

    def test_redfish_firmware_surface(self):
        status, update = _get(self.vulnerable.url("/redfish/v1/UpdateService"))
        self.assertEqual(status, 200)
        self.assertEqual(update["Authentication"], "None")
        self.assertEqual(update["TransferProtocol"], "HTTP")
        self.assertIn("HttpPushUri", update)
        status, inventory = _get(
            self.vulnerable.url("/redfish/v1/UpdateService/FirmwareInventory"))
        self.assertEqual(status, 200)
        self.assertTrue(any(m.get("Signed") is False for m in inventory["Members"]))
        self.assertEqual(_get(self.fixed.url("/redfish/v1/UpdateService"))[0], 401)
        self.assertEqual(
            _get(self.fixed.url("/redfish/v1/UpdateService/FirmwareInventory"))[0], 401)
        status, fixed_inventory = _get(
            self.fixed.url("/redfish/v1/UpdateService/FirmwareInventory"),
            _basic(ADMIN_USER, ADMIN_PASSWORD))
        self.assertEqual(status, 200)
        self.assertTrue(all(m.get("Signed") is True for m in fixed_inventory["Members"]))

    def test_post_not_allowed_and_invalid_mode(self):
        req = Request(self.vulnerable.url("/redfish/v1/"), data=b"{}", method="POST")
        with self.assertRaises(HTTPError) as ctx:
            urlopen(req, timeout=10)
        self.assertEqual(ctx.exception.code, 405)
        with self.assertRaises(ValueError):
            start_all(mode="unsafe")

    def test_context_manager_shuts_down(self):
        with start_all(mode="fixed") as server:
            self.assertEqual(_get(server.url("/health"))[0], 200)
        self.assertTrue(server._closed)


if __name__ == "__main__":
    unittest.main()
