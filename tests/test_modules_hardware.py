"""tests/test_modules_hardware.py — 硬件/交换机只读模块（9 个）fixture 与两态 mock。

覆盖：
- 注册表契约：9 个纯小写键、系列/级别、全部 writes=false；
- fixture 驱动：GPU 驱动/Xid、NVSwitch 拓扑、SONiC/Cumulus、IB SM、SHARP、固件清单；
- 两态 mock：BMC 默认凭据、DPU 服务/凭据、fabric 遥测；
- 负例：干净 fixture / fixed 态无 high finding；
- 固件清单篡改（blob 哈希 + 清单签名）必被检出；
- 模块源码不得引用 lab.hardware_sim（不得依赖仿真器答案）。
"""

import json
import shutil
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from lab.hardware_sim import start_all
from trident.core.evidence import EvidenceStore
from trident.core.registry import load_modules
from trident.core.roe import init_roe
from trident.core.runner import run_module
from trident.core.users import UserStore

REPO = Path(__file__).resolve().parents[1]
MODULES_DIR = REPO / "trident" / "modules"
FIX = REPO / "lab" / "hardware-fixtures"

NEW_MODULES = {
    "gpu-driver-firmware-surface": {
        "series": "侦察", "min_level": "只读侦察", "writes": False},
    "bmc-ipmi-exposure": {
        "series": "侦察", "min_level": "主动探测", "writes": False},
    "nvswitch-nvlink-topology": {
        "series": "网络架构", "min_level": "只读侦察", "writes": False},
    "dpu-smartnic-surface": {
        "series": "侦察", "min_level": "主动探测", "writes": False},
    "switch-os-config-surface": {
        "series": "网络架构", "min_level": "只读侦察", "writes": False},
    "ib-sm-partition-audit": {
        "series": "网络架构", "min_level": "只读侦察", "writes": False},
    "sharp-collective-config": {
        "series": "网络架构", "min_level": "只读侦察", "writes": False},
    "fabric-telemetry-exposure": {
        "series": "网络架构", "min_level": "主动探测", "writes": False},
    "hardware-supply-chain": {
        "series": "侦察", "min_level": "只读侦察", "writes": False},
}


def _detail(finding):
    try:
        return json.loads(finding.get("detail") or "{}")
    except (TypeError, ValueError):
        return {}


def _titles(findings):
    return " | ".join(f.get("title", "") for f in findings)


def _isolated_modules(root: Path) -> Path:
    """只复制本任务 9 模块 + 共享库，免受并行任务在途 module.json 干扰。"""
    dest = root / "modules"
    dest.mkdir(parents=True, exist_ok=True)
    shutil.copy(MODULES_DIR / "_hardware-common.py", dest / "_hardware-common.py")
    for key in NEW_MODULES:
        shutil.copytree(MODULES_DIR / key, dest / key)
    return dest


class RegistryContractTest(unittest.TestCase):
    def test_nine_modules_registered_read_only(self):
        with TemporaryDirectory() as tmp:
            mods = load_modules(_isolated_modules(Path(tmp)))
        for key, spec in NEW_MODULES.items():
            self.assertIn(key, mods, f"缺少模块 {key}")
            meta = mods[key]
            self.assertEqual(meta.series, spec["series"], key)
            self.assertEqual(meta.min_level, spec["min_level"], key)
            self.assertFalse(meta.writes, key)
            self.assertEqual(meta.requires, [], key)

    def test_modules_do_not_import_simulator(self):
        for key in NEW_MODULES:
            source = (MODULES_DIR / key / "run.py").read_text(encoding="utf-8")
            self.assertNotIn("hardware_sim", source, f"{key} 不得依赖仿真器内部答案")
            self.assertNotIn("lab.hardware", source, f"{key} 不得依赖仿真器内部答案")


class HardwareModuleTestBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.modules_tmp = TemporaryDirectory()
        cls.modules_dir = _isolated_modules(Path(cls.modules_tmp.name))
        cls.vulnerable = start_all(mode="vulnerable")
        cls.fixed = start_all(mode="fixed")

    @classmethod
    def tearDownClass(cls):
        cls.vulnerable.shutdown()
        cls.fixed.shutdown()
        cls.modules_tmp.cleanup()

    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = EvidenceStore(self.root, workspace="hardware-lab")
        users = UserStore(self.root / "users.json")
        users.create_user("hardware-tester", "x", "tester", ["hardware-lab"])
        self.session = users.verify("hardware-tester", "x")
        init_roe(self.store, fields={
            "level": "全影响演示",
            "namespaces": ["train", "infer"],
            "cidrs": ["127.0.0.0/8"],
            "window": "hardware-module-tests",
        })
        self._seq = 0

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, key, params):
        self._seq += 1
        run = self.store.create_run(f"hardware-{key}-{self._seq}")
        result = run_module(self.store, self.session, key, params,
                            modules_dir=self.modules_dir, run=run)
        findings = [f for f in run.findings if f["step_key"] == key]
        row = run.query(
            "SELECT result_summary FROM steps WHERE run=? AND step_key=? ORDER BY id DESC LIMIT 1",
            (run.name, key),
        )
        result["result_summary"] = row[0][0] if row else ""
        return result, findings, run

    @staticmethod
    def _summary(result):
        return json.loads(result["result_summary"])


class FixtureDrivenModuleTest(HardwareModuleTestBase):
    def test_gpu_driver_firmware_surface_risky(self):
        result, findings, _ = self._run("gpu-driver-firmware-surface", {
            "snapshot": {
                "nvidia_smi": str(FIX / "gpu" / "nvidia-smi.csv"),
                "nvml": str(FIX / "gpu" / "nvml.json"),
            },
        })
        summary = self._summary(result)
        self.assertEqual(summary["devices"], 4)
        self.assertEqual(summary["cuda_version"], "13.0")
        self.assertIn("565.57.01", summary["driver_versions"])
        self.assertGreaterEqual(summary["ecc_disabled"], 1)
        self.assertGreaterEqual(summary["xid_events"], 1)
        titles = _titles(findings)
        for needle in ("驱动版本低于只读基线", "驱动版本不一致", "VBIOS 版本不一致",
                       "ECC 未启用", "Xid 复位族事件"):
            self.assertIn(needle, titles, titles)
        high = [f for f in findings if f["severity"] == "high"]
        self.assertTrue(high)
        xid_high = next(f for f in high if "Xid" in f["title"])
        detail = _detail(xid_high)
        self.assertTrue(detail["detected"])
        self.assertGreaterEqual(detail["xid_events"], 1)

    def test_gpu_clean_fixture_no_findings(self):
        _, findings, _ = self._run("gpu-driver-firmware-surface", {
            "snapshot": {
                "nvidia_smi": str(FIX / "gpu" / "nvidia-smi-clean.csv"),
                "nvml": str(FIX / "gpu" / "nvml-clean.json"),
            },
        })
        self.assertEqual(findings, [], _titles(findings))

    def test_nvswitch_topology_risky_and_clean(self):
        _, findings, _ = self._run("nvswitch-nvlink-topology", {
            "snapshot": str(FIX / "nvswitch" / "topology.json"),
        })
        titles = _titles(findings)
        for needle in ("分区跨越租户", "IMEX 通道成员跨租户", "共享交换机",
                       "固件版本不一致", "链路非 up"):
            self.assertIn(needle, titles, titles)
        high = [f for f in findings if f["severity"] == "high"]
        self.assertGreaterEqual(len(high), 2, titles)
        _, clean, _ = self._run("nvswitch-nvlink-topology", {
            "snapshot": str(FIX / "nvswitch" / "topology-clean.json"),
        })
        self.assertEqual(clean, [], _titles(clean))

    def test_switch_os_sonic_risky_and_hardened(self):
        result, findings, _ = self._run("switch-os-config-surface", {
            "config": str(FIX / "sonic" / "config_db.json"),
        })
        summary = self._summary(result)
        self.assertEqual(summary["format"], "sonic")
        self.assertFalse(summary["pfc_watchdog"])
        self.assertFalse(summary["ecn_enabled"])
        self.assertEqual(summary["mgmt_acl"], "open")
        self.assertTrue(summary["snmp_public"])
        titles = _titles(findings)
        for needle in ("PFC watchdog 未启用", "ECN/WRED 未在无损队列启用",
                       "管理面 ACL 允许任意来源", "SNMP 弱团体名",
                       "缺少远程 AAA", "未配置 NTP 服务器"):
            self.assertIn(needle, titles, titles)
        _, hardened, _ = self._run("switch-os-config-surface", {
            "config": str(FIX / "sonic" / "config_db_hardened.json"),
        })
        self.assertEqual(hardened, [], _titles(hardened))

    def test_switch_os_cumulus_risky(self):
        result, findings, _ = self._run("switch-os-config-surface", {
            "config": str(FIX / "cumulus" / "config.json"),
        })
        summary = self._summary(result)
        self.assertEqual(summary["format"], "cumulus")
        self.assertEqual(summary["mgmt_acl"], "open")
        titles = _titles(findings)
        self.assertIn("PFC watchdog 未启用", titles)
        self.assertIn("管理面 ACL 允许任意来源", titles)
        self.assertIn("SNMP 弱团体名", titles)

    def test_ib_partition_audit_risky_and_clean(self):
        result, findings, _ = self._run("ib-sm-partition-audit", {
            "snapshot": str(FIX / "ib" / "partition-dump.json"),
        })
        summary = self._summary(result)
        self.assertEqual(summary["sm_count"], 1)
        self.assertTrue(summary["default_partition_wildcard"])
        self.assertGreaterEqual(summary["cross_tenant_partitions"], 1)
        titles = _titles(findings)
        for needle in ("IB SM 无冗余", "IB 默认分区覆盖全部 HCA",
                       "IB Partition 跨越租户", "IB SM 运行在计算节点"):
            self.assertIn(needle, titles, titles)
        _, clean, _ = self._run("ib-sm-partition-audit", {
            "snapshot": str(FIX / "ib" / "partition-dump-clean.json"),
        })
        self.assertEqual(clean, [], _titles(clean))

    def test_sharp_collective_config_risky_and_clean(self):
        result, findings, _ = self._run("sharp-collective-config", {
            "snapshot": str(FIX / "sharp" / "config-dump.json"),
        })
        summary = self._summary(result)
        self.assertEqual(summary["sessions"], 2)
        self.assertEqual(summary["unauth_sessions"], 2)
        self.assertGreaterEqual(summary["cross_tenant_sessions"], 1)
        titles = _titles(findings)
        for needle in ("SHARP 会话无鉴权", "SHARP 聚合节点跨租户共享",
                       "SHARP 会话成员跨租户", "SHARP 聚合缓冲未隔离"):
            self.assertIn(needle, titles, titles)
        _, clean, _ = self._run("sharp-collective-config", {
            "snapshot": str(FIX / "sharp" / "config-dump-clean.json"),
        })
        self.assertEqual(clean, [], _titles(clean))

    def test_hardware_supply_chain_clean(self):
        result, findings, _ = self._run("hardware-supply-chain", {
            "manifest": str(FIX / "firmware" / "manifest.json"),
            "key_file": str(FIX / "firmware" / "fixture-signing-key.txt"),
        })
        summary = self._summary(result)
        self.assertEqual(summary["signature_status"], "valid")
        self.assertEqual(summary["components"], 4)
        self.assertEqual(summary["tampered"], 0)
        self.assertEqual(findings, [], _titles(findings))

    def test_hardware_supply_chain_tampered_blob(self):
        target = self.root / "firmware-tampered"
        shutil.copytree(FIX / "firmware", target)
        blob = target / "blobs" / "nvswitch-fw-1.8.2.bin"
        blob.write_bytes(blob.read_bytes() + b"\nTRIDENT-TAMPER\n")
        result, findings, _ = self._run("hardware-supply-chain", {
            "manifest": str(target / "manifest.json"),
            "key_file": str(FIX / "firmware" / "fixture-signing-key.txt"),
        })
        summary = self._summary(result)
        self.assertEqual(summary["signature_status"], "valid")
        self.assertEqual(summary["tampered"], 1)
        self.assertIn("nvswitch-fw", summary["tampered_components"])
        high = [f for f in findings if f["severity"] == "high"]
        self.assertEqual(len(high), 1, _titles(findings))
        detail = _detail(high[0])
        self.assertTrue(detail["detected"])
        self.assertNotEqual(detail["expected_sha256"], detail["actual_sha256"])

    def test_hardware_supply_chain_bad_signature(self):
        target = self.root / "firmware-signature"
        shutil.copytree(FIX / "firmware", target)
        manifest_path = target / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["components"][0]["version"] = "0.0.0-tampered"
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2),
                                 encoding="utf-8")
        _, findings, _ = self._run("hardware-supply-chain", {
            "manifest": str(manifest_path),
            "key_file": str(FIX / "firmware" / "fixture-signing-key.txt"),
        })
        high = [f for f in findings if f["severity"] == "high"]
        self.assertTrue(high, _titles(findings))
        titles = _titles(high)
        self.assertIn("固件清单签名无效", titles, titles)


class MockBackedModuleTest(HardwareModuleTestBase):
    def test_bmc_default_credential_vulnerable_and_fixed(self):
        _, findings, _ = self._run("bmc-ipmi-exposure", {
            "target": self.vulnerable.url(""),
            "check_default_credentials": True,
        })
        high = [f for f in findings if f["severity"] == "high"]
        self.assertEqual(len(high), 1, _titles(findings))
        detail = _detail(high[0])
        self.assertEqual(detail["default_login_status"], 200)
        self.assertEqual(detail["default_username"], "root")
        self.assertEqual(detail["credential_class"], "vendor-default")
        self.assertTrue(detail["ipmi_over_lan"])
        self.assertEqual(detail["ipmi_port"], 623)
        self.assertTrue(detail["anonymous_manager_read"])
        self.assertNotIn("calvin", json.dumps(findings, ensure_ascii=False).lower())
        _, fixed, _ = self._run("bmc-ipmi-exposure", {
            "target": self.fixed.url(""),
            "check_default_credentials": True,
        })
        self.assertEqual([f for f in fixed if f["severity"] == "high"], [], _titles(fixed))

    def test_dpu_services_vulnerable_and_fixed(self):
        result, findings, _ = self._run("dpu-smartnic-surface", {
            "target": self.vulnerable.url(""),
        })
        summary = self._summary(result)
        self.assertGreaterEqual(summary["unauth_services"], 1)
        self.assertTrue(summary["credentials_exposed"])
        self.assertTrue(summary["ssh_password_auth"])
        self.assertTrue(summary["rshim_exposed"])
        titles = _titles(findings)
        self.assertIn("DPU 管理服务未鉴权暴露", titles)
        self.assertIn("DPU 工厂/默认凭据明文暴露", titles)
        full = json.dumps(findings, ensure_ascii=False)
        self.assertNotIn("mock-dpu-default-pass", full)
        _, fixed, _ = self._run("dpu-smartnic-surface", {
            "target": self.fixed.url(""),
        })
        self.assertEqual([f for f in fixed if f["severity"] == "high"], [], _titles(fixed))

    def test_fabric_telemetry_vulnerable_and_fixed(self):
        result, findings, _ = self._run("fabric-telemetry-exposure", {
            "target": self.vulnerable.url(""),
        })
        summary = self._summary(result)
        self.assertFalse(summary["gnmi_tls"])
        self.assertFalse(summary["gnmi_auth"])
        self.assertEqual(summary["snmp_version"], "2c")
        self.assertEqual(summary["snmp_community"], "public")
        self.assertTrue(summary["tenant_labels"])
        self.assertTrue(summary["serial_labels"])
        titles = _titles(findings)
        for needle in ("遥测匿名暴露跨租户标签", "gNMI 未启用 TLS",
                       "gNMI 未启用认证", "SNMP v2c 弱团体名"):
            self.assertIn(needle, titles, titles)
        _, fixed, _ = self._run("fabric-telemetry-exposure", {
            "target": self.fixed.url(""),
        })
        self.assertEqual([f for f in fixed if f["severity"] == "high"], [], _titles(fixed))


if __name__ == "__main__":
    unittest.main()
