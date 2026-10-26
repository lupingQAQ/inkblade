"""tests/test_chip_modules.py — 芯片/加速器姿态 8 模块（只读优先，写类走备份闸门）。

覆盖：
- 注册表契约：8 个纯小写键；仅 gpu-memory-residue-isolation 为写类；
  SPDM/NVLink-IMEX/CXL 为 C 级 research-only，默认关闭；
- gpu-cc-attestation-chain：真实 NRAS JWKS + nonce + claims 校验（fixture 自签）；
- spdm-pcie-doe：版本/证书链/MeasurementRecord 摘要/DOE；
- iommu-smmu-config：cmdline + IOMMU 组 + SMMU；
- secure-boot-chain：PCR 基线 + Secure Boot/dbx + UKI detached 签名；
- firmware-signature-inventory：厂商 X.509 链 + 分离签名 + 微码基线；
- gpu-memory-residue-isolation：MIG/MPS 残留导出 + active 写读回 + 备份闸门；
- nvlink-imex-isolation：IMEX 域/权限/通道 + NVLink 分区；
- cxl-memory-security：IDE/TSP/租户解码区域（默认隔离）。
"""

import json
import shutil
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from lab.chipsec_sim import start_all
from inkblade.core.evidence import EvidenceStore
from inkblade.core.registry import load_modules
from inkblade.core.roe import init_roe
from inkblade.core.runner import BackupGateRefused, run_module
from inkblade.core.users import UserStore
from inkblade.tee.fixtures import nvidia_fixture

REPO = Path(__file__).resolve().parents[1]
MODULES_DIR = REPO / "inkblade" / "modules"

NEW_MODULES = {
    "gpu-cc-attestation-chain": {"series": "侦察", "min_level": "只读侦察", "writes": False},
    "spdm-pcie-doe": {"series": "侦察", "min_level": "只读侦察", "writes": False},
    "iommu-smmu-config": {"series": "侦察", "min_level": "只读侦察", "writes": False},
    "secure-boot-chain": {"series": "侦察", "min_level": "只读侦察", "writes": False},
    "firmware-signature-inventory": {"series": "侦察", "min_level": "只读侦察", "writes": False},
    "gpu-memory-residue-isolation": {"series": "网络架构", "min_level": "利用验证", "writes": True},
    "nvlink-imex-isolation": {"series": "网络架构", "min_level": "只读侦察", "writes": False},
    "cxl-memory-security": {"series": "侦察", "min_level": "只读侦察", "writes": False},
}
RESEARCH_ONLY = ("spdm-pcie-doe", "nvlink-imex-isolation", "cxl-memory-security")


def _detail(finding):
    try:
        return json.loads(finding.get("detail") or "{}")
    except (TypeError, ValueError):
        return {}


def _titles(findings):
    return " | ".join(f.get("title", "") for f in findings)


def _isolated_modules(root: Path) -> Path:
    dest = root / "modules"
    dest.mkdir(parents=True, exist_ok=True)
    shutil.copy(MODULES_DIR / "_chip-common.py", dest / "_chip-common.py")
    shutil.copy(MODULES_DIR / "_gpu_cloud_common.py", dest / "_gpu_cloud_common.py")
    for key in NEW_MODULES:
        shutil.copytree(MODULES_DIR / key, dest / key)
    return dest


class RegistryContractTest(unittest.TestCase):
    def test_eight_modules_registered(self):
        with TemporaryDirectory() as tmp:
            mods = load_modules(_isolated_modules(Path(tmp)))
        self.assertEqual(set(mods), set(NEW_MODULES))
        for key, spec in NEW_MODULES.items():
            meta = mods[key]
            self.assertEqual(meta.series, spec["series"], key)
            self.assertEqual(meta.min_level, spec["min_level"], key)
            self.assertEqual(meta.writes, spec["writes"], key)
            self.assertTrue(meta.required_surfaces, key)
        for key in RESEARCH_ONLY:
            self.assertFalse(mods[key].default_enabled, key)
            self.assertTrue(mods[key].research_only, key)
        for key in NEW_MODULES:
            if key not in RESEARCH_ONLY:
                self.assertTrue(mods[key].default_enabled, key)
                self.assertFalse(mods[key].research_only, key)

    def test_modules_do_not_import_simulator(self):
        for key in NEW_MODULES:
            source = (MODULES_DIR / key / "run.py").read_text(encoding="utf-8")
            self.assertNotIn("chipsec_sim", source, f"{key} 不得依赖仿真器内部答案")


class ChipModuleTestBase(unittest.TestCase):
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
        self.store = EvidenceStore(self.root, workspace="chip-lab")
        users = UserStore(self.root / "users.json")
        users.create_user("chip-tester", "x", "tester", ["chip-lab"])
        self.session = users.verify("chip-tester", "x")
        init_roe(self.store, fields={
            "level": "全影响演示",
            "namespaces": ["train", "infer"],
            "cidrs": ["127.0.0.0/8"],
            "window": "chip-module-tests",
        })
        self._seq = 0

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, key, params):
        self._seq += 1
        run = self.store.create_run(f"chip-{key}-{self._seq}")
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

    def _export(self, path: str) -> dict:
        from urllib.request import urlopen
        with urlopen(self.vulnerable.url(path), timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))


class GpuCcTest(ChipModuleTestBase):
    def _params(self, token: str, nonce: str, jwks: dict, **extra) -> dict:
        return {"evidence": {"token": token, "expected_nonce": nonce, "jwks": jwks, **extra}}

    def test_valid_token_has_no_high(self):
        fx = nvidia_fixture(nonce="deadbeef" * 4)
        result, findings, _ = self._run(
            "gpu-cc-attestation-chain", self._params(fx.token, fx.nonce, fx.jwks))
        summary = self._summary(result)
        self.assertTrue(summary["signature_valid"])
        self.assertTrue(summary["claims_valid"])
        self.assertTrue(summary["verified"] >= 1)
        self.assertEqual([f for f in findings if f["severity"] == "high"], [], _titles(findings))

    def test_tampered_token_rejected(self):
        risky = self._export("/chip/gpu-cc")
        result, findings, _ = self._run(
            "gpu-cc-attestation-chain",
            self._params(risky["token"], risky["nonce"], risky["jwks"]))
        summary = self._summary(result)
        self.assertFalse(summary["signature_valid"])
        high = [f for f in findings if f["severity"] == "high"]
        self.assertTrue(high, _titles(findings))
        self.assertIn("验签失败", _titles(high))

    def test_nonce_mismatch_rejected(self):
        fx = nvidia_fixture(nonce="11112222" * 4)
        _, findings, _ = self._run(
            "gpu-cc-attestation-chain",
            self._params(fx.token, "ffff" * 8, fx.jwks))
        self.assertIn("nonce 不匹配", _titles(findings))

    def test_expired_and_debug_claims_rejected(self):
        expired = nvidia_fixture(exp_offset=-10)
        _, findings, _ = self._run(
            "gpu-cc-attestation-chain", self._params(expired.token, expired.nonce, expired.jwks))
        self.assertIn("已过期", _titles(findings))
        debug = nvidia_fixture(dbgstat="enabled", secboot=False)
        _, findings2, _ = self._run(
            "gpu-cc-attestation-chain", self._params(debug.token, debug.nonce, debug.jwks))
        titles = _titles(findings2)
        self.assertIn("调试模式未禁用", titles)
        self.assertIn("安全启动未启用", titles)


class SpdmTest(ChipModuleTestBase):
    def test_fixed_export_clean(self):
        from urllib.request import urlopen
        with urlopen(self.fixed.url("/chip/spdm"), timeout=10) as resp:
            doc = json.loads(resp.read().decode("utf-8"))
        result, findings, _ = self._run("spdm-pcie-doe", {"snapshot": doc, "probe": True})
        summary = self._summary(result)
        self.assertEqual(summary["version"], "1.3.0")
        self.assertTrue(summary["chain_ok"])
        self.assertTrue(summary["measurement_match"])
        self.assertEqual(findings, [], _titles(findings))

    def test_vulnerable_export_detected(self):
        doc = self._export("/chip/spdm")
        result, findings, _ = self._run("spdm-pcie-doe", {"snapshot": doc, "probe": True})
        summary = self._summary(result)
        self.assertFalse(summary["chain_ok"])
        self.assertFalse(summary["measurement_match"])
        self.assertFalse(summary["doe"])
        titles = _titles(findings)
        for needle in ("证书已过期", "测量摘要不一致", "版本过低", "DOE 未启用", "双向认证"):
            self.assertIn(needle, titles, titles)

    def test_measurement_record_required_for_digest(self):
        doc = self._export("/chip/spdm")
        doc["spdm"].pop("measurement_record_hex", None)
        _, findings, _ = self._run("spdm-pcie-doe", {"snapshot": doc, "probe": True})
        self.assertIn("缺少 SPDM MeasurementRecord", _titles(findings))


class IommuTest(ChipModuleTestBase):
    def test_vulnerable_passthrough_detected(self):
        doc = self._export("/chip/iommu")
        result, findings, _ = self._run("iommu-smmu-config", {"snapshot": doc})
        summary = self._summary(result)
        self.assertTrue(summary["passthrough"])
        self.assertGreaterEqual(summary["risky_groups"], 1)
        titles = _titles(findings)
        self.assertIn("全局直通", titles)
        self.assertIn("组直通", titles)
        self.assertIn("ACS 未启用", titles)

    def test_fixed_export_clean(self):
        from urllib.request import urlopen
        with urlopen(self.fixed.url("/chip/iommu"), timeout=10) as resp:
            doc = json.loads(resp.read().decode("utf-8"))
        _, findings, _ = self._run("iommu-smmu-config", {"snapshot": doc})
        self.assertEqual(findings, [], _titles(findings))

    def test_iommu_off_and_arm_smmu(self):
        doc = {"arch": "arm64", "kernel_cmdline": "iommu=off",
               "iommu": {"enabled": False, "passthrough": False, "smmu": False},
               "groups": []}
        _, findings, _ = self._run("iommu-smmu-config", {"snapshot": doc})
        titles = _titles(findings)
        self.assertIn("IOMMU 未启用", titles)
        self.assertIn("ARM SMMU 未启用", titles)


class SecureBootTest(ChipModuleTestBase):
    def test_vulnerable_pcr_and_uki_detected(self):
        doc = self._export("/chip/boot")
        result, findings, _ = self._run("secure-boot-chain", {"snapshot": doc})
        summary = self._summary(result)
        self.assertGreaterEqual(summary["pcr_mismatches"], 2)
        self.assertFalse(summary["uki_signature_valid"])
        titles = _titles(findings)
        self.assertIn("PCR 测量值与 golden 基线不一致", titles)
        self.assertIn("UKI 签名校验失败", titles)

    def test_fixed_export_clean(self):
        from urllib.request import urlopen
        with urlopen(self.fixed.url("/chip/boot"), timeout=10) as resp:
            doc = json.loads(resp.read().decode("utf-8"))
        result, findings, _ = self._run("secure-boot-chain", {"snapshot": doc})
        summary = self._summary(result)
        self.assertEqual(summary["pcr_mismatches"], 0)
        self.assertTrue(summary["uki_signature_valid"])
        self.assertEqual(findings, [], _titles(findings))

    def test_secure_boot_off_and_dbx_missing(self):
        doc = {"secure_boot": False, "setup_mode": True, "eventlog_verified": True,
               "pcrs": {}, "baseline": {}, "dbx": {"present": False},
               "tpm": {"pcr_bank": "sha1"}, "uki": {}}
        _, findings, _ = self._run("secure-boot-chain", {"snapshot": doc})
        titles = _titles(findings)
        self.assertIn("Secure Boot 未启用", titles)
        self.assertIn("dbx 撤销库缺失", titles)
        self.assertIn("PCR bank 非 SHA-256", titles)


class FirmwareSignatureTest(ChipModuleTestBase):
    def test_fixed_manifest_all_valid(self):
        from urllib.request import urlopen
        with urlopen(self.fixed.url("/chip/firmware"), timeout=10) as resp:
            doc = json.loads(resp.read().decode("utf-8"))
        result, findings, _ = self._run(
            "firmware-signature-inventory", {"manifest": doc})
        summary = self._summary(result)
        self.assertEqual(summary["components"], 3)
        self.assertEqual(summary["verified"], 3)
        self.assertEqual(summary["invalid_signature"], 0)
        self.assertEqual(findings, [], _titles(findings))

    def test_vulnerable_manifest_bad_signature(self):
        doc = self._export("/chip/firmware")
        result, findings, _ = self._run(
            "firmware-signature-inventory", {"manifest": doc})
        summary = self._summary(result)
        self.assertEqual(summary["invalid_signature"], 1)
        self.assertIn("bmc-fw", summary["invalid_components"])
        high = [f for f in findings if f["severity"] == "high"]
        self.assertTrue(high, _titles(findings))
        self.assertIn("固件签名无效", _titles(high))

    def test_microcode_below_vendor_baseline(self):
        from urllib.request import urlopen
        with urlopen(self.fixed.url("/chip/firmware"), timeout=10) as resp:
            doc = json.loads(resp.read().decode("utf-8"))
        component = dict(doc["components"][0])
        component.update({"name": "cpu-microcode", "kind": "microcode",
                          "version": "0x2", "min_version": "0x2e"})
        doc["components"].append(component)
        result, findings, _ = self._run(
            "firmware-signature-inventory", {"manifest": doc})
        summary = self._summary(result)
        self.assertEqual(summary["microcode_stale"], 1)
        self.assertIn("CPU 微码版本低于安全基线", _titles(findings))

    def test_expired_chain_and_unpinned_root(self):
        doc = self._export("/chip/spdm")
        manifest = {
            "vendor": "MockVendor",
            "components": [{
                "name": "gpu-fw",
                "sha256": "0" * 64,
                "content_b64": "Z3B1LWZ3",
                "chain_pem": doc["spdm"]["chain_pem"],
                "signature_b64": "AAAA",
                "algorithm": "ecdsa-sha384",
            }],
        }
        result, findings, _ = self._run(
            "firmware-signature-inventory", {"manifest": manifest})
        summary = self._summary(result)
        self.assertGreaterEqual(summary["expired"], 1)
        self.assertFalse(summary["trust_root_pinned"])
        titles = _titles(findings)
        self.assertIn("信任根未固定", titles)
        self.assertIn("证书链无效/过期", titles)


class GpuResidueTest(ChipModuleTestBase):
    def test_export_vulnerable_cross_tenant(self):
        doc = self._export("/chip/residue/export")
        result, findings, _ = self._run(
            "gpu-memory-residue-isolation",
            {"snapshot": doc, "tenant": "tenant-a",
             "backup_targets": [{"kind": "http", "url": self.vulnerable.url("/chip/gpu/allocate"),
                                 "state": {}}]})
        summary = self._summary(result)
        self.assertGreaterEqual(summary["residue_readable"], 1)
        self.assertGreaterEqual(summary["cross_tenant"], 1)
        self.assertGreaterEqual(summary["mps_shared"], 1)
        titles = _titles(findings)
        self.assertIn("释放后显存残留可读", titles)
        self.assertIn("跨租户显存残留可读", titles)

    def test_active_backup_write_differential(self):
        params = {
            "target": self.vulnerable.url("/chip"),
            "mode": "backup-write",
            "tenant": "tenant-a",
            "own_device": "gpu-a-1",
            "backup_targets": [{"kind": "http", "url": self.vulnerable.url("/chip/gpu/allocate"),
                                "state": {}}],
        }
        result, findings, run = self._run(
            "gpu-memory-residue-isolation", dict(params, mode="backup-write"))
        summary = self._summary(result)
        self.assertEqual(summary["active"]["readback_status"], 200)
        self.assertTrue(summary["active"]["marker_sha256_match"])
        high = [f for f in findings if f["severity"] == "high"]
        self.assertTrue(high, _titles(findings))
        self.assertIn("释放后显存残留可读", _titles(high))
        self.assertTrue(run.query("SELECT COUNT(*) FROM backups")[0][0] >= 1)

        fixed_params = dict(params, target=self.fixed.url("/chip"))
        result2, findings2, _ = self._run(
            "gpu-memory-residue-isolation", fixed_params)
        summary2 = self._summary(result2)
        self.assertEqual(summary2["active"]["readback_status"], 404)
        self.assertEqual([f for f in findings2 if f["severity"] == "high"], [],
                         _titles(findings2))

    def test_backup_gate_refuses_active_without_backup(self):
        params = {
            "target": self.vulnerable.url("/chip"),
            "mode": "backup-write",
            "tenant": "tenant-a",
            "own_device": "gpu-a-1",
        }
        with self.assertRaises(BackupGateRefused):
            self._run("gpu-memory-residue-isolation", params)


class ImexTest(ChipModuleTestBase):
    def test_vulnerable_cross_tenant(self):
        doc = self._export("/chip/imex")
        result, findings, _ = self._run("nvlink-imex-isolation", {"snapshot": doc, "probe": True})
        summary = self._summary(result)
        self.assertGreaterEqual(summary["cross_tenant_domains"], 1)
        self.assertGreaterEqual(summary["wildcard_permissions"], 1)
        titles = _titles(findings)
        self.assertIn("IMEX 域成员跨租户", titles)
        self.assertIn("IMEX 权限通配", titles)
        self.assertIn("NVLink 默认分区包含多租户", titles)

    def test_fixed_export_clean(self):
        from urllib.request import urlopen
        with urlopen(self.fixed.url("/chip/imex"), timeout=10) as resp:
            doc = json.loads(resp.read().decode("utf-8"))
        _, findings, _ = self._run("nvlink-imex-isolation", {"snapshot": doc, "probe": True})
        self.assertEqual(findings, [], _titles(findings))


class CxlTest(ChipModuleTestBase):
    def test_vulnerable_plaintext_and_shared_region(self):
        doc = self._export("/chip/cxl")
        result, findings, _ = self._run(
            "cxl-memory-security", {"snapshot": doc, "probe": True})
        summary = self._summary(result)
        self.assertFalse(summary["ide_all_enabled"])
        self.assertFalse(summary["tsp_all_enabled"])
        self.assertGreaterEqual(summary["cross_tenant_regions"], 1)
        titles = _titles(findings)
        self.assertIn("CXL 链路未启用 IDE", titles)
        self.assertIn("CXL TSP 未启用", titles)
        self.assertIn("解码区域跨租户", titles)

    def test_fixed_export_clean(self):
        from urllib.request import urlopen
        with urlopen(self.fixed.url("/chip/cxl"), timeout=10) as resp:
            doc = json.loads(resp.read().decode("utf-8"))
        _, findings, _ = self._run(
            "cxl-memory-security", {"snapshot": doc, "probe": True})
        self.assertEqual(findings, [], _titles(findings))

    def test_default_disabled_requires_probe(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.store2 = EvidenceStore(root, workspace="chip-lab")
            init_roe(self.store2, fields={"level": "全影响演示",
                                          "namespaces": ["train"], "cidrs": ["127.0.0.0/8"]})
            users = UserStore(root / "users.json")
            users.create_user("chip-tester", "x", "tester", ["chip-lab"])
            session = users.verify("chip-tester", "x")
            run = self.store2.create_run("cxl-no-probe")
            result = run_module(self.store2, session, "cxl-memory-security",
                                {"snapshot": {"devices": []}},
                                modules_dir=self.modules_dir, run=run)
            self.assertTrue(result["skipped"])
            self.assertTrue(result["status"].startswith("skipped-surface-"))


if __name__ == "__main__":
    unittest.main()
