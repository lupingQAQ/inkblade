"""tests/test_verify_effects_hardware.py — 硬件两项实效（BMC 默认凭据 / 固件清单篡改）。

独立于 tests.test_verify_effects：并行任务可能在该共享测试中登记尚未落地的效果项，
本文件只断言本任务新增的两项存在、PASS，且证据字段/脱敏正确。

并行任务可能写入暂不合法的 module.json（如 min_level 乱码）导致全局 load_modules 失败；
本文件把合法模块复制到临时目录后再跑效果验证，隔离本任务与并行在途产物。
"""

import json
import re
import shutil
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from trident.core.registry import LEVELS, SERIES, load_modules

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "trident" / "verify-effects.py"
MODULES_DIR = REPO / "trident" / "modules"
HARDWARE_IDS = {"hardware-bmc-default-credential", "hardware-firmware-manifest-tamper"}
_KEY_RE = re.compile(r"^[a-z][a-z-]*$")


def _sanitized_modules(root: Path) -> Path:
    """复制合法模块（跳过并行在途的坏 module.json），供 effects 在隔离目录运行。"""
    dest = root / "modules"
    dest.mkdir(parents=True, exist_ok=True)
    for common in MODULES_DIR.glob("_*.py"):
        shutil.copy(common, dest / common.name)
    for folder in sorted(p for p in MODULES_DIR.iterdir() if p.is_dir()):
        manifest = folder / "module.json"
        if not manifest.is_file() or not (folder / "run.py").is_file():
            continue
        try:
            raw = json.loads(manifest.read_text(encoding="utf-8"))
        except ValueError:
            continue
        if (raw.get("key") != folder.name or not _KEY_RE.match(str(raw.get("key", "")))
                or raw.get("series") not in SERIES or raw.get("min_level") not in LEVELS):
            continue
        shutil.copytree(folder, dest / folder.name)
    load_modules(dest)  # 若仍有 requires 缺失，直接失败而不是静默跳过
    return dest


def load_verify():
    import importlib.util
    spec = importlib.util.spec_from_file_location("trident_verify_effects_hardware", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class HardwareEffectsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = TemporaryDirectory()
        verify = load_verify()
        verify.MODULES_DIR = _sanitized_modules(Path(cls.tmp.name))
        cls.result = verify.run_verification(Path(cls.tmp.name) / "effects",
                                             write_docs=False)
        cls.by_id = {c["id"]: c for c in cls.result["checks"]}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_both_hardware_checks_present_and_pass(self):
        self.assertTrue(HARDWARE_IDS <= set(self.by_id),
                        f"缺少硬件效果项: {sorted(HARDWARE_IDS - set(self.by_id))}")
        for cid in HARDWARE_IDS:
            self.assertEqual(self.by_id[cid]["status"], "PASS", self.by_id[cid])
        self.assertGreaterEqual(self.result["summary"]["total"], 22)

    def test_bmc_default_credential_evidence(self):
        ev = self.by_id["hardware-bmc-default-credential"]["evidence"]
        self.assertEqual(ev["http_status"], 200)
        self.assertEqual(ev["default_username"], "root")
        self.assertEqual(ev["credential_class"], "vendor-default")
        self.assertTrue(ev["ipmi_over_lan"])
        self.assertEqual(ev["ipmi_port"], 623)
        self.assertTrue(ev["anonymous_manager_read"])
        self.assertTrue(ev["detected"])

    def test_firmware_tamper_evidence(self):
        ev = self.by_id["hardware-firmware-manifest-tamper"]["evidence"]
        self.assertTrue(ev["detected"])
        self.assertEqual(ev["signature_status"], "valid")
        self.assertIn("nvswitch-fw", ev["tampered_components"])
        self.assertNotEqual(ev["expected_sha256"], ev["actual_sha256"])
        self.assertTrue(ev["sha256_before"] != ev["sha256_after"])

    def test_no_plaintext_default_passwords_in_effects(self):
        text = json.dumps(self.result, ensure_ascii=False).lower()
        self.assertNotIn("calvin", text)
        self.assertNotIn("mock-dpu-default-pass", text)


if __name__ == "__main__":
    unittest.main()
