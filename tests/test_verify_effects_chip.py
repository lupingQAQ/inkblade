"""tests/test_verify_effects_chip.py — 芯片姿态四项实效（证明篡改/IOMMU 直通/PCR 偏移/显存残留）。

独立于 tests.test_verify_effects：并行任务可能在该共享测试中登记尚未落地的效果项，
本文件只断言本任务新增的四项存在、PASS，且证据字段可复核。

并行任务可能写入暂不合法的 module.json；本文件把合法模块复制到临时目录后再跑效果验证，
隔离本任务与并行在途产物。
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
CHIP_IDS = {
    "chip-cc-attestation-tamper",
    "chip-iommu-passthrough",
    "chip-pcr-baseline-offset",
    "chip-gpu-memory-residue",
}
_KEY_RE = re.compile(r"^[a-z][a-z0-9-]*$")


def _sanitized_modules(root: Path) -> Path:
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
    load_modules(dest)
    return dest


def load_verify():
    import importlib.util
    spec = importlib.util.spec_from_file_location("trident_verify_effects_chip", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class ChipEffectsTest(unittest.TestCase):
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

    def test_four_chip_checks_present_and_pass(self):
        self.assertTrue(CHIP_IDS <= set(self.by_id),
                        f"缺少芯片效果项: {sorted(CHIP_IDS - set(self.by_id))}")
        for cid in CHIP_IDS:
            self.assertEqual(self.by_id[cid]["status"], "PASS", self.by_id[cid])

    def test_cc_tamper_evidence(self):
        ev = self.by_id["chip-cc-attestation-tamper"]["evidence"]
        self.assertEqual(ev["valid_high"], 0)
        self.assertGreaterEqual(ev["tampered_high"], 1)
        self.assertFalse(ev["signature_valid"])
        self.assertTrue(ev["nonce"])
        self.assertTrue(ev["detected"])

    def test_iommu_passthrough_evidence(self):
        ev = self.by_id["chip-iommu-passthrough"]["evidence"]
        self.assertTrue(ev["passthrough"])
        self.assertGreaterEqual(ev["risky_groups"], 1)
        self.assertEqual(ev["fixed_high"], 0)
        self.assertTrue(ev["detected"])

    def test_pcr_offset_evidence(self):
        ev = self.by_id["chip-pcr-baseline-offset"]["evidence"]
        self.assertGreaterEqual(ev["pcr_mismatches"], 2)
        self.assertIn("0", ev["mismatched_pcrs"])
        self.assertIn("4", ev["mismatched_pcrs"])
        self.assertEqual(ev["fixed_mismatches"], 0)
        self.assertTrue(ev["detected"])

    def test_gpu_residue_evidence(self):
        ev = self.by_id["chip-gpu-memory-residue"]["evidence"]
        self.assertEqual(ev["readback_status"], 200)
        self.assertTrue(ev["marker_sha256_match"])
        self.assertTrue(ev["readable_after_release"])
        self.assertFalse(ev["zeroized"])
        self.assertEqual(ev["fixed_readback_status"], 404)
        self.assertEqual(ev["fixed_high"], 0)
        self.assertTrue(ev["detected"])

    def test_no_plaintext_secret_material(self):
        text = json.dumps(self.result, ensure_ascii=False).lower()
        for needle in ("fixture-signing-key", "private key", "calvin"):
            self.assertNotIn(needle, text)


if __name__ == "__main__":
    unittest.main()
