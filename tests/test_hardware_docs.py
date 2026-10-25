"""tests/test_hardware_docs.py — 硬件/交换机覆盖文档的诚实边界与三级矩阵。"""

import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DOC = REPO / "docs" / "HARDWARE-SWITCH-COVERAGE.md"

MODULES = (
    "gpu-driver-firmware-surface",
    "bmc-ipmi-exposure",
    "nvswitch-nvlink-topology",
    "dpu-smartnic-surface",
    "switch-os-config-surface",
    "ib-sm-partition-audit",
    "sharp-collective-config",
    "fabric-telemetry-exposure",
    "hardware-supply-chain",
)


class HardwareCoverageDocTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = DOC.read_text(encoding="utf-8")

    def test_doc_exists_and_lists_all_modules(self):
        self.assertTrue(DOC.is_file())
        for key in MODULES:
            self.assertIn(key, self.text, key)

    def test_three_tier_matrix_present(self):
        for heading in ("只读", "需授权主动", "必须真实硬件"):
            self.assertIn(heading, self.text, heading)
        self.assertIn("三级矩阵", self.text)

    def test_no_real_hardware_claimed(self):
        self.assertIn("无真实 GPU/BMC/交换机验证", self.text)
        self.assertIn("fixture", self.text)
        self.assertIn("仿真", self.text)
        self.assertIn("不等于", self.text)

    def test_production_guidance_present(self):
        for phrase in ("只读清点", "变更窗口", "厂商", "备件", "回滚"):
            self.assertIn(phrase, self.text, phrase)
        self.assertIn("默认凭据", self.text)
        self.assertIn("HMAC", self.text)
        self.assertIn("生产", self.text)


if __name__ == "__main__":
    unittest.main()
