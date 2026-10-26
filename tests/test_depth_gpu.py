# -*- coding: utf-8 -*-
"""研究级深度：GPU Operator / NVIDIA 配置面（driver/MIG/DCGM/device plugin/DRA）。"""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from trident.depth import gpu

ROOT = Path(__file__).resolve().parents[1]
MODULES = ROOT / "trident" / "modules"


class _Run:
    def __init__(self, path: Path):
        self.dir = path
        self.name = "depth-gpu"


def load_module(key: str):
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        f"depth_{key.replace('-', '_')}", MODULES / key / "run.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestGpuOperatorDepth(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.snap = gpu.fixture("vulnerable")
        cls.fixed = gpu.fixture("hardened")

    def test_at_least_twelve_cases(self):
        self.assertGreaterEqual(len(gpu.cases()), 12)

    def test_vulnerable_findings_and_hardened_clean(self):
        report = gpu.audit(self.snap)
        self.assertGreaterEqual(report["findings"], 10)
        self.assertGreaterEqual(report["severity"].get("critical", 0), 3)
        self.assertGreaterEqual(report["severity"].get("high", 0), 4)
        clean = gpu.audit(self.fixed)
        self.assertEqual(clean["findings"], 0, clean["details"])

    def test_coverage_domains(self):
        report = gpu.audit(self.snap)
        self.assertTrue({"driver", "mig", "dcgm", "device-plugin", "dra"} <= set(report["domains"]))
        self.assertGreaterEqual(report["checks"], 16)

    def test_operator_module(self):
        with TemporaryDirectory() as td:
            ctx = {"run": _Run(Path(td)), "marker": "TRIDENT-DEPTH"}
            result = load_module("gpu-operator-config-depth").run(ctx, {"snapshot": self.snap})
            self.assertGreaterEqual(len(result["findings"]), 6)
            detail = json.loads(result["findings"][0]["detail"])
            self.assertGreaterEqual(detail["checks"], 16)
            self.assertIn("driver", detail["domains"])

    def test_dra_mig_module(self):
        with TemporaryDirectory() as td:
            ctx = {"run": _Run(Path(td)), "marker": "TRIDENT-DEPTH"}
            result = load_module("gpu-dra-mig-policy").run(ctx, {"snapshot": self.snap})
            self.assertGreaterEqual(len(result["findings"]), 3)
            detail = json.loads(result["findings"][0]["detail"])
            self.assertTrue({"mig", "dra"} & set(detail["domains"]))


if __name__ == "__main__":
    unittest.main()
