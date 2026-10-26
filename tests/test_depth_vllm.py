# -*- coding: utf-8 -*-
"""研究级深度：vLLM/SGLang 版本补丁矩阵 + 五类接口差分 fuzz。"""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from lab.depth_sim import start_all
from trident.depth import vllm

ROOT = Path(__file__).resolve().parents[1]
MODULES = ROOT / "trident" / "modules"


class _Run:
    def __init__(self, path: Path):
        self.dir = path
        self.name = "depth-vllm"


def load_module(key: str):
    import importlib.util
    spec = importlib.util.spec_from_file_location(f"depth_{key.replace('-', '_')}", MODULES / key / "run.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestPatchMatrix(unittest.TestCase):
    def test_entries_and_version_pairs(self):
        data = vllm.load_matrix()
        entries = data["entries"]
        self.assertGreaterEqual(len(entries), 24)
        pairs = [e for e in entries if e.get("fixed")]
        self.assertGreaterEqual(len(pairs), 20)
        for entry in entries:
            self.assertTrue(entry["source"].startswith("https://"))
            self.assertTrue(entry["patch"].strip())
            self.assertTrue(entry["detection"].strip())
            self.assertIn(entry["component"], ("vllm", "sglang"))

    def test_surfaces_cover_all_required_interfaces(self):
        surfaces = {e["surface"] for e in vllm.entries()}
        self.assertTrue({"admin", "plugin", "dev-mode", "serialization", "weights"} <= surfaces)

    def test_version_range_matching(self):
        self.assertTrue(vllm.version_in_range("0.8.4", ">=0.6.5,<0.8.5"))
        self.assertFalse(vllm.version_in_range("0.8.5", ">=0.6.5,<0.8.5"))
        self.assertTrue(vllm.version_in_range("0.5.10", "==0.5.10"))
        self.assertTrue(vllm.version_in_range("0.28.0", ">= 0.28.0"))
        self.assertFalse(vllm.version_in_range("0.27.9", ">= 0.28.0"))

    def test_assess_version_returns_matching_cves(self):
        hits = vllm.assess_version("vllm", "0.8.4")
        self.assertTrue(any(h["cve"] == "CVE-2025-32444" for h in hits))
        clean = vllm.assess_version("vllm", "0.32.0")
        self.assertFalse(any(h["cve"] == "CVE-2025-32444" for h in clean))


class TestSurfaceFuzz(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vuln = start_all(mode="vulnerable")
        cls.fixed = start_all(mode="fixed")

    @classmethod
    def tearDownClass(cls):
        cls.vuln.shutdown()
        cls.fixed.shutdown()

    def test_generated_cases_at_least_200(self):
        cases = vllm.fuzz_cases()
        self.assertGreaterEqual(len(cases), 200)
        self.assertEqual(len({c["id"] for c in cases}), len(cases))
        surfaces = {c["surface"] for c in cases}
        self.assertEqual(surfaces, {"admin", "plugin", "dev-mode", "serialization", "weights"})

    def test_vulnerable_differential_and_fixed_clean(self):
        vuln = vllm.SurfaceFuzzer(self.vuln.url("")).run()
        fixed = vllm.SurfaceFuzzer(self.fixed.url("")).run()
        self.assertEqual(vuln["total"], len(vllm.fuzz_cases()))
        self.assertGreaterEqual(vuln["bypasses"], 100)
        self.assertEqual(fixed["bypasses"], 0, fixed["examples"])
        self.assertGreaterEqual(len(vuln["surfaces_hit"]), 4)
        self.assertEqual(vuln["control_status"], 401)

    def test_module_findings_and_fixed(self):
        with TemporaryDirectory() as td:
            ctx = {"run": _Run(Path(td)), "marker": "TRIDENT-DEPTH"}
            vuln = load_module("vllm-surface-fuzz").run(
                ctx, {"target": self.vuln.url(""), "mode": "probe-only"})
            self.assertGreaterEqual(len(vuln["findings"]), 4)
            detail = json.loads(vuln["findings"][0]["detail"])
            self.assertGreaterEqual(detail["cases"], 200)
            self.assertIn("interface", detail)
            ctx2 = {"run": _Run(Path(td) / "fixed"), "marker": "TRIDENT-DEPTH"}
            fixed = load_module("vllm-surface-fuzz").run(
                ctx2, {"target": self.fixed.url(""), "mode": "probe-only"})
            self.assertEqual(fixed["findings"], [])

    def test_patch_module(self):
        with TemporaryDirectory() as td:
            ctx = {"run": _Run(Path(td)), "marker": "TRIDENT-DEPTH"}
            result = load_module("vllm-sglang-patch-matrix").run(
                ctx, {"versions": {"vllm": "0.8.4", "sglang": "0.5.10"}})
            self.assertGreaterEqual(len(result["findings"]), 2)
            detail = json.loads(result["findings"][0]["detail"])
            self.assertGreaterEqual(detail["matrix_entries"], 24)
            self.assertGreaterEqual(detail["matched"], 1)


if __name__ == "__main__":
    unittest.main()
