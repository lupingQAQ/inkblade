# -*- coding: utf-8 -*-
"""研究级深度：Falco/Tetragon 运行时覆盖盲区（syscall/逃逸后/hostNetwork/短生命周期）。"""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.depth import ebpf

ROOT = Path(__file__).resolve().parents[1]
MODULES = ROOT / "inkblade" / "modules"


class _Run:
    def __init__(self, path: Path):
        self.dir = path
        self.name = "depth-ebpf"


def load_module(key: str):
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        f"depth_{key.replace('-', '_')}", MODULES / key / "run.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestEbpfCoverage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = ebpf.cases()

    def test_at_least_ten_cases(self):
        self.assertGreaterEqual(len(self.cases), 10)

    def test_default_misses_hardened_covers(self):
        report = ebpf.audit(self.cases)
        self.assertGreaterEqual(report["vulnerable_missed"], 10)
        self.assertEqual(report["hardened_missed"], 0, report["hardened_details"])
        self.assertGreaterEqual(report["coverage_gaps"], 6)

    def test_blindspot_categories(self):
        gaps = ebpf.gap_categories(self.cases)
        for required in ("syscall-filter", "post-escape", "host-network",
                         "short-lived", "child-process"):
            self.assertIn(required, gaps)

    def test_module(self):
        with TemporaryDirectory() as td:
            ctx = {"run": _Run(Path(td)), "marker": "INKBLADE-DEPTH"}
            result = load_module("ebpf-runtime-coverage-gap").run(ctx, {})
            self.assertGreaterEqual(len(result["findings"]), 5)
            detail = json.loads(result["findings"][0]["detail"])
            self.assertGreaterEqual(detail["cases"], 10)
            self.assertGreaterEqual(detail["missed"], 10)


if __name__ == "__main__":
    unittest.main()
