# -*- coding: utf-8 -*-
"""研究级深度：Kyverno/Gatekeeper 准入语义差异（审计/豁免/顺序/子资源/CRD）。"""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from trident.depth import admission

ROOT = Path(__file__).resolve().parents[1]
MODULES = ROOT / "trident" / "modules"


class _Run:
    def __init__(self, path: Path):
        self.dir = path
        self.name = "depth-admission"


def load_module(key: str):
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        f"depth_{key.replace('-', '_')}", MODULES / key / "run.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestAdmissionSemantics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = admission.cases()

    def test_at_least_fifteen_research_cases(self):
        self.assertGreaterEqual(len(self.cases), 15)
        self.assertEqual(len({c["id"] for c in self.cases}), len(self.cases))

    def test_exploit_cases_vulnerable_vs_hardened(self):
        for case in self.cases:
            with self.subTest(case=case["id"]):
                vuln = admission.evaluate_case(case, hardened=False)
                hard = admission.evaluate_case(case, hardened=True)
                self.assertTrue(vuln["admitted"], vuln)
                self.assertFalse(hard["admitted"], hard)

    def test_semantic_mechanisms_covered(self):
        mechanisms = {c["mechanism"] for c in self.cases}
        for required in ("audit-mode", "exemption", "mutation-order", "subresource",
                         "ephemeral-container", "init-container", "crd-conversion"):
            self.assertIn(required, mechanisms)
        engines = {c["engine"] for c in self.cases}
        self.assertEqual(engines, {"kyverno", "gatekeeper"})

    def test_audit_summary_and_trace(self):
        report = admission.audit(self.cases)
        self.assertGreaterEqual(report["vulnerable_admitted"], 15)
        self.assertEqual(report["hardened_admitted"], 0)
        self.assertGreaterEqual(report["findings"], 15)
        first = report["results"][0]
        self.assertTrue(first["trace"])
        json.dumps(report, ensure_ascii=False)

    def test_kyverno_module(self):
        with TemporaryDirectory() as td:
            ctx = {"run": _Run(Path(td)), "marker": "TRIDENT-DEPTH"}
            result = load_module("admission-kyverno-semantics").run(ctx, {})
            self.assertGreaterEqual(len(result["findings"]), 5)
            detail = json.loads(result["findings"][0]["detail"])
            self.assertGreaterEqual(detail["cases"], 5)
            self.assertIn("audit-mode", detail["mechanisms"])

    def test_gatekeeper_module(self):
        with TemporaryDirectory() as td:
            ctx = {"run": _Run(Path(td)), "marker": "TRIDENT-DEPTH"}
            result = load_module("admission-gatekeeper-semantics").run(ctx, {})
            self.assertGreaterEqual(len(result["findings"]), 4)
            detail = json.loads(result["findings"][0]["detail"])
            self.assertIn("dryrun", detail["mechanisms"])

    def test_crd_subresource_module(self):
        with TemporaryDirectory() as td:
            ctx = {"run": _Run(Path(td)), "marker": "TRIDENT-DEPTH"}
            result = load_module("admission-crd-subresource-gap").run(ctx, {})
            self.assertGreaterEqual(len(result["findings"]), 3)
            detail = json.loads(result["findings"][0]["detail"])
            self.assertIn("crd-conversion", detail["mechanisms"])


if __name__ == "__main__":
    unittest.main()
