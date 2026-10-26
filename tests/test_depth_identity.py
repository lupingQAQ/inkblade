# -*- coding: utf-8 -*-
"""研究级深度：IRSA/RRSA/PodIdentity/Workload Identity 信任策略绕过矩阵。"""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from trident.depth import identity

ROOT = Path(__file__).resolve().parents[1]
MODULES = ROOT / "trident" / "modules"


class _Run:
    def __init__(self, path: Path):
        self.dir = path
        self.name = "depth-identity"


def load_module(key: str):
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        f"depth_{key.replace('-', '_')}", MODULES / key / "run.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestIdentityFederation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = identity.cases()

    def test_at_least_fifteen_cases(self):
        self.assertGreaterEqual(len(self.cases), 15)
        providers = {c["provider"] for c in self.cases}
        self.assertTrue({"aws-irsa", "aws-rrssa", "gcp-wi", "azure-wi"} <= providers)

    def test_attack_allowed_vulnerable_and_denied_hardened(self):
        for case in self.cases:
            with self.subTest(case=case["id"]):
                vuln = identity.evaluate(case, hardened=False)
                hard = identity.evaluate(case, hardened=True)
                self.assertTrue(vuln["allowed"], vuln)
                self.assertFalse(hard["allowed"], hard)
                legit = identity.evaluate(case, hardened=True, request=case["legit_request"])
                self.assertTrue(legit["allowed"], legit)

    def test_bypass_categories(self):
        categories = identity.bypass_categories()
        for required in ("wildcard-principal", "subject-wildcard", "audience-wildcard",
                         "missing-condition", "oidc-confusion", "source-account-missing"):
            self.assertIn(required, categories)

    def test_federation_module(self):
        with TemporaryDirectory() as td:
            ctx = {"run": _Run(Path(td)), "marker": "TRIDENT-DEPTH"}
            result = load_module("identity-federation-trust-matrix").run(ctx, {})
            self.assertGreaterEqual(len(result["findings"]), 8)
            detail = json.loads(result["findings"][0]["detail"])
            self.assertGreaterEqual(detail["cases"], 15)
            self.assertGreaterEqual(detail["allowed"], 15)

    def test_oidc_confusion_module(self):
        with TemporaryDirectory() as td:
            ctx = {"run": _Run(Path(td)), "marker": "TRIDENT-DEPTH"}
            result = load_module("oidc-issuer-confusion").run(ctx, {})
            self.assertGreaterEqual(len(result["findings"]), 3)
            detail = json.loads(result["findings"][0]["detail"])
            self.assertIn("issuer", detail["categories"])


if __name__ == "__main__":
    unittest.main()
