"""tests/test_payload_gap_variants.py — B 缺口 payload 变体（参数面机制复用，≥20 新增）。"""
import unittest
from pathlib import Path

from trident.core import version_matrix as vm
from trident.core.payloads import PayloadError, param_variants
from trident.core.registry import load_modules

ROOT = Path(__file__).resolve().parents[1]

GAP_MODULES = (
    "overprivileged-sa-escalation", "privileged-gpu-pod-escape", "runtime-socket-escape",
    "kuberay-operator-escalation", "vllm-operator-rbac-escalation", "lws-secrets-lateral",
    "metadata-egress", "outbound-ssrf", "long-context-window-exhaustion",
    "context-limit-bypass", "gpu-tenant-residue", "kv-oom-bomb",
    "multi-cloud-imds-credentials", "model-registry-exposure", "vector-db-exposure",
)


class PayloadGapVariantTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mods = load_modules(ROOT / "trident" / "modules")

    def test_kubernetes_product_registered(self):
        self.assertIn("kubernetes", vm.products())
        self.assertIn("K8s", vm.products()["kubernetes"]["note"])

    def test_gap_modules_covered_with_two_plus_variants(self):
        variants_total = 0
        for module in GAP_MODULES:
            self.assertIn(module, self.mods, module)
            entry = vm.entry(module)
            self.assertIsNotNone(entry, module)
            self.assertEqual(entry["surface"], "params", module)
            self.assertGreaterEqual(len(entry["variants"]), 2, module)
            self.assertIsNone(entry["fixed"], module)
            self.assertTrue(entry["fixed_note"].strip(), module)
            variants_total += len(entry["variants"])
        self.assertGreaterEqual(variants_total, 20, "新增变体须 ≥20")
        self.assertEqual(len({vm.entry(m)["module"] for m in GAP_MODULES}), len(GAP_MODULES))

    def test_materialize_param_variants(self):
        base = {"snapshot": "<fixture>", "mode": "probe-only"}
        for module in GAP_MODULES:
            variants = param_variants(module, base)
            self.assertGreaterEqual(len(variants), 2, module)
            for item in variants:
                self.assertTrue(item["variant"])
                self.assertIn("params", item)
                self.assertEqual(item["params"]["snapshot"], "<fixture>")
                self.assertGreater(len(item["params"]), len(base), module)

    def test_matrix_health_after_extension(self):
        data = vm.load()
        self.assertGreaterEqual(len(data["entries"]), 60)
        modules = {e["module"] for e in data["entries"]}
        self.assertEqual(len(modules), len(data["entries"]), "矩阵条目不得重复")
        self.assertEqual(modules - set(self.mods), set(), "矩阵不得引用幽灵模块")
        self.assertGreaterEqual(len(vm.covered_modules() & set(self.mods)), 60)

    def test_wrong_surface_guard(self):
        with self.assertRaises(PayloadError):
            param_variants("vllm-plugin-auth-bypass", {})  # http 面模块不得走参数面


if __name__ == "__main__":
    unittest.main()
