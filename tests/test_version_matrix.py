# -*- coding: utf-8 -*-
"""版本矩阵（武器级弹药 B①）测试：结构/覆盖/诚实性/来源/区间判定。"""

import unittest
from pathlib import Path

from inkblade.core import version_matrix as vm
from inkblade.core.registry import load_modules

REPO = Path(__file__).resolve().parents[1]

# 经典 19 横向基线（test_modules_lateral LATERAL_CASES 同源；并行新模块由其任务自补矩阵）
LATERAL_BASELINE = {
    "vllm-plugin-auth-bypass", "djev-open-proxy", "sglang-admin-failopen",
    "slime-weight-pull-poison", "sglang-omni-profiler-write", "skyrl-dev-pickle-rce",
    "skyrl-tinker-hijack", "trl-serve-dev-mode", "areal-setenv-engine-rce",
    "areal-load-pickle", "areal-awex-nccl-injection", "verl-checkpoint-pickle",
    "verl-hdfs-command-injection", "ray-dashboard-job", "ssrf-imds-credential",
    "trust-remote-code-supply-chain", "lora-adapter-injection", "reward-model-abuse",
    "nccl-collective-join",
}


class TestMatrixStructure(unittest.TestCase):
    def test_load_and_schema(self):
        data = vm.load()
        self.assertEqual(data["schema"], "inkblade-version-matrix-v1")
        self.assertGreaterEqual(len(data["entries"]), 40)

    def test_every_lateral_module_covered(self):
        """横向利用系列子集断言（共享目录原则：并行任务可增量扩展，矩阵用子集而非全等）。

        锁定：矩阵条目全部真实存在 + 经典横向（19）与绕过（11 defense-bypass）+ aigateway 全覆盖。
        """
        mods = load_modules(REPO / "inkblade" / "modules")
        lateral = {k for k, m in mods.items() if m.series == "横向利用"}
        # 矩阵条目必须在注册表内（防拼写/幻觉模块）
        ghosts = vm.covered_modules() - set(mods)
        self.assertFalse(ghosts, f"矩阵引用了不存在的模块: {sorted(ghosts)}")
        # 经典 19 横向 + 11 绕过 + 8 aigateway 必须全覆盖
        must = {k for k in LATERAL_BASELINE if k in lateral}
        must |= {k for k in lateral if k.startswith("defense-bypass-")}
        must |= {k for k in lateral if k.startswith("aigateway-")}
        missing = must - vm.covered_modules()
        self.assertFalse(missing, f"基线横向/绕过模块缺版本矩阵条目: {sorted(missing)}")

    def test_every_entry_has_two_plus_variants(self):
        for e in vm.entries():
            self.assertGreaterEqual(len(e["variants"]), 2, e["module"])
            kinds = {v["kind"] for v in e["variants"]}
            self.assertGreaterEqual(len(kinds), 1, e["module"])

    def test_honesty_fixed_null_has_note(self):
        for e in vm.entries():
            if e["fixed"] is None:
                self.assertTrue(e["fixed_note"].strip(), e["module"])
            else:  # fixed 给出时必须有 source 支撑
                self.assertTrue(any("github.com" in s or "核验" in s for s in e["sources"]), e["module"])

    def test_sources_nonempty_and_audit_refs(self):
        for e in vm.entries():
            self.assertTrue(e["sources"], e["module"])
            self.assertTrue(e["audit_refs"], e["module"])
            self.assertTrue(all(isinstance(s, str) and s for s in e["sources"]))

    def test_products_referenced_exist(self):
        products = vm.products()
        for e in vm.entries():
            self.assertIn(e["product"], products)

    def test_at_least_ten_official_release_notes_verified(self):
        """官方 release notes 抽查 ≥10 条（products.release_notes 非空且带核验日期）。"""
        checked = {k: p for k, p in vm.products().items() if p.get("release_notes")}
        self.assertGreaterEqual(len(checked), 10)
        for name, p in checked.items():
            self.assertTrue(p.get("checked_at"), name)
            self.assertTrue(p.get("latest_tag_checked") is not None or "404" in (p.get("note") or ""),
                            f"{name}: 缺 latest_tag_checked")

    def test_duplicate_module_entries_rejected(self):
        import json as _json
        from tempfile import NamedTemporaryFile

        data = vm.load()
        bad = dict(data)
        bad["entries"] = data["entries"] + [data["entries"][0]]
        with NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as fh:
            _json.dump(bad, fh, ensure_ascii=False)
            path = fh.name
        try:
            with self.assertRaises(ValueError):
                vm.load(path)
        finally:
            Path(path).unlink()


class TestMatchVersion(unittest.TestCase):
    def test_operators(self):
        self.assertTrue(vm.match_version("0.5.22", "<=0.5.22"))
        self.assertTrue(vm.match_version("0.5.21", "<=0.5.22"))
        self.assertFalse(vm.match_version("0.5.23", "<=0.5.22"))
        self.assertTrue(vm.match_version("1.0", "==1.0.0"))  # 位数补齐
        self.assertTrue(vm.match_version("2.51", "<2.52"))
        self.assertFalse(vm.match_version("2.52", "<2.52"))
        self.assertTrue(vm.match_version("2.59.0", ">=2.59"))

    def test_star_and_note(self):
        self.assertTrue(vm.match_version("9.9.9", "*"))
        self.assertTrue(vm.match_version("0.5.1", "<=0.5.22（注释）"))

    def test_invalid_spec_raises(self):
        for spec in ("~1.2", "abc", ">=x", ""):
            with self.assertRaises(vm.MatrixError, msg=spec):
                vm.match_version("1.0", spec)

    def test_affected_lookup(self):
        self.assertTrue(vm.affected("0.5.10", "sglang-admin-failopen"))
        self.assertFalse(vm.affected("0.6.0", "sglang-admin-failopen"))
        self.assertFalse(vm.affected("1.0", "no-such-module"))


class TestVariantsApi(unittest.TestCase):
    def test_variants_for(self):
        vs = vm.variants_for("sglang-admin-failopen")
        self.assertGreaterEqual(len(vs), 2)
        self.assertTrue(all({"id", "kind", "request", "transform"} <= set(v) for v in vs))

    def test_modules_for_product(self):
        self.assertIn("sglang-admin-failopen", vm.modules_for_product("sglang"))
        self.assertIn("ray-dashboard-job", vm.modules_for_product("ray"))


if __name__ == "__main__":
    unittest.main()
