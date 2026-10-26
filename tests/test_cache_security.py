"""tests/test_cache_security.py — 缓存链/规则/文档契约 + 4 项实效 artifact。

覆盖：
- 2 条链在册，requires/steps 引用 7 模块族，preconditions 以 high finding 为前提；
- 规则包生成后两条链各 ≥1 条规则（sigma/falco/suricata），紫队重放无漏过；
- docs/CACHE-SECURITY.md 缓存类型×威胁×模块×证据矩阵覆盖 7 模块与 5 个公开实现
  （vLLM prefix caching / SGLang radix / GPTCache / Mooncake / LMCache）；
- reports/samples/cache-security/effects.json 4/4 PASS，与 lab.cache_effects 可复现；
- fixed 姿态下 4 项实效均不成立（差异断言）。
"""
import importlib.util
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from lab.cache_effects import run_effects
from trident.core.chains import load_chains
from trident.rules.generate import generate_all
from trident.rules.validate import validate

REPO = Path(__file__).resolve().parents[1]
CHAINS_DIR = REPO / "trident" / "chains"
DOC = REPO / "docs" / "CACHE-SECURITY.md"
EFFECTS = REPO / "reports" / "samples" / "cache-security" / "effects.json"

CHAIN_IDS = ["approx-cache-cross-tenant-chain", "cache-sidechannel-chain"]
CACHE_MODULES = [
    "cache-salt-policy-audit", "similarity-cache-false-hit",
    "cache-timing-sidechannel", "cache-eviction-residue",
    "remote-kv-pool-isolation", "router-cache-metrics-leak",
    "cache-poison-persistence",
]
PUBLIC_SYSTEMS = ["vLLM", "SGLang", "GPTCache", "Mooncake", "LMCache"]


class ChainCatalogTest(unittest.TestCase):
    def test_two_chains_registered_with_cache_modules(self):
        chains = load_chains(CHAINS_DIR)
        for cid in CHAIN_IDS:
            self.assertIn(cid, chains)
            chain = chains[cid]
            mods = {step["module"] for step in chain["steps"]}
            mods |= set(chain.get("requires", []))
            self.assertTrue(mods <= set(CACHE_MODULES), f"{cid} 引用未知模块: {mods}")
            self.assertGreaterEqual(len(chain["steps"]), 2, cid)
            self.assertTrue(chain.get("preconditions"), cid)
            self.assertTrue(chain.get("evidence"), cid)

    def test_approx_chain_order(self):
        chain = load_chains(CHAINS_DIR)["approx-cache-cross-tenant-chain"]
        self.assertEqual([s["module"] for s in chain["steps"]],
                         ["cache-salt-policy-audit", "similarity-cache-false-hit"])
        self.assertEqual(chain["steps"][1]["depends_on"], ["salt-policy"])

    def test_sidechannel_chain_order(self):
        chain = load_chains(CHAINS_DIR)["cache-sidechannel-chain"]
        self.assertEqual([s["module"] for s in chain["steps"]],
                         ["cache-timing-sidechannel", "router-cache-metrics-leak"])
        params = chain["steps"][0]["params"]
        self.assertGreaterEqual(params["per_class"], 25)


class RuleCoverageTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = TemporaryDirectory()
        cls.pack = generate_all(CHAINS_DIR, findings=[], cni="native",
                                out_dir=cls.tmp.name)
        cls.mapping = json.loads(
            (Path(cls.pack.out_dir) / "mapping.json").read_text(encoding="utf-8"))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_each_chain_has_at_least_one_rule(self):
        for cid in CHAIN_IDS:
            self.assertIn(cid, self.mapping["chains"], cid)
            self.assertTrue(self.mapping["chains"][cid]["rules"], cid)

    def test_cache_rules_bind_modules_and_chains(self):
        rules = [r for r in self.mapping["rules"]
                 if any(m in CACHE_MODULES for m in r.get("blocks_modules", []))]
        self.assertGreaterEqual(len(rules), 3)
        for rule in rules:
            self.assertTrue(rule["blocks_chains"], rule["id"])
            self.assertTrue(rule["files"], rule["id"])
        engines = {e for rule in rules for e in rule["engines"]}
        self.assertIn("sigma", engines)
        self.assertIn("suricata", engines)

    def test_purple_replay_has_no_cache_miss(self):
        matrix = validate(self.pack.out_dir)
        for cid in CHAIN_IDS:
            row = matrix["chains"][cid]
            self.assertNotEqual(row["state"], "漏过", cid)
            for cell in row["rules"]:
                self.assertNotEqual(cell["status"], "漏过",
                                    f"{cid}/{cell['rule']}: {cell['evidence']}")
            self.assertTrue(any(c["status"] == "检测" for c in row["rules"]), cid)


class DocumentationTest(unittest.TestCase):
    def test_doc_matrix_covers_modules_and_public_systems(self):
        self.assertTrue(DOC.is_file(), "缺少 docs/CACHE-SECURITY.md")
        text = DOC.read_text(encoding="utf-8")
        for key in CACHE_MODULES + CHAIN_IDS:
            self.assertIn(key, text, key)
        for system in PUBLIC_SYSTEMS:
            self.assertIn(system, text, system)
        for header in ("缓存类型", "威胁", "模块", "证据"):
            self.assertIn(header, text, header)
        self.assertIn("cache_salt", text)
        self.assertIn("radix", text.lower())
        self.assertIn("语义缓存", text)

    def test_committed_effects_are_four_passes(self):
        self.assertTrue(EFFECTS.is_file(), "缺少 cache-security effects.json")
        data = json.loads(EFFECTS.read_text(encoding="utf-8"))
        self.assertEqual(data["summary"], {"total": 4, "passed": 4, "failed": 0})
        ids = {c["id"] for c in data["checks"]}
        self.assertEqual(ids, {
            "approx-cache-false-hit-readback",
            "cache-timing-membership-delta",
            "cache-eviction-residue-readback",
            "remote-kv-pool-namespace-bypass",
        })


class EffectDifferentialTest(unittest.TestCase):
    def test_vulnerable_four_of_four_pass(self):
        result = run_effects("vulnerable")
        self.assertEqual(result["summary"]["passed"], 4)
        evidence = {c["id"]: c["evidence"] for c in result["checks"]}
        self.assertTrue(evidence["approx-cache-false-hit-readback"]["marker_present"])
        self.assertLess(evidence["cache-timing-membership-delta"]["p_value"], 0.05)
        self.assertGreaterEqual(evidence["cache-timing-membership-delta"]["n_total"], 50)
        self.assertEqual(evidence["cache-eviction-residue-readback"]["residue_tenant"],
                         "tenant-b")
        self.assertEqual(evidence["remote-kv-pool-namespace-bypass"]["block_tenant"],
                         "tenant-b")

    def test_fixed_effects_do_not_hold(self):
        result = run_effects("fixed")
        self.assertEqual(result["summary"]["passed"], 0,
                         "fixed 姿态 4 项实效必须全部不成立")
        self.assertEqual(result["summary"]["failed"], 4)


if __name__ == "__main__":
    unittest.main()
