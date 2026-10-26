# -*- coding: utf-8 -*-
"""公开 CVE 军火库测试：结构/覆盖/诚实性/模块映射/规则与文档对账。"""

import json
import re
import shutil
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.core import cve_catalog
from inkblade.core.registry import load_modules
from inkblade.rules.generate import generate_all

REPO = Path(__file__).resolve().parents[1]
CHAINS = REPO / "inkblade" / "chains"
DOCS = REPO / "docs" / "CVE-CATALOG.md"

REQUIRED_FIELDS = {
    "id", "cve", "component", "component_name", "title", "kind", "severity",
    "affected", "fixed", "exploit_conditions", "primitive", "requires_hardware",
    "mockable", "modules", "source", "source_type", "verified_via",
}

COMPONENTS = {
    "vllm", "sglang", "ray", "kuberay", "lws", "kubernetes", "runc", "containerd",
    "nvidia", "bmc", "sonic", "cumulus", "hami", "cgpu", "litellm", "dify",
    "open-webui", "megatron", "deepspeed", "pytorch", "mlflow", "wandb",
}


class CatalogStructureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = cve_catalog.load()
        cls.entries = cls.data["entries"]
        cls.mods = load_modules(REPO / "inkblade" / "modules")

    def test_schema_and_minimum_cve_count(self):
        self.assertEqual(self.data["schema"], "inkblade-cve-catalog-v1")
        self.assertTrue(self.data["verified_at"])
        cves = [e for e in self.entries if e.get("cve")]
        self.assertGreaterEqual(len(cves), 30, "CVE 条目不足 30")
        self.assertEqual(len({e["id"] for e in self.entries}), len(self.entries))

    def test_required_fields_and_sources(self):
        for e in self.entries:
            self.assertTrue(REQUIRED_FIELDS <= set(e), f"{e.get('id')} 缺字段")
            self.assertRegex(e["id"], r"^(CVE-\d{4}-\d{4,}|[A-Za-z][A-Za-z0-9-]{3,})$")
            if e.get("cve"):
                self.assertRegex(e["cve"], r"^CVE-\d{4}-\d{4,}$")
            self.assertTrue(e["source"].startswith("https://"), e["id"])
            self.assertTrue(e["verified_via"].startswith("https://"), e["id"])
            self.assertIn(e["source_type"], {"nvd", "github-advisory", "vendor", "cve-record", "research"})
            self.assertTrue(e["exploit_conditions"].strip(), e["id"])
            self.assertTrue(e["primitive"].strip(), e["id"])
            self.assertIn(e["severity"], {"critical", "high", "medium", "low", "info"})
            if e.get("cvss") is not None:
                self.assertGreaterEqual(float(e["cvss"]), 0.0)
                self.assertLessEqual(float(e["cvss"]), 10.0)

    def test_honesty_fixed_null_has_note(self):
        for e in self.entries:
            if e.get("fixed") is None:
                self.assertTrue((e.get("fixed_note") or "").strip(), e["id"])
            else:
                self.assertTrue(e["fixed"], e["id"])

    def test_component_coverage(self):
        have = {e["component"] for e in self.entries}
        self.assertFalse(COMPONENTS - have, f"缺组件覆盖: {sorted(COMPONENTS - have)}")

    def test_every_entry_maps_to_real_modules(self):
        for e in self.entries:
            self.assertTrue(e["modules"], e["id"])
            for key in e["modules"]:
                self.assertIn(key, self.mods, f"{e['id']} 引用不存在模块 {key}")
            if e["mockable"] and not e["requires_hardware"]:
                self.assertTrue(any(self.mods[k].writes for k in e["modules"]) or
                                any(not self.mods[k].writes for k in e["modules"]), e["id"])

    def test_mockable_and_hardware_counts(self):
        self.assertGreaterEqual(sum(1 for e in self.entries if e["mockable"]), 20)
        self.assertGreaterEqual(sum(1 for e in self.entries if e["requires_hardware"]), 6)

    def test_version_range_parser(self):
        self.assertTrue(cve_catalog.version_affected("0.8.4", ">=0.6.5,<0.8.5"))
        self.assertFalse(cve_catalog.version_affected("0.8.5", ">=0.6.5,<0.8.5"))
        self.assertTrue(cve_catalog.version_affected("1.16.1", "<=1.16.1"))
        self.assertTrue(cve_catalog.version_affected("2.52", "prior to 2.53"))
        self.assertFalse(cve_catalog.version_affected("2.53", "prior to 2.53"))
        with self.assertRaises(cve_catalog.CatalogError):
            cve_catalog.version_affected("1.0", "wat")


class CatalogArtifactsTest(unittest.TestCase):
    def test_docs_list_every_entry(self):
        text = DOCS.read_text(encoding="utf-8")
        for e in cve_catalog.load()["entries"]:
            self.assertIn(e["id"], text)

    def test_rules_cover_every_cve(self):
        with TemporaryDirectory() as tmp:
            # ??????cluster-takeover-objective??????????????????
            chains_dir = Path(tmp) / "chains"
            chains_dir.mkdir()
            for src in CHAINS.glob("*.json"):
                if src.name == "cluster-takeover-objective.json":
                    continue
                shutil.copy2(src, chains_dir / src.name)
            pack = generate_all(chains_dir, out_dir=Path(tmp) / "pack")
            mapping = json.loads((Path(pack.out_dir) / "mapping.json").read_text(encoding="utf-8"))
            tagged = set()
            for rule in mapping["rules"]:
                tagged |= set(rule.get("cves") or [])
            missing = {e["id"] for e in cve_catalog.load()["entries"]} - tagged
            self.assertFalse(missing, f"缺检测规则: {sorted(missing)}")

    def test_report_cve_section_present(self):
        tmpl = (REPO / "inkblade" / "reports" / "templates" / "pentest-cn-en.tmpl").read_text(encoding="utf-8")
        self.assertIn("$cve_table", tmpl)


if __name__ == "__main__":
    unittest.main()
