# -*- coding: utf-8 -*-
"""CVE 三件套判定器：版本边界 / and-or-not / 四态 / unknown 不升级 / 证据与矩阵。"""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.assess.inventory import load_inventory, normalize_inventory
from inkblade.core import applicability as a
from inkblade.core.evidence import EvidenceStore
from inkblade.reports.render import render_pentest

REPO = Path(__file__).resolve().parents[1]
FIX = REPO / "tests" / "fixtures" / "assess"
CATALOG = FIX / "catalog-four-states.json"
INVENTORY = FIX / "inventory-four-states.json"


def _inv() -> dict:
    return load_inventory(INVENTORY)


def _catalog(entries: list[dict]) -> dict:
    return {"schema": "inkblade-cve-catalog-v1", "entries": entries}


class TestVersionRanges(unittest.TestCase):
    def test_boundaries_inclusive_exclusive(self):
        cases = [
            ("1.1.11", "<1.1.12", True),
            ("1.1.12", "<1.1.12", False),
            ("1.1.12", "<=1.1.12", True),
            ("1.24.0", ">=1.24.0,<1.25.0", True),
            ("1.24.99", ">=1.24.0,<1.25.0", True),
            ("1.25.0", ">=1.24.0,<1.25.0", False),
            ("1.23.9", ">=1.24.0,<1.25.0", False),
            ("1.0.0", "1.0.0 - 1.2.0", True),
            ("1.2.0", "1.0.0 - 1.2.0", True),
            ("1.2.1", "1.0.0 - 1.2.0", False),
            ("1.30.2", "<=1.30.2", True),
            ("1.30.3", "<=1.30.2", False),
            ("0.8.4", ">=0.6.5,<0.8.5", True),
            ("0.8.5", ">=0.6.5,<0.8.5", False),
            ("1.1.0", ">=1.0.0 <1.2.0", True),
            ("1.2.0", ">=1.0.0 <1.2.0", False),
            ("v1.36.5+k3s1", "<1.37.0", True),
            ("2.3.4-k3s1.36", "<1.4.3", False),
            ("*", "*", True),
        ]
        for observed, spec, expected in cases:
            with self.subTest(observed=observed, spec=spec):
                self.assertEqual(a.version_in_range(observed, spec), expected)

    def test_or_and_wildcard(self):
        self.assertTrue(a.version_in_range("1.2.3", "<1.0.0 || >=1.2.0,<2.0.0"))
        self.assertTrue(a.version_in_range("1.2.9", "1.2.x"))
        self.assertFalse(a.version_in_range("1.3.0", "1.2.x"))
        self.assertTrue(a.version_in_range("1.2.5", "^1.2.0"))
        self.assertFalse(a.version_in_range("2.0.0", "^1.2.0"))

    def test_invalid_range_raises(self):
        with self.assertRaises(a.ApplicabilityError):
            a.version_in_range("1.0.0", "not-a-range")


class TestConditions(unittest.TestCase):
    def test_and_or_not(self):
        self.assertEqual(a.evaluate_condition(
            {"all": [{"condition": "privileged"}, {"condition": "hostpath"}]}, _inv()
        )["status"], "true")
        self.assertEqual(a.evaluate_condition(
            {"any": [{"condition": "host_network"}, {"condition": "privileged"}]}, _inv()
        )["status"], "true")
        self.assertEqual(a.evaluate_condition(
            {"not": {"condition": "privileged"}}, _inv()
        )["status"], "false")
        self.assertEqual(a.evaluate_condition(
            "privileged and hostpath", _inv()
        )["status"], "true")
        self.assertEqual(a.evaluate_condition(
            "privileged and not hostpath", _inv()
        )["status"], "false")

    def test_unknown_condition_does_not_become_true(self):
        inv = _inv()
        inv["probes"] = {}
        inv["cloud"].pop("imds_reachable", None)
        inv["facts"].pop("imds_reachable", None)
        result = a.evaluate_condition({"condition": "imds_reachable"}, inv)
        self.assertEqual(result["status"], "unknown")
        self.assertTrue(result["missing"])
        self.assertIn("cloud.imds_reachable", result["missing"][0]["field"])

    def test_unsupported_condition_is_unknown(self):
        result = a.evaluate_condition({"condition": "a_condition_that_does_not_exist"},
                                      _inv())
        self.assertEqual(result["status"], "unknown")
        self.assertIn("register_condition", result["missing"][0]["why"])


class TestFourStates(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inv = _inv()
        cls.assessment = a.assess_cves(cls.inv, catalog_path=CATALOG)

    def test_fixture_four_states(self):
        summary = self.assessment["summary"]
        self.assertEqual(summary["total"], 7)
        self.assertGreaterEqual(summary["applicable"], 1)
        self.assertGreaterEqual(summary["blocked"], 1)
        self.assertGreaterEqual(summary["not-applicable"], 1)
        self.assertGreaterEqual(summary["unknown"], 1)
        states = {e["cve"]: e["state"] for e in self.assessment["entries"]}
        self.assertEqual(states["CVE-2024-21626"], "applicable")
        self.assertEqual(states["CVE-2020-8558"], "blocked")
        self.assertEqual(states["CVE-2021-25741"], "not-applicable")
        self.assertEqual(states["CVE-2023-48022"], "unknown")

    def test_evidence_has_field_and_source(self):
        entry = next(e for e in self.assessment["entries"]
                     if e["cve"] == "CVE-2024-21626")
        self.assertTrue(entry["evidence"])
        for ev in entry["evidence"]:
            self.assertIn("field", ev)
            self.assertIn("source", ev)
        self.assertTrue(any(ev["field"] == "nodes[0].runc" or
                            "runc" in str(ev["field"]) for ev in entry["evidence"]))

    def test_blocked_lists_missing_condition(self):
        entry = next(e for e in self.assessment["entries"]
                     if e["cve"] == "CVE-2020-8558")
        self.assertEqual(entry["state"], "blocked")
        self.assertTrue(entry["missing"])
        self.assertTrue(any("kubelet" in str(m.get("field")) for m in entry["missing"]))

    def test_unknown_not_upgraded_to_applicable(self):
        entry = next(e for e in self.assessment["entries"]
                     if e["cve"] == "CVE-2023-48022")
        self.assertEqual(entry["state"], "unknown")
        self.assertNotEqual(entry["state"], "applicable")
        self.assertTrue(entry["missing"])
        self.assertIn("unknown", entry["state"])

    def test_explain_is_human_readable(self):
        text = a.explain(self.assessment, "CVE-2020-8558")
        self.assertIn("结论", text)
        self.assertIn("为什么", text)
        self.assertIn("缺什么", text)
        self.assertIn("怎么补采", text)
        self.assertIn("kubelet", text)

    def test_matrix_contains_all_states(self):
        md = a.render_matrix(self.assessment)
        self.assertIn("CVE |", md)
        for state in ("applicable", "blocked", "not-applicable", "unknown"):
            self.assertIn(state, md)
        self.assertIn("CVE-2024-21626", md)
        self.assertIn("CVE-2020-8558", md)


class TestUnknownAndBoundary(unittest.TestCase):
    def test_missing_product_version_is_unknown(self):
        inv = _inv()
        inv["nodes"][0]["runc"] = ""
        inv["nodes"][0]["runc_present"] = False
        cat = _catalog([{
            "id": "CVE-TEST-RUNC", "component": "runc",
            "version_range": "<1.1.12",
            "conditions": {"all": [{"condition": "privileged"}]},
            "modules": ["runc-escape-detect"],
        }])
        result = a.assess_cves(inv, catalog=cat)
        entry = result["entries"][0]
        self.assertEqual(entry["state"], "unknown")
        self.assertTrue(entry["missing"])

    def test_condition_false_blocks(self):
        inv = _inv()
        inv["facts"]["workloads.privileged"] = False
        cat = _catalog([{
            "id": "CVE-TEST-RUNC", "component": "runc",
            "version_range": "<1.1.12",
            "conditions": {"all": [{"condition": "privileged"}]},
            "modules": ["runc-escape-detect"],
        }])
        result = a.assess_cves(inv, catalog=cat)
        entry = result["entries"][0]
        self.assertEqual(entry["state"], "blocked")
        self.assertTrue(entry["missing"])

    def test_condition_unknown_keeps_unknown(self):
        inv = _inv()
        inv["probes"] = {}
        inv["cloud"].pop("imds_reachable", None)
        cat = _catalog([{
            "id": "CVE-TEST-IMDS", "component": "runc",
            "version_range": "<1.1.12",
            "conditions": {"all": [{"condition": "imds_reachable"}]},
            "modules": ["runc-escape-detect"],
        }])
        result = a.assess_cves(inv, catalog=cat)
        entry = result["entries"][0]
        self.assertEqual(entry["state"], "unknown")
        self.assertNotEqual(entry["state"], "applicable")

    def test_version_boundary_entry(self):
        cat = _catalog([{
            "id": "CVE-TEST-BOUNDARY", "component": "runc",
            "version_range": ">=1.0.0,<1.1.12",
            "modules": ["runc-escape-detect"],
        }])
        for runc, expected in (("1.1.11", "applicable"), ("1.1.12", "not-applicable")):
            inv = _inv()
            inv["nodes"][0]["runc"] = runc
            inv["facts"]["workloads.privileged"] = False
            entry = a.assess_cves(inv, catalog=cat)["entries"][0]
            self.assertEqual(entry["state"], expected, runc)


class TestCatalogTolerance(unittest.TestCase):
    def test_root_list_and_affected_mapping(self):
        cat = [{
            "id": "CVE-TEST-1", "component": "runc",
            "affected": {"runc": "<1.1.12"},
            "conditions": "privileged and hostpath",
        }]
        result = a.assess_cves(_inv(), catalog=cat)
        entry = result["entries"][0]
        self.assertEqual(entry["state"], "applicable")

    def test_introduced_fixed_and_list_ranges(self):
        cat = {"cves": [{
            "cve": "CVE-TEST-2", "component": "runc",
            "affected": {"introduced": "1.0.0", "fixed": "1.1.12"},
            "conditions": {"any": [{"condition": "privileged"},
                                    {"condition": "host_network"}]},
        }]}
        entry = a.assess_cves(_inv(), catalog=cat)["entries"][0]
        self.assertEqual(entry["state"], "applicable")
        self.assertEqual(entry["version"]["checks"][0]["range"], ">=1.0.0,<1.1.12")

    def test_textual_condition_unmapped_is_unknown(self):
        cat = _catalog([{
            "id": "CVE-TEST-3", "component": "runc",
            "version_range": "<1.1.12",
            "exploit_conditions": "需要攻击者已经拥有集群管理员权限（无法从清单验证）",
            "modules": ["runc-escape-detect"],
        }])
        entry = a.assess_cves(_inv(), catalog=cat)["entries"][0]
        self.assertEqual(entry["state"], "unknown")

    def test_empty_catalog_does_not_crash(self):
        result = a.assess_cves({}, catalog={"entries": []})
        self.assertEqual(result["summary"]["total"], 0)
        self.assertEqual(result["entries"], [])


class TestModuleGate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.assessment = a.assess_cves(_inv(), catalog_path=CATALOG)

    def test_applicable_module_open(self):
        gate = a.gate_module(self.assessment, "runc-escape-detect")
        self.assertTrue(gate["gated"])
        self.assertTrue(gate["allow"])
        self.assertEqual(gate["state"], "applicable")

    def test_blocked_module_closed_with_missing(self):
        gate = a.gate_module(self.assessment, "kubelet-surface")
        self.assertTrue(gate["gated"])
        self.assertFalse(gate["allow"])
        self.assertEqual(gate["state"], "blocked")
        self.assertTrue(gate["missing"])

    def test_unknown_module_closed(self):
        gate = a.gate_module(self.assessment, "ray-job-marker-rce")
        self.assertTrue(gate["gated"])
        self.assertFalse(gate["allow"])
        self.assertEqual(gate["state"], "unknown")

    def test_unlinked_module_not_gated(self):
        gate = a.gate_module(self.assessment, "network-policy-coverage")
        self.assertFalse(gate["gated"])
        self.assertTrue(gate["allow"])


class TestRealCatalogIfPresent(unittest.TestCase):
    def test_catalog_loads_and_links(self):
        cat = a.load_catalog()
        if not cat["found"]:
            self.skipTest("cve-catalog.json not on disk")
        self.assertGreaterEqual(len(cat["entries"]), 50)
        ids = {e["id"] for e in cat["entries"]}
        self.assertIn("CVE-2024-21626", ids)
        entry = next(e for e in cat["entries"] if e["id"] == "CVE-2024-21626")
        self.assertTrue(entry["versions"])
        self.assertIn("cve-weaponized-surface-takeover", entry["chains"])
        self.assertTrue(entry["rules"])
        result = a.assess_cves({}, cat)
        self.assertEqual(result["summary"]["total"], len(cat["entries"]))
        self.assertEqual(result["summary"]["unknown"], len(cat["entries"]))


class TestChainGating(unittest.TestCase):
    def _module(self, root: Path, key: str) -> None:
        d = root / "modules" / key
        d.mkdir(parents=True, exist_ok=True)
        (d / "module.json").write_text(json.dumps({
            "key": key, "name": {"zh": key, "en": key}, "series": "横向利用",
            "description": "fixture", "min_level": "只读侦察", "writes": False,
            "requires": [],
        }, ensure_ascii=False), encoding="utf-8")
        (d / "template.json").write_text(json.dumps({
            "schema": "inkblade-probe-template-v1", "key": key, "version": "1.0.0",
            "meta": {"name": {"zh": key, "en": key}, "series": "横向利用",
                     "min_level": "只读侦察", "writes": False, "requires": []},
            "steps": [{"id": "noop", "op": "fs", "action": "stat", "path": "/",
                       "save": "noop"}],
            "findings": [],
        }, ensure_ascii=False), encoding="utf-8")

    def test_dry_run_marks_blocked_and_unknown(self):
        from inkblade.core.chains import dry_run

        assessment = a.assess_cves(_inv(), catalog_path=CATALOG)
        chain = {
            "id": "cve-gate", "title": {"zh": "gate", "en": "gate"},
            "category": "横向利用", "preconditions": [],
            "steps": [
                {"id": "runc", "module": "runc-escape-detect"},
                {"id": "kubelet", "module": "kubelet-surface"},
                {"id": "ray", "module": "ray-job-marker-rce"},
            ],
        }
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            for key in ("runc-escape-detect", "kubelet-surface", "ray-job-marker-rce"):
                self._module(root, key)
            plan = dry_run(chain, [], root / "modules", applicability=assessment)
        steps = {s["id"]: s for s in plan["steps"]}
        self.assertEqual(steps["runc"]["status"], "ready")
        self.assertEqual(steps["kubelet"]["status"], "blocked")
        self.assertIn("前置", steps["kubelet"]["blocked_reason"])
        self.assertEqual(steps["ray"]["status"], "blocked")
        self.assertEqual(steps["ray"]["applicability"]["state"], "unknown")
        self.assertTrue(plan["applicability"]["evaluated"])
        self.assertIn("kubelet-surface", plan["applicability"]["blocked_steps"])
        self.assertIn("ray-job-marker-rce", plan["applicability"]["unknown_steps"])

    def test_execute_skips_blocked_step_before_runner(self):
        from inkblade.core.chains import execute
        from inkblade.core.evidence import EvidenceStore
        from inkblade.core.roe import init_roe
        from inkblade.core.users import Session

        assessment = a.assess_cves(_inv(), catalog_path=CATALOG)
        chain = {
            "id": "cve-gate", "title": {"zh": "gate", "en": "gate"},
            "category": "横向利用", "preconditions": [],
            "steps": [
                {"id": "runc", "module": "runc-escape-detect"},
                {"id": "kubelet", "module": "kubelet-surface"},
            ],
        }
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = EvidenceStore(root, workspace="local-lab")
            init_roe(store, fields={"level": "只读侦察",
                                    "namespaces": ["train"],
                                    "cidrs": ["127.0.0.0/8"]})
            self._module(root, "runc-escape-detect")
            self._module(root, "kubelet-surface")
            session = Session(None, "tester", "tester", ["local-lab"], "t")
            result = execute(chain, store, session, root / "modules",
                             findings=[], workers=1, applicability=assessment)
        self.assertEqual(result["steps"]["runc"]["status"], "success")
        self.assertEqual(result["steps"]["kubelet"]["status"], "skipped")
        self.assertIn("CVE 适用性闸门", result["steps"]["kubelet"]["reason"])
        self.assertFalse(result["ok"])
        self.assertEqual(result["applicability"]["blocked_steps"],
                         ["kubelet-surface"])


class TestReportMatrix(unittest.TestCase):
    def test_pentest_report_includes_applicability_matrix(self):
        with TemporaryDirectory() as tmp:
            store = EvidenceStore(Path(tmp), workspace="local-lab")
            run = store.create_run("run-applicability")
            run.finalize_run()
            assessment = a.assess_cves(_inv(), catalog_path=CATALOG)
            md = render_pentest(store, "run-applicability", assessment=assessment)
            self.assertIn("漏洞适用性矩阵", md)
            self.assertIn("CVE-2024-21626", md)
            self.assertIn("CVE-2020-8558", md)
            self.assertTrue("unknown" in md.lower() or "information" in md.lower())


if __name__ == "__main__":
    unittest.main()
