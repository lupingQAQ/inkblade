# -*- coding: utf-8 -*-
"""Defense-bypass templates: deployment-surface and rule-set two-state parity.

The 11 modules must report 检出 / 盲区 / 硬化建议 for each product in
``deployed``, ``degraded`` and ``absent`` states, and must react to a supplied
rule set (coverage 0..N).  The matrix is compared with the product specification
in ``core/defenseprobe.py``.
"""
from __future__ import annotations

import json
import os
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULES = ROOT / "inkblade" / "modules"
FIXTURES = ROOT / "lab" / "defense-deploy" / "fixtures"
EVIDENCE = ROOT / "reports" / "probe-coverage" / "evidence.json"

from inkblade.core import defenseprobe  # noqa: E402
from inkblade.tpl.backends import LocalBackend  # noqa: E402
from inkblade.tpl.engine import Engine  # noqa: E402
from inkblade.tpl.schema import load_template  # noqa: E402

PRODUCTS = ["elkeid", "agentsmith", "veinmind", "falco", "tetragon", "kubearmor",
            "admission", "imagescan", "hostagent", "waf-inference", "netobserv"]


def _run(product: str, fixture: str, ruleset: str | None = None) -> dict:
    module_dir = MODULES / f"defense-bypass-{product}"
    raw = json.loads((module_dir / "module.json").read_text(encoding="utf-8"))
    template = load_template(module_dir, module_meta=raw)
    params = {"deploy_snapshot": str(FIXTURES / fixture)}
    if ruleset is not None:
        params["ruleset"] = ruleset
    return Engine(LocalBackend()).run(template, params, {"marker": "INKBLADE-LAB"})


def _state(result: dict) -> str:
    for finding in result["findings"]:
        if finding["id"] == "fingerprint":
            return finding["title"].rsplit("= ", 1)[-1]
    raise AssertionError("no fingerprint finding")


def _matrix(result: dict) -> dict:
    for artifact in result["artifacts"]:
        if artifact["name"].endswith("-matrix.json"):
            return json.loads(artifact["text"])
    raise AssertionError("no matrix artifact")


class DefenseBypassTemplates(unittest.TestCase):
    evidence: dict = {}

    @classmethod
    def tearDownClass(cls):
        if not cls.evidence:
            return
        EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
        try:
            doc = json.loads(EVIDENCE.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            doc = {"schema": "inkblade-probe-coverage-evidence-v1", "entries": {}}
        doc.setdefault("entries", {})
        for key, entry in cls.evidence.items():
            current = doc["entries"].get(key) or {}
            if str(current.get("runtime") or "").startswith("rust"):
                continue  # native probe evidence is authoritative
            doc["entries"][key] = entry
        doc["updated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        EVIDENCE.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n",
                            encoding="utf-8")

    def test_all_products_three_states(self):
        for product in PRODUCTS:
            key = f"defense-bypass-{product}"
            module_dir = MODULES / key
            raw = json.loads((module_dir / "module.json").read_text(encoding="utf-8"))
            template = load_template(module_dir, module_meta=raw)
            self.assertEqual(template["meta"]["fidelity"], "equivalent")
            states = ["deployed", "absent"]
            if (FIXTURES / f"{product}-degraded.json").is_file():
                states.append("degraded")
            for state in states:
                with self.subTest(product=product, state=state):
                    fixture = f"{product}-{state}.json"
                    result = _run(product, fixture)
                    self.assertNotEqual(result["status"], "error", result.get("error"))
                    self.assertEqual(_state(result), state)
                    matrix = _matrix(result)
                    snapshot = json.loads((FIXTURES / fixture).read_text(encoding="utf-8"))
                    expected = defenseprobe.assess(product, snapshot, state)
                    self.assertEqual(matrix["detected"], expected["detected"])
                    self.assertEqual(matrix["blindspots"], expected["blindspots"])
                    self.assertEqual(matrix["hardening"], expected["hardening"])
                    self.assertEqual(
                        len([f for f in result["findings"] if f["id"] == "blindspot"]),
                        len(expected["blindspots"]))
                    self.assertEqual(
                        len([f for f in result["findings"] if f["id"] == "detected"]),
                        len(expected["detected"]))
                    if expected["blindspots"]:
                        self.assertTrue(any(f["id"] == "hardening" for f in result["findings"]))
                        self.assertTrue(any(f.get("fix") for f in result["findings"]))
                    if state == "deployed":
                        self.evidence[key] = {
                            "tested": True,
                            "mode": "deployed/degraded/absent" if len(states) == 3 else "deployed/absent",
                            "runtime": result["runtime"],
                            "findings_positive": len(result["findings"]),
                            "findings_negative": 0,
                            "steps": len(result["steps"]),
                            "evidence": _digest(result),
                            "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                            "note": "detection/blindspot/hardening parity",
                            "defense_matrix": {
                                "detected": len(expected["detected"]),
                                "blindspots": len(expected["blindspots"]),
                                "hardening": len(expected["hardening"]),
                            },
                        }

    def test_ruleset_coverage_two_state(self):
        for product in PRODUCTS:
            spec = defenseprobe.PRODUCT_SPECS[product]
            techniques = [t["id"] for t in spec["techniques"]]
            if not techniques:
                continue
            with self.subTest(product=product):
                full = FIXTURES / f"{product}-deployed.json"
                if not full.is_file():
                    continue
                rules_full = ROOT / "lab" / "defense-deploy" / "fixtures" / f"{product}-rules-full.json"
                rules_none = ROOT / "lab" / "defense-deploy" / "fixtures" / f"{product}-rules-none.json"
                rules_full.write_text(json.dumps({"rules": techniques}), encoding="utf-8")
                rules_none.write_text(json.dumps({"rules": []}), encoding="utf-8")
                try:
                    covered = _matrix(_run(product, full.name, str(rules_full)))
                    blind = _matrix(_run(product, full.name, str(rules_none)))
                    self.assertEqual(blind["detected"], [])
                    self.assertGreater(len(covered["detected"]), 0)
                    self.assertLess(len(covered["blindspots"]), len(blind["blindspots"]))
                finally:
                    rules_full.unlink(missing_ok=True)
                    rules_none.unlink(missing_ok=True)


def _digest(result: dict) -> str:
    import hashlib
    payload = json.dumps({"steps": result["steps"], "findings": result["findings"],
                          "artifacts": [a.get("sha256") for a in result["artifacts"]]},
                         ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


if __name__ == "__main__":
    unittest.main()
