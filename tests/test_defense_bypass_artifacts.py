"""Assert the real defense-bypass path evidence is complete and honest.

The test skips only when the e2e artifact has not been generated yet; once
``result.json`` exists, every claim in it must be backed by a raw log and the
counts must add up.  A technique that landed a marker but produced an alert for
the same family must be labelled ``detected``, never ``bypass-confirmed``.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "reports" / "samples" / "defense-bypass-path"
RESULT = OUT / "result.json"
LOGS = OUT / "logs"
REQUIRED = {"namespace-scope-evasion", "fileless-memfd-exec",
            "existing-binary-exec", "sa-permission-selection"}
RESULTS = {"bypass-confirmed", "detected", "failed", "not-attempted"}


@unittest.skipUnless(RESULT.is_file(), "defense-bypass e2e artifact not generated")
class TestDefenseBypassPathArtifacts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc = json.loads(RESULT.read_text(encoding="utf-8"))
        cls.techniques = {item["id"]: item for item in cls.doc.get("techniques") or []}

    def test_schema_and_environment(self):
        self.assertEqual(self.doc["schema"], "inkblade-defense-bypass-path/v1")
        env = self.doc["environment"]
        self.assertEqual(env["k3s_version"].split("+")[0], "v1.36.5")
        products = {item["product"] for item in
                    (self.doc.get("posture") or {}).get("products") or []}
        self.assertIn("falco", products)
        self.assertIn("admission", products)

    def test_required_techniques_present(self):
        self.assertTrue(REQUIRED.issubset(set(self.techniques)))

    def test_agent_graph_and_gate_wiring(self):
        graph = self.doc["graph"]
        self.assertIn("defense:falco", graph["facts"])
        self.assertFalse(graph["gate_without_bypass"]["allow"])
        self.assertEqual(graph["gate_without_bypass"]["kind"],
                         "DefenseBypassRequired")
        self.assertTrue(graph["gate_with_bypass"]["allow"])
        self.assertTrue(graph["gate_with_bypass"]["technique_id"])

    def test_every_technique_is_complete(self):
        for tid, item in self.techniques.items():
            with self.subTest(technique=tid):
                self.assertTrue(item.get("product"))
                self.assertTrue(item.get("action"))
                self.assertIn(item.get("result"), RESULTS)
                self.assertIsInstance(item.get("alerts"), list)
                self.assertIsInstance(item.get("denials"), list)
                self.assertTrue(item.get("limitations"))

    def test_counts_add_up(self):
        counts = self.doc["counts"]
        self.assertEqual(counts["attempted"], len(self.techniques))
        changed = sum(counts.get(key, 0) for key in RESULTS)
        self.assertEqual(changed, len(self.techniques))

    def test_markers_and_alerts_are_consistent(self):
        for tid, item in self.techniques.items():
            alerts = item.get("alerts") or []
            relevant = [alert for alert in alerts
                        if tid in (alert.get("technique_ids") or [])]
            if item.get("marker_achieved") and relevant:
                with self.subTest(technique=tid):
                    self.assertEqual(item["result"], "detected",
                                     f"{tid} landed a marker but has a matching alert")
            if item.get("result") == "bypass-confirmed":
                with self.subTest(technique=tid):
                    self.assertFalse(relevant, f"{tid} claims bypass but alert is relevant")

    def test_scope_bypass_has_a_denied_control(self):
        item = self.techniques["namespace-scope-evasion"]
        self.assertTrue(item["control"]["denied"])
        self.assertNotEqual(item["control"]["rc"], 0)
        self.assertTrue(item["marker_achieved"])

    def test_raw_logs_exist(self):
        for name in ("phase1-falco.log", "phase1-kyverno.log",
                     "phase2-memfd-falco.log", "kyverno-control-apply.log"):
            with self.subTest(log=name):
                path = LOGS / name
                self.assertTrue(path.is_file())
                self.assertTrue(path.read_text(encoding="utf-8").strip())

    def test_benign_only(self):
        raw = RESULT.read_text(encoding="utf-8")
        for bad in ("msfvenom", "rootkit", "/etc/shadow", "chmod 4755",
                    "shellcode", "nc -e"):
            with self.subTest(pattern=bad):
                self.assertNotIn(bad, raw)
        for item in self.doc["techniques"]:
            marker = str(item.get("marker") or "")
            if marker:
                self.assertTrue(marker.startswith("INKBLADE-BENIGN"))


if __name__ == "__main__":
    unittest.main()
