"""Assert the real defense-lab evidence records are complete and non-fabricated.

These tests do not deploy anything. They enforce the contract of the layer-10
lab: 11 module records, real evidence files on disk, detection/bypass
consistency, and explicit N/A reasons for products that were not deployed.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SAMPLES = REPO / "reports" / "samples" / "defense-lab"
EVIDENCE = REPO / "lab" / "defense-lab" / "evidence"

PRODUCTS = {
    "elkeid": "defense-bypass-elkeid",
    "agentsmith": "defense-bypass-agentsmith",
    "veinmind": "defense-bypass-veinmind",
    "falco": "defense-bypass-falco",
    "tetragon": "defense-bypass-tetragon",
    "kubearmor": "defense-bypass-kubearmor",
    "admission": "defense-bypass-admission",
    "imagescan": "defense-bypass-imagescan",
    "hostagent": "defense-bypass-hostagent",
    "waf-inference": "defense-bypass-waf-inference",
    "netobserv": "defense-bypass-netobserv",
}
DEPLOYED = {"admission", "falco", "imagescan", "waf-inference"}


def _records() -> dict[str, dict]:
    return {
        p.stem: json.loads(p.read_text(encoding="utf-8"))
        for p in sorted(SAMPLES.glob("*.json"))
    }


class TestDefenseLabArtifacts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = _records()

    def test_exactly_eleven_products(self):
        self.assertEqual(set(self.records), set(PRODUCTS))
        for product, module in PRODUCTS.items():
            self.assertEqual(self.records[product]["module"], module)

    def test_schema_and_environment(self):
        for product, rec in self.records.items():
            with self.subTest(product=product):
                self.assertEqual(rec["schema"], "inkblade-defense-lab/v1")
                self.assertIs(rec["mock"], False)
                self.assertIs(rec["benign_only"], True)
                env = rec["environment"]
                self.assertEqual(env["cluster"], "qemu-k3s")
                self.assertTrue(env["k3s"].startswith("v1.36"))
                self.assertTrue(env["kernel"].startswith("6.18"))
                self.assertEqual(env["vm"], "QEMU TCG, 6 vCPU, 6144 MB")

    def test_deployed_split_is_four_and_seven(self):
        deployed = {p for p, r in self.records.items() if r["deployed"]}
        self.assertEqual(deployed, DEPLOYED)
        for product in DEPLOYED:
            self.assertEqual(self.records[product]["state"], "deployed")
            self.assertNotEqual(self.records[product]["product_version"], "not deployed")
        for product in set(PRODUCTS) - DEPLOYED:
            rec = self.records[product]
            self.assertFalse(rec["deployed"])
            self.assertEqual(rec["state"], "n/a")
            self.assertTrue(rec["deployment"]["reason"])
            self.assertTrue(rec["deployment"]["blocking_fact"])
            self.assertEqual(rec["probes"], [])
            self.assertEqual(rec["detected"], [])
            self.assertEqual(rec["bypasses"], [])

    def test_every_evidence_path_exists_and_is_real(self):
        for product, rec in self.records.items():
            self.assertTrue(rec["evidence"], product)
            for rel in rec["evidence"]:
                path = (REPO / rel).resolve()
                with self.subTest(product=product, evidence=rel):
                    self.assertTrue(path.exists(), f"missing evidence {rel}")
                    self.assertTrue(path.is_file())
                    self.assertIn(str(EVIDENCE.resolve()), str(path))
                    self.assertGreater(path.stat().st_size, 0)

    def test_deployed_has_version_workload_and_ground_truth(self):
        for product in DEPLOYED:
            rec = self.records[product]
            with self.subTest(product=product):
                self.assertTrue(rec["product_version"])
                self.assertTrue(rec["deployment"]["method"])
                self.assertTrue(rec["deployment"]["ground_truth"])
                self.assertTrue(rec["probes"])
                self.assertTrue(all(p["evidence"] for p in rec["probes"]))

    def test_detection_requires_a_signal(self):
        for product, rec in self.records.items():
            for p in rec["probes"]:
                with self.subTest(product=product, technique=p["technique"]):
                    # Every probe must carry evidence and a marker label.
                    self.assertTrue(p["benign_marker"])
                    self.assertTrue(p["evidence"])
                    if p["detected"]:
                        self.assertTrue(p.get("product_signal"), "detected without product signal")
                    # blocked implies detected for the products in this lab
                    if p["blocked"]:
                        self.assertTrue(p["detected"])
                    # bypass is only possible when the marker landed and was not seen
                    if p["bypass"]:
                        self.assertTrue(p["marker_landed"])
                        self.assertFalse(p["detected"])
                        self.assertFalse(p["control"])
                    if p["marker_landed"] and not p["detected"] and not p["control"]:
                        self.assertTrue(p["bypass"])

    def test_detected_and_bypass_lists_match_probes(self):
        for product, rec in self.records.items():
            if not rec["deployed"]:
                continue
            with self.subTest(product=product):
                detected = {p["technique"] for p in rec["probes"] if p["detected"]}
                bypasses = {p["technique"] for p in rec["probes"] if p["bypass"]}
                self.assertEqual(set(rec["detected"]), detected)
                self.assertEqual(set(rec["bypasses"]), bypasses)
                self.assertTrue(detected.isdisjoint(bypasses))

    def test_real_lab_totals(self):
        probes = sum(len(r["probes"]) for r in self.records.values())
        detected = sum(1 for r in self.records.values() for p in r["probes"] if p["detected"])
        bypasses = sum(1 for r in self.records.values() for p in r["probes"] if p["bypass"])
        self.assertEqual(probes, 21)
        self.assertEqual(detected, 11)
        self.assertEqual(bypasses, 8)

    def test_no_simulated_language_in_claims(self):
        forbidden = ("simulated", "assumed deployed", "fixture says")
        for product, rec in self.records.items():
            blob = json.dumps(rec, ensure_ascii=False).lower()
            for word in forbidden:
                with self.subTest(product=product, word=word):
                    self.assertNotIn(word, blob)


if __name__ == "__main__":
    unittest.main()
