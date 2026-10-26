# -*- coding: utf-8 -*-
import copy
import json
import tempfile
import unittest
from pathlib import Path

from inkblade.core import reserve as R


def entry(eid, *, source="audit-history", status="verified", dynamic=True, verdict=None,
          state=None, component="demo", root=True, evidence=True):
    data = {
        "id": eid,
        "source": source,
        "component": component,
        "product": component,
        "title": f"{eid} title",
        "module": f"mod-{eid}",
        "version": "1.0",
        "root_cause": {"file": "pkg/a.py", "line": 7, "function": "sink"} if root else {},
        "preconditions": ["attacker can reach the sink"],
        "exploit": "crafted input -> sink -> marker",
        "evidence": {"path": "README.md", "mode": "rerun"} if evidence else {},
        "verification": {"status": status, "dynamic": dynamic, "method": "dynamic-function"},
        "reachability": "request -> parser -> sink",
    }
    if verdict:
        data["novelty_result"] = {"verdict": verdict, "reason": "fixture", "providers": {}}
    if state:
        data["state"] = state
    return data


class TestStateMachine(unittest.TestCase):
    def test_legal_chain(self):
        e = entry("a", verdict="confirmed-unpublished")
        self.assertEqual(R.transition("candidate", "verified-exploitable", e), "verified-exploitable")
        self.assertEqual(R.transition("verified-exploitable", "novelty-checked", e), "novelty-checked")
        self.assertEqual(R.transition("novelty-checked", "disclosed", e), "disclosed")
        self.assertEqual(R.transition("disclosed", "public", e), "public")

    def test_illegal_skip_rejected(self):
        with self.assertRaises(R.ReserveError):
            R.transition("candidate", "novelty-checked", entry("a", verdict="confirmed-unpublished"))
        with self.assertRaises(R.ReserveError):
            R.transition("candidate", "public", entry("a", verdict="already-public"))
        with self.assertRaises(R.ReserveError):
            R.transition("verified-exploitable", "disclosed", entry("a", verdict="confirmed-unpublished"))

    def test_backward_rejected(self):
        with self.assertRaises(R.ReserveError):
            R.transition("novelty-checked", "verified-exploitable", entry("a", verdict="confirmed-unpublished"))

    def test_same_state_idempotent(self):
        self.assertEqual(R.transition("candidate", "candidate"), "candidate")

    def test_verified_requires_dynamic(self):
        with self.assertRaises(R.ReserveError):
            R.transition("candidate", "verified-exploitable", entry("a", dynamic=False))

    def test_disclosure_requires_confirmed(self):
        with self.assertRaises(R.ReserveError):
            R.transition("novelty-checked", "disclosed", entry("a", verdict="inconclusive"))

    def test_novelty_checked_public_requires_already_public(self):
        with self.assertRaises(R.ReserveError):
            R.transition("novelty-checked", "public", entry("a", verdict="confirmed-unpublished"))


class TestRegistry(unittest.TestCase):
    def _registry(self, *entries):
        inventory = {"schema": "fixture", "entries": list(entries)}
        return R.build_registry(inventory, {"verdicts": {}})

    def test_reserve_counts_only_verified_confirmed(self):
        reg = self._registry(
            entry("reserve-1", verdict="confirmed-unpublished"),
            entry("public-1", verdict="already-public"),
            entry("inconclusive-1", verdict="inconclusive"),
            entry("static-1", status="static-only", dynamic=False, verdict="confirmed-unpublished"),
            entry("unsupported-1", status="unsupported", dynamic=False, verdict="confirmed-unpublished"),
        )
        s = reg["summary"]
        self.assertEqual(s["reserve"], 1)
        self.assertEqual(s["reserve_ids"], ["reserve-1"])
        self.assertEqual(s["public"], 1)
        self.assertEqual(s["inconclusive"], 1)
        self.assertEqual(s["static"], 1)
        self.assertEqual(s["unsupported"], 1)
        self.assertEqual(s["total"], 5)
        self.assertEqual(len([e for e in reg["entries"] if R.is_reserve(e)]), s["reserve"])

    def test_public_never_reserve_even_if_confirmed_field_present(self):
        e = entry("x", verdict="already-public")
        e["novelty_result"]["verdict"] = "already-public"
        reg = self._registry(e)
        self.assertEqual(reg["summary"]["reserve"], 0)
        self.assertEqual(reg["entries"][0]["state"], "public")

    def test_duplicate_id_rejected(self):
        with self.assertRaises(R.ReserveError):
            self._registry(entry("dup"), entry("dup"))

    def test_verified_without_evidence_rejected(self):
        with self.assertRaises(R.ReserveError):
            self._registry(entry("x", evidence=False))

    def test_verified_without_root_cause_rejected(self):
        with self.assertRaises(R.ReserveError):
            self._registry(entry("x", root=False))

    def test_invalid_verification_status_rejected(self):
        with self.assertRaises(R.ReserveError):
            self._registry(entry("x", status="claimed"))

    def test_derive_state(self):
        self.assertEqual(R.derive_state(entry("a")), "verified-exploitable")
        self.assertEqual(R.derive_state(entry("a", verdict="confirmed-unpublished")), "novelty-checked")
        self.assertEqual(R.derive_state(entry("a", verdict="already-public")), "public")
        self.assertEqual(R.derive_state(entry("a", verdict="inconclusive")), "verified-exploitable")
        self.assertEqual(R.derive_state(entry("a", status="static-only", dynamic=False)), "candidate")

    def test_source_breakdown_and_markdown(self):
        reg = self._registry(
            entry("a", source="omni-jev", verdict="confirmed-unpublished"),
            entry("b", source="mining", verdict="already-public"),
            entry("c", source="new-discovery", verdict="inconclusive"),
        )
        self.assertEqual(reg["summary"]["by_source"]["omni-jev"]["total"], 1)
        self.assertEqual(reg["summary"]["by_source"]["mining"]["public"], 1)
        md = R.render_markdown(reg)
        self.assertIn("审计历史-OMNI/JEV", md)
        self.assertIn("0day Reserve", md)
        self.assertIn("a", md)
        self.assertIn("already-public", md)
        self.assertIn("inconclusive", md)

    def test_build_writes_registry_and_doc(self):
        with tempfile.TemporaryDirectory() as td:
            inv = Path(td) / "inventory.json"
            nov = Path(td) / "novelty.json"
            reg = Path(td) / "registry.json"
            doc = Path(td) / "doc.md"
            inv.write_text(json.dumps({"schema": "fixture", "entries": [entry("a", verdict="confirmed-unpublished")]}),
                           encoding="utf-8")
            nov.write_text(json.dumps({"verdicts": {}}), encoding="utf-8")
            data = R.build(inv, nov, reg, doc)
            self.assertEqual(data["summary"]["reserve"], 1)
            self.assertTrue(reg.is_file())
            self.assertIn("0day Reserve", doc.read_text(encoding="utf-8"))


class TestRealInventory(unittest.TestCase):
    def setUp(self):
        self.inventory_path = R.DEFAULT_INVENTORY
        if not self.inventory_path.is_file():
            self.skipTest("inventory not built")
        self.inventory = json.loads(self.inventory_path.read_text(encoding="utf-8"))
        self.novelty_path = R.DEFAULT_NOVELTY
        self.novelty = json.loads(self.novelty_path.read_text(encoding="utf-8")) if self.novelty_path.is_file() else {"verdicts": {}}

    def test_source_coverage(self):
        entries = self.inventory["entries"]
        counts = {}
        for e in entries:
            counts[e["source"]] = counts.get(e["source"], 0) + 1
        self.assertEqual(counts.get("mining"), 96)
        self.assertGreaterEqual(counts.get("audit-history", 0), 27)
        self.assertGreaterEqual(counts.get("omni-jev", 0), 14)
        self.assertEqual(counts.get("agent-platform"), 6)
        self.assertGreaterEqual(counts.get("new-discovery", 0), 3)
        self.assertGreaterEqual(counts.get("legacy-candidate", 0), 22)
        idx = self.inventory["source_index"]
        self.assertGreaterEqual(len(idx["master"]), 40)
        self.assertGreaterEqual(len(idx["omni"]), 15)
        self.assertEqual(len(idx["agent"]), 6)
        self.assertGreaterEqual(len(idx["latest"]), 30)

    def test_new_discovery_results_are_dynamic_verified(self):
        new = [e for e in self.inventory["entries"] if e["source"] == "new-discovery"]
        self.assertGreaterEqual(len(new), 3)
        for e in new:
            path = R.resolve_path(e["evidence"]["path"])
            self.assertTrue(path.is_file(), f"{e['id']}: missing {path}")
            result = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(result["status"], "verified", e["id"])
            self.assertTrue(result["verified"], e["id"])
            self.assertTrue(result["marker"]["after_has_marker"], e["id"])
            self.assertTrue(result["root_cause"]["file"])
            self.assertTrue(result["root_cause"]["line"])

    def test_registry_counts_are_internally_consistent(self):
        reg = R.build_registry(self.inventory, self.novelty)
        s = reg["summary"]
        reserve = [e for e in reg["entries"] if R.is_reserve(e)]
        self.assertEqual(s["reserve"], len(reserve))
        self.assertEqual(s["reserve"], len(s["reserve_ids"]))
        self.assertEqual(s["reserve"], sum(v["reserve"] for v in s["by_source"].values()))
        self.assertEqual(s["reserve_unique"],
                         len({R.dedupe_key(e) for e in reserve}))
        self.assertLessEqual(s["reserve_unique"], s["reserve"])
        for e in reg["entries"]:
            if e["id"] in s["reserve_ids"]:
                self.assertEqual(e["verification"]["status"], "verified")
                self.assertTrue(e["verification"]["dynamic"])
                self.assertEqual(e["novelty_result"]["verdict"], "confirmed-unpublished")
            if (e.get("novelty_result") or {}).get("verdict") == "already-public":
                self.assertNotIn(e["id"], s["reserve_ids"])

    def test_omni_section_and_states(self):
        reg = R.build_registry(self.inventory, self.novelty)
        omni = [e for e in reg["entries"]
                if e["source"] == "omni-jev" or "omni-jev" in (e.get("source_tags") or [])]
        self.assertGreaterEqual(len(omni), 14)
        ids = {e["id"] for e in omni}
        for required in ("vllm-omni-media-ssrf", "vllm-omni-trust-remote-code",
                         "sglang-omni-admin-failopen", "djev-open-proxy",
                         "siliconlab-credential-exfil", "onejev-media-ssrf",
                         "llm2jev-image-file", "openjev-sglang-unauth", "slime-pull-weights"):
            self.assertIn(required, ids)
        md = R.render_markdown(reg)
        self.assertIn("审计历史-OMNI/JEV", md)
        self.assertIn("vllm-omni-media-ssrf", md)

    def test_sglang_cve_not_reserved_when_result_present(self):
        result_path = R.ROOT / "corpus" / "novelty" / "sglang-legacy-tar-weights-rce.json"
        if not result_path.is_file():
            self.skipTest("sglang novelty result not present")
        result = json.loads(result_path.read_text(encoding="utf-8"))
        verdict = result["verdicts"]["sglang-legacy-tar-weights-rce"]["verdict"]
        self.assertEqual(verdict, "already-public")
        nov = {"verdicts": {"sglang-legacy-tar-weights-rce": result["verdicts"]["sglang-legacy-tar-weights-rce"]}}
        reg = R.build_registry(self.inventory, nov)
        e = next(x for x in reg["entries"] if x["id"] == "sglang-legacy-tar-weights-rce")
        self.assertEqual(e["state"], "public")
        self.assertNotIn(e["id"], reg["summary"]["reserve_ids"])


if __name__ == "__main__":
    unittest.main()
