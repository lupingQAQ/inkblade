# -*- coding: utf-8 -*-
"""Disclosure packages must be CVE-ready, schema-valid, redacted and unsent."""

from __future__ import annotations

import json
import re
import unittest
from datetime import datetime
from pathlib import Path

from inkblade.core import cvss
from inkblade.core.cveschema import SchemaError, validate_cve_record

ROOT = Path(__file__).resolve().parents[1]
DISCLOSURE = ROOT / "disclosure"
INDEX = DISCLOSURE / "INDEX.json"
ELIGIBILITY = ROOT / "corpus" / "zeroday" / "disclosure-eligibility.json"
REGISTRY = ROOT / "inkblade" / "core" / "zeroday-registry.json"
INVENTORY = ROOT / "corpus" / "zeroday" / "inventory.json"

ELIGIBLE_FILES = {
    "report-en.md", "cve-request.json", "evidence.sha256",
    "vendor-contact.txt", "timeline.json", "status.json",
}
INTERNAL_PATTERNS = [
    re.compile(r"(?<![A-Za-z0-9])[A-Za-z]:[\\/]"),
    re.compile(r"/home/[A-Za-z0-9_.-]+"),
    re.compile(r"projects/repro-2026-10/"),
    re.compile(r"projects/agent-2026-10/"),
    re.compile(r"lab/upstream_verify/"),
    re.compile(r"lab/zeroday_reserve/"),
    re.compile(re.escape(str(ROOT).replace("\\", "/"))),
]


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


@unittest.skipUnless(INDEX.is_file(), "disclosure packages not built")
class TestDisclosureIndex(unittest.TestCase):
    def setUp(self):
        self.index = load_json(INDEX)
        self.eligibility = load_json(ELIGIBILITY)
        self.registry = load_json(REGISTRY)
        self.rows = {row["id"]: row for row in self.index["rows"]}

    def test_no_send_is_explicit(self):
        self.assertTrue(self.index["no_send"])
        self.assertEqual(self.index["generated_at"], "2026-10-27T00:00:00+00:00")

    def test_counts_match_rows_and_directories(self):
        eligible = [r for r in self.index["rows"] if r["decision"] == "cve"]
        hardening = [r for r in self.index["rows"] if r["decision"] == "hardening"]
        self.assertEqual(self.index["eligible_cve_packages"], len(eligible))
        self.assertEqual(self.index["hardening_only"], len(hardening))
        dirs = {p.name for p in DISCLOSURE.iterdir() if p.is_dir() and p.name != "schema"}
        self.assertEqual(dirs, set(self.rows))
        for row in eligible:
            self.assertEqual(set(p.name for p in (DISCLOSURE / row["id"]).iterdir()),
                             ELIGIBLE_FILES)
        for row in hardening:
            self.assertEqual(set(p.name for p in (DISCLOSURE / row["id"]).iterdir()),
                             {"status.json", "hardening-advice.md"})

    def test_every_reserve_row_is_screened(self):
        covered = set()
        for item in self.eligibility["entries"].values():
            covered.add(item["id"])
            covered.update(item.get("merged_ids") or [])
        self.assertEqual(set(self.registry["summary"]["reserve_ids"]) - covered, set())
        self.assertEqual(covered - set(self.registry["summary"]["reserve_ids"]), set())

    def test_eligibility_decisions_are_well_formed(self):
        keys = set()
        for eid, item in self.eligibility["entries"].items():
            self.assertIn(item["decision"], ("cve", "hardening"))
            self.assertTrue(item["reason"].strip(), eid)
            self.assertTrue(item["cwe"], eid)
            self.assertTrue(item["versions"], eid)
            cvss.check(item["cvss31"]["vector"], item["cvss31"]["score"], item["cvss31"]["severity"])
            if item["eligible"]:
                self.assertTrue(item["cve_key"], eid)
                self.assertNotIn(item["cve_key"], keys, f"duplicate cve_key {item['cve_key']}")
                keys.add(item["cve_key"])
                self.assertEqual(item["decision"], "cve")
            else:
                self.assertIsNone(item["cve_key"], eid)
                self.assertEqual(item["decision"], "hardening")


class TestDisclosurePackages(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not INDEX.is_file():
            raise unittest.SkipTest("disclosure packages not built")
        cls.index = load_json(INDEX)
        cls.eligible = [r for r in cls.index["rows"] if r["decision"] == "cve"]
        cls.hardening = [r for r in cls.index["rows"] if r["decision"] == "hardening"]

    def test_cve_records_validate_against_bundled_official_schema(self):
        for row in self.eligible:
            record = load_json(DISCLOSURE / row["id"] / "cve-request.json")
            validate_cve_record(record)

    def test_validator_rejects_a_broken_record(self):
        record = load_json(DISCLOSURE / self.eligible[0]["id"] / "cve-request.json")
        broken = json.loads(json.dumps(record))
        del broken["containers"]["cna"]["descriptions"]
        with self.assertRaises(SchemaError):
            validate_cve_record(broken)

    def test_placeholders_only_no_real_cve(self):
        for row in self.eligible:
            record = load_json(DISCLOSURE / row["id"] / "cve-request.json")
            cve_id = record["cveMetadata"]["cveId"]
            self.assertRegex(cve_id, r"^CVE-0000-\d{4,}$")
            self.assertIsNone(record["containers"]["cna"]["x_inkblade"]["realCveId"])
            self.assertEqual(record["containers"]["cna"]["x_inkblade"]["state"],
                             "draft-request-not-submitted")
            self.assertNotRegex(json.dumps(record), r"CVE-20\d\d-\d{4,}")

    def test_status_says_not_sent(self):
        for row in self.eligible:
            status = load_json(DISCLOSURE / row["id"] / "status.json")
            self.assertFalse(status["sent"])
            self.assertIsNone(status["sent_at"])
            self.assertFalse(status["vendor_notified"])
            self.assertIsNone(status["cve_id"])
            self.assertEqual(status["cve_state"], "not-requested")
            self.assertEqual(status["state"], "draft-not-sent")
            self.assertEqual(status["legal_review"], "required")
            self.assertTrue(status["redaction"]["internal_paths_removed"])

    def test_timeline_has_90_day_nodes_and_no_actual_send(self):
        for row in self.eligible:
            timeline = load_json(DISCLOSURE / row["id"] / "timeline.json")
            self.assertFalse(timeline["sent"])
            self.assertIsNone(timeline["t0_actual"])
            labels = [m["label"] for m in timeline["milestones"]]
            self.assertEqual(labels, ["T0", "T0+7", "T0+30", "T0+60", "T0+90"])
            times = [datetime.fromisoformat(m["due"]) for m in timeline["milestones"]]
            self.assertEqual(times, sorted(times))
            self.assertEqual((times[-1] - times[0]).days, 90)

    def test_reports_have_required_sections(self):
        for row in self.eligible:
            report = (DISCLOSURE / row["id"] / "report-en.md").read_text(encoding="utf-8")
            for section in ("## 1. Summary", "## 2. Root cause", "## 3. Preconditions",
                            "## 4. Reproduction", "## 5. Impact", "## 6. Fix",
                            "## 7. Disclosure timeline", "## 8. Evidence bundle"):
                self.assertIn(section, report, row["id"])
            self.assertIn("DRAFT — NOT SENT", report)
            self.assertIn("Root cause", report)

    def test_no_internal_paths_or_secrets(self):
        for path in DISCLOSURE.rglob("*"):
            if not path.is_file() or path.suffix not in {".md", ".json", ".txt", ".sha256"}:
                continue
            text = path.read_text(encoding="utf-8")
            for pattern in INTERNAL_PATTERNS:
                self.assertIsNone(pattern.search(text), f"{path}: {pattern.pattern}")
            self.assertNotIn("BEGIN PRIVATE KEY", text)
            self.assertNotIn("Bearer eyJ", text)

    def test_evidence_bundle_has_hashes(self):
        for row in self.eligible:
            lines = [ln for ln in (DISCLOSURE / row["id"] / "evidence.sha256").read_text(
                encoding="utf-8").splitlines() if ln and not ln.startswith("#")]
            self.assertGreaterEqual(len(lines), 1, row["id"])
            for line in lines:
                digest, _, name = line.partition("  ")
                self.assertRegex(digest, r"^[0-9a-f]{64}$")
                self.assertTrue(name)
                self.assertNotIn("/", name)
                self.assertNotIn("\\", name)

    def test_vendor_contact_lists_private_and_cnvd_channels(self):
        for row in self.eligible:
            text = (DISCLOSURE / row["id"] / "vendor-contact.txt").read_text(encoding="utf-8")
            self.assertIn("NOT SENT", text)
            self.assertIn("CNVD", text)
            self.assertIn("CNNVD", text)
            self.assertIn("github.com", text)

    def test_hardening_entries_have_no_cve(self):
        for row in self.hardening:
            self.assertFalse((DISCLOSURE / row["id"] / "cve-request.json").exists())
            advice = (DISCLOSURE / row["id"] / "hardening-advice.md").read_text(encoding="utf-8")
            self.assertIn("not CVE-eligible", advice)
            status = load_json(DISCLOSURE / row["id"] / "status.json")
            self.assertFalse(status["eligible_for_cve"])
            self.assertEqual(status["state"], "hardening-only")

    def test_doc_index_block_matches_generated_counts(self):
        doc = (ROOT / "docs" / "0DAY-DISCLOSURE.md").read_text(encoding="utf-8")
        self.assertIn("<!-- DISCLOSURE-INDEX:START -->", doc)
        self.assertIn(f"CVE-ready packages: **{self.index['eligible_cve_packages']}**", doc)
        self.assertIn(f"hardening-only: **{self.index['hardening_only']}**", doc)


if __name__ == "__main__":
    unittest.main()
