# -*- coding: utf-8 -*-
"""CVSS 3.1 scoring and the bundled CVE JSON schema validator."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from inkblade.core import cvss
from inkblade.core.cveschema import SchemaError, Validator, validate_cve_record

ROOT = Path(__file__).resolve().parents[1]


def minimal_record() -> dict:
    return {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.1",
        "cveMetadata": {
            "cveId": "CVE-0000-0001",
            "assignerOrgId": "00000000-0000-4000-8000-000000000000",
            "assignerShortName": "INKBLADE-RESERVE",
            "state": "PUBLISHED",
            "serial": 1,
            "dateUpdated": "2026-10-27T00:00:00+00:00",
        },
        "containers": {
            "cna": {
                "providerMetadata": {
                    "orgId": "00000000-0000-4000-8000-000000000000",
                    "shortName": "INKBLADE-RESERVE",
                },
                "title": "demo",
                "descriptions": [{"lang": "en", "value": "demo vulnerability"}],
                "affected": [{
                    "vendor": "demo",
                    "product": "demo",
                    "versions": [{"version": "1.0", "status": "affected"}],
                    "defaultStatus": "unaffected",
                }],
                "problemTypes": [{"descriptions": [
                    {"lang": "en", "cweId": "CWE-306", "description": "CWE-306", "type": "CWE"}]}],
                "metrics": [{"cvssV3_1": {
                    "version": "3.1",
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "baseScore": 9.8,
                    "baseSeverity": "CRITICAL",
                }}],
                "references": [{"url": "https://example.test/advisory"}],
            }
        },
    }


class TestCvss(unittest.TestCase):
    def test_known_scores(self):
        cases = [
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "CRITICAL"),
            ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8, "HIGH"),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.8, "HIGH"),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H", 9.6, "CRITICAL"),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 9.1, "CRITICAL"),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", 8.2, "HIGH"),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "HIGH"),
            ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N", 7.7, "HIGH"),
            ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2, "HIGH"),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "NONE"),
        ]
        for vector, score, level in cases:
            with self.subTest(vector=vector):
                self.assertEqual(cvss.base_score(vector), score)
                self.assertEqual(cvss.severity(score), level)
                cvss.check(vector, score, level)

    def test_rejects_mismatched_score(self):
        with self.assertRaises(ValueError):
            cvss.check("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 7.5)
        with self.assertRaises(ValueError):
            cvss.parse_vector("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P")
        with self.assertRaises(ValueError):
            cvss.parse_vector("CVSS:3.1/AV:N/AC:L")


class TestCveSchema(unittest.TestCase):
    def test_minimal_record_is_valid(self):
        validate_cve_record(minimal_record())

    def test_missing_required_container_field_is_rejected(self):
        record = minimal_record()
        del record["containers"]["cna"]["descriptions"]
        with self.assertRaises(SchemaError):
            validate_cve_record(record)

    def test_bad_cve_id_is_rejected(self):
        record = minimal_record()
        record["cveMetadata"]["cveId"] = "CVE-26-1"
        with self.assertRaises(SchemaError):
            validate_cve_record(record)

    def test_additional_property_is_rejected(self):
        record = minimal_record()
        record["containers"]["cna"]["unexpected"] = True
        with self.assertRaises(SchemaError):
            validate_cve_record(record)

    def test_bad_severity_is_rejected(self):
        record = minimal_record()
        record["containers"]["cna"]["metrics"][0]["cvssV3_1"]["baseSeverity"] = "SEVERE"
        with self.assertRaises(SchemaError):
            validate_cve_record(record)

    def test_last_modified_style_extension_is_allowed(self):
        record = minimal_record()
        record["containers"]["cna"]["x_inkblade"] = {"state": "draft"}
        validate_cve_record(record)

    def test_validator_is_not_a_noop(self):
        validator = Validator()
        self.assertTrue(validator.is_valid(minimal_record()))
        broken = copy.deepcopy(minimal_record())
        broken["containers"]["cna"]["affected"] = []
        self.assertFalse(validator.is_valid(broken))


if __name__ == "__main__":
    unittest.main()
