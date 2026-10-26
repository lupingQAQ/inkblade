# -*- coding: utf-8 -*-
"""机器可读导出测试：SARIF 2.1.0 / OCSF 1.x Detection Finding / OpenVEX 风格 JSON。"""

import json
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.core.evidence import EvidenceStore
from inkblade.export import build_ocsf, build_sarif, build_vex, export_run

REPO = Path(__file__).resolve().parents[1]
PY = sys.executable

SAMPLE_FINDINGS = [
    {"step_key": "rbac-escape", "severity": "critical", "title": "vLLM Operator RBAC 越权",
     "detail": "cluster-admin RoleBinding", "evidence_path": "steps/rbac-escape.tar.gz",
     "is_zeroday": False},
    {"step_key": "weight-poison", "severity": "high", "title": "共享卷权重投毒",
     "detail": "checkpoint 可写", "evidence_path": "steps/weight-poison.tar.gz",
     "is_zeroday": True},
    {"step_key": "prompt-injection", "severity": "medium", "title": "间接提示词注入",
     "detail": "网页内容进入 agent 工具链", "evidence_path": "steps/prompt-injection.tar.gz",
     "is_zeroday": False},
]

META = {
    "workspace": "local-lab",
    "run": "run-export",
    "generated_at": "2026-10-25T00:00:00Z",
    "tool_version": "0.1.0",
    "evidence_sha": {
        "steps/rbac-escape.tar.gz": "a" * 64,
        "steps/weight-poison.tar.gz": "b" * 64,
        "steps/prompt-injection.tar.gz": "c" * 64,
    },
}


def _seed(store: EvidenceStore, name: str = "run-export") -> str:
    run = store.create_run(name)
    art = store.root / "art.txt"
    art.write_text("export-evidence", encoding="utf-8")
    for f in SAMPLE_FINDINGS:
        run.add_step(f["step_key"], "cmd", {}, "done", artifacts=[art])
    archives = {r[0]: r[1] for r in run.query("SELECT step_key, archive FROM steps")}
    for f in SAMPLE_FINDINGS:
        f2 = dict(f, evidence_path=archives[f["step_key"]])
        run.add_finding(f2["step_key"], f2["severity"], f2["title"], f2["detail"],
                        evidence_path=f2["evidence_path"], is_zeroday=f2["is_zeroday"])
    run.finalize_run()
    return name


class TestSarif(unittest.TestCase):
    def setUp(self):
        self.doc = build_sarif(SAMPLE_FINDINGS, META)

    def test_top_level(self):
        self.assertEqual(self.doc["version"], "2.1.0")
        self.assertIn("sarif", self.doc["$schema"])
        self.assertEqual(len(self.doc["runs"]), 1)

    def test_driver_and_rules(self):
        run = self.doc["runs"][0]
        driver = run["tool"]["driver"]
        self.assertEqual(driver["name"], "InkBlade")
        self.assertTrue(driver["version"])
        self.assertEqual(len(driver["rules"]), 3)
        ids = [r["id"] for r in driver["rules"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(driver["rules"][0]["defaultConfiguration"]["level"], "error")

    def test_results(self):
        run = self.doc["runs"][0]
        self.assertEqual(len(run["results"]), 3)
        levels = {r["ruleId"]: r["level"] for r in run["results"]}
        self.assertEqual(len(levels), 3)
        for result in run["results"]:
            self.assertTrue(0 <= result["ruleIndex"] < len(run["tool"]["driver"]["rules"]))
            self.assertTrue(result["message"]["text"])
            loc = result["locations"][0]["physicalLocation"]
            self.assertTrue(loc["artifactLocation"]["uri"])
            self.assertEqual(loc["region"]["startLine"], 1)
            self.assertRegex(result["partialFingerprints"]["inkbladeFindingHash/v1"],
                             r"^[0-9a-f]{16}$")

    def test_severity_levels(self):
        by_sev = {r["ruleId"]: r["level"] for r in self.doc["runs"][0]["results"]}
        self.assertIn("error", by_sev.values())
        med = next(r for r in self.doc["runs"][0]["results"]
                   if r["properties"]["severity"] == "medium")
        self.assertEqual(med["level"], "warning")

    def test_properties_carry_evidence_and_zeroday(self):
        results = self.doc["runs"][0]["results"]
        zd = [r for r in results if r["properties"]["is_zeroday"]]
        self.assertEqual(len(zd), 1)
        self.assertRegex(zd[0]["properties"]["evidence_sha256"], r"^[0-9a-f]{64}$")
        self.assertTrue(zd[0]["properties"]["compliance"])


class TestOcsf(unittest.TestCase):
    def setUp(self):
        self.doc = build_ocsf(SAMPLE_FINDINGS, META)
        self.events = self.doc["events"]

    def test_document(self):
        self.assertTrue(self.doc["ocsf_version"].startswith("1."))
        self.assertEqual(self.doc["count"], 3)

    def test_detection_finding_fields(self):
        for ev in self.events:
            self.assertEqual(ev["class_uid"], 2004)
            self.assertEqual(ev["class_name"], "Detection Finding")
            self.assertEqual(ev["category_uid"], 2)
            self.assertEqual(ev["type_uid"], 200401)
            self.assertEqual(ev["activity_id"], 1)
            self.assertEqual(ev["metadata"]["product"]["vendor_name"], "InkBlade")
            self.assertIn("version", ev["metadata"])
            self.assertIsInstance(ev["time"], int)
            self.assertTrue(ev["finding_info"]["uid"])
            self.assertTrue(ev["finding_info"]["title"])
            self.assertTrue(ev["finding_info"]["types"])

    def test_severity_mapping(self):
        sev = {ev["finding_info"]["title"]: ev["severity_id"] for ev in self.events}
        self.assertEqual(sev["vLLM Operator RBAC 越权"], 5)
        self.assertEqual(sev["共享卷权重投毒"], 4)
        self.assertEqual(sev["间接提示词注入"], 3)
        self.assertEqual({ev["severity_id"] for ev in self.events}, {3, 4, 5})

    def test_uids_unique_and_zeroday_marked(self):
        uids = [ev["finding_info"]["uid"] for ev in self.events]
        self.assertEqual(len(uids), len(set(uids)))
        zd = next(ev for ev in self.events if ev["finding_info"]["title"] == "共享卷权重投毒")
        self.assertIn("Zero-Day", zd["finding_info"]["types"])
        self.assertEqual(zd["resources"][0]["name"], "local-lab")


class TestVex(unittest.TestCase):
    def setUp(self):
        self.doc = build_vex(SAMPLE_FINDINGS, META)

    def test_openvex_shape(self):
        self.assertIn("openvex.dev/ns", self.doc["@context"])
        self.assertTrue(self.doc["@id"].startswith("https://inkblade.local/vex/"))
        self.assertTrue(self.doc["author"])
        self.assertEqual(self.doc["version"], 1)
        self.assertRegex(self.doc["timestamp"], r"^\d{4}-\d{2}-\d{2}T.*Z$")
        self.assertEqual(len(self.doc["statements"]), 3)

    def test_statements(self):
        valid = {"not_affected", "affected", "fixed", "under_investigation"}
        for st in self.doc["statements"]:
            self.assertIn(st["status"], valid)
            self.assertTrue(st["vulnerability"]["name"])
            self.assertTrue(st["products"])
            self.assertTrue(st["products"][0]["@id"].startswith("pkg:"))
            self.assertTrue(st["action_statement"])
            self.assertRegex(st["timestamp"], r"^\d{4}-\d{2}-\d{2}T.*Z$")
        status = {st["vulnerability"]["name"]: st["status"] for st in self.doc["statements"]}
        self.assertIn("affected", status.values())
        self.assertIn("under_investigation", status.values())

    def test_deterministic_id(self):
        again = build_vex(SAMPLE_FINDINGS, META)
        self.assertEqual(self.doc["@id"], again["@id"])

    def test_cve_passthrough(self):
        doc = build_vex([dict(SAMPLE_FINDINGS[0], title="CVE-2026-12345 RBAC 越权")], META)
        self.assertEqual(doc["statements"][0]["vulnerability"]["name"], "CVE-2026-12345")
        self.assertIn("CVE-2026-12345", doc["statements"][0]["vulnerability"]["aliases"][0])


class TestExportCli(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = EvidenceStore(self.root, workspace="local-lab")
        _seed(self.store)

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, *args):
        env = dict(os.environ)
        env["PYTHONIOENCODING"] = "utf-8"
        return subprocess.run([PY, "-m", "inkblade", *args], cwd=str(REPO),
                              capture_output=True, timeout=60, env=env)

    def test_export_run_functions(self):
        sarif = export_run(self.store, "run-export", "sarif")
        self.assertEqual(sarif["version"], "2.1.0")
        ocsf = export_run(self.store, "run-export", "ocsf")
        self.assertEqual(ocsf["count"], 3)
        vex = export_run(self.store, "run-export", "vex")
        self.assertEqual(len(vex["statements"]), 3)
        with self.assertRaises(ValueError):
            export_run(self.store, "run-export", "csv")

    def test_cli_three_formats(self):
        for fmt in ("sarif", "ocsf", "vex"):
            out = self.root / f"out.{fmt}.json"
            r = self._run("--home", str(self.root), "export", "--workspace", "local-lab",
                          "--run", "run-export", "--format", fmt, "--out", str(out))
            self.assertEqual(r.returncode, 0, r.stderr.decode("utf-8", "replace"))
            data = json.loads(out.read_text(encoding="utf-8"))
            if fmt == "sarif":
                self.assertEqual(data["version"], "2.1.0")
            elif fmt == "ocsf":
                self.assertEqual(data["count"], 3)
            else:
                self.assertEqual(len(data["statements"]), 3)

    def test_cli_stdout_and_errors(self):
        r = self._run("--home", str(self.root), "export", "--workspace", "local-lab",
                      "--run", "run-export", "--format", "sarif")
        self.assertEqual(r.returncode, 0, r.stderr.decode("utf-8", "replace"))
        self.assertEqual(json.loads(r.stdout.decode("utf-8"))["version"], "2.1.0")

        bad = self._run("--home", str(self.root), "export", "--workspace", "local-lab",
                        "--run", "no-such-run", "--format", "sarif")
        self.assertEqual(bad.returncode, 2)

        bad_fmt = self._run("--home", str(self.root), "export", "--workspace", "local-lab",
                            "--run", "run-export", "--format", "csv")
        self.assertNotEqual(bad_fmt.returncode, 0)

    def test_sarif_uri_matches_manifest(self):
        doc = export_run(self.store, "run-export", "sarif")
        for result in doc["runs"][0]["results"]:
            uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            self.assertTrue((self.store.ws_dir / "run-export" / uri).exists(), uri)
            self.assertRegex(result["properties"]["evidence_sha256"], r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
