# -*- coding: utf-8 -*-
"""Weapon readiness: deployment classification, packs and one-click entry."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from inkblade.core import deployment, weaponization  # noqa: E402
from inkblade.core.runner import BackupGateRefused  # noqa: E402
from inkblade.core.weapon_runner import execute, plan  # noqa: E402

EXPLOIT = ROOT / "inkblade" / "core" / "exploit-registry.json"
ZERODAY = ROOT / "inkblade" / "core" / "zeroday-registry.json"
PACKS = ROOT / "inkblade" / "core" / "data" / "weapon-packs.json"
DOC = ROOT / "docs" / "WEAPON-READINESS.md"


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def run_cli(*args: str, home: str | None = None) -> subprocess.CompletedProcess:
    command = [sys.executable, "-m", "inkblade"]
    if home:
        command += ["--home", home]
    command += list(args)
    return subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                          encoding="utf-8", timeout=120)


class DeploymentClassificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = load(EXPLOIT)
        self.entries = self.registry["entries"]

    def test_every_entry_has_a_valid_requirement(self) -> None:
        self.assertEqual(len(self.entries), 152)
        for entry in self.entries:
            self.assertIn(entry.get("deployment_requirement"), deployment.ALLOWED,
                          entry["id"])
            self.assertIn(entry.get("deployment_basis"),
                          {"runtime", "source-line", "advisory"}, entry["id"])

    def test_every_evidence_is_specific(self) -> None:
        for entry in self.entries:
            problems = deployment.validate_evidence(entry.get("deployment_evidence") or "")
            self.assertEqual(problems, [], f"{entry['id']}: {problems}")

    def test_counts_match_the_registry_summary(self) -> None:
        counts = deployment.summarize(self.entries)
        self.assertEqual(self.registry["deployment"]["counts"], counts)
        self.assertEqual(sum(counts.values()), len(self.entries))

    def test_default_exposed_set_is_exactly_the_eleven_reachable_paths(self) -> None:
        ids = {e["id"] for e in self.entries
               if e["deployment_requirement"] == "default-exposed"}
        self.assertEqual(len(ids), 11)
        for expected in (
            "CVE-2026-92972",
            "cephcsi-httpserver-go-pprof-exposed-l37-regex",
            "cephcsi-cephcsi-go-bind-all-l255-regex",
            "kueue-server-go-pprof-exposed-l30-regex",
            "juicefscsi-controller-manager-go-go-bind-all-l71-regex",
            "llamafactory-app-py-bind-all-interfaces-l130-regex",
            "llamafactory-interface-py-bind-all-interfaces-l94-regex",
        ):
            self.assertIn(expected, ids)

    def test_default_exploitable_is_the_verified_subset(self) -> None:
        verified = sorted(e["id"] for e in self.entries
                          if e["deployment_requirement"] == "default-exposed"
                          and e["status"] == "verified")
        self.assertEqual(self.registry["deployment"]["default_exploitable"], verified)
        self.assertGreaterEqual(len(verified), 4)

    def test_full_stack_and_hardware_evidence_is_concrete(self) -> None:
        cases = {
            "CVE-2025-3466": "dify-sandbox",
            "CVE-2026-35029": "Postgres",
            "CVE-2025-59425": "GPU",
            "CVE-2013-4786": "UDP-623",
        }
        by_id = {e["id"]: e for e in self.entries}
        for case_id, anchor in cases.items():
            self.assertIn(anchor, by_id[case_id]["deployment_evidence"], case_id)

    def test_exposure_verified_cohort_is_six_and_never_claims_rce(self) -> None:
        exposure = [e for e in self.entries if e["status"] == "exposure-verified"]
        self.assertEqual(len(exposure), 6)
        self.assertEqual(self.registry["summary"]["total"]["exposure_verified"], 6)
        self.assertEqual(sorted(self.registry["exposure_verified"]),
                         sorted(e["id"] for e in exposure))
        for entry in exposure:
            self.assertTrue(entry["id"].startswith("llamafactory-"))
            case = (ROOT / "lab" / "upstream_verify" / "cases" / "llamafactory"
                    / entry["id"])
            payload = load(case / "evidence" / "exposure.json")
            self.assertEqual(payload["impact"], "exposure")
            self.assertEqual(payload["bind"], "0.0.0.0")
            self.assertTrue(payload["unauthenticated"])
            self.assertIn(payload["http"]["status"], (200, 201))
            result = load(case / "result.json")
            self.assertEqual(result["status"], "exposure-verified")
            self.assertFalse(result["verified"])

    def test_default_exposure_verified_matches_the_cohort(self) -> None:
        ids = sorted(e["id"] for e in self.entries
                     if e["deployment_requirement"] == "default-exposed"
                     and e["status"] == "exposure-verified")
        self.assertEqual(len(ids), 6)
        self.assertEqual(self.registry["deployment"]["default_exposure_verified"], ids)

    def test_reserve_entries_are_classified(self) -> None:
        reserve = [e for e in load(ZERODAY)["entries"]
                   if e.get("state") == "novelty-checked"]
        self.assertEqual(len(reserve), 47)
        for entry in reserve:
            self.assertIn(entry.get("deployment_requirement"), deployment.ALLOWED)
            self.assertEqual(
                deployment.validate_evidence(entry.get("deployment_evidence") or ""), [],
                entry["id"])
        exposed = [e["id"] for e in reserve if e.get("default_exposed")]
        self.assertEqual(sorted(exposed), sorted([
            "cephcsi-httpserver-go-pprof-exposed-l37-regex",
            "dify-shellctl-unauth-rce",
            "djev-open-proxy",
            "msswift-media-local-read",
            "sglang-omni-admin-failopen",
        ]))


class WeaponPackTests(unittest.TestCase):
    def setUp(self) -> None:
        self.document = load(PACKS)
        self.packs = self.document["packs"]

    def test_all_reserve_entries_have_exactly_one_pack(self) -> None:
        reserve = {e["id"] for e in load(ZERODAY)["entries"]
                   if e.get("state") == "novelty-checked"}
        pack_ids = {p["id"] for p in self.packs}
        self.assertEqual(pack_ids, reserve)
        self.assertEqual(self.document["total"], 47)

    def test_structure_is_valid(self) -> None:
        self.assertEqual(weaponization.validate(), [])

    def test_every_pack_has_two_or_more_variants(self) -> None:
        for pack in self.packs:
            variants = pack.get("variants") or []
            self.assertGreaterEqual(len(variants), 2, pack["id"])
            self.assertEqual(len({v["id"] for v in variants}), len(variants), pack["id"])
        self.assertGreaterEqual(sum(len(p["variants"]) for p in self.packs), 47 * 2)

    def test_every_pack_has_a_version_matrix_row(self) -> None:
        matrix = {row["module"]: row for row in load(
            ROOT / "inkblade" / "core" / "data" / "version-matrix.json")["entries"]}
        for pack in self.packs:
            self.assertIn(pack["module"], matrix, pack["id"])
            self.assertGreaterEqual(len(matrix[pack["module"]]["variants"]), 2, pack["id"])

    def test_every_pack_has_a_one_click_entry(self) -> None:
        for pack in self.packs:
            one_click = pack["one_click"]
            self.assertTrue(one_click["dry_run"].startswith("inkblade exploit "))
            self.assertTrue(one_click["real"].startswith("inkblade exploit "))
            self.assertEqual(one_click["marker"], "INKBLADE-<run>")

    def test_dry_run_plan_is_side_effect_free(self) -> None:
        for pack in self.packs:
            result = plan(pack, modules_dir=ROOT / "inkblade" / "modules")
            self.assertEqual(result["id"], pack["id"])
            self.assertEqual(result["marker_template"], "INKBLADE-<run>")
            self.assertGreaterEqual(result["variant_count"], 2)
            self.assertIn("deployment_evidence", result)
            self.assertFalse(Path("exploit-marker.txt").exists())

    def test_default_exposed_reserve_count(self) -> None:
        exposed = [p["id"] for p in self.packs if p["default_exposed"]]
        self.assertEqual(len(exposed), 5)

    def test_registry_entry_resolves_to_a_synthetic_pack(self) -> None:
        pack = weaponization.resolve("CVE-2026-92972")
        self.assertEqual(pack["module"], "sglang-route-poison")
        self.assertGreaterEqual(len(pack["variants"]), 2)
        self.assertEqual(pack["deployment_requirement"], "default-exposed")

    def test_deployment_summary_matches_both_registries(self) -> None:
        summary = load(ROOT / "inkblade" / "core" / "data" / "deployment-summary.json")
        registry = load(EXPLOIT)
        self.assertEqual(summary["exploit_registry"]["total"], len(registry["entries"]))
        self.assertEqual(summary["exploit_registry"]["counts"],
                         registry["deployment"]["counts"])
        self.assertEqual(len(summary["exploit_registry"]["default_exposure_verified"]), 6)
        reserve = [e for e in load(ZERODAY)["entries"]
                   if e.get("state") == "novelty-checked"]
        self.assertEqual(summary["zeroday_reserve"]["total"], len(reserve))
        self.assertEqual(sum(summary["zeroday_reserve"]["counts"].values()), len(reserve))

    def test_module_less_registry_entry_is_refused(self) -> None:
        with self.assertRaises(weaponization.WeaponPackError):
            weaponization.resolve("deepspeed-engine-py-eval-call-l2889-regex")

    def test_unknown_id_is_refused(self) -> None:
        with self.assertRaises(weaponization.WeaponPackError):
            weaponization.resolve("no-such-exploit")

    def test_backup_gate_refuses_write_pack_without_target(self) -> None:
        pack = weaponization.resolve("skyrl-tinker-api")
        with self.assertRaises(BackupGateRefused):
            execute(pack, None, None, {"target": "http://127.0.0.1:9"},
                    modules_dir=ROOT / "inkblade" / "modules")


class ReadinessTests(unittest.TestCase):
    def test_readiness_counts(self) -> None:
        data = weaponization.readiness()
        self.assertEqual(data["reserve"]["total"], 47)
        self.assertEqual(data["exploit_registry"]["total"], 152)
        self.assertEqual(data["combined"]["total"], 199)
        self.assertEqual(data["reserve"]["by_requirement"]["default-exposed"], 5)
        self.assertEqual(data["exploit_registry"]["by_requirement"]["default-exposed"], 11)

    def test_document_contains_every_default_exposed_id(self) -> None:
        text = DOC.read_text(encoding="utf-8")
        for entry in load(EXPLOIT)["entries"]:
            if entry["deployment_requirement"] == "default-exposed":
                self.assertIn(entry["id"], text)
        for entry in load(ZERODAY)["entries"]:
            if entry.get("state") == "novelty-checked" and entry.get("default_exposed"):
                self.assertIn(entry["id"], text)

    def test_document_records_the_verified_shortfall(self) -> None:
        text = DOC.read_text(encoding="utf-8")
        self.assertIn("37/152 verified", text)
        self.assertIn(">=50/152", text)

    def test_cli_list_reports_199(self) -> None:
        proc = run_cli("exploit", "--list")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["combined"]["total"], 199)

    def test_cli_dry_run(self) -> None:
        proc = run_cli("exploit", "djev-open-proxy")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["deployment_requirement"], "default-exposed")
        self.assertEqual(payload["marker_template"], "INKBLADE-<run>")
        self.assertGreaterEqual(payload["variant_count"], 2)

    def test_cli_dry_run_for_registry_cve(self) -> None:
        proc = run_cli("exploit", "CVE-2026-92972")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["module"], "sglang-route-poison")
        self.assertEqual(payload["deployment_requirement"], "default-exposed")
        self.assertTrue(payload["backup_required"])

    def test_cli_real_write_pack_returns_91(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc = run_cli("exploit", "skyrl-tinker-api", "--real",
                           "--target", "http://127.0.0.1:9", home=tmp)
        self.assertEqual(proc.returncode, 91, proc.stderr)
        self.assertIn("E301", proc.stderr)


if __name__ == "__main__":
    unittest.main()
