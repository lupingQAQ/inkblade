"""Structure/consistency tests for the ARTEX-in-VM benchmark artefacts.

These tests do NOT re-run the VM bench (that needs QEMU + a booted guest).
They assert that:

* the shipped scripts and the report exist and are wired together,
* the machine-readable result has the expected shape and internally consistent
  numbers (total RSS == sum of per-container peaks, latencies ordered, ...),
* every headline number in the prose report can be traced back to the JSON,
* when the local raw dump (gitignored) is present, the JSON matches it exactly —
  this is the anti-fabrication guard: re-running the collector on a changed dump
  makes the test fail instead of silently keeping stale numbers.

Run: python -m unittest tests.test_artex_bench_artifacts -v
"""
from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
ART = REPO / "reports" / "samples" / "artex-bench"
JSON_PATH = ART / "artex-bench.json"
MD_PATH = ART / "artex-bench.md"
DOC = REPO / "docs" / "ARTEX-BENCH-RESULT.md"
QEMU = REPO / "lab" / "qemu-k3s"
RAW = QEMU / "out" / "artex-bench-raw.txt"


class ArtefactPresenceTest(unittest.TestCase):
    def test_scripts_exist(self):
        for name in (
            "artex-bench.ps1",
            "artex-bench-setup.sh",
            "artex-bench-run.sh",
            "artex-bench-collect.py",
            "artex-mock-llm.py",
            "start-vm.ps1",
        ):
            with self.subTest(name=name):
                path = QEMU / name
                self.assertTrue(path.is_file(), f"missing {path}")
                self.assertGreater(path.stat().st_size, 500, f"{path} looks empty")

    def test_reports_and_doc_exist(self):
        for path in (JSON_PATH, MD_PATH, DOC):
            with self.subTest(path=path.name):
                self.assertTrue(path.is_file(), f"missing {path}")

    def test_start_vm_is_parameterised(self):
        text = (QEMU / "start-vm.ps1").read_text(encoding="utf-8")
        self.assertIn("[int]$MemoryMB", text)
        self.assertIn("[int]$Smp", text)
        self.assertIn("Alias('Memory')", text)
        self.assertIn("Alias('Cpus')", text)
        self.assertIn("-machine', $Machine", text)
        self.assertIn("$ArtexPort-:8787", text)

    def test_mock_llm_speaks_openai_chat(self):
        text = (QEMU / "artex-mock-llm.py").read_text(encoding="utf-8")
        self.assertIn("/chat/completions", text)
        self.assertIn("/messages", text)
        self.assertIn("text/event-stream", text)
        self.assertIn("tool_calls", text)


class ResultJsonTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(JSON_PATH.read_text(encoding="utf-8"))

    def test_identity(self):
        d = self.data
        self.assertEqual(d["bench"], "artex-in-qemu-vm")
        self.assertEqual(d["subject"]["name"], "ARTEX")
        self.assertEqual(d["subject"]["tag"], "v0.3.23")
        self.assertIn("ruoji6/artex", d["subject"]["image"])
        self.assertIn("AGPL", d["subject"]["license"])
        self.assertRegex(d["generated_utc"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

    def test_environment_records_tcg_and_cpus(self):
        env = self.data["environment"]
        self.assertEqual(env["guest_cpus"], 6)
        self.assertGreaterEqual(env["guest_mem_total_mb"], 5000)
        self.assertIn("tcg", env["vm"].lower())
        self.assertIn("6144", env["vm"])

    def test_cold_start_numbers(self):
        cs = self.data["cold_start"]
        self.assertTrue(cs["postgres_ready"])
        self.assertTrue(cs["artex_health_ok"])
        self.assertEqual(cs["artex_health_http"], 200)
        self.assertGreater(cs["postgres_ready_ms"], 1000)
        # ARTEX cannot be healthy before PostgreSQL finished initialising.
        self.assertGreaterEqual(cs["artex_health_ms"], cs["postgres_ready_ms"])
        self.assertEqual(cs["auth_init_http"], 200)
        self.assertEqual(cs["auth_login_http"], 200)
        self.assertLess(cs["auth_handshake_ms"], 60_000)

    def test_api_latency_is_ordered(self):
        import statistics
        block = self.data["api_latency"]["health"]
        self.assertGreaterEqual(block["n"], 10)
        self.assertEqual(block["n"], len(block["samples_ms"]))
        self.assertTrue(all(isinstance(v, int) and v > 0 for v in block["samples_ms"]))
        self.assertLessEqual(block["min_ms"], block["p50_ms"])
        self.assertLessEqual(block["p50_ms"], block["p95_ms"])
        self.assertLessEqual(block["p95_ms"], block["max_ms"])
        # summary stats must be derivable from the raw sample list
        self.assertEqual(block["min_ms"], min(block["samples_ms"]))
        self.assertEqual(block["max_ms"], max(block["samples_ms"]))
        self.assertAlmostEqual(block["p50_ms"], statistics.median(block["samples_ms"]), delta=0.5)

    def test_rss_totals_match_containers(self):
        res = self.data["resources"]
        per = res["per_container_mib"]
        self.assertIn("artex", per)
        self.assertTrue(any(k.startswith("artex-pg") for k in per), per.keys())
        container_peak_sum = round(sum(v["max"] for v in per.values()), 2)
        self.assertAlmostEqual(res["total_mib"]["max"], container_peak_sum, delta=0.5)
        # 10 samples were requested by the runner; each container must have them.
        for name, series in per.items():
            self.assertEqual(len(series["samples"]), 10, name)

    def test_images_and_disk(self):
        images = " ".join(self.data["resources"]["images"])
        self.assertIn("ruoji6/artex:v0.3.23", images)
        self.assertIn("postgres:16-alpine", images)
        self.assertGreater(self.data["resources"]["docker_root_bytes"], 1_000_000_000)

    def test_task_submission_recorded_honestly(self):
        task = self.data["task_run"]
        self.assertEqual(task["http"], 201)
        self.assertTrue(task["id"])
        self.assertGreater(task["accept_ms"], 0)
        self.assertIn(task["final_status"], {"created", "running", "paused", "done", "failed"})
        # This run did not complete: if it is not terminal, the report must say so
        # and must not pretend the target was scanned.
        if task["final_status"] not in ("done", "failed"):
            self.assertTrue(self.data["limitations"])
            joined = " ".join(self.data["limitations"]).lower()
            self.assertIn("not claimed", joined)
        self.assertIsNotNone(task["llm_calls"])

    def test_limitations_cover_the_known_caveats(self):
        joined = " ".join(self.data["limitations"]).lower()
        for needle in ("tcg", "mock", "rss", "k3s", "pull"):
            self.assertIn(needle, joined, f"limitation text must mention {needle}")


class RawConsistencyTest(unittest.TestCase):
    """If the local run dump is present, JSON must be derived from it (no drift)."""

    def setUp(self):
        if not RAW.is_file():
            self.skipTest("local raw dump not present (gitignored evidence)")
        self.raw = {}
        for line in RAW.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" in line:
                key, _, value = line.partition("=")
                self.raw.setdefault(key, value)
        self.data = json.loads(JSON_PATH.read_text(encoding="utf-8"))

    def test_cold_start_matches_raw(self):
        self.assertEqual(self.data["cold_start"]["artex_health_ms"], int(self.raw["COLD_START_HEALTH_MS"]))
        self.assertEqual(self.data["cold_start"]["postgres_ready_ms"], int(self.raw["PG_READY_MS"]))
        self.assertEqual(self.data["cold_start"]["auth_handshake_ms"], int(self.raw["AUTH_MS"]))

    def test_latency_samples_match_raw(self):
        expected = [int(x) for x in self.raw["HEALTH_MS_LIST"].split(",")]
        self.assertEqual(self.data["api_latency"]["health"]["samples_ms"], expected)

    def test_task_matches_raw(self):
        total_raw = self.raw.get("TASK_TOTAL_MS") or self.raw.get("TASK_MS")
        self.assertEqual(self.data["task_run"]["total_ms"], int(total_raw))
        self.assertEqual(self.data["task_run"]["final_status"], self.raw["TASK_FINAL_STATUS"])

    def test_disk_matches_raw(self):
        self.assertEqual(self.data["resources"]["docker_root_bytes"], int(self.raw["DOCKER_ROOT_BYTES"]))


class ProseMatchesJsonTest(unittest.TestCase):
    """Headline numbers quoted in the doc/markdown must exist in the JSON."""

    def test_markdown_quotes_json_values(self):
        data = json.loads(JSON_PATH.read_text(encoding="utf-8"))
        md = MD_PATH.read_text(encoding="utf-8")
        cs = data["cold_start"]
        self.assertIn(f"{cs['artex_health_ms']}", md)
        rss = data["resources"]["total_mib"]["max"]
        self.assertIn(f"{rss:g}", md)
        if data["task_run"]["final_status"] not in ("done", "failed"):
            self.assertIn("not a completed scan", md)

    def test_doc_quotes_json_values(self):
        data = json.loads(JSON_PATH.read_text(encoding="utf-8"))
        doc = DOC.read_text(encoding="utf-8")
        self.assertIn("QEMU", doc)
        self.assertIn("TCG", doc)
        self.assertIn("ruoji6/artex:v0.3.23", doc)
        # the cold start actually measured in this run must be quoted in the doc
        self.assertIn(f"{data['cold_start']['artex_health_ms']}", doc)
        self.assertIn(f"{data['resources']['total_mib']['max']:.1f}", doc)
        for section in ("## 1. 环境", "## 2. 步骤", "## 3. 原始数据", "## 4. 与 Trident 对照",
                        "## 5. 复现", "## 6. 失败点"):
            self.assertIn(section, doc)

    def test_doc_claims_completed_scan_only_with_same_target_evidence(self):
        """同靶场声明必须与 same-target.json 的证据一致（撤销旧的“未达成”结论后新增的一致性锚）。"""
        doc = DOC.read_text(encoding="utf-8")
        same = ART / "same-target.json"
        self.assertTrue(same.is_file(), "same-target.json must ship with the report")
        data = json.loads(same.read_text(encoding="utf-8"))
        artex = data["artex"]
        if "未达成" in doc or "未跑到靶场" in doc:
            self.fail("the report still claims the same-target scan was not achieved")
        self.assertIn("same-target", doc)
        self.assertGreaterEqual(artex["target_hit_count"], 3)
        self.assertEqual(artex["task_final_status"], "done")


if __name__ == "__main__":
    unittest.main()
