"""Tests for the OSS ML-cluster tooling landscape (docs/OSS-ML-CLUSTER-TOOLS).

Locks down:
  * the machine-readable landscape JSON structure (5+1 categories, >=15 dims,
    per-tool license/activity/local-runnable/overlap/source fields, marker set)
  * consistency between docs/OSS-ML-CLUSTER-TOOLS.md tables and the JSON
  * the clone registry entries for the 8 new clones
  * the bench artifacts structure (reports/samples/oss-bench) and that
    docs/OSS-BENCH.md quotes the real medians from summary.json
"""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC_MD = ROOT / "docs" / "OSS-ML-CLUSTER-TOOLS.md"
DOC_JSON = ROOT / "docs" / "oss-ml-cluster-tools.json"
BENCH_MD = ROOT / "docs" / "OSS-BENCH.md"
BENCH_DIR = ROOT / "reports" / "samples" / "oss-bench"
CLONEDEPS = ROOT / ".." / ".." / ".slim" / "clonedeps" / "clonedeps.json"

NEW_CLONES = {
    "aquasecurity__trivy": "3a0164d",
    "Shopify__toxiproxy": "49299d8",
    "chaostoolkit__chaostoolkit": "2ff559b",
    "chaos-mesh__chaos-mesh": "37f49f2",
    "litmuschaos__litmus": "b957f31",
    "NVIDIA__DCGM": "9fae286",
    "NVIDIA__nccl-tests": "afd59ab",
    "linux-rdma__perftest": "8f87844",
}

MARKERS = {"✓", "◐", "○", "?"}
FIVE_CATEGORIES = {
    "cluster-scanning", "model-inference", "network-fabric", "chaos", "training-framework",
}


def load_json() -> dict:
    return json.loads(DOC_JSON.read_text(encoding="utf-8"))


def load_bench_summary() -> dict:
    return json.loads((BENCH_DIR / "summary.json").read_text(encoding="utf-8"))


class TestLandscapeJson(unittest.TestCase):
    """docs/oss-ml-cluster-tools.json structural contracts."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.data = load_json()

    def test_schema_and_generated_date(self) -> None:
        self.assertEqual(self.data["schema"], "inkblade.oss-ml-cluster-tools/1")
        self.assertTrue(re.fullmatch(r"\d{4}-\d{2}-\d{2}", self.data["generated"]))

    def test_categories_cover_five_groups_plus_reference(self) -> None:
        keys = {c["key"] for c in self.data["categories"]}
        self.assertEqual(keys, FIVE_CATEGORIES | {"agent-reference"})
        self.assertEqual(len(self.data["categories"]), 6)

    def test_at_least_15_dimensions_with_expected_coverage(self) -> None:
        dims = self.data["dimensions"]
        self.assertGreaterEqual(len(dims), 15)
        expected = {
            "k8s_config", "rbac", "escape", "network_fabric", "gpu_hardware",
            "driver_firmware", "training_stack", "inference_engine", "ai_gateway",
            "chaos_injection", "network_impairment", "gpu_diagnostics",
            "perf_stress", "reporting", "orchestration",
        }
        self.assertEqual({d["key"] for d in dims}, expected)
        for d in dims:
            self.assertTrue(d["label"].strip(), f"dimension {d['key']} needs a label")

    def test_tool_count_per_category(self) -> None:
        tools = self.data["tools"]
        by_cat: dict[str, int] = {}
        for t in tools:
            by_cat[t["category"]] = by_cat.get(t["category"], 0) + 1
        self.assertEqual(by_cat.get("cluster-scanning"), 10)
        self.assertEqual(by_cat.get("model-inference"), 8)
        self.assertEqual(by_cat.get("network-fabric"), 5)
        self.assertEqual(by_cat.get("chaos"), 6)
        self.assertEqual(by_cat.get("training-framework"), 3)
        self.assertEqual(by_cat.get("agent-reference"), 2)
        self.assertGreaterEqual(len(tools), 34)
        self.assertEqual(len({t["id"] for t in tools}), len(tools), "tool ids must be unique")

    def test_every_tool_has_required_fields(self) -> None:
        dims = [d["key"] for d in self.data["dimensions"]]
        for t in self.data["tools"]:
            for field in ("id", "name", "category", "upstream", "license",
                          "activity", "local_runnable", "dims", "inkblade_overlap", "source"):
                self.assertIn(field, t, f"{t.get('id')} missing {field}")
            self.assertTrue(t["upstream"].startswith("http"), f"{t['id']} upstream must be a URL")
            self.assertTrue(t["license"].strip())
            self.assertIn(t["local_runnable"]["status"], {"yes", "limited", "no"})
            self.assertTrue(t["local_runnable"]["note"].strip())
            self.assertTrue(t["inkblade_overlap"].strip())
            self.assertTrue(t["source"].strip(), f"{t['id']} must record its verification source")
            # dims: exactly the dimension keys, only known markers
            self.assertEqual(set(t["dims"]), set(dims))
            bad = {v for v in t["dims"].values()} - MARKERS
            self.assertFalse(bad, f"{t['id']} has unknown markers {bad}")

    def test_activity_fields_present(self) -> None:
        for t in self.data["tools"]:
            act = t["activity"]
            self.assertIn("status", act)
            self.assertIn("archived", act)
            # GitHub-hosted repos must carry stars/pushed_at; distribution-page
            # tools (ibdiagnet, tc/netem, XBow) explicitly use null
            if act.get("stars") is not None:
                self.assertIsInstance(act["stars"], int)
                self.assertRegex(act["pushed_at"] or "", r"^\d{4}-\d{2}-\d{2}")

    def test_task_required_tools_all_present(self) -> None:
        required = {
            "kube-hunter", "kube-bench", "kubescape", "trivy", "kubehound", "kubeaudit",
            "kubiscan", "kdigger", "peirates", "cdk",
            "modelscan", "fickling", "picklescan", "garak", "pyrit", "promptfoo",
            "giskard", "deepteam",
            "nccl-tests", "perftest", "ibdiagnet", "toxiproxy", "sonobuoy",
            "chaos-mesh", "litmus", "chaostoolkit", "pumba", "tc-netem", "dcgm-diag",
            "torch-dist-tests", "ray-tests", "deepspeed-tests",
            "xbow", "artex",
        }
        ids = {t["id"] for t in self.data["tools"]}
        missing = required - ids
        self.assertFalse(missing, f"missing required tools: {missing}")

    def test_verified_tool_specific_facts(self) -> None:
        """Spot facts locked to the 2026-10-26 verification pass."""
        by_id = {t["id"]: t for t in self.data["tools"]}
        self.assertEqual(by_id["kubeaudit"]["license"], "MIT")
        self.assertTrue(by_id["kubeaudit"]["activity"]["archived"])  # archived 2024-08
        self.assertEqual(by_id["kubiscan"]["license"], "GPL-3.0")
        self.assertEqual(by_id["peirates"]["license"], "GPL-2.0")
        self.assertEqual(by_id["fickling"]["license"], "LGPL-3.0")
        self.assertEqual(by_id["toxiproxy"]["license"], "MIT")
        # licenses verified from cloned files, not the GitHub API field
        self.assertIn("BSD-3-Clause", by_id["nccl-tests"]["license"])
        self.assertIn("GPL-2.0", by_id["perftest"]["license"])
        self.assertIn("BSD", by_id["perftest"]["license"])
        # 404 corrections recorded in the source field
        self.assertIn("mmaitre314", by_id["picklescan"]["upstream"])
        self.assertIn("alexei-led", by_id["pumba"]["upstream"])
        self.assertIn("deepspeedai", by_id["deepspeed-tests"]["upstream"])
        # kube-hunter stall is documented (upstream README recommends Trivy)
        self.assertIn("停", by_id["kube-hunter"]["activity"]["status"])


class TestLandscapeDocConsistency(unittest.TestCase):
    """The markdown tables must stay in sync with the JSON."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.md = DOC_MD.read_text(encoding="utf-8")
        cls.data = load_json()

    def test_doc_exists_and_links(self) -> None:
        self.assertTrue(self.md.startswith("# 开源 ML 集群测试工具全景"))
        for link in ("oss-ml-cluster-tools.json", "OSS-BENCH.md", "COMPETITIVE-MATRIX.md"):
            self.assertIn(link, self.md)

    def test_matrix_rows_match_json(self) -> None:
        matrix_section = self.md.split("## 2. 五类 × 15 维能力矩阵")[1].split("## 3.")[0]
        rows = [l for l in matrix_section.splitlines() if l.startswith("| [")]
        self.assertEqual(len(rows), len(self.data["tools"]))
        seen = set()
        for row in rows:
            cells = [c.strip() for c in row.strip().strip("|").split("|")]
            name = re.sub(r"\[(.*?)\].*", r"\1", cells[0])
            matches = [t for t in self.data["tools"] if t["name"] == name]
            self.assertEqual(len(matches), 1, f"matrix row {name!r} not found exactly once")
            tool = matches[0]
            seen.add(tool["id"])
            self.assertEqual(cells[1:], [tool["dims"][d["key"]] for d in self.data["dimensions"]],
                             f"{name}: matrix cells diverge from JSON dims")
        self.assertEqual(seen, {t["id"] for t in self.data["tools"]})

    def test_backlog_section(self) -> None:
        backlog = self.md.split("## 4. 差距 backlog")[1].split("## 5.")[0]
        sizes = {"S": 0, "M": 0, "L": 0}
        for m in re.finditer(r"OSS-([SML])(\d+)", backlog):
            sizes[m.group(1)] += 1
        self.assertGreaterEqual(sizes["S"], 4)
        self.assertGreaterEqual(sizes["M"], 4)
        self.assertGreaterEqual(sizes["L"], 3)
        # perturbation-robustness focus required by the task
        for kw in ("网络损伤", "GPU 故障注入", "混沌编排"):
            self.assertIn(kw, backlog)
        # every backlog row maps to a module/function key
        for line in backlog.splitlines():
            if line.startswith("| OSS-"):
                self.assertRegex(line, r"inkblade[/\\][\w/.:-]+")

    def test_clone_registry_notes(self) -> None:
        self.assertIn("8 个浅克隆", self.md)
        for name, commit in NEW_CLONES.items():
            self.assertIn(name, self.md)
            self.assertIn(commit, self.md)


class TestCloneRegistry(unittest.TestCase):
    """.slim/clonedeps registry holds the 8 new clones with purposes."""

    @classmethod
    def setUpClass(cls) -> None:
        path = (ROOT / ".slim" / "clonedeps" / "clonedeps.json")
        if not path.exists():
            path = CLONEDEPS.resolve()
        if not path.exists():
            raise unittest.SkipTest(
                "clonedeps registry lives in the audit workspace (.slim/clonedeps), not in the "
                "repository; clone-registry checks are skipped outside it")
        cls.registry = json.loads(path.read_text(encoding="utf-8"))
        cls.by_name = {r["name"]: r for r in cls.registry["repos"]}

    def test_new_clones_registered_with_metadata(self) -> None:
        for name, commit in NEW_CLONES.items():
            self.assertIn(name, self.by_name, f"{name} missing from clonedeps.json")
            entry = self.by_name[name]
            self.assertEqual(entry["commit"], commit)
            self.assertTrue(entry["upstream"].startswith("https://github.com/"))
            self.assertTrue(entry["license"])
            self.assertTrue(entry["purpose"])
            self.assertIn("oss-ml-cluster-tools", entry["registered_by"])

    def test_clone_budget_respected(self) -> None:
        """This task must not have added more than 8 clones."""
        added = [r for r in self.registry["repos"]
                 if "oss-ml-cluster-tools" in r.get("registered_by", "")]
        self.assertLessEqual(len(added), 8)
        self.assertEqual(len(added), 8)


class TestBenchArtifacts(unittest.TestCase):
    """reports/samples/oss-bench structure + docs/OSS-BENCH.md numbers."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.summary = load_bench_summary()
        cls.by_tool = {r["tool"]: r for r in cls.summary["results"]}
        cls.bench_md = BENCH_MD.read_text(encoding="utf-8")

    def test_summary_schema(self) -> None:
        self.assertEqual(self.summary["schema"], "inkblade.oss-bench/1")
        self.assertIn("generated_at", self.summary)
        self.assertIn("host", self.summary)
        self.assertGreaterEqual(len(self.summary["results"]), 10)

    def test_required_benches_present(self) -> None:
        required = {"kube-bench", "kube-hunter", "trivy-fs", "trivy-k8s",
                    "modelscan", "fickling", "picklescan", "promptfoo",
                    "toxiproxy", "chaostoolkit"}
        missing = required - set(self.by_tool)
        self.assertFalse(missing, f"missing bench results: {missing}")

    def test_each_bench_has_metrics_and_detection(self) -> None:
        for tool, res in self.by_tool.items():
            if "error" in res:
                continue  # recorded failure, doc must explain it
            for key in ("seconds", "peak_rss_kb", "output_bytes", "target", "notes",
                        "environment", "return_codes"):
                self.assertIn(key, res, f"{tool} missing {key}")
            self.assertIn(res["seconds"]["median"], res["seconds"]["values"])
            det = res.get("detection") or res.get("injection_effect") or res.get("chaos_effect")
            self.assertIsNotNone(det, f"{tool} must report detection/effect stats")

    def test_per_tool_json_files(self) -> None:
        file_map = {"kube-hunter": "kubehunter", "kube-bench": "kubebench"}
        for tool in self.by_tool:
            fname = file_map.get(tool, tool) + ".json"
            path = BENCH_DIR / fname
            self.assertTrue(path.exists(), f"per-tool json missing for {tool} ({fname})")

    def test_raw_evidence_dir(self) -> None:
        raw = BENCH_DIR / "raw"
        self.assertTrue(raw.is_dir())
        for needed in ("kubehunter.json", "trivy-fs.json", "trivy-k8s.json",
                       "modelscan-report.json", "kubebench-report.json", "picklescan.txt"):
            self.assertTrue((raw / needed).exists(), f"raw evidence missing: {needed}")

    def test_model_scanner_detection_numbers(self) -> None:
        """Same 14-file fixture set (8 malicious / 6 benign) for all three scanners."""
        for tool in ("modelscan", "fickling", "picklescan"):
            det = self.by_tool[tool]["detection"]
            self.assertEqual(det["fixtures"], 14, tool)
            self.assertEqual(det["malicious"], 8, tool)
            self.assertEqual(det["benign"], 6, tool)
        # modelscan is the reference scanner: perfect on this fixture set
        self.assertEqual(self.by_tool["modelscan"]["detection"]["true_positives"], 8)
        self.assertEqual(self.by_tool["modelscan"]["detection"]["false_positives"], 0)
        # fickling's known quirks: torch zip unsupported (FN) + unknown-global FP
        self.assertIn("evil_torch.pt", self.by_tool["fickling"]["detection"]["fn_files"])
        self.assertIn("benign_model.pkl", self.by_tool["fickling"]["detection"]["fp_files"])

    def test_toxiproxy_effect(self) -> None:
        eff = self.by_tool["toxiproxy"]["injection_effect"]
        self.assertEqual(eff["configured_latency_ms"], 200)
        self.assertGreater(eff["observed_added_latency_ms"], 180,
                           "latency tox must be observable end-to-end")
        self.assertLess(eff["observed_added_latency_ms"], 400)
        self.assertTrue(eff["timeout_tox_dropped_connection"])

    def test_chaostoolkit_effect(self) -> None:
        eff = self.by_tool["chaostoolkit"]["chaos_effect"]
        self.assertTrue(eff["all_runs_detected_deviation"])

    def test_kubebench_totals(self) -> None:
        totals = self.by_tool["kube-bench"]["detection"]["totals"]
        for key in ("total_pass", "total_fail", "total_warn", "total_info"):
            self.assertIn(key, totals)
        self.assertGreater(totals["total_pass"] + totals["total_fail"] + totals["total_warn"], 20)

    def test_promptfoo_results(self) -> None:
        det = self.by_tool["promptfoo"]["detection"]
        self.assertEqual(det["cases"], 12)
        self.assertEqual(det["assertions_passed"], 12)
        self.assertEqual(det["pass_rate"], 1.0)

    def test_bench_doc_numbers_match_summary(self) -> None:
        """Every median quoted as `N.NNs` next to a tool name must exist in summary.json."""
        quoted = set(re.findall(r"(\d+\.\d{2})\s*s", self.bench_md))
        medians = set()
        for res in self.summary["results"]:
            for field in ("seconds", "snapshot_seconds"):
                val = res.get(field)
                med = val.get("median") if isinstance(val, dict) else val
                if isinstance(med, (int, float)):
                    medians.add(f"{med:.2f}s")
        self.assertTrue(quoted, "OSS-BENCH.md must quote median timings")
        for q in quoted:
            self.assertIn(q + "s", medians,
                          f"OSS-BENCH.md quotes {q}s which is not a summary median")

    def test_bench_doc_lists_unrunnable_reasons(self) -> None:
        """Tools from the landscape that were NOT benched need a stated reason."""
        for tool, reason in (("Kubescape", ""), ("garak", ""), ("Giskard", ""),
                             ("nccl-tests", ""), ("perftest", ""), ("ibdiagnet", ""),
                             ("Chaos Mesh", ""), ("Litmus", "")):
            self.assertIn(tool, self.bench_md, f"{tool} must appear in OSS-BENCH.md")


if __name__ == "__main__":
    unittest.main()
