"""tests/test_cis_benchmark.py — CIS Kubernetes 基准全集（fixture 驱动，只读判定）。

覆盖：
- 目录契约：≥150 项，kube-bench cis-1.8 官方 130 项逐条覆盖，控制面/节点/etcd/
  kubelet/调度器分区齐全，人工项保留 manual；
- 判定引擎：flag 解析（= / 空格 / 裸开关）、文件权限八进制比较、缺失证据 → manual；
- 脆弱 fixture：关键项检出（匿名认证/AlwaysAllow/审计缺失/etcd 无证书/kubelet 只读端口…）；
- 合规 fixture：0 fail（合规通过），score=1.0，manual 项不冒充 pass；
- 超出项：GPU Operator / vLLM / SGLang 部署基线独立目录与判定；
- 模块 cis-benchmark-audit 输出 pass/fail/manual 矩阵；
- docs/CIS-PARITY.md 与 kube-bench 官方条目数一致。
"""
import importlib.util
import json
import unittest
from pathlib import Path

from inkblade.core.registry import load_modules
from inkblade.cis.catalog import CATALOG, OFFICIAL_IDS, kube_bench_counts
from inkblade.cis.engine import assess, findings, parse_args, file_mode_ok
from inkblade.cis.ml import ML_CHECKS, assess_ml

ROOT = Path(__file__).resolve().parents[1]
MODULES = ROOT / "inkblade" / "modules"
FIXTURES = ROOT / "lab" / "fixtures" / "cis"
VULN = FIXTURES / "vulnerable-cluster.json"
GOOD = FIXTURES / "compliant-cluster.json"
PARITY_DOC = ROOT / "docs" / "CIS-PARITY.md"


def load_run(key: str):
    spec = importlib.util.spec_from_file_location(f"cis_{key.replace('-', '_')}",
                                                  MODULES / key / "run.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class CatalogContractTest(unittest.TestCase):
    def test_size_and_unique_ids(self):
        self.assertGreaterEqual(len(CATALOG), 150)
        ids = [c["id"] for c in CATALOG]
        self.assertEqual(len(ids), len(set(ids)), "检查项 id 不得重复")

    def test_required_fields(self):
        for check in CATALOG:
            for field in ("id", "section", "component", "title", "level", "kind",
                          "tier", "scored", "source", "remediation"):
                self.assertIn(field, check, f"{check.get('id')} 缺 {field}")
            self.assertIn(check["level"], (1, 2))
            self.assertIn(check["kind"], ("flag", "pair", "file", "owner", "evidence",
                                          "manual", "plugin", "kubelet", "kubelet_pair"))
            self.assertIsInstance(check["scored"], bool)
            self.assertTrue(check["remediation"])

    def test_kube_bench_parity_130(self):
        self.assertEqual(len(OFFICIAL_IDS), 130)
        ids = {c["id"] for c in CATALOG}
        self.assertLessEqual(set(OFFICIAL_IDS), ids, "kube-bench cis-1.8 条目缺失")
        official = [c for c in CATALOG if c["tier"] == "cis-1.8"]
        self.assertEqual(len(official), 130)
        for cid in ("1.1.1", "1.2.1", "1.2.30", "1.3.7", "1.4.2", "2.7",
                    "3.2.2", "4.1.9", "4.2.13", "5.1.13", "5.2.13", "5.7.4"):
            self.assertIn(cid, ids)

    def test_section_and_component_coverage(self):
        sections = {c["section"] for c in CATALOG}
        for sec in ("1.1", "1.2", "1.3", "1.4", "2", "3.1", "3.2",
                    "4.1", "4.2", "4.3", "5.1", "5.2", "5.3", "5.4", "5.5", "5.7"):
            self.assertIn(sec, sections, sec)
        components = {c["component"] for c in CATALOG}
        for comp in ("apiserver", "controller-manager", "scheduler", "etcd",
                     "kubelet", "kube-proxy", "node"):
            self.assertIn(comp, components, comp)

    def test_manual_items_preserved(self):
        manual = [c for c in CATALOG if c["kind"] == "manual"]
        self.assertGreaterEqual(len(manual), 35)
        # CIS 明确标注 Manual 的关键条目必须留在 manual
        ids = {c["id"] for c in manual}
        for cid in ("1.2.21", "3.1.1", "3.2.2", "5.1.1", "5.1.13", "5.2.1",
                    "5.4.2", "5.5.1", "5.7.4"):
            self.assertIn(cid, ids)

    def test_kube_bench_counts_table(self):
        counts = kube_bench_counts()
        self.assertEqual(counts["total"], 130)
        self.assertEqual(counts["1.2"], 30)
        self.assertEqual(counts["5.1"], 13)
        self.assertEqual(counts["5.2"], 13)
        self.assertEqual(sum(v for k, v in counts.items()
                             if k not in ("total", "manual", "scored")), 130)


class EngineUnitTest(unittest.TestCase):
    def test_parse_args_styles(self):
        args = ["kube-apiserver", "--anonymous-auth=false", "--insecure-port", "0",
                "--enable-admission-plugins=NodeRestriction,ServiceAccount", "--v", "2",
                "--profiling"]
        flags = parse_args(args)
        self.assertEqual(flags["anonymous-auth"], "false")
        self.assertEqual(flags["insecure-port"], "0")
        self.assertEqual(flags["v"], "2")
        self.assertEqual(flags["profiling"], "true")
        self.assertIn("NodeRestriction", flags["enable-admission-plugins"])

    def test_file_mode_octal(self):
        self.assertTrue(file_mode_ok("600", "600"))
        self.assertTrue(file_mode_ok("400", "600"))
        self.assertFalse(file_mode_ok("644", "600"))
        self.assertFalse(file_mode_ok("777", "600"))
        self.assertIsNone(file_mode_ok("", "600"))

    def test_check_result_shape(self):
        report = assess({})
        self.assertEqual(report["summary"]["total"], len(CATALOG))
        self.assertEqual(report["summary"]["manual"], len(CATALOG))
        self.assertEqual(report["summary"]["fail"], 0)
        for row in report["checks"]:
            self.assertIn(row["status"], ("pass", "fail", "manual"))
            self.assertIn("expected", row)
            self.assertIn("observed", row)
        for sec, cell in report["matrix"].items():
            self.assertEqual(cell["total"], cell["pass"] + cell["fail"] + cell["manual"], sec)


class VulnerableFixtureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.snapshot = json.loads(VULN.read_text(encoding="utf-8"))
        cls.report = assess(cls.snapshot)
        cls.by_id = {row["id"]: row for row in cls.report["checks"]}

    def test_many_failures_detected(self):
        summary = self.report["summary"]
        self.assertGreaterEqual(summary["fail"], 60, summary)
        self.assertGreaterEqual(summary["pass"], 20)
        self.assertGreaterEqual(summary["manual"], 35)
        self.assertEqual(summary["total"], len(CATALOG))

    def test_control_plane_findings(self):
        for cid in ("1.2.1", "1.2.2", "1.2.3", "1.2.4", "1.2.6", "1.2.7", "1.2.8",
                    "1.2.15", "1.2.16", "1.2.17", "1.2.18", "1.2.22", "1.2.26",
                    "1.3.3", "1.3.6", "1.3.7", "1.4.1", "1.4.2", "2.2", "2.3"):
            self.assertEqual(self.by_id[cid]["status"], "fail", cid)
        self.assertEqual(self.by_id["1.2.21"]["status"], "manual")

    def test_worker_and_etcd_findings(self):
        for cid in ("1.1.1", "1.1.11", "1.1.13", "1.1.21", "2.1", "2.4", "2.6",
                    "4.1.1", "4.1.5", "4.1.9", "4.2.1", "4.2.2", "4.2.4",
                    "4.2.10", "4.2.13", "4.3.1"):
            self.assertEqual(self.by_id[cid]["status"], "fail", cid)

    def test_extension_findings(self):
        for cid in ("DL-1.5.1", "DL-1.1.1.1", "DL-4.1.1.1", "DL-6.1.2",
                    "K3S-1", "K3S-2", "K3S-4"):
            self.assertEqual(self.by_id[cid]["status"], "fail", cid)

    def test_findings_only_fail(self):
        items = findings(self.report)
        self.assertTrue(items)
        self.assertGreaterEqual(len(items), 60)
        for item in items:
            self.assertTrue(item.get("cis_id"))
            self.assertEqual(item.get("status"), "fail")
            self.assertIn(item["sev"], ("critical", "high", "medium", "low"))
            self.assertTrue(item.get("remediation"))


class CompliantFixtureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.snapshot = json.loads(GOOD.read_text(encoding="utf-8"))
        cls.report = assess(cls.snapshot)
        cls.by_id = {row["id"]: row for row in cls.report["checks"]}

    def test_zero_fail_and_score(self):
        summary = self.report["summary"]
        self.assertEqual(summary["fail"], 0,
                         [r["id"] for r in self.report["checks"] if r["status"] == "fail"])
        self.assertGreaterEqual(summary["pass"], 110)
        self.assertGreaterEqual(summary["manual"], 35)
        self.assertEqual(summary["score"], 1.0)
        self.assertEqual(summary["total"], len(CATALOG))

    def test_manual_stays_manual(self):
        for cid in ("1.2.21", "3.1.1", "3.2.2", "5.1.1", "5.2.7", "5.7.4"):
            self.assertEqual(self.by_id[cid]["status"], "manual", cid)

    def test_key_controls_pass(self):
        for cid in ("1.2.1", "1.2.2", "1.2.6", "1.2.15", "1.2.17", "1.3.3",
                    "1.4.2", "2.2", "4.2.1", "4.2.4", "4.3.1",
                    "DL-1.5.1", "K3S-1"):
            self.assertEqual(self.by_id[cid]["status"], "pass", cid)


class MLBaselineTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vuln = assess_ml(json.loads(VULN.read_text(encoding="utf-8")))
        cls.good = assess_ml(json.loads(GOOD.read_text(encoding="utf-8")))

    def test_catalog(self):
        self.assertGreaterEqual(len(ML_CHECKS), 12)
        areas = {c["area"] for c in ML_CHECKS}
        self.assertEqual(areas, {"gpu-operator", "vllm", "sglang", "deployment"})
        ids = [c["id"] for c in ML_CHECKS]
        self.assertEqual(len(ids), len(set(ids)))

    def test_vulnerable_ml_detected(self):
        summary = self.vuln["summary"]
        self.assertGreaterEqual(summary["fail"], 10, summary)
        failed = {r["id"] for r in self.vuln["checks"] if r["status"] == "fail"}
        for mid in ("ML-GPU-01", "ML-GPU-03", "ML-VLLM-01", "ML-VLLM-02",
                    "ML-SGL-01", "ML-NET-01", "ML-SEC-01"):
            self.assertIn(mid, failed)

    def test_compliant_ml_passes(self):
        self.assertEqual(self.good["summary"]["fail"], 0,
                         [r["id"] for r in self.good["checks"] if r["status"] == "fail"])
        self.assertGreaterEqual(self.good["summary"]["pass"], 12)

    def test_absent_ml_is_manual(self):
        report = assess_ml({})
        self.assertEqual(report["summary"]["manual"], len(ML_CHECKS))
        self.assertEqual(report["summary"]["fail"], 0)


class ModuleContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_run("cis-benchmark-audit")
        cls.vuln = cls.mod.run({}, {"snapshot": str(VULN)})
        cls.good = cls.mod.run({}, {"snapshot": str(GOOD)})

    def test_matrix_summary(self):
        summary = json.loads(self.vuln["summary"])
        self.assertEqual(summary["rules_total"], len(CATALOG))
        self.assertEqual(summary["total"], len(CATALOG))
        self.assertGreaterEqual(summary["fail"], 60)
        self.assertIn("matrix", summary)
        self.assertEqual(summary["matrix"]["1.2"]["total"],
                         sum(1 for c in CATALOG if c["section"] == "1.2"))
        self.assertIn("ml", summary)
        self.assertGreaterEqual(summary["ml"]["fail"], 10)

    def test_compliant_summary(self):
        summary = json.loads(self.good["summary"])
        self.assertEqual(summary["fail"], 0)
        self.assertEqual(summary["score"], 1.0)
        self.assertEqual(summary["ml"]["fail"], 0)

    def test_findings_have_ids(self):
        items = self.vuln["findings"]
        self.assertTrue(items)
        for item in items:
            self.assertTrue(item.get("cis_id") or item.get("ml_id"))
            self.assertIn(item["sev"], ("critical", "high", "medium", "low"))

    def test_empty_snapshot_zero_findings(self):
        result = self.mod.run({}, {"snapshot": {}})
        self.assertEqual(result["findings"], [])
        summary = json.loads(result["summary"])
        self.assertEqual(summary["fail"], 0)
        self.assertEqual(summary["manual"], len(CATALOG))

    def test_registry(self):
        meta = load_modules(MODULES)["cis-benchmark-audit"]
        self.assertEqual(meta.series, "侦察")
        self.assertFalse(meta.writes)
        self.assertEqual(meta.min_level, "只读侦察")


class ParityDocTest(unittest.TestCase):
    def test_doc_matches_catalog(self):
        text = PARITY_DOC.read_text(encoding="utf-8")
        self.assertIn("kube-bench", text)
        self.assertIn("130", text)
        self.assertIn(str(len(CATALOG)), text)
        self.assertIn("cis-1.8", text)
        for token in ("GPU Operator", "vLLM", "SGLang", "pass/fail/manual"):
            self.assertIn(token, text)


if __name__ == "__main__":
    unittest.main()
