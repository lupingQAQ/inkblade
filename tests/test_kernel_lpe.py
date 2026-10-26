"""tests/test_kernel_lpe.py — 内核 LPE 检测库（trident/lpe，仅检测不利用）。

覆盖：
- 目录契约：≥40 条，每条含受影响区间/检测前置/来源/修复版本/严重度；
- KubeTrail 16 条 LPE CVE 全部包含（超集断言）；
- 版本命中（含稳定分支边界）与新版不误报；
- 模块 kernel-lpe-audit 契约 + 注册表断言；
- docs/LPE-PARITY.md 关键结论与库一致。
"""
import importlib.util
import json
import unittest
from pathlib import Path

from trident.core.registry import load_modules
from trident.kubetrail.lpe import RULES as KUBETRAIL_RULES
from trident.lpe.catalog import CATALOG
from trident.lpe.engine import assess, version_in_range

ROOT = Path(__file__).resolve().parents[1]
MODULES = ROOT / "trident" / "modules"
FIXTURE = ROOT / "lab" / "fixtures" / "lpe" / "kernels.json"
PARITY_DOC = ROOT / "docs" / "LPE-PARITY.md"


def load_run(key: str):
    spec = importlib.util.spec_from_file_location(f"lpe_{key.replace('-', '_')}",
                                                  MODULES / key / "run.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class CatalogContractTest(unittest.TestCase):
    def test_catalog_size_and_fields(self):
        self.assertGreaterEqual(len(CATALOG), 40)
        ids = set()
        for rule in CATALOG:
            for field in ("cve", "name", "category", "sev", "component",
                          "introduced", "fixed", "requires", "source", "note"):
                self.assertIn(field, rule, f"{rule.get('cve')} 缺 {field}")
            self.assertIn(rule["cve"], rule["source"])
            self.assertTrue(rule["note"])
            self.assertIn(rule["sev"], ("critical", "high", "medium", "low"))
            self.assertIn(rule["component"], ("kernel", "pkexec", "sudo", "polkit",
                                              "runc", "containerd"))
            ids.add(rule["cve"])
        self.assertEqual(len(CATALOG), len(ids), "CVE 不得重复")

    def test_series_coverage(self):
        by_cat = {}
        for rule in CATALOG:
            by_cat.setdefault(rule["category"], []).append(rule["cve"])
        self.assertGreaterEqual(len(by_cat["io_uring"]), 3)
        self.assertGreaterEqual(len(by_cat["nftables"]), 10)
        self.assertGreaterEqual(len(by_cat["overlayfs"]), 4)
        self.assertGreaterEqual(len(by_cat["ebpf"]), 3)
        for must in ("CVE-2022-0847", "CVE-2016-5195"):
            self.assertIn(must, by_cat.get("pipe", []) + by_cat.get("dirty_cow", [])
                          + [c for cs in by_cat.values() for c in cs])

    def test_kubetrail_superset(self):
        ours = {rule["cve"] for rule in CATALOG}
        theirs = {rule["cve"] for rule in KUBETRAIL_RULES}
        self.assertEqual(len(theirs), 16)
        self.assertLessEqual(theirs, ours, f"KubeTrail 16 条须全部包含：{theirs - ours}")

    def test_kernel_rules_are_majority(self):
        kernel = sum(1 for rule in CATALOG if rule["component"] == "kernel")
        self.assertGreaterEqual(kernel, 30)


class RangeLogicTest(unittest.TestCase):
    def test_dirty_pipe_streams(self):
        rule = next(r for r in CATALOG if r["cve"] == "CVE-2022-0847")
        self.assertTrue(version_in_range("5.8.0", rule))
        self.assertTrue(version_in_range("5.15.24", rule))
        self.assertFalse(version_in_range("5.15.25", rule))   # 5.15 流修复边界
        self.assertFalse(version_in_range("5.10.102", rule))  # 5.10 流修复边界
        self.assertFalse(version_in_range("5.4.109", rule))   # 早于引入
        self.assertFalse(version_in_range("6.8.0", rule))

    def test_nftables_stream_no_false_positive(self):
        rule = next(r for r in CATALOG if r["cve"] == "CVE-2023-4206")
        self.assertTrue(version_in_range("6.1.44", rule))
        self.assertFalse(version_in_range("6.1.50", rule))    # 6.1 流 6.1.45 已修复
        self.assertFalse(version_in_range("6.5.0", rule))

    def test_io_uring_series(self):
        r0582 = next(r for r in CATALOG if r["cve"] == "CVE-2024-0582")
        self.assertFalse(version_in_range("6.1.0", r0582))
        self.assertTrue(version_in_range("6.6.0", r0582))
        self.assertFalse(version_in_range("6.7.0", r0582))
        r3491 = next(r for r in CATALOG if r["cve"] == "CVE-2021-3491")
        self.assertTrue(version_in_range("5.8.0", r3491))
        self.assertFalse(version_in_range("5.12.4", r3491))

    def test_release_suffix_ignored(self):
        rule = next(r for r in CATALOG if r["cve"] == "CVE-2022-0847")
        self.assertTrue(version_in_range("5.8.18-200-generic", rule))


class AssessTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = assess(json.loads(FIXTURE.read_text(encoding="utf-8")))

    def test_nodes_present(self):
        self.assertGreaterEqual(len(self.report["nodes"]), 5)

    def test_legacy_kernel_hits(self):
        node = self.report["nodes"]["lab-legacy-3-10"]
        cves = {hit["cve"] for hit in node["hits"]}
        for must in ("CVE-2016-5195", "CVE-2017-6074", "CVE-2017-11176"):
            self.assertIn(must, cves)
        self.assertNotIn("CVE-2022-0847", cves)  # 3.10 早于 5.8 引入

    def test_dirtypipe_node_hits(self):
        node = self.report["nodes"]["lab-dirtypipe-5-8"]
        cves = {hit["cve"] for hit in node["hits"]}
        self.assertIn("CVE-2022-0847", cves)
        self.assertIn("CVE-2021-3491", cves)      # io_uring 5.7 引入
        self.assertIn("CVE-2021-3490", cves)      # eBPF ALU32（unpriv bpf 开启）
        self.assertIn("CVE-2022-0995", cves)      # watch_queue 5.8 引入
        for hit in node["hits"]:
            self.assertEqual(hit["confidence"], "detection-only")
            self.assertTrue(hit["fixed_in"])

    def test_nft_node_stream_logic(self):
        node = self.report["nodes"]["lab-nft-6-1-50"]
        cves = {hit["cve"] for hit in node["hits"]}
        self.assertIn("CVE-2024-1086", cves)      # 6.1 流修复 6.1.76，6.1.50 受影响
        self.assertIn("CVE-2023-32233", cves)
        for fixed_stream in ("CVE-2023-4206", "CVE-2023-4207", "CVE-2023-4208"):
            self.assertNotIn(fixed_stream, cves)  # 6.1.45 已修复 → 不误报

    def test_modern_kernel_no_false_positive(self):
        node = self.report["nodes"]["lab-modern-6-12"]
        self.assertEqual(node["hits"], [], f"新内核不得误报：{node['hits']}")
        self.assertEqual(node["kernel_component_hits"], [])

    def test_requires_gate(self):
        node = self.report["nodes"]["lab-caps-none-5-15"]
        cves = {hit["cve"] for hit in node["hits"]}
        # 5.15 且未开 userns/unpriv bpf：需要前置的 nftables/eBPF 条目不报
        self.assertNotIn("CVE-2024-1086", cves)   # 需要 userns/net_admin
        self.assertNotIn("CVE-2021-3490", cves)   # 需要 unprivileged_bpf_disabled<2
        self.assertIn("CVE-2022-0847", cves)      # 无前置，直接命中（5.15.24）

    def test_component_detection(self):
        node = self.report["nodes"]["lab-userspace"]
        cves = {hit["cve"] for hit in node["kernel_component_hits"]}
        self.assertIn("CVE-2021-4034", cves)      # pkexec 存在
        self.assertIn("CVE-2021-3156", cves)      # sudo 1.8.21 < 1.9.5p2
        self.assertIn("CVE-2024-21626", cves)     # runc 1.1.5 < 1.1.12
        self.assertIn("CVE-2020-15257", cves)     # containerd 1.3.4 < 1.4.3

    def test_aggregate(self):
        agg = self.report["aggregate"]
        self.assertEqual(agg["rules"], len(CATALOG))
        self.assertGreaterEqual(agg["nodes"], 5)
        self.assertGreaterEqual(agg["hit_cves"], 10)


class ModuleContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_run("kernel-lpe-audit")
        cls.result = cls.mod.run({}, {"snapshot": str(FIXTURE)})

    def test_run_shape(self):
        for field in ("summary", "findings", "artifacts"):
            self.assertIn(field, self.result)
        summary = json.loads(self.result["summary"])
        self.assertEqual(summary["rules"], len(CATALOG))
        self.assertGreaterEqual(summary["nodes"], 5)
        self.assertTrue(all(f.get("cve") for f in self.result["findings"]))

    def test_findings_confidence_marker(self):
        for f in self.result["findings"]:
            if f.get("cve"):
                self.assertEqual(f.get("confidence"), "detection-only")
                self.assertIn("未执行利用", f["detail"])

    def test_empty_snapshot_zero_findings(self):
        result = self.mod.run({}, {"snapshot": {}})
        self.assertEqual(result["findings"], [])

    def test_registry(self):
        mods = load_modules(MODULES)
        meta = mods["kernel-lpe-audit"]
        self.assertEqual(meta.series, "侦察")
        self.assertFalse(meta.writes)
        self.assertEqual(meta.min_level, "只读侦察")


class ParityDocTest(unittest.TestCase):
    def test_doc_states_catalog_and_kubetrail(self):
        text = PARITY_DOC.read_text(encoding="utf-8")
        self.assertIn(str(len(CATALOG)), text)
        self.assertIn("KubeTrail", text)
        self.assertIn("16", text)
        for cve in ("CVE-2022-0847", "CVE-2024-1086", "CVE-2024-0582"):
            self.assertIn(cve, text)


if __name__ == "__main__":
    unittest.main()
