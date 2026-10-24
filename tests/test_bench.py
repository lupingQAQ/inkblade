"""bench 冒烟与 KIND hostNetwork 旁路实证交付物测试。

- bench smoke（lab/bench/bench.py）：对 lab mock 靶场跑最小链探测计时；
  优先走 trident/core/chains.load_chains 选只读链，模块未就绪则 urllib 五路由兜底（记录 Ruling）。
- KIND 实证交付物（lab/kind/）：hostnetwork-bypass.yaml / default-deny-netpol.yaml / run-proof.sh。
"""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from lab.bench import bench

REPO = Path(__file__).resolve().parents[1]
BENCH_DIR = REPO / "lab" / "bench"
KIND_DIR = REPO / "lab" / "kind"


class TestBenchSmoke(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = bench.run_smoke(iterations=2)

    def test_result_core_fields(self):
        r = self.result
        for field in ("elapsed_ms", "max_rss_kb", "requests", "mode", "ruling"):
            self.assertIn(field, r, f"缺少字段 {field}")
        self.assertGreater(r["elapsed_ms"], 0)
        self.assertGreater(r["max_rss_kb"], 0)
        self.assertGreaterEqual(r["requests"], 1)
        if r["mode"] == "fallback-urllib":
            self.assertGreaterEqual(r["requests"], 5)

    def test_mode_and_ruling_recorded(self):
        r = self.result
        self.assertIn(r["mode"], ("chain", "fallback-urllib"))
        self.assertTrue(str(r["ruling"]).strip())
        if r["mode"] == "fallback-urllib":
            self.assertEqual(len(r["routes"]), 5)
            for rt in r["routes"]:
                self.assertGreaterEqual(rt["avg_ms"], 0.0)

    def test_fallback_forced_when_modules_unready(self):
        """强制模块目录为空 = 模块未就绪，必走 urllib 五路由兜底并记录 Ruling。"""
        with TemporaryDirectory() as tmp:
            r = bench.run_smoke(iterations=1, modules_dir=Path(tmp) / "no-modules")
        self.assertEqual(r["mode"], "fallback-urllib")
        self.assertEqual(r["requests"], 5)
        self.assertEqual(len(r["routes"]), 5)
        self.assertIn("降级", r["ruling"])
        for rt in r["routes"]:
            self.assertEqual(rt["status"], rt["expect"])

    def test_fallback_routes_are_readonly(self):
        """兜底五路由必须对靶场零写入（ROUTE_TABLE writes=false）。"""
        from lab.mock_targets import ROUTE_TABLE

        writes = {(e["method"], e["path"].rstrip("/")) for e in ROUTE_TABLE if e.get("writes")}
        for rt in bench.FALLBACK_ROUTES:
            self.assertNotIn((rt["method"], rt["path"].rstrip("/")), writes,
                             f"兜底路由含写类面: {rt}")

    def test_cli_writes_json_and_md(self):
        with TemporaryDirectory() as tmp:
            jp = Path(tmp) / "smoke.json"
            mp = Path(tmp) / "smoke.md"
            rc = bench.main(["smoke", "--iterations", "1",
                             "--json", str(jp), "--md", str(mp)])
            self.assertEqual(rc, 0)
            data = json.loads(jp.read_text(encoding="utf-8"))
            for field in ("elapsed_ms", "max_rss_kb", "requests"):
                self.assertIn(field, data)
            self.assertGreater(data["elapsed_ms"], 0)
            self.assertGreater(data["max_rss_kb"], 0)
            self.assertGreaterEqual(data["requests"], 1)
            if data["mode"] == "fallback-urllib":
                self.assertGreaterEqual(data["requests"], 5)
            md = mp.read_text(encoding="utf-8")
            self.assertIn("elapsed_ms", md)
            self.assertIn("Ruling", md)


class TestKindDeliverables(unittest.TestCase):
    def test_manifests_present_and_sane(self):
        host = (KIND_DIR / "hostnetwork-bypass.yaml").read_text(encoding="utf-8")
        self.assertIn("hostNetwork: true", host)
        deny = (KIND_DIR / "default-deny-netpol.yaml").read_text(encoding="utf-8")
        self.assertIn("policyTypes", deny)
        self.assertIn("Ingress", deny)
        self.assertIn("Egress", deny)

    def test_run_proof_script_selfcontained(self):
        sh = (KIND_DIR / "run-proof.sh").read_text(encoding="utf-8")
        for needle in (
            "kind create cluster",
            "disableDefaultCNI",
            "calico",
            "hostnetwork-bypass.yaml",
            "default-deny-netpol.yaml",
            "PROOF-hostnetwork-bypass.md",
        ):
            self.assertIn(needle, sh, f"run-proof.sh 缺少要素: {needle}")

    def test_bench_result_doc(self):
        doc = (BENCH_DIR / "BENCH-RESULT.md").read_text(encoding="utf-8")
        self.assertIn("ARTEX", doc)
        self.assertIn("冒烟初值", doc)
        self.assertIn("artex-bench.sh", doc)


if __name__ == "__main__":
    unittest.main()
