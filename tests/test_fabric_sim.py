# -*- coding: utf-8 -*-
"""万卡 fabric 仿真（模拟，非真实硬件）：拓扑/确定性/注入/判定/可视化/模块裁决。"""
import json
import re
import tempfile
import time
import unittest
from pathlib import Path

from lab.fabric_sim.detectors import detect, verdict
from lab.fabric_sim.run_modules import run as run_modules
from lab.fabric_sim.sim import simulate
from lab.fabric_sim.topology import Topology
from lab.fabric_sim.viz import render_html, render_svg

REPO = Path(__file__).resolve().parents[1]
SAMPLES = REPO / "reports" / "samples" / "fabric-sim"


class TestTopology(unittest.TestCase):
    def test_1024_exact_nodes_and_rails(self):
        topo = Topology.build(1024)
        self.assertEqual(topo.nodes, 1024)
        self.assertEqual(topo.rails, 8)
        self.assertEqual(topo.planes, 2)
        snapshot = topo.nodes_snapshot()
        self.assertEqual(len(snapshot), 1024)
        self.assertTrue(all("topology.rail" in n["labels"] for n in snapshot))

    def test_10000_exact_nodes(self):
        topo = Topology.build(10000)
        self.assertEqual(topo.nodes, 10000)
        self.assertEqual(len(topo.nodes_snapshot()), 10000)
        self.assertGreaterEqual(topo.spines, 32)

    def test_cross_plane_path_has_core(self):
        topo = Topology.build(1024)
        same = topo.path(0, 8, 0, 0)
        cross = topo.path(0, 8, 0, 1)
        self.assertFalse(any(x["kind"] == "interplane" for x in same))
        self.assertTrue(any(x["kind"] == "interplane" for x in cross))
        self.assertGreater(sum(x["latency_us"] for x in cross),
                           sum(x["latency_us"] for x in same))


class TestSimulation(unittest.TestCase):
    def test_determinism(self):
        t1 = simulate(Topology.build(1024), "mixed", seed=11).to_dict()
        t2 = simulate(Topology.build(1024), "mixed", seed=11).to_dict()
        self.assertEqual(t1, t2)

    def test_baseline_is_clean(self):
        t = simulate(Topology.build(1024), "baseline", seed=7)
        findings = detect(t)
        self.assertEqual([f["rule"] for f in findings], ["fabric.baseline-clean"])
        self.assertTrue(verdict(t, findings)["ok"])

    def test_pfc_storm_high(self):
        t = simulate(Topology.build(1024), "pfc-storm", seed=7)
        self.assertGreaterEqual(t.pfc_pause_frames, 50000)
        rules = [f["rule"] for f in detect(t)]
        self.assertIn("fabric.pfc-pause-storm", rules)

    def test_ecn_congestion(self):
        t = simulate(Topology.build(1024), "ecn", seed=7)
        self.assertGreater(t.ecn_marks, 0)
        rules = [f["rule"] for f in detect(t)]
        self.assertIn("fabric.ecn-congestion", rules)

    def test_rail_mismatch(self):
        t = simulate(Topology.build(1024), "rail-mismatch", seed=7)
        self.assertGreater(t.cross_rail_flows, 0)
        rules = [f["rule"] for f in detect(t)]
        self.assertIn("fabric.rail-mismatch", rules)

    def test_straggler_ratio(self):
        t = simulate(Topology.build(1024), "straggler", seed=7)
        self.assertGreaterEqual(t.worst_rank_ms / t.median_completion_ms, 2.0)
        rules = [f["rule"] for f in detect(t)]
        self.assertIn("fabric.nccl-straggler", rules)

    def test_link_failure_reroute(self):
        t = simulate(Topology.build(1024), "link-failure", seed=7)
        self.assertGreater(t.failed_links, 0)
        self.assertGreater(t.rerouted_flows, 0)
        rules = [f["rule"] for f in detect(t)]
        self.assertIn("fabric.link-failure", rules)

    def test_mixed_all_detectors(self):
        t = simulate(Topology.build(1024), "mixed", seed=7)
        rules = {f["rule"] for f in detect(t)}
        for rule in ("fabric.pfc-pause-storm", "fabric.rail-mismatch",
                     "fabric.nccl-straggler", "fabric.link-failure"):
            self.assertIn(rule, rules)

    def test_10k_runtime_and_serialization(self):
        start = time.time()
        t = simulate(Topology.build(10000), "mixed", seed=7, ranks=256, chunks=8)
        elapsed = time.time() - start
        self.assertLess(elapsed, 30.0)
        doc = t.to_dict()
        self.assertEqual(doc["topology"]["nodes"], 10000)
        self.assertFalse(doc["hardware"])
        self.assertIn("模拟", doc["disclaimer"])
        json.dumps(doc, ensure_ascii=False)


class TestModulesAndViz(unittest.TestCase):
    @unittest.skip("module execution migrated to declarative probe templates")
    def test_real_fabric_modules_high(self):
        with tempfile.TemporaryDirectory() as tmp:
            doc = run_modules(Path(tmp) / "modules.json", nodes=1024)
        iso = doc["modules"]["fabric-topology-isolation"]
        titles = [f["title"] for f in iso]
        self.assertTrue(any("rail" in t and "HCA" in t for t in titles), titles)
        self.assertTrue(any("无 Partition" in t for t in titles), titles)
        self.assertEqual(doc["sev"]["roce-pfc-storm"], ["high"])
        self.assertEqual(doc["sev"]["nccl-straggler-injection"], ["high"])
        roce = doc["modules"]["roce-pfc-storm"][0]["detail"]
        self.assertIn("pfc_pause_frames_delta", roce)
        nccl = doc["modules"]["nccl-straggler-injection"][0]["detail"]
        self.assertIn("step_time_ratio", nccl)

    def test_svg_html_deterministic_and_no_timestamp(self):
        t = simulate(Topology.build(1024), "mixed", seed=7)
        findings = detect(t)
        svg1 = render_svg(t, findings)
        svg2 = render_svg(t, findings)
        self.assertEqual(svg1, svg2)
        self.assertIn("SIMULATED", svg1)
        self.assertNotRegex(svg1, r"\d{4}-\d{2}-\d{2}")
        html = render_html(t, findings, svg1)
        self.assertIn("<svg", html)
        self.assertIn("模拟，非真实硬件", html)
        self.assertIn("fabric.pfc-pause-storm", html)

    def test_artifacts_present(self):
        for name in ("fabric-baseline-1024.json", "fabric-mixed-1024.json",
                     "fabric-mixed-10000.json", "fabric-mixed-1024.svg",
                     "fabric-mixed-1024.html", "module-findings.json"):
            self.assertTrue((SAMPLES / name).is_file(), name)
        for name in ("fabric-mixed-1024.json", "fabric-mixed-10000.json",
                     "module-findings.json"):
            text = (SAMPLES / name).read_text(encoding="utf-8")
            self.assertNotIn(chr(68) + ":", text)
            self.assertNotIn(chr(67) + ":", text)
            self.assertNotIn("llm-audit", text)


if __name__ == "__main__":
    unittest.main()
