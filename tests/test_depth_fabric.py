# -*- coding: utf-8 -*-
"""研究级深度：SONiC/IB/SHARP 配置审计 + fabric_sim 联动。"""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from lab.fabric_sim.detectors import detect
from lab.fabric_sim.sim import simulate
from lab.fabric_sim.topology import Topology
from trident.depth import fabric

ROOT = Path(__file__).resolve().parents[1]
MODULES = ROOT / "trident" / "modules"


class _Run:
    def __init__(self, path: Path):
        self.dir = path
        self.name = "depth-fabric"


def load_module(key: str):
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        f"depth_{key.replace('-', '_')}", MODULES / key / "run.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestFabricConfigDepth(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.snap = fabric.fixture("vulnerable")
        cls.fixed = fabric.fixture("hardened")

    def test_at_least_twenty_checks(self):
        self.assertGreaterEqual(len(fabric.checks()), 20)

    def test_vulnerable_and_hardened(self):
        report = fabric.audit(self.snap)
        self.assertGreaterEqual(report["checks"], 20)
        self.assertGreaterEqual(report["failed"], 15)
        self.assertGreaterEqual(len(report["domains"]), 3)
        clean = fabric.audit(self.fixed)
        self.assertEqual(clean["failed"], 0, clean["failed_ids"])

    def test_fabric_sim_bridge(self):
        plan = fabric.fabric_sim_plan(self.snap)
        self.assertIn("pfc-storm", plan["scenarios"])
        self.assertIn("ecn", plan["scenarios"])
        topo = Topology.build(1024)
        storm = detect(simulate(topo, "pfc-storm", seed=7))
        self.assertIn("fabric.pfc-pause-storm", {f["rule"] for f in storm})
        clean = detect(simulate(topo, "baseline", seed=7))
        self.assertEqual([f["rule"] for f in clean], ["fabric.baseline-clean"])

    def test_sonic_module(self):
        with TemporaryDirectory() as td:
            ctx = {"run": _Run(Path(td)), "marker": "TRIDENT-DEPTH"}
            result = load_module("sonic-fabric-config-audit").run(ctx, {"snapshot": self.snap})
            self.assertGreaterEqual(len(result["findings"]), 8)
            detail = json.loads(result["findings"][0]["detail"])
            self.assertGreaterEqual(detail["checks"], 20)
            self.assertIn("sonic", detail["domains"])

    def test_sharp_module(self):
        with TemporaryDirectory() as td:
            ctx = {"run": _Run(Path(td)), "marker": "TRIDENT-DEPTH"}
            result = load_module("sharp-session-trust-audit").run(ctx, {"snapshot": self.snap})
            self.assertGreaterEqual(len(result["findings"]), 3)
            detail = json.loads(result["findings"][0]["detail"])
            self.assertIn("sharp", detail["domains"])


if __name__ == "__main__":
    unittest.main()
