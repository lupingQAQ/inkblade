# -*- coding: utf-8 -*-
"""Slurm depth + residual gap documentation integrity tests."""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SLURM_DOC = REPO / "docs" / "SLURM-HPC-COVERAGE.md"
SLURM_PROFILE = REPO / "trident" / "profiles" / "slurm-hpc.json"
CONF = REPO / "docs" / "CONFERENCE-2026-GAPS.md"
RESIDUAL = REPO / "docs" / "RESIDUAL-GAPS-2026.md"

SLURM_MODULES = (
    "slurmctld-config-audit", "slurmd-config-audit", "munge-auth-audit",
    "spank-plugin-integrity", "slurm-cgroup-constraint-audit",
    "slurm-node-partition-policy", "slurm-shared-storage-audit",
    "slurmrestd-exposure", "slurm-jwt-auth-audit", "slurm-accountingdbd-audit",
    "slurm-gres-gpu-isolation", "slurm-prolog-epilog-audit",
)
RESIDUAL_MODULES = (
    "hypervisor-audit-integrity", "agent-skill-registry-supply-chain",
    "operator-cross-namespace-reference", "mcp-control-plane-governance",
    "ai-infra-baseline", "inference-tenant-isolation-baseline",
    "agent-native-control-plane",
)


class SlurmDocTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = SLURM_DOC.read_text(encoding="utf-8")
        cls.profile = json.loads(SLURM_PROFILE.read_text(encoding="utf-8"))

    def test_requested_areas_and_modules(self):
        self.assertTrue(SLURM_DOC.is_file())
        for needle in ("slurmctld", "slurmd", "Munge", "SPANK", "cgroup",
                       "drain", "分区", "QOS", "Lustre", "GPFS", "slurmrestd", "JWT"):
            self.assertIn(needle, self.text, needle)
        for key in SLURM_MODULES:
            self.assertIn(key, self.text, key)
            self.assertIn(key, {p.name for p in (REPO / "trident" / "modules").iterdir()})

    def test_coverage_math_and_honest_metric_split(self):
        self.assertIn("3/17 = 17.6", self.text)
        self.assertIn("15/17 = 88.2", self.text)
        self.assertIn("目标 ≥40% 达成", self.text)
        self.assertIn("25.8%", self.text)
        self.assertIn("no Kubernetes API", self.text)
        self.assertIn("不得", self.text)

    def test_profile_declares_all_surfaces(self):
        selectors = {s["selector"] for s in self.profile["surfaces"]}
        for selector in ("slurm/slurm.conf", "slurm/cgroup.conf", "slurm/munge.conf",
                         "slurm/munge.key.meta", "slurm/plugstack.conf",
                         "slurm/slurmrestd.env", "slurm/jwt.json", "slurm/nodes.json",
                         "slurm/partitions.json", "slurm/qos.json", "slurm/gres.json",
                         "slurm/prolog-epilog.json", "storage/lustre/mounts.json",
                         "storage/gpfs/mounts.json", "runtime-agent/slurmctld",
                         "runtime-agent/slurmd", "runtime-agent/munge", "runtime-agent/spank",
                         "runtime-agent/cgroup", "runtime-agent/slurmdbd"):
            self.assertIn(selector, selectors, selector)
        self.assertFalse([s for s in self.profile["surfaces"] if s["type"] == "k8s-object"],
                         "Slurm 画像不应声明 k8s-object 面")

    def test_fixture_paths_present(self):
        for posture in ("vulnerable", "fixed"):
            self.assertTrue((REPO / "lab" / "fixtures" / "slurm" / posture).is_dir(), posture)


class ResidualDocTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = RESIDUAL.read_text(encoding="utf-8")
        cls.conf = CONF.read_text(encoding="utf-8")

    def test_all_seven_modules_and_sources(self):
        for key in RESIDUAL_MODULES:
            self.assertIn(key, self.text, key)
            self.assertIn(key, self.conf, key)
        for url in ("usenix.org", "ndss-symposium.org", "ieee-security.org",
                    "cloud-village.org", "rsaconference.com", "dwcon.cn", "yunqi.aliyun.com"):
            self.assertIn(url, self.text, url)

    def test_necessity_and_default_gating(self):
        for phrase in ("为什么是残余", "实现", "不覆盖", "默认开关规则",
                       "default_enabled=false", "至少 3 项"):
            self.assertIn(phrase, self.text, phrase)
        rows = re.findall(r"^\| R0[1-7] \|", self.conf, flags=re.M)
        self.assertGreaterEqual(len(rows), 7, rows)

    def test_effects_are_named(self):
        for cid in ("residual-hypervisor-audit-race", "residual-agent-skill-poison",
                    "residual-operator-cross-namespace", "residual-mcp-control-plane"):
            self.assertIn(cid, self.text, cid)


if __name__ == "__main__":
    unittest.main()
