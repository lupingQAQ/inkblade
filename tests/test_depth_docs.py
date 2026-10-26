# -*- coding: utf-8 -*-
"""研究级深度：文档、用例总数、检测规则与六类效果验证。"""

import json
import unittest
from pathlib import Path

from inkblade import depth_effects
from inkblade.depth import admission, ebpf, fabric, gpu, identity, vllm

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "DEPTH-REVIEW.md"
RULES = ROOT / "corpus" / "depth" / "detection_rules.json"


class TestDepthDocsAndRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = DOC.read_text(encoding="utf-8")

    def test_doc_sections(self):
        for title in ("vLLM/SGLang", "K8s 准入绕过", "eBPF 运行时盲区",
                      "GPU Operator/NVIDIA", "SONiC/IB/SHARP", "身份联邦"):
            self.assertIn(title, self.text)
        for field in ("研究问题", "方法", "发现", "证据", "模块键", "规则"):
            self.assertGreaterEqual(self.text.count(field), 6, field)

    def test_case_total_at_least_280(self):
        counts = {
            "vllm_fuzz": len(vllm.fuzz_cases()),
            "vllm_matrix": len(vllm.entries()),
            "admission": len(admission.cases()),
            "ebpf": len(ebpf.cases()),
            "gpu": len(gpu.cases()),
            "fabric": len(fabric.checks()),
            "identity": len(identity.cases()),
        }
        self.assertGreaterEqual(sum(counts.values()), 280, counts)
        for key, value in counts.items():
            self.assertIn(f"{key}", self.text.lower(), key)

    def test_detection_rules(self):
        rules = json.loads(RULES.read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(rules["rules"]), 12)
        engines = {r["engine"] for r in rules["rules"]}
        self.assertTrue({"sigma", "falco", "kyverno", "gatekeeper"} <= engines)
        for rule in rules["rules"]:
            self.assertTrue(rule["id"])
            self.assertTrue(rule["match"].strip())
            self.assertTrue(rule["module"])

    def test_no_placeholders(self):
        self.assertNotIn("TODO", self.text.upper())
        self.assertNotIn("TBD", self.text.upper())


class TestDepthEffects(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.checks = depth_effects.run_all()

    def test_six_effects_pass(self):
        self.assertEqual(len(self.checks), 6)
        for check in self.checks:
            self.assertEqual(check["status"], "PASS", check)
            self.assertTrue(check["evidence"], check["id"])

    def test_effect_ids(self):
        ids = {c["id"] for c in self.checks}
        self.assertEqual(ids, {
            "depth-vllm-fuzz", "depth-admission-semantics", "depth-ebpf-blindspot",
            "depth-gpu-operator-config", "depth-sonic-fabric-link",
            "depth-identity-federation",
        })

    def test_evidence_contains_differentials(self):
        by_id = {c["id"]: c["evidence"] for c in self.checks}
        self.assertGreaterEqual(by_id["depth-vllm-fuzz"]["vulnerable_bypasses"], 100)
        self.assertEqual(by_id["depth-vllm-fuzz"]["fixed_bypasses"], 0)
        self.assertGreaterEqual(by_id["depth-admission-semantics"]["vulnerable_admitted"], 15)
        self.assertEqual(by_id["depth-admission-semantics"]["hardened_admitted"], 0)
        self.assertGreaterEqual(by_id["depth-ebpf-blindspot"]["missed"], 10)
        self.assertGreaterEqual(by_id["depth-gpu-operator-config"]["critical"], 3)
        self.assertGreaterEqual(by_id["depth-sonic-fabric-link"]["failed"], 15)
        self.assertIn("fabric.pfc-pause-storm", by_id["depth-sonic-fabric-link"]["detectors"])
        self.assertGreaterEqual(by_id["depth-identity-federation"]["allowed"], 15)


if __name__ == "__main__":
    unittest.main()
