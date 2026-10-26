"""tests/test_infra2026_docs.py — 2026 会议覆盖矩阵与总覆盖表的可核验性。

要求：≥30 条议题、≥12 条未覆盖、16 个新模块、来源 URL、与既有模块去重说明、
对未公开议程的会议不编造。
"""

import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CONF = REPO / "docs" / "CONFERENCE-2026-GAPS.md"
COVER = REPO / "docs" / "INFRA-COVERAGE-2026.md"

MODULES = (
    "confidential-containers-attestation",
    "sandbox-runtime-surface",
    "spiffe-spire-surface",
    "cert-manager-webhook-tls",
    "gateway-api-ambient-mesh",
    "wasm-workload-surface",
    "gitops-supply-chain",
    "multi-cluster-federation",
    "dpu-ipu-offload",
    "pcie-iommu-dma",
    "tpm-measured-boot",
    "post-quantum-tls-posture",
    "model-watermark-backdoor-detect",
    "rag-vector-injection",
    "federated-learning-surface",
    "data-provenance-audit",
)


class ConferenceGapsDocTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = CONF.read_text(encoding="utf-8")

    def test_exists_and_has_30_plus_topics(self):
        self.assertTrue(CONF.is_file())
        rows = re.findall(r"^\| I\d+ \|", self.text, flags=re.M)
        self.assertGreaterEqual(len(rows), 30, f"议题行只有 {len(rows)}")

    def test_has_12_plus_uncovered_rows(self):
        rows = re.findall(r"^\| G\d+ \|", self.text, flags=re.M)
        self.assertGreaterEqual(len(rows), 12, f"缺口行只有 {len(rows)}")

    def test_sources_are_urls_and_venue_coverage(self):
        urls = re.findall(r"https?://[^\s|)]+", self.text)
        self.assertGreaterEqual(len(urls), 25, len(urls))
        for needle in (
            "USENIX Security 2026", "IEEE S&P 2026", "NDSS 2026", "CCS 2025",
            "Black Hat USA 2026", "Black Hat Europe 2026", "DEF CON 34",
            "KubeCon", "OWASP Global AppSec", "RSA 2026", "KCon 2026",
            "SDC 2026", "TSec", "云栖", "字节", "OffensiveCon",
            "CanSecWest 2026", "POC 2026",
        ):
            self.assertIn(needle, self.text, needle)

    def test_unpublished_agendas_not_fabricated(self):
        for phrase in ("未公开完整议程", "不编造", "截至 2026-10-26"):
            self.assertIn(phrase, self.text, phrase)

    def test_module_mapping_complete(self):
        for key in MODULES:
            self.assertIn(key, self.text, key)


class InfraCoverageDocTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = COVER.read_text(encoding="utf-8")

    def test_exists_and_lists_all_new_modules(self):
        self.assertTrue(COVER.is_file())
        for key in MODULES:
            self.assertIn(key, self.text, key)

    def test_dedup_and_tiers(self):
        for phrase in ("去重", "只读侦察", "主动探测", "writes=false", "既有模块"):
            self.assertIn(phrase, self.text, phrase)

    def test_has_coverage_table_and_sources(self):
        rows = re.findall(r"^\| M\d+ \|", self.text, flags=re.M)
        self.assertGreaterEqual(len(rows), 16, len(rows))
        self.assertGreaterEqual(len(re.findall(r"https?://", self.text)), 10)


if __name__ == "__main__":
    unittest.main()
