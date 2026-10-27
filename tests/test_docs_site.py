# -*- coding: utf-8 -*-
"""tests/test_docs_site.py — contracts for the public documentation surface.

The documentation site is a public artefact. These tests keep it boringly
safe: no external references, no local identifiers, no internal research paths,
no exploit material in the 0-day ledger, and no drift between the generator and
the committed HTML.
"""

from __future__ import annotations

import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

PAGES = [DOCS / "index.html", DOCS / "en" / "index.html", DOCS / "zh" / "index.html"]
ASSETS = [DOCS / "assets" / "style.css", DOCS / "assets" / "app.js"]

PUBLIC_MD = [
    ROOT / "README.md",
    ROOT / "README.zh-CN.md",
    DOCS / "USAGE.md",
    DOCS / "INSTALL.md",
    DOCS / "FEATURES.md",
    DOCS / "WORKFLOW.md",
    DOCS / "MODULES.md",
    DOCS / "FAQ.md",
    DOCS / "0DAY-PUBLIC.md",
    DOCS / "ARCHITECTURE.md",
    DOCS / "DETECTION-LAYERS.md",
    DOCS / "README-SITE.md",
]

PUBLIC_ALL = PAGES + ASSETS + PUBLIC_MD

LOCAL_MARKERS = re.compile(
    r"(?<![A-Za-z0-9])[A-Za-z]:[\\/]|\b21169\b|llm-audit|TRIDENT|\.slim|/mnt/",
    re.IGNORECASE,
)

INTERNAL_MATERIAL = (
    "disclosure/",
    "corpus/zeroday",
    "lab/upstream_verify",
    "lab/zeroday_reserve",
    "lab/mining-fixture",
    "reports/samples/kill-chain",
    "reports/samples/real-cluster",
    "zeroday/",
)

EXPLOIT_TOKENS = re.compile(r"\bPoC\b|proof-of-concept|payload|file:line|curl\s+-|POST\s+/", re.IGNORECASE)

SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*:")
ATTR_URL = re.compile(r"(?:href|src)\s*=\s*[\"']([^\"']+)[\"']", re.IGNORECASE)
CSS_URL = re.compile(r"url\(\s*['\"]?([^'\")]+)", re.IGNORECASE)
MD_LINK = re.compile(r"!?\[[^\]]*\]\(\s*<?([^)\s>]+)>?")
FENCE = re.compile(r"```.*?```", re.S)


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


class SiteFilesTest(unittest.TestCase):
    def test_required_files_exist(self):
        for path in PUBLIC_ALL:
            self.assertTrue(path.is_file(), f"missing: {path.relative_to(ROOT).as_posix()}")
        self.assertTrue((DOCS / ".nojekyll").is_file(), "docs/.nojekyll missing")
        for rel in (
            "scripts/build-docs-site.py",
            "scripts/build-pages-site.py",
            "scripts/check-docs-links.py",
        ):
            self.assertTrue((ROOT / rel).is_file(), f"missing: {rel}")

    def test_assets_are_local_and_used(self):
        index = read(DOCS / "index.html")
        self.assertIn('href="assets/style.css"', index)
        self.assertIn('src="assets/app.js"', index)
        self.assertIn("<style>", index, "critical CSS should be inline")
        self.assertIn("<script>", index, "language bootstrap should be inline")
        for page in PAGES:
            html = read(page)
            for match in re.findall(r'(?:href|src)="([^"]+)"', html):
                if match.startswith(("assets/", "../assets/")):
                    target = (page.parent / match).resolve()
                    self.assertTrue(target.is_file(), f"{page.name} references missing asset {match}")

    def test_no_external_references(self):
        for path in PUBLIC_ALL:
            text = read(path)
            if path.suffix == ".html":
                refs = ATTR_URL.findall(text) + CSS_URL.findall(text)
            elif path.suffix == ".css":
                refs = CSS_URL.findall(text)
            else:
                refs = MD_LINK.findall(FENCE.sub("", text))
            for ref in refs:
                ref = ref.strip()
                self.assertFalse(
                    SCHEME.match(ref) or ref.startswith("//") or "http" in ref.lower(),
                    f"{path.relative_to(ROOT).as_posix()}: external reference {ref!r}",
                )

    def test_no_local_identifiers(self):
        for path in PUBLIC_ALL:
            match = LOCAL_MARKERS.search(read(path))
            if match is not None:
                self.fail(
                    f"{path.relative_to(ROOT).as_posix()}: local identifier {match.group(0)!r}"
                )

    def test_no_internal_material_referenced(self):
        for path in PUBLIC_ALL:
            text = read(path)
            for marker in INTERNAL_MATERIAL:
                self.assertNotIn(
                    marker,
                    text,
                    f"{path.relative_to(ROOT).as_posix()} references internal material {marker!r}",
                )


class ZeroDayLedgerTest(unittest.TestCase):
    def test_ledger_lists_39_unique_primitives(self):
        text = read(DOCS / "0DAY-PUBLIC.md")
        rows = [line for line in text.splitlines() if line.startswith("| `")]
        self.assertEqual(len(rows), 78, f"expected 39 rows per language, found {len(rows)}")
        for value in ("169", "60", "47", "46", "39", "21"):
            self.assertIn(value, text)

    def test_ledger_has_no_exploit_material(self):
        match = EXPLOIT_TOKENS.search(read(DOCS / "0DAY-PUBLIC.md"))
        if match is not None:
            self.fail(f"0DAY-PUBLIC.md: exploit material marker {match.group(0)!r}")

    def test_components_and_versions_are_present(self):
        text = read(DOCS / "0DAY-PUBLIC.md")
        for component in ("vllm-jev", "dify", "msswift", "deepspeed", "areal", "skyrl"):
            self.assertIn(f"`{component}`", text)
        self.assertIn("v0.32.0", text)


class BilingualTest(unittest.TestCase):
    def test_landing_page_has_both_languages(self):
        index = read(DOCS / "index.html")
        self.assertIn('class="lang-block" data-lang="en"', index)
        self.assertIn('class="lang-block" data-lang="zh"', index)
        self.assertIn("Training &amp; Inference Cluster Penetration Testing Platform", index)
        self.assertIn("训练与推理集群渗透测试平台", index)

    def test_language_pages_declare_language(self):
        en = read(DOCS / "en" / "index.html")
        zh = read(DOCS / "zh" / "index.html")
        self.assertIn('<html lang="en"', en)
        self.assertIn('<html lang="zh-Hans"', zh)
        self.assertIn("InkBlade", en)
        self.assertIn("墨刃零", zh)

    def test_readme_pair(self):
        en = read(ROOT / "README.md")
        zh = read(ROOT / "README.zh-CN.md")
        self.assertIn("InkBlade", en)
        self.assertIn("InkBlade", zh)




class GeneratedSiteTest(unittest.TestCase):
    def test_generator_output_is_current(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "build-docs-site.py"), "--check"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)

    def test_link_checker_passes(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check-docs-links.py")],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_pages_workflow_is_removed(self):
        # The repository is private and Pages is intentionally disabled.
        self.assertFalse((ROOT / ".github" / "workflows" / "pages.yml").exists())


class DetectionLayersTest(unittest.TestCase):
    def test_site_summarises_ten_layers(self):
        index = read(DOCS / "index.html")
        self.assertIn("Ten detection layers", index)
        self.assertIn("十层检测", index)
        self.assertIn("DETECTION-LAYERS.md", index)
        for layer in ("Architecture", "Product / framework", "Cache security",
                      "Cross-combination", "Defense bypass"):
            self.assertIn(layer, index)

    def test_framework_matrix_is_explicit(self):
        doc = read(DOCS / "DETECTION-LAYERS.md")
        for framework in (
            "vLLM", "SGLang", "TRL", "verl", "AReaL", "SkyRL", "OpenRLHF", "slime",
            "LLaMA-Factory", "ms-swift", "Megatron-LM", "DeepSpeed", "transformers",
            "djev / vllm-jev", "Dify", "LiteLLM",
        ):
            self.assertIn(framework, doc)
        for point in ("prime_math", "prime_code", "recv_pyobj", "HDFS", "set_env", "/awex",
                      "Tinker", "serve_rm", "pull_weights"):
            self.assertIn(point, doc)

    def test_ten_layer_sections_exist(self):
        doc = read(DOCS / "DETECTION-LAYERS.md")
        for number in range(1, 11):
            self.assertIn(f"### {number}. ", doc)
        chinese = doc[doc.index("## 中文"):]
        for number in range(1, 11):
            self.assertIn(f"### {number}. ", chinese)
