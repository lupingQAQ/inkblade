# -*- coding: utf-8 -*-
"""Documentation index and public product-doc checks.

These tests keep the product docs and the index aligned with the public
documentation policy:

- the product documents exist and are linked from ``docs/DOC-INDEX.md``;
- internal working documents are not linked from the index;
- every relative link in the index resolves inside the repository;
- the public documents contain no external URL, local machine path, AI-scan
  reference or internal status wording;
- every public document states the authorization prerequisite.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
INDEX = DOCS / "DOC-INDEX.md"
PAGES = [DOCS / "index.html", DOCS / "en" / "index.html", DOCS / "zh" / "index.html"]

REQUIRED = [
    "docs/QUICKSTART.md",
    "docs/PRODUCT.md",
    "docs/FEATURES.md",
    "docs/WORKFLOW.md",
    "docs/DETECTION-LAYERS.md",
    "docs/USAGE.md",
    "docs/INSTALL.md",
    "docs/FAQ.md",
    "docs/DOC-INDEX.md",
    "docs/ARCHITECTURE-PROBE.md",
    "docs/PROBE-PROTOCOL.md",
    "docs/PROBE-DEPLOY.md",
]

TOUCHED = [
    "README.md",
    "README.zh-CN.md",
    "docs/QUICKSTART.md",
    "docs/PRODUCT.md",
    "docs/FEATURES.md",
    "docs/WORKFLOW.md",
    "docs/DETECTION-LAYERS.md",
    "docs/USAGE.md",
    "docs/INSTALL.md",
    "docs/FAQ.md",
    "docs/DOC-INDEX.md",
]

INTERNAL = (
    "MASTER-REPORT.md",
    "SOTA-2026-10.md",
    "REQUIREMENTS-MATRIX.md",
    "PROGRESS.md",
    "DEV-LOG.md",
    "REFLECTION-",
    "SECTION3-",
    "GAP-",
    "ENTERPRISE-",
    "AI-SCAN-RESULT.md",
    "DYNAMIC-VERIFICATION.md",
    "PROBE-COVERAGE.md",
)

FORBIDDEN = re.compile(
    r"blocked-resource|partial|not-done|未完成|迁移中|preview|reduced|研究-only|TODO|TBD",
    re.IGNORECASE,
)
AI_SCAN = re.compile(r"ai-scan|ai 检测|ai 分数|ai score", re.IGNORECASE)

MD_LINK = re.compile(r"!?\[[^\]]*\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
FENCE = re.compile(r"```.*?```", re.S)
INLINE = re.compile(r"`[^`]*`")
EXTERNAL = re.compile(r"https?://", re.I)
DRIVE = re.compile(r"(?<![A-Za-z])[A-Za-z]:" + re.escape("\\"))
LOCAL_TOKENS = ("211" + "69", "llm" + "-audit", "." + "slim", "/" + "mnt/")


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


class DocsIndexTest(unittest.TestCase):
    def test_required_docs_exist(self):
        missing = [rel for rel in REQUIRED if not (ROOT / rel).is_file()]
        self.assertEqual(missing, [], f"missing required documents: {missing}")

    def test_product_docs_are_indexed(self):
        text = INDEX.read_text(encoding="utf-8")
        linked = {
            unquote(ref).rsplit("/", 1)[-1]
            for ref in MD_LINK.findall(FENCE.sub("", text))
            if ref.endswith(".md") and not ref.startswith("#")
        }
        missing = sorted({Path(rel).name for rel in REQUIRED} - linked)
        self.assertEqual(missing, [], f"product docs not linked from the index: {missing}")

    def test_index_excludes_internal_documents(self):
        text = INDEX.read_text(encoding="utf-8")
        linked = [
            unquote(ref).rsplit("/", 1)[-1]
            for ref in MD_LINK.findall(FENCE.sub("", text))
            if ref.endswith(".md")
        ]
        leaked = sorted(
            name for name in linked if any(name.startswith(prefix) for prefix in INTERNAL)
        )
        self.assertEqual(leaked, [], f"internal documents linked from the public index: {leaked}")

    def test_index_links_resolve(self):
        text = FENCE.sub("", INDEX.read_text(encoding="utf-8"))
        text = INLINE.sub("", text)
        broken = []
        for ref in MD_LINK.findall(text):
            ref = ref.strip()
            if not ref or ref.startswith("#"):
                continue
            if EXTERNAL.search(ref) or ref.startswith("//"):
                broken.append(f"{ref} (external)")
                continue
            target_part = unquote(ref.partition("#")[0])
            if not target_part:
                continue
            target = (INDEX.parent / target_part).resolve()
            try:
                target.relative_to(ROOT.resolve())
            except ValueError:
                broken.append(f"{ref} (outside repository)")
                continue
            if not target.exists():
                broken.append(f"{ref} (missing)")
        self.assertEqual(broken, [], f"index links do not resolve: {broken}")

    def test_public_docs_have_no_external_links(self):
        bad = {}
        for rel in TOUCHED:
            hits = EXTERNAL.findall(read(rel))
            if hits:
                bad[rel] = len(hits)
        self.assertEqual(bad, {}, f"external URLs found in public docs: {bad}")

    def test_public_docs_have_no_local_markers(self):
        bad = {}
        for rel in TOUCHED:
            text = read(rel)
            hits = [token for token in LOCAL_TOKENS if token in text]
            if DRIVE.search(text):
                hits.append("drive-path")
            if hits:
                bad[rel] = hits
        self.assertEqual(bad, {}, f"local machine markers found in public docs: {bad}")

    def test_public_docs_have_no_internal_status_wording(self):
        bad = {}
        for rel in TOUCHED:
            hits = sorted({m.group(0).lower() for m in FORBIDDEN.finditer(read(rel))})
            if hits:
                bad[rel] = hits
        for page in PAGES:
            hits = sorted({m.group(0).lower() for m in FORBIDDEN.finditer(page.read_text(encoding="utf-8"))})
            if hits:
                bad[page.name] = hits
        self.assertEqual(bad, {}, f"internal status wording found in public docs: {bad}")

    def test_public_docs_have_no_ai_scan_material(self):
        bad = {}
        for rel in TOUCHED:
            if AI_SCAN.search(read(rel)):
                bad[rel] = AI_SCAN.search(read(rel)).group(0)
        for page in PAGES:
            text = page.read_text(encoding="utf-8")
            if AI_SCAN.search(text):
                bad[page.name] = AI_SCAN.search(text).group(0)
        self.assertEqual(bad, {}, f"AI-scan material found in public docs: {bad}")

    def test_public_docs_state_authorized_use(self):
        missing = [
            rel for rel in TOUCHED
            if "授权" not in read(rel) and "Authorized use" not in read(rel)
        ]
        self.assertEqual(missing, [], f"authorization prerequisite missing from: {missing}")

    def test_probe_docs_state_target_side_boundary(self):
        arch = read("docs/ARCHITECTURE-PROBE.md")
        for phrase in ("目标侧零 Python", "probe_id", "parent_id", "http", "tcp",
                       "exec", "fs", "k8s", "socks", "spawn"):
            self.assertIn(phrase, arch, f"probe architecture document missing: {phrase}")
        product = read("docs/PRODUCT.md")
        for key in (
            "defense-bypass-elkeid",
            "defense-bypass-agentsmith",
            "defense-bypass-veinmind",
            "defense-bypass-falco",
            "defense-bypass-tetragon",
            "defense-bypass-kubearmor",
            "defense-bypass-admission",
            "defense-bypass-imagescan",
            "defense-bypass-hostagent",
            "defense-bypass-waf-inference",
            "defense-bypass-netobserv",
        ):
            self.assertIn(key, product, f"defense-bypass module missing from PRODUCT.md: {key}")

    def test_quick_start_uses_real_onboarding(self):
        text = read("docs/USAGE.md")
        for command in ("inkblade up", "session open", "probe deploy", "agent run", "report"):
            self.assertIn(command, text, f"real onboarding step missing from USAGE.md: {command}")
        lowered = text.lower()
        for legacy in ("inkblade demo", "inkblade trial", "inkblade doctor", "mock"):
            self.assertNotIn(legacy, lowered, f"legacy onboarding wording in USAGE.md: {legacy}")


if __name__ == "__main__":
    unittest.main()
