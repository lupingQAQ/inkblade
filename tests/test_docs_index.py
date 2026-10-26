# -*- coding: utf-8 -*-
"""Documentation index and probe-architecture doc checks.

These tests keep the product docs and the index from drifting apart:

- the probe-centric documents exist and are linked from the index;
- every Markdown document under ``docs/`` appears in ``docs/DOC-INDEX.md``;
- every relative link in the index resolves inside the repository;
- the touched documents contain no external URL or local machine path;
- each touched document ends with an evidence/limits section.
"""

from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
INDEX = DOCS / "DOC-INDEX.md"

REQUIRED = [
    "README.md",
    "README.zh-CN.md",
    "docs/PRODUCT.md",
    "docs/ARCHITECTURE-PROBE.md",
    "docs/PROBE-PROTOCOL.md",
    "docs/PROBE-DEPLOY.md",
    "docs/DYNAMIC-VERIFICATION.md",
    "docs/INSTALL.md",
    "docs/USAGE.md",
    "docs/FAQ.md",
    "docs/DOC-INDEX.md",
    "docs/HOW-TO-DESIGN-COMMERCIAL-AGENT.md",
]

TOUCHED = [
    "README.md",
    "README.zh-CN.md",
    "docs/PRODUCT.md",
    "docs/ARCHITECTURE-PROBE.md",
    "docs/PROBE-PROTOCOL.md",
    "docs/PROBE-DEPLOY.md",
    "docs/DYNAMIC-VERIFICATION.md",
    "docs/INSTALL.md",
    "docs/USAGE.md",
    "docs/FAQ.md",
    "docs/DOC-INDEX.md",
    "docs/HOW-TO-DESIGN-COMMERCIAL-AGENT.md",
]

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
        self.assertEqual(missing, [], f"缺少文档: {missing}")

    def test_every_markdown_doc_is_in_index(self):
        text = INDEX.read_text(encoding="utf-8")
        linked = {
            unquote(ref)
            for ref in MD_LINK.findall(FENCE.sub("", text))
            if ref.endswith(".md") and not ref.startswith("#")
        }
        try:
            tracked = subprocess.check_output(
                ["git", "ls-files", "docs"], cwd=ROOT, text=True, stderr=subprocess.DEVNULL
            ).splitlines()
            docs = {Path(rel).name for rel in tracked if rel.endswith(".md")}
        except (OSError, subprocess.CalledProcessError):
            docs = {path.name for path in DOCS.glob("*.md")}
        missing = sorted(docs - linked)
        self.assertEqual(missing, [], f"DOC-INDEX 未收录: {missing}")
        extra = sorted(name for name in linked if name not in docs and (DOCS / name).exists())
        self.assertEqual(extra, [], f"DOC-INDEX 链接了未跟踪文档: {extra}")

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
        self.assertEqual(broken, [], f"DOC-INDEX 存在失效链接: {broken}")

    def test_touched_docs_have_no_external_links(self):
        bad = {}
        for rel in TOUCHED:
            hits = EXTERNAL.findall(read(rel))
            if hits:
                bad[rel] = len(hits)
        self.assertEqual(bad, {}, f"文档包含外链: {bad}")

    def test_touched_docs_have_no_local_markers(self):
        bad = {}
        for rel in TOUCHED:
            text = read(rel)
            hits = [token for token in LOCAL_TOKENS if token in text]
            if DRIVE.search(text):
                hits.append("drive-path")
            if hits:
                bad[rel] = hits
        self.assertEqual(bad, {}, f"文档包含本地路径/工作区标记: {bad}")

    def test_touched_docs_have_evidence_and_limits(self):
        missing = [rel for rel in TOUCHED if "证据 / 限制" not in read(rel)]
        self.assertEqual(missing, [], f"缺少「证据 / 限制」小节: {missing}")

    def test_probe_docs_state_target_side_boundary(self):
        arch = read("docs/ARCHITECTURE-PROBE.md")
        for phrase in ("目标侧零 Python", "probe_id", "parent_id", "http", "tcp",
                       "exec", "fs", "k8s", "socks", "spawn"):
            self.assertIn(phrase, arch, f"架构文档缺少: {phrase}")
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
            self.assertIn(key, product, f"产品文档缺少防护绕过模块: {key}")

    def test_quick_start_uses_probe_flow(self):
        text = read("docs/USAGE.md")
        for command in ("doctor", "session start", "probe deploy", "exec", "scan", "report"):
            self.assertIn(command, text, f"使用手册缺少命令: {command}")


if __name__ == "__main__":
    unittest.main()
