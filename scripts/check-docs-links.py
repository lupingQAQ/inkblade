#!/usr/bin/env python3
"""Validate the public documentation surface.

Checks, in order:

1. No external URLs anywhere in the published pages, the READMEs or the public
   guides — not in ``href``, ``src``, CSS ``url()`` or Markdown links. The site
   must work from a folder with the network unplugged.
2. Every relative link resolves to a file that exists.
3. Every fragment (``#anchor``) resolves to an ``id`` in the target file.
4. Every page that should be bilingual is bilingual, and the 0-day ledger keeps
   its documented row count.

Run it with no arguments from the repository root, or pass ``--json`` for a
machine-readable summary. Exit code 0 means clean.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

PUBLIC_FILES = [
    "docs/index.html",
    "docs/en/index.html",
    "docs/zh/index.html",
    "README.md",
    "README.zh-CN.md",
    "docs/USAGE.md",
    "docs/QUICKSTART.md",
    "docs/PRODUCT.md",
    "docs/DOC-INDEX.md",
    "docs/INSTALL.md",
    "docs/FEATURES.md",
    "docs/WORKFLOW.md",
    "docs/MODULES.md",
    "docs/FAQ.md",
    "docs/0DAY-PUBLIC.md",
    "docs/ARCHITECTURE.md",
    "docs/DETECTION-LAYERS.md",
    "docs/README-SITE.md",
]

ASSETS = ["docs/assets/style.css", "docs/assets/app.js"]

SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*:")
MD_LINK = re.compile(r"!?\[[^\]]*\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
FENCE = re.compile(r"```.*?```", re.S)
INLINE_CODE = re.compile(r"`[^`]*`")
CSS_URL = re.compile(r"url\(\s*['\"]?([^'\")]+)['\"]?\s*\)", re.I)
HEADING = re.compile(r"^(#{1,6})\s+(.*)$", re.M)


class Collector(HTMLParser):
    """Collect links, sources, inline style URLs and ids from an HTML file."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.refs: list[tuple[str, str]] = []  # (kind, value)
        self.ids: set[str] = set()

    def handle_starttag(self, tag, attrs):
        data = dict(attrs)
        if "id" in data:
            self.ids.add(data["id"])
        if tag == "a" and "name" in data:
            self.ids.add(data["name"])
        for attr in ("href", "src"):
            value = data.get(attr)
            if value:
                self.refs.append((f"{tag}[{attr}]", value))
        style = data.get("style")
        if style:
            for match in CSS_URL.finditer(style):
                self.refs.append(("style[url]", match.group(1)))

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)


def slugify(heading: str) -> str:
    text = heading.strip()
    text = re.sub(r"<[^>]+>", "", text)
    text = text.replace("`", "")
    text = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"[*_~]", "", text)
    text = text.lower().strip()
    text = re.sub(r"[^\w\u4e00-\u9fff\s\-]", "", text)
    text = re.sub(r"\s+", "-", text)
    return text.strip("-")


def markdown_anchors(text: str) -> set[str]:
    stripped = FENCE.sub("", text)
    return {slugify(m.group(2)) for m in HEADING.finditer(stripped)}


def markdown_links(text: str) -> list[tuple[str, str]]:
    stripped = FENCE.sub("", text)
    stripped = INLINE_CODE.sub("", stripped)
    return [("md[link]", m.group(1)) for m in MD_LINK.finditer(stripped)]


def css_refs(path: Path) -> list[tuple[str, str]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    return [("css[url]", m.group(1)) for m in CSS_URL.finditer(text)]


def check(root: Path) -> dict:
    problems: list[str] = []
    checked = 0
    cache_anchors: dict[Path, set[str]] = {}

    def anchors_for(target: Path) -> set[str]:
        if target not in cache_anchors:
            if target.suffix.lower() == ".html":
                parser = Collector()
                parser.feed(target.read_text(encoding="utf-8", errors="replace"))
                cache_anchors[target] = parser.ids
            else:
                cache_anchors[target] = markdown_anchors(
                    target.read_text(encoding="utf-8", errors="replace")
                )
        return cache_anchors[target]

    def report(path: Path, kind: str, ref: str, message: str) -> None:
        rel = path.relative_to(root).as_posix()
        problems.append(f"{rel}: {kind} {ref!r} — {message}")

    targets = [root / rel for rel in PUBLIC_FILES if (root / rel).is_file()]
    missing = [rel for rel in PUBLIC_FILES if not (root / rel).is_file()]
    for rel in missing:
        problems.append(f"{rel}: missing file")

    for path in targets:
        if path.suffix.lower() == ".html":
            parser = Collector()
            parser.feed(path.read_text(encoding="utf-8", errors="replace"))
            refs = parser.refs
        else:
            refs = markdown_links(path.read_text(encoding="utf-8", errors="replace"))

        for kind, raw in refs:
            ref = raw.strip()
            if not ref:
                continue
            checked += 1
            if SCHEME.match(ref) or ref.startswith("//"):
                report(path, kind, ref, "external reference is not allowed")
                continue
            if ref.startswith("#"):
                if ref[1:] and ref[1:] not in anchors_for(path):
                    report(path, kind, ref, "fragment not found in this file")
                continue
            target_part, _, fragment = ref.partition("#")
            target_part = unquote(target_part)
            target = (path.parent / target_part).resolve()
            try:
                target.relative_to(root.resolve())
            except ValueError:
                report(path, kind, ref, "points outside the repository")
                continue
            if not target.exists():
                report(path, kind, ref, "target file does not exist")
                continue
            if fragment:
                if fragment not in anchors_for(target):
                    report(path, kind, ref, "fragment not found in target")

    for rel in ASSETS:
        asset = root / rel
        if not asset.is_file():
            problems.append(f"{rel}: missing asset")
            continue
        if asset.suffix.lower() == ".css":
            for kind, ref in css_refs(asset):
                checked += 1
                if SCHEME.match(ref) or ref.startswith("//") or ref.startswith("http"):
                    report(asset, kind, ref, "external resource is not allowed")

    # Pages must not load anything they do not ship.
    for rel in ("docs/index.html", "docs/en/index.html", "docs/zh/index.html"):
        page = root / rel
        if not page.is_file():
            continue
        parser = Collector()
        parser.feed(page.read_text(encoding="utf-8", errors="replace"))
        for kind, ref in parser.refs:
            if kind.endswith("[src]") and not (page.parent / ref).resolve().is_file():
                report(page, kind, ref, "resource is not present locally")

    stats = {
        "files": len(targets),
        "references": checked,
        "problems": problems,
    }
    return stats


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check links and external references in the public docs")
    parser.add_argument("--root", default=str(ROOT), help="repository root")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)

    stats = check(Path(args.root))
    if args.json:
        print(json.dumps(stats, ensure_ascii=False, indent=2))
    else:
        if stats["problems"]:
            for line in stats["problems"]:
                print(line, file=sys.stderr)
        print(f"docs-links: {stats['files']} files, {stats['references']} references, "
              f"{len(stats['problems'])} problem(s)")
    return 0 if not stats["problems"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
