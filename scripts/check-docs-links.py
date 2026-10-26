#!/usr/bin/env python3
"""Validate the public documentation surface.

1. No external URLs anywhere in the published pages, the READMEs or the guides.
2. Every relative link resolves to a file that exists.
3. Every fragment (``#anchor``) resolves to an ``id`` in the target file.

Exit code 0 means clean. ``--json`` prints a machine-readable summary.
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
    "README.md",
    "README.zh-CN.md",
] + [
    f"docs/{name}"
    for name in (
        "INSTALL.html", "USAGE.html", "FEATURES.html", "WORKFLOW.html",
        "MODULES.html", "ARCHITECTURE.html", "AGENT-LLM.html",
        "VULNERABILITY-COVERAGE.html",
        "PILOT-KIT.html", "PLUGIN-SDK.html", "FAQ.html", "VERSIONING.html",
        "README-SITE.md", "INSTALL.md", "USAGE.md", "FEATURES.md",
        "WORKFLOW.md", "MODULES.md", "ARCHITECTURE.md", "AGENT-LLM.md",
        "VULNERABILITY-COVERAGE.md", "PILOT-KIT.md", "PLUGIN-SDK.md",
        "FAQ.md", "VERSIONING.md",
    )
]

ASSETS = ["docs/assets/style.css"]

SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*:")
MD_LINK = re.compile(r"!?\[[^\]]*\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
FENCE = re.compile(r"```.*?```", re.S)
INLINE_CODE = re.compile(r"`[^`]*`")
CSS_URL = re.compile(r"url\(\s*['\"]?([^'\")]+)['\"]?\s*\)", re.I)
HEADING = re.compile(r"^(#{1,6})\s+(.*)$", re.M)


class Collector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.ids: set[str] = set()
        self.external: list[str] = []

    def handle_starttag(self, tag, attrs):
        data = dict(attrs)
        if "id" in data:
            self.ids.add(data["id"])
        for key in ("href", "src"):
            value = data.get(key)
            if not value:
                continue
            if value.startswith("data:"):
                continue
            if SCHEME.match(value) or value.startswith("//"):
                self.external.append(f"<{tag} {key}={value}>")
            else:
                self.links.append(value)
        style = data.get("style") or ""
        if "url(" in style.lower():
            self.external.append(f"<{tag} style={style}>")


def md_anchors(path: Path) -> set[str]:
    ids: set[str] = set()
    for _level, title in HEADING.findall(path.read_text(encoding="utf-8")):
        text = re.sub(r"`", "", title)
        text = re.sub(r"[^\w\u4e00-\u9fff -]", "", text).strip().lower()
        ids.add(re.sub(r"\s+", "-", text))
    return ids


def check() -> list[str]:
    problems: list[str] = []
    cache: dict[Path, tuple[set[str], list[str]]] = {}

    def load(path: Path) -> tuple[set[str], list[str]]:
        if path in cache:
            return cache[path]
        if path.suffix in (".html", ".htm"):
            parser = Collector()
            parser.feed(path.read_text(encoding="utf-8"))
            result = (parser.ids, parser.links + parser.external)
            problems.extend(f"{path.relative_to(ROOT).as_posix()}: external {item}"
                            for item in parser.external)
        elif path.suffix == ".md":
            text = path.read_text(encoding="utf-8")
            body = INLINE_CODE.sub("", FENCE.sub("", text))
            links = [m.group(1) for m in MD_LINK.finditer(body)]
            external = [link for link in links if SCHEME.match(link) or link.startswith("//")]
            problems.extend(f"{path.relative_to(ROOT).as_posix()}: external {item}"
                            for item in external)
            result = (md_anchors(path), [link for link in links if link not in external])
        else:
            result = (set(), [])
        cache[path] = result
        return result

    for asset in ASSETS:
        path = ROOT / asset
        if not path.is_file():
            problems.append(f"{asset}: missing asset")
            continue
        for match in CSS_URL.finditer(path.read_text(encoding="utf-8")):
            target = match.group(1)
            if SCHEME.match(target) or target.startswith("//"):
                problems.append(f"{asset}: external {target}")

    for rel in PUBLIC_FILES:
        path = ROOT / rel
        if not path.is_file():
            problems.append(f"{rel}: missing")
            continue
        ids, links = load(path)
        for link in links:
            if not link or link.startswith("mailto:"):
                continue
            target, _, fragment = link.partition("#")
            target = target.split("?")[0]
            resolved = path if not target else (path.parent / unquote(target)).resolve()
            if not target:
                if fragment and fragment not in ids:
                    problems.append(f"{rel}: missing anchor #{fragment}")
                continue
            if not resolved.is_file():
                problems.append(f"{rel}: broken link {link}")
                continue
            if fragment:
                target_ids, _ = load(resolved)
                if fragment not in target_ids:
                    problems.append(f"{rel}: missing anchor {link}")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="InkBlade docs link checker")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    problems = check()
    if args.json:
        print(json.dumps({"ok": not problems, "problems": problems},
                         ensure_ascii=False, indent=2))
    else:
        for item in problems:
            print(item, file=sys.stderr)
        print(f"docs-links: {len(problems)} problem(s)")
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
