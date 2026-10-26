#!/usr/bin/env python3
"""Stage the public documentation site into a directory for GitHub Pages.

Only an allowlist is copied. The repository also contains design notes, lab
records and vendor-report material that must never be served from a public URL;
pointing Pages at ``docs/`` wholesale would publish all of it.

    python scripts/build-pages-site.py --out _site

The staged tree contains no external references; ``scripts/check-docs-links.py``
verifies that before this script runs in CI.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

FILES = [
    "index.html",
    "en/index.html",
    "zh/index.html",
    "assets/style.css",
    "assets/app.js",
    ".nojekyll",
    "USAGE.md",
    "INSTALL.md",
    "FEATURES.md",
    "WORKFLOW.md",
    "MODULES.md",
    "FAQ.md",
    "0DAY-PUBLIC.md",
    "ARCHITECTURE.md",
    "DETECTION-LAYERS.md",
    "AI-SCAN-RESULT.md",
    "README-SITE.md",
]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Stage the public docs site")
    parser.add_argument("--out", default="_site", help="output directory (recreated)")
    args = parser.parse_args(argv)

    out = (ROOT / args.out).resolve()
    if ROOT not in out.parents and out != ROOT:
        print(f"refusing to write outside the repository: {out}", file=sys.stderr)
        return 2
    if out == ROOT:
        print("refusing to use the repository root as output", file=sys.stderr)
        return 2

    missing = [rel for rel in FILES if not (DOCS / rel).is_file()]
    if missing:
        for rel in missing:
            print(f"missing: docs/{rel}", file=sys.stderr)
        return 1

    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    for rel in FILES:
        target = out / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(DOCS / rel, target)

    total = sum(1 for path in out.rglob("*") if path.is_file())
    print(f"staged {total} files into {Path(args.out).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
