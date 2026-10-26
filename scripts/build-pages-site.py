#!/usr/bin/env python3
"""Stage the documentation site for GitHub Pages.

The whole ``docs/`` tree is publishable now that it is curated, but the stage is
still explicit: an allowlist keeps a stray internal file from being served.

    python scripts/build-pages-site.py --out _site
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

GLOBS = [
    "*.html",
    "*.md",
    "assets/*.css",
    "assets/*.js",
    "assets/*.svg",
    ".nojekyll",
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
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    staged = 0
    for pattern in GLOBS:
        for src in sorted(DOCS.glob(pattern)):
            if not src.is_file():
                continue
            target = out / src.relative_to(DOCS)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, target)
            staged += 1

    if not (out / "index.html").is_file():
        print("missing index.html after staging", file=sys.stderr)
        return 1
    print(f"staged {staged} files into {Path(args.out).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
