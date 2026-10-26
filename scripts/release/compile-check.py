#!/usr/bin/env python3
"""Byte-compile every first-party package listed in pyproject.toml.

Name-agnostic: the package directory is derived from
``[tool.setuptools.packages.find].include`` so this keeps working across the
Trident -> InkBlade rename without edits.

Exit codes: 0 = all modules compiled, 1 = syntax errors found.
"""
from __future__ import annotations

import argparse
import compileall
import sys
from pathlib import Path

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - 3.10 fallback
    tomllib = None  # type: ignore[assignment]

SKIP_DIR_NAMES = {
    "__pycache__", ".git", ".github", "build", "dist", "tests", "lab",
    "scripts", "docs", "corpus", "reports", "evidence", "disclosure", "tools",
}


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def package_roots(root: Path) -> list[Path]:
    """Return first-party package directories declared in pyproject.toml."""
    pyproject = root / "pyproject.toml"
    patterns: list[str] = []
    if tomllib and pyproject.is_file():
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        find = (
            data.get("tool", {})
            .get("setuptools", {})
            .get("packages", {})
            .get("find", {})
        )
        patterns = [str(p) for p in find.get("include", []) or []]
    if not patterns:
        # Fallback: any top-level directory containing __init__.py.
        patterns = [
            p.name for p in root.iterdir()
            if p.is_dir() and (p / "__init__.py").is_file()
        ]
    roots: list[Path] = []
    for pattern in patterns:
        base = pattern.split("*")[0].rstrip("/\\")
        target = root / base if base else root
        if target.is_dir() and target not in roots:
            roots.append(target)
    return roots


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=None, help="repository root (default: auto)")
    args = parser.parse_args(argv)
    root = Path(args.root).resolve() if args.root else repo_root()

    targets = package_roots(root)
    if not targets:
        print("compile-check: no first-party package found", file=sys.stderr)
        return 1

    ok = True
    for target in targets:
        rel = target.relative_to(root).as_posix()
        compiled = compileall.compile_dir(
            str(target), quiet=1, force=True, legacy=False,
            rx=None, workers=1,
        )
        print(f"compile-check: {rel} -> {'ok' if compiled else 'FAILED'}")
        ok = ok and compiled
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
