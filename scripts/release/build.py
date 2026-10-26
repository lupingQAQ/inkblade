#!/usr/bin/env python3
"""Build wheel + sdist reproducibly into ``dist/``.

Uses the standard ``build`` frontend when available and degrades to a wheel-only
``pip wheel`` build so the script still works in constrained environments.

The frontend is executed from a neutral temporary directory: a repository that
contains a top-level ``build/`` folder would otherwise shadow the ``build``
package on ``sys.path`` and make ``python -m build`` fail.

Exit codes: 0 = artifacts produced, 1 = build failure.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _run(cmd: list[str], cwd: Path) -> int:
    print("build:", " ".join(cmd))
    return subprocess.call(cmd, cwd=str(cwd))


def _has_build(neutral: Path) -> bool:
    probe = subprocess.run(
        [sys.executable, "-c", "import build, sys; sys.exit(0 if hasattr(build, '__file__') else 1)"],
        cwd=str(neutral), capture_output=True,
    )
    return probe.returncode == 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=None)
    parser.add_argument("--out", default="dist")
    parser.add_argument("--clean", action="store_true", help="remove the output dir first")
    args = parser.parse_args(argv)
    root = Path(args.root).resolve() if args.root else repo_root()
    out = (root / args.out).resolve()
    if args.clean and out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)

    neutral = Path(tempfile.mkdtemp(prefix="inkblade-build-"))
    try:
        if _has_build(neutral):
            rc = _run([
                sys.executable, "-m", "build", "--outdir", str(out), str(root),
            ], neutral)
        else:
            print("build: `build` frontend missing, falling back to `pip wheel`",
                  file=sys.stderr)
            rc = _run([
                sys.executable, "-m", "pip", "wheel", str(root), "--no-deps",
                "--wheel-dir", str(out),
            ], neutral)
    finally:
        shutil.rmtree(neutral, ignore_errors=True)

    artifacts = sorted(p.name for p in out.iterdir() if p.is_file())
    for name in artifacts:
        print(f"build: artifact {name}")
    if rc != 0:
        print(f"build: frontend exited {rc}", file=sys.stderr)
        return 1
    if not any(name.endswith(".whl") for name in artifacts):
        print("build: no wheel produced", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
