#!/usr/bin/env python3
"""Run the public test subset.

The public build ships the tests that do not need the private research
workspace: no synthetic range, no corpus cache, no internal evidence tree.
``tests/public-subset.txt`` lists the modules; everything else in ``tests/`` is
either absent or excluded on purpose.

    python scripts/run-public-tests.py          # quiet
    python scripts/run-public-tests.py -v       # verbose
"""

from __future__ import annotations

import argparse
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LIST = ROOT / "tests" / "public-subset.txt"


def load_names() -> list[str]:
    if not LIST.is_file():
        raise SystemExit(f"missing {LIST.relative_to(ROOT)}")
    names = []
    for raw in LIST.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            names.append(line)
    return names


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the public test subset")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    sys.path.insert(0, str(ROOT))
    names = load_names()
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    missing = []
    for name in names:
        try:
            suite.addTests(loader.loadTestsFromName(f"tests.{name}"))
        except Exception as exc:  # noqa: BLE001
            missing.append(f"{name}: {exc}")
    if missing:
        for item in missing:
            print(f"cannot load {item}", file=sys.stderr)
        return 2

    result = unittest.TextTestRunner(verbosity=2 if args.verbose else 1).run(suite)
    print(f"public subset: {len(names)} modules, "
          f"{result.testsRun} tests, {len(result.failures)} failures, "
          f"{len(result.errors)} errors")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
