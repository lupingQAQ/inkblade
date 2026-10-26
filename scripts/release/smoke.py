#!/usr/bin/env python3
"""Smoke-test the declared console entry point.

The entry point name and target are read from ``[project.scripts]`` in
pyproject.toml, so this script survives the Trident -> InkBlade rename.

Modes:
  * default  - import the target and run ``main(["--help"])`` (source tree)
  * --installed - resolve the console script on PATH and run ``--help``

Exit codes: 0 = help printed and exit status is 0, 1 = failure.
"""
from __future__ import annotations

import argparse
import importlib
import shutil
import subprocess
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - 3.10 fallback
    tomllib = None  # type: ignore[assignment]


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def read_scripts(root: Path) -> dict[str, str]:
    pyproject = root / "pyproject.toml"
    if not pyproject.is_file():
        raise SystemExit("smoke: pyproject.toml not found")
    text = pyproject.read_text(encoding="utf-8")
    if tomllib:
        data = tomllib.loads(text)
        scripts = (data.get("project", {}) or {}).get("scripts", {}) or {}
    else:  # Python 3.10: minimal [project.scripts] reader
        scripts = _read_scripts_fallback(text)
    if not scripts:
        raise SystemExit("smoke: no [project.scripts] entry declared")
    return {str(k): str(v) for k, v in scripts.items()}


def _read_scripts_fallback(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    section = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line
            continue
        if section != "[project.scripts]" or "=" not in line:
            continue
        key, _, value = line.partition("=")
        out[key.strip().strip("\"'")] = value.strip().strip("\"'")
    return out


def run_source(root: Path, name: str, target: str) -> int:
    sys.path.insert(0, str(root))
    module_name, _, attr = target.partition(":")
    module = importlib.import_module(module_name)
    func = module
    for part in (attr or "main").split("."):
        func = getattr(func, part)
    sys.argv = [name, "--help"]
    try:
        rc = func(["--help"])
    except SystemExit as exc:  # argparse --help
        rc = 0 if exc.code in (None, 0) else int(exc.code)
    print(f"smoke: {name} = {target} -> {rc}")
    return 0 if rc in (0, None) else 1


def run_installed(name: str) -> int:
    exe = shutil.which(name) or shutil.which(name + ".exe")
    if not exe:
        print(f"smoke: console script {name!r} not on PATH", file=sys.stderr)
        return 1
    proc = subprocess.run([exe, "--help"], capture_output=True, text=True)
    head = (proc.stdout or proc.stderr).splitlines()[:3]
    print(f"smoke: {exe} --help -> {proc.returncode}")
    for line in head:
        print(f"  | {line}")
    return 0 if proc.returncode == 0 else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=None)
    parser.add_argument("--installed", action="store_true")
    args = parser.parse_args(argv)
    root = Path(args.root).resolve() if args.root else repo_root()
    scripts = read_scripts(root)
    name, target = sorted(scripts.items())[0]
    if args.installed:
        return run_installed(name)
    return run_source(root, name, target)


if __name__ == "__main__":
    raise SystemExit(main())
