#!/usr/bin/env python3
"""Generate a CycloneDX 1.5 JSON SBOM for the Python distribution.

No third-party dependencies: the document is assembled from pyproject metadata
plus SHA-256 hashes of the build artifacts.  Each artifact becomes a CycloneDX
``file`` component; the project itself is the metadata component.

Usage:
    python scripts/release/sbom.py --dist dist --out dist/sbom.cdx.json

Exit codes: 0 = SBOM written, 1 = no artifacts / unreadable metadata.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - 3.10 fallback
    tomllib = None  # type: ignore[assignment]

SPEC_VERSION = "1.5"
BOM_FORMAT = "CycloneDX"


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _git(root: Path, *args: str) -> str:
    try:
        proc = subprocess.run(["git", *args], cwd=str(root), capture_output=True, text=True)
    except OSError:
        return ""
    return (proc.stdout or "").strip() if proc.returncode == 0 else ""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _normalize(name: str) -> str:
    return name.strip().lower().replace("_", "-").replace(".", "-")


def build_sbom(root: Path, dist: Path) -> dict:
    pyproject = root / "pyproject.toml"
    if not tomllib or not pyproject.is_file():
        raise ValueError("pyproject.toml unreadable (python >= 3.11 tomllib required)")
    project = tomllib.loads(pyproject.read_text(encoding="utf-8")).get("project", {})
    name = str(project.get("name") or "")
    version = str(project.get("version") or "0.0.0")
    if not name:
        raise ValueError("pyproject.toml has no [project].name")
    license_text = str((project.get("license") or {}).get("text") or "Apache-2.0")
    urls = {str(k): str(v) for k, v in (project.get("urls") or {}).items()}
    repository = urls.get("Repository") or urls.get("Source") or ""
    vcs = _git(root, "rev-parse", "HEAD")
    branch = _git(root, "rev-parse", "--abbrev-ref", "HEAD")

    artifacts = sorted(p for p in dist.iterdir() if p.is_file()) if dist.is_dir() else []
    if not artifacts:
        raise ValueError(f"no build artifacts under {dist}")

    components = []
    for art in artifacts:
        if art.name.endswith(".json") and art.name.startswith("sbom"):
            continue
        components.append({
            "type": "file",
            "name": art.name,
            "hashes": [{"alg": "SHA-256", "content": _sha256(art)}],
            "properties": [{"name": "inkblade:artifact:size", "value": str(art.stat().st_size)}],
        })

    doc = {
        "bomFormat": BOM_FORMAT,
        "specVersion": SPEC_VERSION,
        "serialNumber": "urn:uuid:" + _stable_uuid(name, version, components),
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": [{"vendor": "InkBlade", "name": "scripts/release/sbom.py", "version": "1"}],
            "component": {
                "type": "application",
                "bom-ref": f"pkg:pypi/{_normalize(name)}@{version}",
                "name": name,
                "version": version,
                "licenses": [{"license": {"id": license_text}}],
                "purl": f"pkg:pypi/{_normalize(name)}@{version}",
                "externalReferences": (
                    [{"type": "vcs", "url": repository}] if repository else []
                ),
                "properties": [
                    {"name": "inkblade:git:commit", "value": vcs or "unknown"},
                    {"name": "inkblade:git:branch", "value": branch or "unknown"},
                    {"name": "inkblade:build:python", "value": sys.version.split()[0]},
                ],
            },
        },
        "components": components,
    }
    return doc


def _stable_uuid(name: str, version: str, components: list[dict]) -> str:
    seed = json.dumps([name, version, [c["hashes"][0]["content"] for c in components]])
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    return f"{digest[0:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=None)
    parser.add_argument("--dist", default="dist")
    parser.add_argument("--out", default="-", help="output path or '-' for stdout")
    args = parser.parse_args(argv)
    root = Path(args.root).resolve() if args.root else repo_root()
    dist = (root / args.dist).resolve()
    try:
        doc = build_sbom(root, dist)
    except ValueError as exc:
        print(f"sbom: {exc}", file=sys.stderr)
        return 1
    text = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
    if args.out == "-":
        sys.stdout.write(text)
    else:
        out = Path(args.out)
        if not out.is_absolute():
            out = root / out
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        print(f"sbom: {out} ({len(doc['components'])} file components)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
