#!/usr/bin/env python3
"""cosign keyless signature bundles for release artifacts (best effort).

Signs every distributable in ``--dist`` with Sigstore keyless (Fulcio + Rekor)
and writes ``<artifact>.sigstore.json`` bundles next to the artifact.

Exit codes:
  0 = all artifacts signed, or signing skipped because cosign is absent
  1 = cosign present but at least one signature failed

The CI workflow treats the same operation as non-blocking; this script is for
maintainers who want a hard failure locally.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def targets(dist: Path) -> list[Path]:
    out: list[Path] = []
    for path in sorted(dist.iterdir()):
        if not path.is_file() or path.name.endswith(".sigstore.json"):
            continue
        if (
            path.name.endswith(".whl")
            or path.name.endswith(".tar.gz")
            or path.name.endswith(".json")
            or path.name == "SHA256SUMS"
        ):
            out.append(path)
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=None)
    parser.add_argument("--dist", default="dist")
    parser.add_argument("--identity", default=None,
                        help="expected certificate identity (verification only)")
    parser.add_argument("--verify", action="store_true",
                        help="verify existing bundles instead of signing")
    args = parser.parse_args(argv)
    root = Path(args.root).resolve() if args.root else repo_root()
    dist = (root / args.dist).resolve()
    if not dist.is_dir():
        print(f"sign: no dist directory at {dist}", file=sys.stderr)
        return 1

    cosign = shutil.which("cosign")
    if not cosign:
        print("sign: SKIPPED - cosign not on PATH "
              "(install: https://docs.sigstore.dev/cosign/installation/)")
        return 0

    files = targets(dist)
    if not files:
        print(f"sign: no artifacts in {dist}", file=sys.stderr)
        return 1

    failures = 0
    for path in files:
        bundle = path.with_name(path.name + ".sigstore.json")
        if args.verify:
            cmd = [cosign, "verify-blob", "--bundle", str(bundle), str(path)]
            if args.identity:
                cmd += [
                    "--certificate-identity-regexp", args.identity,
                    "--certificate-oidc-issuer",
                    "https://token.actions.githubusercontent.com",
                ]
        else:
            cmd = [cosign, "sign-blob", "--yes", "--bundle", str(bundle), str(path)]
        print("sign:", " ".join(cmd))
        rc = subprocess.call(cmd)
        if rc != 0:
            failures += 1
            print(f"sign: FAILED {path.name} (exit {rc})", file=sys.stderr)
    print(f"sign: {len(files) - failures}/{len(files)} ok")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
