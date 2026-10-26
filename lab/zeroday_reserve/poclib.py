# -*- coding: utf-8 -*-
"""Shared helpers for the standalone 0day-reserve cases."""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

CASE_DIR = Path(os.environ.get("ZERODAY_CASE_DIR", Path(__file__).resolve().parent)).resolve()
EVIDENCE_DIR = Path(os.environ.get("ZERODAY_EVIDENCE_DIR", CASE_DIR / "evidence")).resolve()
MARKER_FILE = Path(os.environ.get("ZERODAY_MARKER_FILE", EVIDENCE_DIR / "marker.txt")).resolve()
MARKER_TEXT = os.environ.get("ZERODAY_MARKER_TEXT", "TRIDENT-ZERODAY-PROOF")
LAB_ROOT = Path(__file__).resolve().parent
REPO_ROOT = LAB_ROOT.parents[1]
UPSTREAM = LAB_ROOT / "upstream"


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def rel(path: str | Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(REPO_ROOT)).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def upstream_path(relative: str | Path) -> Path:
    return UPSTREAM / Path(relative)


def start_marker() -> None:
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    if MARKER_FILE.exists():
        MARKER_FILE.unlink()


def mark(text: str | None = None) -> None:
    MARKER_FILE.parent.mkdir(parents=True, exist_ok=True)
    MARKER_FILE.write_text(text or MARKER_TEXT, encoding="utf-8")


def marker_ok() -> bool:
    return MARKER_FILE.is_file() and MARKER_TEXT in MARKER_FILE.read_text(encoding="utf-8", errors="replace")


def fail(message: str, **extra) -> None:
    payload = {"status": "failed", "error": message, **extra}
    (EVIDENCE_DIR / "failure.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(payload, ensure_ascii=False), file=sys.stderr)
    raise SystemExit(1)


def finish_verified(payload: dict) -> None:
    if not marker_ok():
        fail("proof marker is missing")
    payload = dict(payload)
    payload["status"] = "verified"
    payload["marker"] = MARKER_TEXT
    payload["marker_path"] = rel(MARKER_FILE)
    payload["marker_sha256"] = sha256_file(MARKER_FILE)
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    raise SystemExit(0)
