"""Shared helpers for upstream-verification PoCs.

PoCs are executed by ``lab.upstream_verify.harness`` with these environment
variables set:

* ``UV_CASE_DIR``      absolute case directory (contains manifest.json / poc.py)
* ``UV_EVIDENCE_DIR``  absolute evidence directory
* ``UV_REPO_ROOT``     repository root
* ``UV_MARKER_TEXT``   marker string the case must prove
* ``UV_MARKER``        marker file path (inside the evidence directory)

The module intentionally has no third-party dependency so it can be imported
by every component venv used by the pipeline.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path

CASE_DIR = Path(os.environ.get("UV_CASE_DIR") or Path(__file__).resolve().parent)
EVIDENCE_DIR = Path(os.environ.get("UV_EVIDENCE_DIR") or (CASE_DIR / "evidence"))
MARKER_FILE = Path(os.environ.get("UV_MARKER") or (EVIDENCE_DIR / "marker.txt"))
MARKER_TEXT = os.environ.get("UV_MARKER_TEXT") or "TRIDENT-UPSTREAM-VERIFIED"
REPO_ROOT = Path(os.environ.get("UV_REPO_ROOT") or Path(__file__).resolve().parents[2])

EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def rel(path: str | Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(REPO_ROOT)).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def write_json(name: str, payload: dict) -> Path:
    path = EVIDENCE_DIR / name
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")
    return path


def read_text(path: str | Path, default: str = "") -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return default


def start_marker(text: str = "ABSENT") -> str:
    """Reset the marker to a known non-proof value and return the old state."""
    old = read_text(MARKER_FILE, "")
    MARKER_FILE.write_text(text, encoding="utf-8")
    return old


def prove_marker(text: str | None = None) -> None:
    MARKER_FILE.write_text(text or MARKER_TEXT, encoding="utf-8")


def marker_ok(text: str | None = None) -> bool:
    return (text or MARKER_TEXT) in read_text(MARKER_FILE, "")


def finish_verified(payload: dict, *, marker: str | None = None) -> None:
    """Write run.json and exit 0 only if the marker proof is present."""
    text = marker or MARKER_TEXT
    if text not in read_text(MARKER_FILE, ""):
        fail("marker not observed after exploit", **payload)
    payload = dict(payload)
    payload.update(
        {
            "schema": "trident-upstream-run-v1",
            "status": "verified",
            "finished_at": now(),
            "marker_text": text,
            "marker_file": rel(MARKER_FILE),
            "marker_sha256": sha256_file(MARKER_FILE),
            "exit_code": 0,
        }
    )
    write_json("run.json", payload)
    print(json.dumps({"status": "verified", "marker": text, "evidence": rel(EVIDENCE_DIR)}))
    sys.exit(0)


def fail(message: str, **extra) -> None:
    payload = {
        "schema": "trident-upstream-run-v1",
        "status": "failed",
        "finished_at": now(),
        "error": message,
        "traceback": traceback.format_exc(),
        "evidence_dir": rel(EVIDENCE_DIR),
    }
    payload.update(extra)
    write_json("run.json", payload)
    print(json.dumps({"status": "failed", "error": message}, ensure_ascii=False))
    sys.exit(1)


def require(condition: bool, message: str, **extra) -> None:
    if not condition:
        fail(message, **extra)


def upstream_path(relative: str) -> Path:
    """Resolve a repository-relative upstream source path."""
    path = Path(relative)
    return path if path.is_absolute() else REPO_ROOT / path


def static_result(manifest: dict, *, ok: bool, evidence: dict) -> None:
    payload = {
        "schema": "trident-upstream-static-check-v1",
        "status": "static-only" if ok else "failed",
        "finished_at": now(),
        "case_id": manifest.get("id"),
        "source_level": manifest.get("static_evidence_level", "advisory"),
        "evidence": evidence,
    }
    write_json("static-check.json", payload)
    print(json.dumps({"status": payload["status"], "case": manifest.get("id")}, ensure_ascii=False))
    sys.exit(0 if ok else 1)


def unsupported_result(manifest: dict, *, reason: str, evidence: dict | None = None) -> None:
    payload = {
        "schema": "trident-upstream-unsupported-v1",
        "status": "unsupported",
        "finished_at": now(),
        "case_id": manifest.get("id"),
        "reason": reason,
        "evidence": evidence or {},
    }
    write_json("unsupported.json", payload)
    print(json.dumps({"status": "unsupported", "case": manifest.get("id"), "reason": reason}, ensure_ascii=False))
    sys.exit(0)
