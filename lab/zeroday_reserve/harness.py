# -*- coding: utf-8 -*-
"""Run one 0day-reserve case and write a hash-pinned result.json.

Usage::

    python tools/run-zeroday-cases.py --all
    python tools/run-zeroday-cases.py --id vllm-rl-dev-auth-bypass
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CASES = Path(__file__).resolve().parent / "cases"
DATA = Path(__file__).resolve().parent
WORKSPACE = ROOT.parents[1]


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def rel(path: Path) -> str:
    return str(path.resolve().relative_to(ROOT)).replace("\\", "/")


_DRIVE_PATH_RE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]:[\\/][^\s\"'<>|]+")
_TEXT_SUFFIXES = {".txt", ".log", ".json", ".yaml", ".yml", ".md", ".py"}


def sanitize_text(text: str) -> str:
    for old, new in ((str(ROOT), "<repo>"), (str(WORKSPACE), "<workspace>"),
                     (str(ROOT).replace("\\", "/"), "<repo>"),
                     (str(WORKSPACE).replace("\\", "/"), "<workspace>")):
        text = text.replace(old, new)
    return _DRIVE_PATH_RE.sub("<path>", text)


def sanitize_obj(obj):
    if isinstance(obj, str):
        return sanitize_text(obj)
    if isinstance(obj, list):
        return [sanitize_obj(x) for x in obj]
    if isinstance(obj, dict):
        return {k: sanitize_obj(v) for k, v in obj.items()}
    return obj


def sanitize_evidence(case_dir: Path) -> None:
    for path in (case_dir / "evidence").rglob("*"):
        if not path.is_file() or path.suffix.lower() not in _TEXT_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        cleaned = sanitize_text(text)
        if cleaned != text:
            path.write_text(cleaned, encoding="utf-8")


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def case_dirs() -> list[Path]:
    return sorted(p.parent for p in CASES.glob("*/manifest.json"))


def find_case(case_id: str) -> Path:
    for case_dir in case_dirs():
        manifest = load(case_dir / "manifest.json")
        if manifest.get("id") == case_id or case_dir.name == case_id:
            return case_dir
    raise SystemExit(f"unknown case id: {case_id}")


def run_case(case_dir: Path, *, timeout: int = 300) -> dict:
    case_dir = case_dir.resolve()
    manifest = load(case_dir / "manifest.json")
    evidence = case_dir / "evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    marker = evidence / "marker.txt"
    if marker.exists():
        marker.unlink()
    env = dict(os.environ)
    env.update({
        "ZERODAY_CASE_DIR": str(case_dir),
        "ZERODAY_EVIDENCE_DIR": str(evidence),
        "ZERODAY_MARKER_FILE": str(marker),
        "ZERODAY_MARKER_TEXT": manifest["marker_text"],
        "PYTHONPATH": str(ROOT) + os.pathsep + str(DATA) + os.pathsep + env.get("PYTHONPATH", ""),
    })
    started = time.time()
    try:
        proc = subprocess.run([sys.executable, str(case_dir / "poc.py")], cwd=case_dir, env=env,
                              capture_output=True, text=True, timeout=timeout)
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        proc = exc
        timed_out = True
    duration = round(time.time() - started, 3)
    stdout = (proc.stdout or "") if not isinstance(proc.stdout, bytes) else proc.stdout.decode(errors="replace")
    stderr = (proc.stderr or "") if not isinstance(proc.stderr, bytes) else proc.stderr.decode(errors="replace")
    stdout = sanitize_text(stdout)
    stderr = sanitize_text(stderr)
    sanitize_evidence(case_dir)
    exit_code = None if timed_out else proc.returncode
    after = marker.read_text(encoding="utf-8", errors="replace") if marker.is_file() else ""
    verified = bool(exit_code == 0 and manifest["marker_text"] in after and not timed_out)

    evidence_files = []
    for path in sorted(p for p in evidence.rglob("*") if p.is_file()):
        evidence_files.append({"path": rel(path), "sha256": sha256_file(path), "size": path.stat().st_size})

    source = manifest.get("root_cause", {}).get("source")
    source_sha = None
    if source:
        source_path = Path(source)
        if not source_path.is_absolute():
            source_path = ROOT / source_path
        if source_path.is_file():
            source_sha = sha256_file(source_path)
    result = {
        "schema": "inkblade-zeroday-result-v1",
        "id": manifest["id"],
        "component": manifest.get("component"),
        "title": manifest.get("title"),
        "status": "verified" if verified else "failed",
        "verified": verified,
        "method": manifest.get("method"),
        "version": manifest.get("version"),
        "version_ref": manifest.get("version_ref"),
        "root_cause": manifest.get("root_cause"),
        "source_sha256": source_sha,
        "command": f"{sys.executable} {rel(case_dir / 'poc.py')}",
        "exit_code": exit_code,
        "timed_out": timed_out,
        "duration_s": duration,
        "started_at": now(),
        "marker": {"text": manifest["marker_text"], "after_has_marker": bool(manifest["marker_text"] in after),
                   "after_sha256": sha256_file(marker) if marker.is_file() else None},
        "stdout": stdout[-8000:],
        "stderr": stderr[-8000:],
        "evidence": evidence_files,
        "poc_sha256": sha256_file(case_dir / "poc.py"),
        "manifest_sha256": sha256_file(case_dir / "manifest.json"),
        "notes": manifest.get("notes", ""),
    }
    for line in reversed(stdout.strip().splitlines()):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict) and payload.get("status") == "verified":
            result["payload"] = payload
            break
    result = sanitize_obj(result)
    (case_dir / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=1, sort_keys=True),
                                          encoding="utf-8")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run 0day reserve dynamic cases")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--id", action="append", default=[])
    parser.add_argument("--timeout", type=int, default=300)
    args = parser.parse_args(argv)
    if not args.all and not args.id:
        parser.error("pass --all or --id")
    dirs = case_dirs() if args.all else [find_case(i) for i in args.id]
    failed = 0
    for case_dir in dirs:
        result = run_case(case_dir, timeout=args.timeout)
        print(f"{result['id']}: {result['status']} exit={result['exit_code']} marker={result['marker']['after_has_marker']}")
        if not result["verified"]:
            failed += 1
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
