"""Static-only case check.

This is deliberately not an exploit.  It re-validates the pinned upstream
source line (or, when no source is vendored, the advisory anchor) and records
a ``static-only`` verdict.  Static cases are never placed in the registry's
``exploitable`` array.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
import poclib  # noqa: E402


def _normalize(text: str) -> str:
    return " ".join(text.strip().split())


def main() -> None:
    manifest = json.loads((poclib.CASE_DIR / "manifest.json").read_text(encoding="utf-8"))
    rc = manifest.get("root_cause") or {}
    source = rc.get("source")
    expected = rc.get("snippet") or ""
    evidence = {
        "case_id": manifest.get("id"),
        "root_cause": {k: rc.get(k) for k in ("file", "line", "function", "snippet", "note")},
        "advisory": manifest.get("advisory"),
        "verdict": manifest.get("static_verdict", "not-dynamically-verified"),
    }

    if source:
        path = poclib.upstream_path(source)
        if not path.is_file():
            poclib.static_result(manifest, ok=False, evidence={**evidence, "error": f"missing source {path}"})
        data = path.read_bytes()
        text = data.decode("utf-8", errors="replace")
        lines = text.splitlines()
        line = int(rc.get("line") or 0)
        actual = lines[line - 1] if 0 < line <= len(lines) else ""
        source_ok = bool(expected) and (
            _normalize(expected) in _normalize(actual) or _normalize(actual) in _normalize(expected)
        )
        if manifest.get("static_evidence_level") == "source-line" and not source_ok:
            poclib.static_result(
                manifest,
                ok=False,
                evidence={
                    **evidence,
                    "source": poclib.rel(path),
                    "expected": expected,
                    "actual": actual,
                    "error": "pinned line does not match claimed snippet",
                },
            )
        evidence.update(
            {
                "source": poclib.rel(path),
                "source_sha256": poclib.sha256_file(path),
                "source_size": len(data),
                "line": line,
                "actual_line": actual.strip(),
                "line_matches": source_ok,
                "source_line_verified": source_ok,
            }
        )
    else:
        if manifest.get("static_evidence_level") == "source-line":
            poclib.static_result(manifest, ok=False, evidence={**evidence, "error": "source-line level without source"})
        evidence["source_line_verified"] = False
        evidence["advisory_sha256"] = poclib.sha256_text(str(manifest.get("advisory") or ""))

    evidence["analysis"] = manifest.get("static_analysis") or ""
    poclib.static_result(manifest, ok=True, evidence=evidence)


if __name__ == "__main__":
    main()
