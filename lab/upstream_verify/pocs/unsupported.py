"""Unsupported case: records why the environment cannot host the vulnerable path."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
import poclib  # noqa: E402


def main() -> None:
    manifest = json.loads((poclib.CASE_DIR / "manifest.json").read_text(encoding="utf-8"))
    unsupported = manifest.get("unsupported") or {}
    poclib.unsupported_result(
        manifest,
        reason=unsupported.get("reason") or "no environment for this vulnerable path",
        evidence={
            "requires": unsupported.get("requires") or [],
            "blocked_by": unsupported.get("blocked_by") or [],
            "advisory": manifest.get("advisory"),
            "root_cause": manifest.get("root_cause"),
        },
    )


if __name__ == "__main__":
    main()
