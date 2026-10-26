"""example-hello - reference read-only module for the InkBlade plugin SDK.

What it demonstrates
--------------------
* the ``run(ctx, params) -> {"summary", "findings", "artifacts"}`` contract
* writing artifacts only under ``ctx["run"].dir``
* a deterministic, network-free collector (safe to run in CI)
* stable finding shape: ``sev`` / ``title`` / ``detail`` (JSON string)

Deliberately out of scope: sockets, subprocesses, cluster access. A real
collector must declare the surfaces it needs in ``module.json`` and must set
``writes: true`` plus ``min_level: exploit`` if it changes any state.
"""
from __future__ import annotations

import json
from pathlib import Path

KEY = "example-hello"


def summarise(target: str, note: str, marker: str, trusted: bool) -> dict:
    """Build the artifact body. Pure function, no I/O."""
    return {
        "module": KEY,
        "target": target or "",
        "note": note or "",
        "marker": marker,
        "trusted_plugin": trusted,
        "checks": {
            "target_present": bool(target),
            "note_present": bool(note),
        },
    }


def run(ctx: dict, params: dict) -> dict:
    marker = str(ctx.get("marker") or "INKBLADE")
    plugin_meta = dict(ctx.get("plugin") or {})
    trusted = bool(plugin_meta.get("trusted"))
    target = str(params.get("target") or "")
    note = str(params.get("note") or "")

    body = summarise(target, note, marker, trusted)
    artifact = Path(ctx["run"].dir) / "artifacts" / (KEY + ".json")
    artifact.write_text(
        json.dumps(body, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    findings = [
        {
            "sev": "info",
            "title": "example-hello: target recorded",
            "detail": json.dumps(
                {"target": target, "trusted": trusted, "marker": marker},
                ensure_ascii=False,
                sort_keys=True,
            ),
        }
    ]

    return {
        "summary": KEY + ": target=" + (target or "<none>"),
        "findings": findings,
        "artifacts": [str(artifact)],
    }
