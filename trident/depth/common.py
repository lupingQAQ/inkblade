# -*- coding: utf-8 -*-
"""Shared helpers for the research-depth auditors (standard library only)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

SEVS = ("critical", "high", "medium", "low", "info")
_RANK = {s: i for i, s in enumerate(SEVS)}


def finding(sev: str, title: str, detail: dict | str = "", *, evidence: str = "",
            mapping: str = "", fix: str = "", **extra) -> dict:
    if sev not in SEVS:
        sev = "info"
    item = {
        "sev": sev,
        "title": title,
        "detail": json.dumps(detail, ensure_ascii=False) if isinstance(detail, dict) else str(detail),
    }
    if evidence:
        item["evidence"] = evidence
    if mapping:
        item["mapping"] = mapping
    if fix:
        item["fix"] = fix
    item.update(extra)
    return item


def summary_json(family: str, findings: list[dict], *, extra: dict | None = None,
                 source: str = "") -> str:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.get("sev", "info")] = counts.get(f.get("sev", "info"), 0) + 1
    payload = {
        "family": family,
        "findings": len(findings),
        "severity": {s: counts[s] for s in SEVS if counts.get(s)},
        "top": min((f.get("sev", "info") for f in findings),
                   key=lambda s: _RANK.get(s, len(_RANK)), default="none"),
        "source": source,
    }
    payload.update(extra or {})
    return json.dumps(payload, ensure_ascii=False)


def write_artifact(ctx: dict, name: str, payload: dict) -> list[str]:
    run = ctx.get("run") if isinstance(ctx, dict) else None
    if run is None:
        return []
    adir = Path(run.dir) / "artifacts"
    adir.mkdir(parents=True, exist_ok=True)
    path = adir / name
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")
    return [str(path)]


def load_json_ref(value, default=None):
    if value is None:
        return default
    if isinstance(value, dict):
        return value
    return json.loads(Path(str(value)).read_text(encoding="utf-8"))


def hash_payload(payload) -> str:
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def as_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "on", "enabled")


def sev_rank(sev: str) -> int:
    return _RANK.get(sev, len(_RANK))
