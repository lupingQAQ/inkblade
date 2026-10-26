# -*- coding: utf-8 -*-
"""Shared read-only helpers for the emerging-surface audit modules.

These modules are deliberately inventory-first: when the component is not in
the collected deployment they return ``not-deployed`` without a finding.  The
surface gate in ``core.runner`` normally prevents execution before this point;
the same check here protects direct fixture/test calls.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

try:  # normal package import
    from inkblade.core.surface import SurfaceContext, detect, load_collection
except ImportError:  # pragma: no cover - direct script loading
    import importlib.util

    _spec = importlib.util.spec_from_file_location(
        "_inkblade_surface", Path(__file__).resolve().parent.parent / "core" / "surface.py")
    _surface = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_surface)
    SurfaceContext, detect, load_collection = (
        _surface.SurfaceContext, _surface.detect, _surface.load_collection)


def collection(params: dict) -> dict | None:
    ref = params.get("collect") or params.get("collection")
    if isinstance(ref, dict):
        return ref
    if ref:
        try:
            return load_collection(ref)
        except (OSError, ValueError):
            return None
    return None


def surface_state(meta: dict, params: dict, doc: dict | None) -> dict:
    profile = params.get("profile")
    if not profile and (doc or {}).get("profile"):
        profile = (doc or {}).get("profile")
    try:
        ctx = SurfaceContext.build(profile=profile, collection=doc, params=params,
                                   probe=bool(params.get("probe")))
        results = detect(meta.get("surfaces") or meta.get("required_surfaces") or [], ctx)
    except (OSError, ValueError):
        return {"status": "unknown", "results": []}
    statuses = {r.status for r in results}
    status = "not-deployed" if "absent" in statuses else (
        "unknown" if "unknown" in statuses else "deployed")
    return {"status": status, "results": [r.as_dict() for r in results],
            "mode": ctx.mode, "profile": ctx.profile_name}


def objects(doc: dict | None, kind: str | None = None) -> list[dict]:
    items = [o for o in ((doc or {}).get("k8s") or {}).get("objects") or []
             if isinstance(o, dict)]
    if kind:
        items = [o for o in items if str(o.get("kind", "")).lower() == kind.lower()]
    return items


def endpoints(doc: dict | None) -> list[dict]:
    return [e for e in ((doc or {}).get("http") or {}).get("endpoints") or []
            if isinstance(e, dict)]


def files(doc: dict | None) -> list[dict]:
    return [f for f in ((doc or {}).get("files") or {}).get("files") or []
            if isinstance(f, dict)]


def hardware(doc: dict | None, key: str) -> list[dict]:
    return [h for h in ((doc or {}).get("hardware") or {}).get(key) or []
            if isinstance(h, dict)]


def names(doc: dict | None, kind: str | None = None) -> list[str]:
    return [str(o.get("name", "")) for o in objects(doc, kind)]


def endpoint_hit(doc: dict | None, needle: str) -> dict | None:
    for ep in endpoints(doc):
        text = f"{ep.get('path', '')} {ep.get('url', '')}".lower()
        if needle.lower() in text and int(ep.get("status") or 0) in range(200, 300):
            return ep
    return None


def finding(sev: str, title: str, detail: dict, evidence: str = "") -> dict:
    payload = dict(detail)
    if evidence:
        payload.setdefault("evidence", evidence)
    return {"sev": sev, "title": title,
            "detail": json.dumps(payload, ensure_ascii=False)}


def artifact(ctx: dict, key: str, payload: dict) -> str:
    run = ctx.get("run")
    directory = getattr(run, "dir", None)
    if directory is None:
        return ""
    path = Path(directory) / f"{key}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return str(path)


def result(ctx: dict, key: str, state: dict, findings: list[dict],
           summary: str, extra: dict | None = None) -> dict:
    payload = {"module": key, "surface": state, **(extra or {})}
    art = artifact(ctx, key, payload)
    return {"summary": summary, "artifacts": [art] if art else [],
            "findings": findings, "surface": state}


def not_deployed(ctx: dict, key: str, state: dict) -> dict:
    return result(ctx, key, state, [], f"{key}: component not deployed in this profile/collection")
