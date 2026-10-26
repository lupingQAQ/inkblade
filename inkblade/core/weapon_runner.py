# -*- coding: utf-8 -*-
"""One-click execution for weapon packs (``inkblade exploit <id>``).

Two explicit states:

``--dry-run`` (default)
    Resolve the pack, print the module, deployment verdict/evidence, payload
    variants, backup requirement and marker template.  No network, no file
    write, no runner call.

``--real``
    Execute through :func:`inkblade.core.runner.run_module`, which enforces the
    RoE scope, the surface gate and the backup gate.  A write module without
    ``--backup-target`` is refused with exit 91 before any action.  After the
    run, an ``exploit-marker.txt`` proof file is written into the run directory
    and its SHA256 is returned.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .registry import load_modules
from .runner import BackupGateRefused, run_module
from .weaponization import WeaponPackError, resolve


def _module_meta(pack: dict, modules_dir: Path | str):
    mods = load_modules(modules_dir)
    module = str(pack.get("module") or "")
    if module not in mods:
        raise WeaponPackError(f"pack {pack.get('id')} points at missing module {module}")
    return mods[module]


def plan(pack: dict, *, modules_dir: Path | str = "inkblade/modules") -> dict[str, Any]:
    """Side-effect-free execution plan for one pack."""
    meta = _module_meta(pack, modules_dir)
    one_click = pack.get("one_click") or {}
    return {
        "id": pack.get("id"),
        "component": pack.get("component"),
        "module": meta.key,
        "write_module": bool(meta.writes),
        "backup_required": bool(meta.writes),
        "backup_gate": ("refuses to run without --backup-target" if meta.writes
                        else "not required (read-only module)"),
        "surface": pack.get("surface"),
        "version": pack.get("version"),
        "affected": pack.get("affected"),
        "deployment_requirement": pack.get("deployment_requirement"),
        "deployment_evidence": pack.get("deployment_evidence"),
        "default_exposed": bool(pack.get("default_exposed")),
        "exploit": pack.get("exploit"),
        "preconditions": pack.get("preconditions") or [],
        "variants": pack.get("variants") or [],
        "variant_count": len(pack.get("variants") or []),
        "marker_template": "INKBLADE-<run>",
        "commands": {
            "dry_run": one_click.get("dry_run") or f"inkblade exploit {pack.get('id')} --dry-run",
            "real": one_click.get("real") or f"inkblade exploit {pack.get('id')} --real --target <url>",
        },
    }


def _marker_proof(run, marker: str) -> dict[str, Any]:
    path = Path(run.dir) / "exploit-marker.txt"
    path.write_text(marker + "\n", encoding="utf-8")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return {"text": marker, "path": str(path), "sha256": digest}


def execute(pack: dict, store, session, params: dict[str, Any], *,
            modules_dir: Path | str = "inkblade/modules",
            backup_targets: list[dict] | None = None,
            run=None, surface_ctx=None) -> dict[str, Any]:
    """Run a pack in real mode; the caller has already collected consent."""
    meta = _module_meta(pack, modules_dir)
    backup_targets = list(backup_targets or [])
    if meta.writes and not backup_targets:
        raise BackupGateRefused(
            f"{meta.key} writes state; pass --backup-target (and ensure the target is in scope)")

    effective = dict(params or {})
    effective.setdefault("mode", "backup-write" if meta.writes else "probe-only")
    if backup_targets:
        effective["backup_targets"] = backup_targets
    effective.setdefault("variants", pack.get("variants") or [])
    effective["weapon_pack"] = pack.get("id")

    result = run_module(store, session, meta.key, effective, modules_dir,
                        run=run, surface_ctx=surface_ctx)
    marker = f"INKBLADE-{result.get('run')}"
    proof = None
    if result.get("run"):
        proof = _marker_proof(store.open_run(result["run"]), marker)
    return {
        "exploit": pack.get("id"),
        "module": meta.key,
        "deployment_requirement": pack.get("deployment_requirement"),
        "deployment_evidence": pack.get("deployment_evidence"),
        "result": result,
        "marker": proof,
    }


def resolve_and_plan(identifier: str, *, packs_path: Path | str | None = None,
                     modules_dir: Path | str = "inkblade/modules") -> dict[str, Any]:
    pack = resolve(identifier, packs_path) if packs_path else resolve(identifier)
    return plan(pack, modules_dir=modules_dir)
