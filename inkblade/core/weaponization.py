# -*- coding: utf-8 -*-
"""Weapon-pack registry: one-click exploit entry + readiness accounting.

A *weapon pack* is the join of four artifacts:

1. a module under ``inkblade/modules/<key>`` (run.py + module.json),
2. a version-matrix row (affected/fixed range + >=2 payload variants),
3. a deployment verdict with concrete evidence,
4. an entrypoint: ``inkblade exploit <id>`` (dry-run by default, ``--real``
   to execute through the runner's RoE/backup/surface gates).

The readiness table is grouped by component so a report can answer
"of the X findings in Dify, how many are verified, default-exposed, and
one-click runnable?" without re-deriving anything from prose.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
PACKS_PATH = ROOT / "inkblade" / "core" / "data" / "weapon-packs.json"
MATRIX_PATH = ROOT / "inkblade" / "core" / "data" / "version-matrix.json"
EXPLOIT_PATH = ROOT / "inkblade" / "core" / "exploit-registry.json"
MODULES_DIR = ROOT / "inkblade" / "modules"

SCHEMA = "inkblade-weapon-packs-v1"
REQUIREMENTS = ("default-exposed", "needs-config", "function-level", "hardware-only")


class WeaponPackError(ValueError):
    """Malformed pack registry or ambiguous id."""


def load(path: Path | str = PACKS_PATH) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def packs(path: Path | str = PACKS_PATH) -> list[dict]:
    return list(load(path).get("packs") or [])


def index(path: Path | str = PACKS_PATH) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for pack in packs(path):
        out[str(pack["id"])] = pack
    return out


def resolve(identifier: str, path: Path | str = PACKS_PATH) -> dict:
    """Resolve an exact pack id, a module key, or a unique case-insensitive prefix.

    Reserve packs win; otherwise a catalog/mining registry entry with a module
    is synthesised into the same pack shape (so ``inkblade exploit CVE-...``
    works for the 152-entry registry too).
    """
    identifier = str(identifier or "").strip()
    if not identifier:
        raise WeaponPackError("empty exploit id")
    by_id = index(path)
    if identifier in by_id:
        return by_id[identifier]
    lowered = identifier.lower()
    for pack in by_id.values():
        if str(pack.get("module")) == identifier:
            return pack
    hits = [pack for key, pack in by_id.items() if key.lower().startswith(lowered)]
    if len(hits) == 1:
        return hits[0]
    if not hits:
        synthetic = pack_from_registry(identifier)
        if synthetic is not None:
            return synthetic
        raise WeaponPackError(f"unknown exploit id: {identifier}")
    raise WeaponPackError(
        f"ambiguous exploit id {identifier!r}: " + ", ".join(sorted(p["id"] for p in hits)[:8]))


def _generic_variants(surface: str) -> list[dict]:
    if surface == "http":
        return [
            {"id": "v1-path-trailing", "kind": "path", "request": "append / to the route",
             "transform": {"op": "path_suffix", "arg": "/"}},
            {"id": "v2-method-alt", "kind": "method", "request": "alternate HTTP method",
             "transform": {"op": "method", "arg": "POST"}},
        ]
    return [
        {"id": "v1-relative-path", "kind": "file", "request": "relative traversal payload"},
        {"id": "v2-absolute-path", "kind": "file", "request": "absolute path payload"},
    ]


def pack_from_registry(identifier: str, *, registry_path: Path | str = EXPLOIT_PATH,
                       matrix_path: Path | str = MATRIX_PATH,
                       modules_dir: Path | str = MODULES_DIR) -> dict | None:
    """Synthesise a pack for an exploit-registry entry that has a module."""
    doc = json.loads(Path(registry_path).read_text(encoding="utf-8"))
    entry = next((e for e in doc.get("entries") or [] if e.get("id") == identifier), None)
    if entry is None:
        return None
    module = str(entry.get("module") or "")
    module_dir = Path(modules_dir) / module
    if not module or not (module_dir / "run.py").is_file():
        raise WeaponPackError(
            f"{identifier} has no module (status={entry.get('status')}); "
            "only classified, module-backed entries are one-click runnable")
    matrix = _matrix_rows(matrix_path)
    row = matrix.get(module) or {}
    surface = str(row.get("surface") or "file")
    variants = list(row.get("variants") or []) or _generic_variants(surface)
    return {
        "id": entry["id"],
        "component": entry.get("component"),
        "module": module,
        "surface": surface,
        "version": entry.get("version"),
        "affected": row.get("affected"),
        "deployment_requirement": entry.get("deployment_requirement"),
        "deployment_evidence": entry.get("deployment_evidence"),
        "default_exposed": entry.get("deployment_requirement") == "default-exposed",
        "exploit": entry.get("title"),
        "preconditions": [],
        "disclosure": {},
        "verification": {"status": entry.get("status"),
                         "method": entry.get("method"),
                         "evidence": entry.get("evidence")},
        "variants": variants,
        "one_click": {
            "dry_run": f"inkblade exploit {entry['id']} --dry-run",
            "real": f"inkblade exploit {entry['id']} --real --target <url>",
            "backup_required": False,
            "marker": "INKBLADE-<run>",
        },
        "module_metadata": {},
        "source": "exploit-registry",
    }


def registry_packs(*, modules_dir: Path | str = MODULES_DIR) -> list[dict]:
    """All exploit-registry entries that have a runnable module (one-click)."""
    doc = json.loads(Path(EXPLOIT_PATH).read_text(encoding="utf-8"))
    out: list[dict] = []
    modules = Path(modules_dir)
    for entry in doc.get("entries") or []:
        module = str(entry.get("module") or "")
        if module and (modules / module / "run.py").is_file():
            pack = pack_from_registry(entry["id"], modules_dir=modules_dir)
            if pack is not None:
                out.append(pack)
    return out


def _matrix_rows(path: Path | str = MATRIX_PATH) -> dict[str, dict]:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    return {str(row["module"]): row for row in doc.get("entries") or []}


def validate(path: Path | str = PACKS_PATH, *, modules_dir: Path | str = MODULES_DIR,
             matrix_path: Path | str = MATRIX_PATH) -> list[str]:
    """Return every structural problem; empty list means the packs are usable."""
    errors: list[str] = []
    try:
        doc = load(path)
    except (OSError, ValueError) as exc:
        return [f"cannot load pack registry: {exc}"]
    if doc.get("schema") != SCHEMA:
        errors.append(f"bad pack schema: {doc.get('schema')!r}")
    pack_list = list(doc.get("packs") or [])
    if not pack_list:
        return ["pack registry has no packs"]
    if doc.get("total") != len(pack_list):
        errors.append("pack total does not match pack list")
    matrix = _matrix_rows(matrix_path)
    modules = Path(modules_dir)
    seen: set[str] = set()
    for pack in pack_list:
        pid = str(pack.get("id") or "")
        if not pid:
            errors.append("pack without id")
            continue
        if pid in seen:
            errors.append(f"{pid}: duplicate pack id")
        seen.add(pid)
        module = str(pack.get("module") or "")
        module_dir = modules / module
        if not (module_dir / "module.json").is_file() or not (module_dir / "run.py").is_file():
            errors.append(f"{pid}: module {module!r} missing run.py/module.json")
        if module not in matrix:
            errors.append(f"{pid}: module {module!r} has no version-matrix row")
        variants = list(pack.get("variants") or [])
        if len(variants) < 2:
            errors.append(f"{pid}: needs >=2 payload variants, got {len(variants)}")
        if len({str(v.get('id')) for v in variants}) != len(variants):
            errors.append(f"{pid}: duplicate payload variant ids")
        requirement = str(pack.get("deployment_requirement") or "")
        if requirement not in REQUIREMENTS:
            errors.append(f"{pid}: invalid deployment requirement {requirement!r}")
        if not str(pack.get("deployment_evidence") or "").strip():
            errors.append(f"{pid}: missing deployment evidence")
        one_click = pack.get("one_click") or {}
        for key in ("dry_run", "real"):
            command = str(one_click.get(key) or "")
            if not command.startswith("inkblade exploit "):
                errors.append(f"{pid}: one_click.{key} is not an inkblade exploit entry")
        if one_click.get("marker") != "INKBLADE-<run>":
            errors.append(f"{pid}: marker template is not INKBLADE-<run>")
    return errors


def component_rows(pack_list: list[dict] | None = None,
                   path: Path | str = PACKS_PATH) -> list[dict]:
    """Aggregate packs by component for WEAPON-READINESS.md."""
    grouped: dict[str, list[dict]] = {}
    for pack in (pack_list if pack_list is not None else packs(path)):
        grouped.setdefault(str(pack.get("component") or "unknown"), []).append(pack)
    rows: list[dict] = []
    for component, items in sorted(grouped.items()):
        counts = {key: 0 for key in REQUIREMENTS}
        for item in items:
            counts[str(item.get("deployment_requirement"))] += 1
        rows.append({
            "component": component,
            "total": len(items),
            "verified": sum(1 for i in items
                            if (i.get("verification") or {}).get("status") == "verified"),
            "default_exposed": counts["default-exposed"],
            "needs_config": counts["needs-config"],
            "function_level": counts["function-level"],
            "hardware_only": counts["hardware-only"],
            "variants": sum(len(i.get("variants") or []) for i in items),
            "one_click": sum(1 for i in items if (i.get("one_click") or {}).get("real")),
            "packs": items,
        })
    return rows


def _merge_rows(rows: list[list[dict]]) -> list[dict]:
    merged: dict[str, dict] = {}
    for group in rows:
        for row in group:
            target = merged.setdefault(row["component"], {
                "component": row["component"], "total": 0, "verified": 0,
                "default_exposed": 0, "needs_config": 0, "function_level": 0,
                "hardware_only": 0, "variants": 0, "one_click": 0,
            })
            for key in ("total", "verified", "default_exposed", "needs_config",
                        "function_level", "hardware_only", "variants", "one_click"):
                target[key] += row[key]
    return [merged[key] for key in sorted(merged)]


def registry_rows(*, registry_path: Path | str = EXPLOIT_PATH,
                  matrix_path: Path | str = MATRIX_PATH,
                  modules_dir: Path | str = MODULES_DIR) -> list[dict]:
    """Per-component rows for all 152 catalog/mining entries.

    ``one_click`` counts entries with a runnable module; ``variants`` sums the
    version-matrix variants of the owning modules (0 when no module exists).
    """
    doc = json.loads(Path(registry_path).read_text(encoding="utf-8"))
    matrix = _matrix_rows(matrix_path)
    modules = Path(modules_dir)
    grouped: dict[str, dict] = {}
    for entry in doc.get("entries") or []:
        component = str(entry.get("component") or "unknown")
        row = grouped.setdefault(component, {
            "component": component, "total": 0, "verified": 0,
            "default_exposed": 0, "needs_config": 0, "function_level": 0,
            "hardware_only": 0, "variants": 0, "one_click": 0,
        })
        row["total"] += 1
        if entry.get("status") == "verified":
            row["verified"] += 1
        requirement = str(entry.get("deployment_requirement") or "")
        key = {"default-exposed": "default_exposed", "needs-config": "needs_config",
               "function-level": "function_level", "hardware-only": "hardware_only"}.get(requirement)
        if key:
            row[key] += 1
        module = str(entry.get("module") or "")
        if module:
            row["variants"] += len((matrix.get(module) or {}).get("variants") or [])
            if (modules / module / "run.py").is_file():
                row["one_click"] += 1
    return [grouped[key] for key in sorted(grouped)]


def readiness(path: Path | str = PACKS_PATH,
              modules_dir: Path | str = MODULES_DIR) -> dict[str, Any]:
    doc = load(path)
    reserve_packs = list(doc.get("packs") or [])
    catalog = registry_rows(modules_dir=modules_dir)
    return {
        "schema": "inkblade-weapon-readiness-v1",
        "reserve": {
            "total": len(reserve_packs),
            "modules": len({p.get("module") for p in reserve_packs}),
            "variants": sum(len(p.get("variants") or []) for p in reserve_packs),
            "by_requirement": {key: sum(1 for p in reserve_packs
                                        if p.get("deployment_requirement") == key)
                               for key in REQUIREMENTS},
            "components": component_rows(reserve_packs),
        },
        "exploit_registry": {
            "total": sum(row["total"] for row in catalog),
            "modules": len({p.get("module") for p in registry_packs(modules_dir=modules_dir)}),
            "variants": sum(row["variants"] for row in catalog),
            "by_requirement": {key: sum(row[{"default-exposed": "default_exposed",
                                             "needs-config": "needs_config",
                                             "function-level": "function_level",
                                             "hardware-only": "hardware_only"}[key]]
                                        for row in catalog)
                               for key in REQUIREMENTS},
            "components": catalog,
        },
        "combined": {
            "total": sum(row["total"] for row in catalog) + len(reserve_packs),
            "modules": len({p.get("module") for p in reserve_packs}
                           | {p.get("module") for p in registry_packs(modules_dir=modules_dir)}),
            "variants": sum(row["variants"] for row in catalog)
                        + sum(len(p.get("variants") or []) for p in reserve_packs),
            "by_requirement": {
                key: sum(row[{"default-exposed": "default_exposed",
                              "needs-config": "needs_config",
                              "function-level": "function_level",
                              "hardware-only": "hardware_only"}[key]] for row in catalog)
                     + sum(1 for p in reserve_packs if p.get("deployment_requirement") == key)
                for key in REQUIREMENTS
            },
            "components": _merge_rows([catalog, component_rows(reserve_packs)]),
        },
    }
