# -*- coding: utf-8 -*-
"""Real attack-surface detection.

A module is only executable when the deployment surfaces it needs actually
exist.  Every module declares ``required_surfaces`` (in ``module.json`` or the
legacy ``inkblade/profiles/surface-map.json``); a detector resolves each
requirement to ``present`` / ``absent`` / ``unknown`` with evidence.

Design rules
------------
* ``present`` is backed by a real collection (kubectl read-only snapshot,
  HTTP probe, config/model file export, BMC/switch import) or by an explicit
  ``--probe`` acknowledgement.
* ``absent`` is authoritative only when the inventory is complete: a profile
  declaration marked ``complete`` or a live collection whose section is
  ``ok``.
* ``unknown`` never executes by default; the operator must pass ``--probe``.
* Fixture data is always labelled (``mode=fixture``) and must never be
  silently mixed into a production verdict.
"""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

SURFACE_TYPES = (
    "k8s-object",
    "http-endpoint",
    "config-file",
    "out-of-band",
    "bmc",
    "switch",
    "model-file",
    "runtime-agent",
)

STATUSES = ("present", "absent", "unknown")
VERDICTS = ("production-testable", "conditional", "no-surface")

_INKBLADE = Path(__file__).resolve().parents[1]
PROFILES_DIR = _INKBLADE / "profiles"
DEFAULT_PROFILE = "bare-k8s-gpu"

_ALIASES = {
    "k8s": "k8s-object",
    "k8s_object": "k8s-object",
    "kubernetes": "k8s-object",
    "object": "k8s-object",
    "http": "http-endpoint",
    "endpoint": "http-endpoint",
    "url": "http-endpoint",
    "config": "config-file",
    "file": "config-file",
    "config_file": "config-file",
    "oob": "out-of-band",
    "out_of_band": "out-of-band",
    "oob-management": "out-of-band",
    "model": "model-file",
    "weights": "model-file",
    "model_file": "model-file",
    "agent": "runtime-agent",
    "runtime": "runtime-agent",
    "runtime_agent": "runtime-agent",
}

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")


# --------------------------------------------------------------------------- model


@dataclass(frozen=True)
class Requirement:
    type: str
    selector: str = "any"
    optional: bool = False
    note: str = ""

    def as_dict(self) -> dict:
        out = {"type": self.type, "selector": self.selector}
        if self.optional:
            out["optional"] = True
        if self.note:
            out["note"] = self.note
        return out


@dataclass(frozen=True)
class AvailableSurface:
    type: str
    id: str
    source: str
    status: str = "present"
    detail: str = ""

    def as_dict(self) -> dict:
        return {"type": self.type, "id": self.id, "source": self.source,
                "status": self.status, "detail": self.detail}


@dataclass
class SurfaceResult:
    requirement: Requirement
    status: str
    evidence: str
    matched: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    probed: bool = False

    def as_dict(self) -> dict:
        return {
            "surface": self.requirement.as_dict(),
            "status": self.status,
            "evidence": self.evidence,
            "matched": list(self.matched),
            "sources": list(self.sources),
            "probed": self.probed,
        }


# --------------------------------------------------------------------------- parsing


def normalize_type(value: str) -> str:
    key = str(value or "").strip().lower().replace(" ", "-")
    key = _ALIASES.get(key, key)
    if key not in SURFACE_TYPES:
        raise ValueError(f"unknown surface type: {value!r}; expected one of {', '.join(SURFACE_TYPES)}")
    return key


def normalize_requirement(raw: Any) -> Requirement:
    if isinstance(raw, str):
        text = raw.strip()
        if ":" in text:
            kind, selector = text.split(":", 1)
            return Requirement(normalize_type(kind), selector.strip() or "any")
        # A bare string is a selector; infer the most useful type.
        low = text.lower()
        if low.startswith(("http://", "https://", "/")):
            return Requirement("http-endpoint", text)
        if any(low.endswith(ext) for ext in (".yaml", ".yml", ".json", ".toml", ".conf", ".ini")):
            return Requirement("config-file", text)
        if any(low.endswith(ext) for ext in (".safetensors", ".bin", ".pt", ".pth", ".ckpt", ".onnx")):
            return Requirement("model-file", text)
        return Requirement("k8s-object", text)
    if not isinstance(raw, dict):
        raise ValueError(f"surface requirement must be object or string, got {type(raw).__name__}")
    kind = normalize_type(raw.get("type") or raw.get("surface") or raw.get("kind") or "")
    selector = str(raw.get("selector") or raw.get("id") or raw.get("path") or "any").strip()
    return Requirement(kind, selector or "any", bool(raw.get("optional")), str(raw.get("note") or ""))


def normalize_requirements(items: Iterable[Any] | None) -> list[Requirement]:
    out: list[Requirement] = []
    for item in items or []:
        req = item if isinstance(item, Requirement) else normalize_requirement(item)
        if req not in out:
            out.append(req)
    return out


def _norm_id(value: str) -> str:
    return str(value or "").strip().strip("/").lower()


def surface_matches(req: Requirement, surface: AvailableSurface) -> bool:
    allowed = {"bmc", "switch"} if req.type == "out-of-band" else {req.type}
    if surface.type not in allowed:
        return False
    selector = _norm_id(req.selector)
    sid = _norm_id(surface.id)
    if selector in ("", "any", "*"):
        return True
    if fnmatch.fnmatch(sid, selector) or fnmatch.fnmatch(selector, sid):
        return True
    if selector in sid:
        return True
    # Type shorthand: "Deployment" matches "Deployment/vllm"; "Node/*" too.
    if req.type == "k8s-object" and "/" not in selector and sid.startswith(selector + "/"):
        return True
    if req.type == "runtime-agent" and "/" not in selector and sid.startswith("runtime-agent/"):
        return selector in sid.split("/", 1)[1]
    return False


# --------------------------------------------------------------------------- profiles


def profile_names() -> list[str]:
    if not PROFILES_DIR.exists():
        return []
    return sorted(p.stem for p in PROFILES_DIR.glob("*.json")
                  if not p.name.startswith("_")
                  and p.stem not in ("surface-map", "quarantine"))


def load_profile(name_or_path: str | Path | None) -> dict:
    if name_or_path in (None, ""):
        raise ValueError("profile is required")
    path = Path(name_or_path)
    if not path.is_file():
        if not _NAME_RE.match(str(name_or_path)):
            raise ValueError(f"invalid profile name: {name_or_path!r}")
        path = PROFILES_DIR / f"{name_or_path}.json"
    if not path.is_file():
        raise ValueError(f"unknown profile: {name_or_path}; available: {', '.join(profile_names())}")
    doc = _load_profile_file(path)
    if not isinstance(doc, dict) or not doc.get("name"):
        raise ValueError(f"profile {path} missing name")
    surfaces = []
    for raw in doc.get("surfaces") or []:
        req = normalize_requirement(raw)
        item = AvailableSurface(req.type, req.selector,
                                str(raw.get("source") or f"profile:{doc['name']}"),
                                str(raw.get("status") or "present"),
                                str(raw.get("detail") or ""))
        if item not in surfaces:
            surfaces.append(item)
    doc["surfaces"] = surfaces
    doc["complete"] = bool(doc.get("complete", True))
    doc["path"] = str(path)
    return doc


def _load_profile_file(path: Path, seen: set[str] | None = None) -> dict:
    seen = seen or set()
    key = str(path.resolve())
    if key in seen:
        raise ValueError(f"profile inheritance cycle: {path}")
    seen.add(key)
    doc = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict):
        raise ValueError(f"profile {path} must be a JSON object")
    merged: list[dict] = []
    for parent in doc.get("inherit") or []:
        parent_path = PROFILES_DIR / f"{parent}.json"
        if not parent_path.is_file():
            raise ValueError(f"profile {doc.get('name', path.stem)} inherits missing {parent}")
        parent_doc = _load_profile_file(parent_path, seen)
        merged.extend(parent_doc.get("surfaces") or [])
        for k, v in (parent_doc.get("components") or {}).items():
            doc.setdefault("components", {}).setdefault(k, v)
    merged.extend(doc.get("surfaces") or [])
    blocked = {str(x).lower() for x in (doc.get("exclude") or [])}
    if blocked:
        merged = [s for s in merged
                  if str(s.get("selector") or s.get("id") or "").lower() not in blocked]
    doc["surfaces"] = merged
    return doc


def load_profiles() -> list[dict]:
    return [load_profile(name) for name in profile_names()]


def profile_collection(profile: dict | str, *, mode: str = "profile") -> dict:
    """Turn a profile declaration into a collection-shaped inventory."""
    prof = load_profile(profile) if not isinstance(profile, dict) else profile
    out = {
        "schema": "inkblade-collection-v1",
        "mode": mode,
        "fixture": mode == "fixture",
        "profile": prof["name"],
        "collected_at": "",
        "k8s": {"status": "ok" if prof.get("complete") else "unknown", "objects": []},
        "http": {"status": "ok" if prof.get("complete") else "unknown", "endpoints": []},
        "files": {"status": "ok" if prof.get("complete") else "unknown", "files": []},
        "hardware": {"status": "ok" if prof.get("complete") else "unknown", "bmc": [], "switches": []},
        "runtime": {"status": "ok" if prof.get("complete") else "unknown", "agents": []},
    }
    for s in prof["surfaces"]:
        if s.type == "k8s-object":
            kind, _, name = s.id.partition("/")
            out["k8s"]["objects"].append({"kind": kind, "name": name or "*", "namespace": "",
                                          "apiVersion": "", "labels": {}, "source": s.source})
        elif s.type == "http-endpoint":
            out["http"]["endpoints"].append({"url": s.id, "path": s.id, "status": 200,
                                             "server": "", "product": "", "version": "",
                                             "source": s.source})
        elif s.type in ("config-file", "model-file"):
            out["files"]["files"].append({"path": s.id, "kind": s.type, "size": 0,
                                          "sha256": "", "source": s.source})
            kinds = out["files"].setdefault("kinds", {})
            kinds[s.type] = kinds.get(s.type, 0) + 1
        elif s.type == "bmc":
            out["hardware"]["bmc"].append({"id": s.id, "source": s.source})
        elif s.type == "switch":
            out["hardware"]["switches"].append({"id": s.id, "source": s.source})
        elif s.type == "runtime-agent":
            out["runtime"]["agents"].append({"name": s.id, "source": s.source})
        elif s.type == "out-of-band":
            out["hardware"]["bmc"].append({"id": s.id, "source": s.source})
    return out


# --------------------------------------------------------------------------- collection


_SECTION_STATUS = ("ok", "partial", "unavailable", "unknown")


def load_collection(path: str | Path) -> dict:
    p = Path(path)
    if p.is_file():
        doc = json.loads(p.read_text(encoding="utf-8"))
    elif p.is_dir():
        candidate = p / "collection.json"
        if candidate.is_file():
            doc = json.loads(candidate.read_text(encoding="utf-8"))
        else:
            doc = {"schema": "inkblade-collection-v1", "mode": "live", "fixture": False}
            for name in ("k8s", "http", "files", "hardware", "runtime"):
                section = p / f"{name}.json"
                if section.is_file():
                    doc[name] = json.loads(section.read_text(encoding="utf-8"))
    else:
        raise ValueError(f"collection not found: {path}")
    if not isinstance(doc, dict):
        raise ValueError(f"collection must be a JSON object: {path}")
    doc.setdefault("mode", "live")
    doc.setdefault("fixture", doc.get("mode") == "fixture")
    return doc


def _section_status(doc: dict | None, name: str) -> str:
    if not isinstance(doc, dict):
        return "unknown"
    section = doc.get(name)
    if not isinstance(section, dict):
        return "unknown"
    status = str(section.get("status") or "unknown").lower()
    if status not in _SECTION_STATUS:
        status = "unknown"
    return status


def collection_surfaces(doc: dict | None) -> list[AvailableSurface]:
    if not isinstance(doc, dict):
        return []
    out: list[AvailableSurface] = []
    source = f"collection:{doc.get('mode', 'live')}"

    k8s = doc.get("k8s") or {}
    for obj in k8s.get("objects") or []:
        if not isinstance(obj, dict):
            continue
        kind = str(obj.get("kind") or "").strip()
        name = str(obj.get("name") or "").strip()
        if not kind:
            continue
        out.append(AvailableSurface("k8s-object", f"{kind}/{name or '*'}", source,
                                    "present", str(obj.get("source") or "")))
        labels = obj.get("labels") or {}
        for label, value in labels.items():
            out.append(AvailableSurface("k8s-object", f"{kind}/label:{label}={value}",
                                        source, "present", "label"))
        if kind.lower() in ("daemonset", "pod"):
            out.append(AvailableSurface("runtime-agent", f"runtime-agent/{name}", source,
                                        "present", "k8s workload"))
        annotations = obj.get("annotations") or {}
        for ann, value in annotations.items():
            out.append(AvailableSurface("k8s-object", f"{kind}/annotation:{ann}={value}",
                                        source, "present", "annotation"))

    http = doc.get("http") or {}
    for ep in http.get("endpoints") or []:
        if not isinstance(ep, dict):
            continue
        url = str(ep.get("url") or ep.get("path") or "").strip()
        if not url:
            continue
        out.append(AvailableSurface("http-endpoint", url, source,
                                    "present", f"status={ep.get('status')}"))
        path = str(ep.get("path") or "")
        if path and path != url:
            out.append(AvailableSurface("http-endpoint", path, source,
                                        "present", f"status={ep.get('status')}"))
        for group in ep.get("tls", {}).get("groups") or []:
            out.append(AvailableSurface("http-endpoint", f"{url}#group={group}", source,
                                        "present", "tls-group"))

    files = doc.get("files") or {}
    for item in files.get("files") or []:
        if not isinstance(item, dict):
            continue
        path = str(item.get("path") or "").strip()
        if not path:
            continue
        kind = str(item.get("kind") or "")
        stype = "model-file" if kind == "model-file" or _looks_model(path) else "config-file"
        out.append(AvailableSurface(stype, path, source, "present", f"sha256={item.get('sha256', '')}"))
        if _looks_model(path):
            out.append(AvailableSurface("model-file", path, source, "present", "extension"))

    hw = doc.get("hardware") or {}
    for item in hw.get("bmc") or []:
        ident = item.get("id") if isinstance(item, dict) else item
        if ident:
            out.append(AvailableSurface("bmc", str(ident), source, "present",
                                        str(item.get("vendor") if isinstance(item, dict) else "")))
    for item in hw.get("switches") or []:
        ident = item.get("id") if isinstance(item, dict) else item
        if ident:
            out.append(AvailableSurface("switch", str(ident), source, "present",
                                        str(item.get("os") if isinstance(item, dict) else "")))
    for item in hw.get("tpm") or []:
        ident = item.get("id") if isinstance(item, dict) else item
        if ident:
            out.append(AvailableSurface("bmc", f"tpm/{ident}", source, "present", "tpm"))

    runtime = doc.get("runtime") or {}
    for item in runtime.get("agents") or []:
        name = item.get("name") if isinstance(item, dict) else item
        if name:
            ident = str(name)
            if not ident.startswith("runtime-agent/"):
                ident = f"runtime-agent/{ident}"
            out.append(AvailableSurface("runtime-agent", ident, source,
                                        "present", "runtime"))
    for obj in k8s.get("objects") or []:
        if isinstance(obj, dict) and str(obj.get("kind") or "").lower() in (
                "runtimeclass", "daemonset", "pod"):
            name = str(obj.get("name") or "")
            if name:
                out.append(AvailableSurface("runtime-agent", f"runtime-agent/{name}", source,
                                            "present", "k8s object"))
    return out


def _looks_model(path: str) -> bool:
    low = path.lower()
    return any(low.endswith(ext) for ext in (
        ".safetensors", ".bin", ".pt", ".pth", ".ckpt", ".onnx", ".gguf", ".h5",
    )) or any(part in low for part in ("/weights/", "\\weights\\", "/checkpoint/", "\\checkpoint\\"))


# --------------------------------------------------------------------------- context


@dataclass
class SurfaceContext:
    profile: dict | None = None
    collection: dict | None = None
    probe: bool = False
    fixture: bool = False
    params: dict = field(default_factory=dict)
    extra: list[AvailableSurface] = field(default_factory=list)
    enforce: bool = False

    @classmethod
    def build(
        cls,
        *,
        profile: str | dict | None = None,
        collection: str | dict | None = None,
        params: dict | None = None,
        probe: bool = False,
        fixture: bool = False,
        enforce: bool | None = None,
    ) -> "SurfaceContext":
        if isinstance(profile, dict):
            prof = profile
            if profile.get("surfaces") and isinstance(profile["surfaces"][0], dict):
                prof = load_profile(profile.get("name") or profile.get("path"))
        else:
            prof = load_profile(profile) if profile not in (None, "") else None
        coll = load_collection(collection) if isinstance(collection, (str, Path)) else collection
        if coll is None and fixture:
            if prof is None:
                raise ValueError("--fixture requires --profile")
            coll = profile_collection(prof, mode="fixture")
        if coll is not None and coll.get("fixture"):
            fixture = True
        ctx = cls(profile=prof if isinstance(prof, dict) else None,
                  collection=coll if isinstance(coll, dict) else None,
                  probe=bool(probe), fixture=bool(fixture), params=dict(params or {}))
        if enforce is None:
            enforce = bool(ctx.profile or ctx.collection or ctx.probe or ctx.fixture)
        ctx.enforce = enforce
        return ctx

    @property
    def mode(self) -> str:
        if self.fixture or (self.collection or {}).get("fixture"):
            return "fixture"
        if self.collection:
            return str((self.collection or {}).get("mode") or "live")
        if self.profile:
            return "profile"
        return "direct"

    @property
    def profile_name(self) -> str:
        return str((self.profile or {}).get("name") or "")

    @property
    def complete(self) -> bool:
        if self.collection:
            sections = [_section_status(self.collection, n) for n in ("k8s", "http", "files", "hardware")]
            if all(s == "ok" for s in sections):
                return True
            if (self.profile or {}).get("complete"):
                return True
            return False
        return bool((self.profile or {}).get("complete"))

    def available(self) -> list[AvailableSurface]:
        out: list[AvailableSurface] = []
        if self.profile:
            for s in self.profile.get("surfaces") or []:
                out.append(AvailableSurface(s.type, s.id, f"profile:{self.profile_name}",
                                            "present", s.detail))
        if self.collection:
            out.extend(collection_surfaces(self.collection))
        # A direct HTTP target is a real surface even before a collection run.
        target = str(self.params.get("target") or self.params.get("url") or "").strip()
        if target.startswith(("http://", "https://")):
            out.append(AvailableSurface("http-endpoint", target, "params:target", "present",
                                        "explicit target"))
        out.extend(self.extra)
        # De-duplicate deterministically.
        seen: set[tuple[str, str, str]] = set()
        uniq: list[AvailableSurface] = []
        for s in out:
            key = (s.type, _norm_id(s.id), s.source)
            if key in seen:
                continue
            seen.add(key)
            uniq.append(s)
        return uniq

    def as_dict(self) -> dict:
        return {"profile": self.profile_name, "mode": self.mode, "fixture": self.fixture,
                "probe": self.probe, "complete": self.complete, "enforce": self.enforce}


# --------------------------------------------------------------------------- detection


def detect(requirements: Iterable[Any], ctx: SurfaceContext) -> list[SurfaceResult]:
    reqs = normalize_requirements(requirements)
    surfaces = ctx.available()
    results: list[SurfaceResult] = []
    for req in reqs:
        matches = [s for s in surfaces if surface_matches(req, s)]
        if matches:
            results.append(SurfaceResult(
                req, "present",
                f"{len(matches)} match(es): " + ", ".join(s.id for s in matches[:4]),
                [s.id for s in matches], sorted({s.source for s in matches})))
            continue
        if req.optional:
            results.append(SurfaceResult(req, "present", "optional surface not present",
                                         [], [], probed=False))
            continue
        if ctx.probe:
            results.append(SurfaceResult(
                req, "present", "explicit --probe (operator confirmed the deployment)",
                [], ["probe"], probed=True))
            continue
        if ctx.complete:
            where = []
            if ctx.profile:
                where.append(f"profile {ctx.profile_name}")
            if ctx.collection:
                where.append(f"collection ({ctx.mode})")
            results.append(SurfaceResult(
                req, "absent", "not found in " + " + ".join(where or ["empty inventory"])))
            continue
        detail = "no complete inventory"
        if ctx.collection:
            states = ", ".join(f"{n}={_section_status(ctx.collection, n)}"
                               for n in ("k8s", "http", "files", "hardware"))
            detail = f"incomplete collection: {states}"
        results.append(SurfaceResult(
            req, "unknown",
            detail + "; rerun collection or pass --probe to acknowledge the deployment"))
    return results


def verdict(results: list[SurfaceResult]) -> str:
    required = [r for r in results if not r.requirement.optional]
    if not required:
        return "production-testable"
    statuses = {r.status for r in required}
    if "absent" in statuses and statuses == {"absent"}:
        return "no-surface"
    if "absent" in statuses:
        return "conditional"
    if "unknown" in statuses:
        return "conditional"
    return "production-testable"


def matrix(profile: str | Path, modules: dict | None = None, *, collection=None,
           include_disabled: bool = False, probe: bool = False) -> dict:
    """Build the full module x surface matrix for one deployment profile."""
    from .registry import load_modules

    prof = load_profile(profile)
    mods = modules if modules is not None else load_modules(_INKBLADE / "modules")
    ctx = SurfaceContext.build(profile=prof, collection=collection, probe=probe)
    rows: list[dict] = []
    for key in sorted(mods):
        meta = mods[key]
        results = detect(meta.required_surfaces, ctx)
        v = verdict(results)
        rows.append({
            "module": key,
            "name": (meta.name or {}).get("en", key),
            "series": meta.series,
            "default_enabled": meta.default_enabled,
            "required_surfaces": [r.as_dict() for r in results],
            "verdict": v,
            "present": sum(1 for r in results if r.status == "present"),
            "absent": sum(1 for r in results if r.status == "absent"),
            "unknown": sum(1 for r in results if r.status == "unknown"),
        })
    total = len(rows)
    default_total = sum(1 for r in rows if r["default_enabled"])
    prod = sum(1 for r in rows if r["verdict"] == "production-testable")
    cond = sum(1 for r in rows if r["verdict"] == "conditional")
    none = sum(1 for r in rows if r["verdict"] == "no-surface")
    quarantined = sum(1 for r in rows if not r["default_enabled"])
    quarantined_none = sum(1 for r in rows
                           if not r["default_enabled"] and r["verdict"] == "no-surface")
    default_prod = sum(1 for r in rows if r["default_enabled"] and r["verdict"] == "production-testable")
    default_cond = sum(1 for r in rows if r["default_enabled"] and r["verdict"] == "conditional")
    default_none = sum(1 for r in rows if r["default_enabled"] and r["verdict"] == "no-surface")
    denom = total if include_disabled else default_total
    covered = prod if include_disabled else default_prod
    operable_n = (prod + cond) if include_disabled else (default_prod + default_cond)
    coverage = (covered / denom * 100.0) if denom else 0.0
    operable = (operable_n / denom * 100.0) if denom else 0.0
    return {
        "schema": "inkblade-surface-matrix-v1",
        "profile": prof["name"],
        "description": prof.get("description", ""),
        "mode": ctx.mode,
        "fixture": ctx.fixture,
        "complete": ctx.complete,
        "generated_at": _now(),
        "summary": {
            "modules": total,
            "default_enabled": default_total,
            "production_testable": prod,
            "conditional": cond,
            "no_surface": none,
            "default_production_testable": default_prod,
            "default_conditional": default_cond,
            "default_no_surface": default_none,
            "quarantined": quarantined,
            "quarantined_no_surface": quarantined_none,
            "coverage_basis": "all_modules" if include_disabled else "default_enabled",
            "coverage_pct": round(coverage, 2),
            "operable_pct": round(operable, 2),
        },
        "modules": rows,
    }


def render_matrix_md(doc: dict, *, detail: bool = True) -> str:
    s = doc["summary"]
    lines = [
        f"# Surface matrix — `{doc['profile']}`",
        "",
        doc.get("description", ""),
        "",
        f"- Data mode: **{doc['mode']}**" + (" (fixture)" if doc.get("fixture") else ""),
        f"- Default-enabled modules: **{s['default_enabled']}** / inventory {s['modules']}",
        f"- production-testable: **{s['default_production_testable']}** · "
        f"conditional: **{s['default_conditional']}** · no-surface: **{s['default_no_surface']}**",
        f"- Production coverage: **{s['coverage_pct']}%** · operable (incl. conditional): **{s['operable_pct']}%**",
        "",
        "| Module | Verdict | Required surfaces | Evidence |",
        "|---|---|---|---|",
    ]
    for row in doc["modules"]:
        req = "; ".join(
            f"{r['surface']['type']}:{r['surface']['selector']}={r['status']}"
            for r in row["required_surfaces"]) or "—"
        ev = "; ".join(r["evidence"] for r in row["required_surfaces"]) or "—"
        lines.append(f"| `{row['module']}` | {row['verdict']} | {_cell(req)} | {_cell(ev)} |")
    if not detail:
        return "\n".join(lines[:12])
    return "\n".join(lines)


def report_section(profile: str | Path, *, collection=None, include_disabled: bool = False) -> str:
    doc = matrix(profile, collection=collection, include_disabled=include_disabled)
    s = doc["summary"]
    lines = [
        "## 模块真实面覆盖 / Module surface coverage",
        "",
        f"- Profile: `{doc['profile']}` · data mode: **{doc['mode']}**"
        + (" · **FIXTURE DATA — not a production verdict**" if doc.get("fixture") else "")
        + (" · **PROFILE DECLARATION — not a live collection**"
           if doc.get("mode") == "profile" else ""),
        f"- Default-enabled modules: {s['default_enabled']}; production-testable "
        f"{s['default_production_testable']} ({s['coverage_pct']}%), conditional "
        f"{s['default_conditional']}, no-surface {s['default_no_surface']}.",
        "",
        "| Module | Verdict | Missing / unknown surfaces |",
        "|---|---|---|",
    ]
    no_surface = [r for r in doc["modules"] if r["verdict"] == "no-surface"]
    conditional = [r for r in doc["modules"] if r["verdict"] == "conditional"]
    for row in (no_surface + conditional)[:80]:
        missing = ", ".join(
            f"{r['surface']['type']}:{r['surface']['selector']} ({r['status']})"
            for r in row["required_surfaces"] if r["status"] != "present") or "—"
        lines.append(f"| `{row['module']}` | {row['verdict']} | {_cell(missing)} |")
    if len(no_surface) + len(conditional) > 80:
        lines.append(f"| … | | {len(no_surface) + len(conditional) - 80} more |")
    lines += ["", "Skipped modules are excluded from chain execution and coverage; they remain "
                  "available for customers that actually deploy the component."]
    return "\n".join(lines)


def gate(meta, ctx: SurfaceContext) -> dict:
    reqs = list(meta.required_surfaces or [])
    if not ctx.enforce and meta.default_enabled:
        return {"status": "run", "reason": "surface gate not requested (legacy direct call)",
                "results": [], "context": ctx.as_dict()}
    if not reqs:
        return {"status": "run", "reason": "module declares no deployment surface",
                "results": [], "context": ctx.as_dict()}
    results = detect(reqs, ctx)
    absent = [r for r in results if r.status == "absent" and not r.requirement.optional]
    unknown = [r for r in results if r.status == "unknown" and not r.requirement.optional]
    if absent:
        return {
            "status": "skipped-surface-absent",
            "reason": "required deployment surface is absent: "
                      + ", ".join(f"{r.requirement.type}:{r.requirement.selector}" for r in absent),
            "results": [r.as_dict() for r in results],
            "context": ctx.as_dict(),
        }
    if unknown:
        return {
            "status": "skipped-surface-unknown",
            "reason": "surface state is unknown; rerun `inkblade collect` or pass --probe: "
                      + ", ".join(f"{r.requirement.type}:{r.requirement.selector}" for r in unknown),
            "results": [r.as_dict() for r in results],
            "context": ctx.as_dict(),
        }
    return {"status": "run", "reason": "all required surfaces present",
            "results": [r.as_dict() for r in results], "context": ctx.as_dict()}


def default_module_keys(modules: dict) -> list[str]:
    return sorted(k for k, m in modules.items() if m.default_enabled)


def no_surface_modules(modules: dict) -> list[str]:
    return sorted(k for k, m in modules.items() if not m.default_enabled)


# --------------------------------------------------------------------------- helpers


def _cell(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _now() -> str:
    import datetime as _dt

    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


# --------------------------------------------------------------------------- derivation


_RULES: list[tuple[tuple[str, ...], tuple[tuple[str, str], ...]]] = [
    (("bmc", "ipmi", "redfish"), (("bmc", "bmc/redfish"),)),
    (("sonic", "cumulus", "switch-os"), (("switch", "switch/sonic"),)),
    (("ib-", "infiniband", "sharp", "fabric-", "roce-", "rail-mismatch",
      "rail-optimized", "rail topology"), (("switch", "switch/fabric"),)),
    (("dpu",), (("http-endpoint", "/dpu"), ("bmc", "bmc/dpu"))),
    (("cloud-", "imds", "metadata-egress", "ssrf"), (("http-endpoint", "metadata"),
                                                      ("k8s-object", "Pod"))),
    (("kubelet",), (("k8s-object", "Node"), ("http-endpoint", "/healthz"))),
    (("etcd",), (("k8s-object", "Pod"), ("http-endpoint", ":2379"))),
    (("apiserver", "api-server", "apiservice"), (("k8s-object", "APIService"),
                                                 ("http-endpoint", "/healthz"))),
    (("admission", "webhook"), (("k8s-object", "ValidatingWebhookConfiguration"),
                                ("http-endpoint", "/validate"))),
    (("ray", "kuberay"), (("k8s-object", "RayCluster"), ("http-endpoint", "/dashboard"))),
    (("lws",), (("k8s-object", "LeaderWorkerSet"), ("http-endpoint", "/healthz"))),
    (("hami", "cgpu", "gpu-pool", "gpu-sharing"), (("k8s-object", "DaemonSet/hami-device-plugin"),
                                                   ("http-endpoint", "/metrics"))),
    (("mig-", "mps-", "gpu-", "nvidia", "driver-"), (("k8s-object", "Node"),
                                                      ("runtime-agent", "nvidia-device-plugin"))),
    (("vllm",), (("http-endpoint", "/v1/models"), ("config-file", "vllm"))),
    (("sglang",), (("http-endpoint", "/v1/models"), ("config-file", "sglang"))),
    (("litellm", "aigateway", "ai-gateway"), (("http-endpoint", "/v1/models"),
                                              ("config-file", "litellm"))),
    (("dify", "open-webui"), (("http-endpoint", "/api"), ("config-file", "app"))),
    (("mlflow", "model-registry", "experiment-tracker"), (("http-endpoint", "/api"),
                                                          ("model-file", "model"))),
    (("cache", "kv-", "prefix-", "router-cache"), (("http-endpoint", "/v1/chat/completions"),
                                                    ("k8s-object", "Pod"))),
    (("megatron", "deepspeed", "llamafactory", "msswift", "torchrun", "trl-", "verl",
      "skyrl", "areal", "slime", "checkpoint", "pretrain", "sft-", "rl-", "training-",
      "data-pipeline", "tokenizer", "reward-"), (("config-file", "train"),
                                                  ("model-file", "checkpoint"))),
    (("nccl", "collective", "long-context-training"), (("k8s-object", "Pod"),
                                                        ("runtime-agent", "nccl"))),
    (("vector-db",), (("http-endpoint", "/collections"),)),
    (("observability",), (("http-endpoint", "/metrics"), ("k8s-object", "Pod"))),
    (("storage", "csi-", "pvc"), (("k8s-object", "CSIDriver"), ("runtime-agent", "csi"))),
    (("defense-bypass-",), (("runtime-agent", "runtime-agent"), ("k8s-object", "Pod"))),
    (("kube-audit", "kubetrail"), (("k8s-object", "Pod"), ("config-file", "audit"))),
    (("cis-", "kube-bench"), (("k8s-object", "Node"), ("config-file", "kubelet"))),
    (("privileged", "escape-", "runtime-socket", "runc", "containerd", "kernel",
      "cni-", "rbac", "csr-", "impersonate", "sa-token", "secret-", "gitops",
      "attack-path", "kubehound", "kubehunter", "kubiscan", "peirates",
      "overprivileged", "reverse-rbac", "network-policy"), (("k8s-object", "Pod"),)),
    (("gang-scheduler", "scheduler"), (("k8s-object", "Pod"), ("config-file", "scheduler"))),
    (("spiffe", "spire"), (("k8s-object", "Deployment/spire-server"),
                           ("runtime-agent", "spire-agent"), ("config-file", "spire"))),
    (("ambient", "istio", "mesh"), (("k8s-object", "DaemonSet/ztunnel"),
                                    ("runtime-agent", "ztunnel"), ("http-endpoint", "/healthz/ready"))),
    (("confidential", "kata", "tee-"), (("k8s-object", "RuntimeClass/kata-cc"),
                                        ("runtime-agent", "kata"), ("config-file", "kata"))),
    (("wasm",), (("k8s-object", "RuntimeClass/wasm"), ("runtime-agent", "wasmtime"))),
    (("post-quantum", "pq-tls"), (("http-endpoint", "/tls"),)),
    (("federated", "nvflare", "flower"), (("http-endpoint", "/fl"), ("k8s-object", "Deployment"))),
    (("watermark",), (("http-endpoint", "/watermark"), ("model-file", "model"))),
    (("provenance", "in-toto", "slsa"), (("config-file", "provenance"), ("model-file", "model"))),
    (("pcie", "iommu"), (("k8s-object", "Node"), ("config-file", "iommu"))),
    (("tpm", "attestation"), (("bmc", "tpm"), ("config-file", "attest"))),
]


def derive_surfaces(key: str, description: str = "", series: str = "") -> list[dict]:
    """Best-effort declaration used to bootstrap the central surface map."""
    text = f"{key} {description} {series}".lower()
    picked: list[dict] = []
    for words, surfaces in _RULES:
        if any(w in text for w in words):
            for stype, selector in surfaces:
                item = {"type": stype, "selector": selector}
                if item not in picked:
                    picked.append(item)
    if not picked:
        picked = [{"type": "k8s-object", "selector": "Pod"},
                  {"type": "http-endpoint", "selector": "/healthz"}]
    return picked
