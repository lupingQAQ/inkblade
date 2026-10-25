# -*- coding: utf-8 -*-
"""Public CVE catalog: load / validate / version-range match / Markdown render.

Data file: ``trident/core/cve-catalog.json``. Every entry carries a primary
source URL and a CVE.org verification anchor. Honesty rules (locked by tests):
a fixed version is recorded only when the advisory states one; otherwise
``fixed=null`` with a non-empty ``fixed_note``. A vendor's "won't fix" is not
recorded as fixed.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

CATALOG_PATH = Path(__file__).resolve().parent / "cve-catalog.json"
SCHEMA = "trident-cve-catalog-v1"
SEVERITIES = ("critical", "high", "medium", "low", "info")
SOURCE_TYPES = ("nvd", "github-advisory", "vendor", "cve-record", "research")

_REQUIRED = (
    "id", "cve", "component", "component_name", "title", "kind", "severity",
    "affected", "version_range", "fixed", "exploit_conditions", "primitive",
    "requires_hardware", "mockable", "modules", "source", "source_type",
    "verified_via",
)
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_ID_RE = re.compile(r"^(CVE-\d{4}-\d{4,}|[A-Za-z][A-Za-z0-9-]{3,})$")
_TOKEN_RE = re.compile(r"^(>=|<=|>|<|==|=)?\s*v?(\d+(?:\.\d+)*)$")


class CatalogError(ValueError):
    """Invalid catalog structure or version expression."""


@lru_cache(maxsize=1)
def load(path: Path | str | None = None) -> dict:
    p = Path(path) if path else CATALOG_PATH
    data = json.loads(p.read_text(encoding="utf-8"))
    if data.get("schema") != SCHEMA:
        raise CatalogError(f"{p}: unknown schema {data.get('schema')!r}")
    entries = data.get("entries") or []
    seen: set[str] = set()
    for e in entries:
        missing = [f for f in _REQUIRED if f not in e]
        if missing:
            raise CatalogError(f"{e.get('id', '?')}: missing fields {missing}")
        if not _ID_RE.match(str(e["id"])):
            raise CatalogError(f"invalid entry id {e['id']!r}")
        if e["id"] in seen:
            raise CatalogError(f"duplicate entry {e['id']}")
        seen.add(e["id"])
        if e["cve"] is not None and not _CVE_RE.match(str(e["cve"])):
            raise CatalogError(f"{e['id']}: invalid cve field {e['cve']!r}")
        if e["severity"] not in SEVERITIES:
            raise CatalogError(f"{e['id']}: unknown severity {e['severity']!r}")
        if not str(e["source"]).startswith("https://"):
            raise CatalogError(f"{e['id']}: source must be an https URL")
        if not str(e["verified_via"]).startswith("https://"):
            raise CatalogError(f"{e['id']}: verified_via must be an https URL")
        if e["source_type"] not in SOURCE_TYPES:
            raise CatalogError(f"{e['id']}: unknown source_type {e['source_type']!r}")
        if not e["modules"]:
            raise CatalogError(f"{e['id']}: modules is empty")
        if e["fixed"] is None and not str(e.get("fixed_note") or "").strip():
            raise CatalogError(f"{e['id']}: fixed=null but fixed_note is empty")
        if e.get("cvss") is not None:
            score = float(e["cvss"])
            if not 0.0 <= score <= 10.0:
                raise CatalogError(f"{e['id']}: cvss out of range {score}")
        version_affected("0", e["version_range"])
    cves = [e for e in entries if e["cve"]]
    if len(cves) < 30:
        raise CatalogError(f"{p}: {len(cves)} CVE entries (<30)")
    return data


def entries() -> list[dict]:
    return list(load()["entries"])


def entry(cve_or_id: str) -> dict | None:
    needle = cve_or_id.strip().upper()
    return next((e for e in entries() if str(e["id"]).upper() == needle
                 or str(e.get("cve") or "").upper() == needle), None)


def for_module(module_key: str) -> list[dict]:
    return [e for e in entries() if module_key in e["modules"]]


def by_component(component: str) -> list[dict]:
    return [e for e in entries() if e["component"] == component]


def _version_tuple(v: str) -> tuple[int, ...]:
    text = str(v).strip().lstrip("vV")
    if not re.match(r"^\d+(?:\.\d+)*$", text):
        raise CatalogError(f"invalid version {v!r}")
    return tuple(int(x) for x in text.split("."))


def _cmp(observed: str, op: str, ref: str) -> bool:
    obs, want = _version_tuple(observed), _version_tuple(ref)
    width = max(len(obs), len(want))
    obs += (0,) * (width - len(obs))
    want += (0,) * (width - len(want))
    return {"<": obs < want, "<=": obs <= want, ">": obs > want,
            ">=": obs >= want, "==": obs == want, "=": obs == want}[op]


def version_affected(observed: str, expression: str) -> bool:
    """Return True when the version falls in the expression.

    Grammar: ``*``; comma/semicolon-separated AND clauses; each clause accepts
    ``>=X``/``<=X``/``>X``/``<X``/``==X``/``X``; also ``prior to X`` and
    ``X to Y``. Unknown forms raise CatalogError (never fail open).
    """
    text = str(expression).strip()
    if not text:
        raise CatalogError("empty version range")
    if text == "*":
        return True
    text = text.replace(",", ",").replace(";", ";")
    clauses = [c.strip() for c in re.split(r"[;,]", text) if c.strip()]
    for clause in clauses:
        low = clause.lower()
        if low.startswith("prior to "):
            if not _cmp(observed, "<", clause[len("prior to "):].strip()):
                return False
            continue
        m = re.match(r"^(\d+(?:\.\d+)*)\s+to\s+(\d+(?:\.\d+)*)$", clause)
        if m:
            if not (_cmp(observed, ">=", m.group(1)) and _cmp(observed, "<=", m.group(2))):
                return False
            continue
        m = _TOKEN_RE.match(clause)
        if not m:
            raise CatalogError(f"unparseable version clause: {clause!r}")
        op, ver = m.group(1) or "==", m.group(2)
        if not _cmp(observed, op, ver):
            return False
    return True


def _md_escape(value) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ").strip()


def render_markdown(data: dict | None = None) -> str:
    data = data or load()
    entries = data["entries"]
    cves = [e for e in entries if e["cve"]]
    mockable = [e for e in entries if e["mockable"]]
    hw = [e for e in entries if e["requires_hardware"]]
    lines = [
        "# Public CVE Arsenal (Trident)",
        "",
        f"- Verified: {data['verified_at']}",
        f"- Entries: **{len(entries)}** (CVE {len(cves)} + component advisories {len(entries) - len(cves)})",
        f"- Mockable: **{len(mockable)}**; real-hardware required: **{len(hw)}**",
        "- Sources: NVD / GitHub Security Advisory / vendor advisory / CVE.org; each entry webfetch-verified.",
        "- Honesty: entries without an observed official fix use `fixed=null` plus `fixed_note`; no invented versions.",
        "",
        "> Authorized lab / owned-asset use only. Modules default to read-only probes; write surfaces "
        "require `backup_targets` and pass the runner backup gate. Hardware-only surfaces are "
        "version-fingerprint / read-only checks and explicitly report `unsupported` without real data.",
        "",
        "## Summary",
        "",
        "| CVE/Advisory | Component | Type | CVSS | Affected | Fixed | Mockable | Hardware | Modules |",
        "|---|---|---|---:|---|---|---|---|---|",
    ]
    for e in sorted(entries, key=lambda x: (x["component"], x["id"])):
        fixed = e["fixed"] or "unfixed / no official fix"
        lines.append(
            f"| `{e['id']}` | {_md_escape(e['component_name'])} | {e['kind']} | "
            f"{e.get('cvss') if e.get('cvss') is not None else 'N/A'} | "
            f"{_md_escape(e['affected'])} | {_md_escape(fixed)} | "
            f"{'yes' if e['mockable'] else 'no'} | {'yes' if e['requires_hardware'] else 'no'} | "
            f"{', '.join(f'`{m}`' for m in e['modules'])} |"
        )
    lines += ["", "## Entry details", ""]
    for e in sorted(entries, key=lambda x: (x["component"], x["id"])):
        lines += [
            f"### {e['id']} - {e['component_name']}",
            "",
            f"- Component/type: `{e['component']}` / `{e['kind']}`; severity: **{e['severity']}**"
            f" (CVSS {e.get('cvss') if e.get('cvss') is not None else 'N/A'})",
            f"- Affected: `{e['affected']}`; fixed: `{e['fixed'] or 'unfixed / no official fix'}`",
        ]
        if e.get("fixed_note"):
            lines.append(f"- Fix note: {e['fixed_note']}")
        lines += [
            f"- Conditions: {e['exploit_conditions']}",
            f"- Primitive: {e['primitive']}",
            f"- Mockable / hardware: {'yes' if e['mockable'] else 'no'} / "
            f"{'yes' if e['requires_hardware'] else 'no'}",
            f"- Modules: {', '.join(f'`{m}`' for m in e['modules'])}",
            f"- Source: {e['source']} ({e['source_type']})",
            f"- Verified via: {e['verified_via']}",
            "",
        ]
    return "\n".join(lines).rstrip() + "\n"
