# -*- coding: utf-8 -*-
"""BMC / switch / TPM configuration import convention.

Expected export layout::

    <root>/bmc/*.json          {"id","vendor","model","firmware","address"}
    <root>/switches/*.json     {"id","vendor","os","version","address"}
    <root>/tpm/*.json          {"id","vendor","version","ek_sha256"}
    <root>/inventory.json      optional overall inventory

Credentials are never persisted: keys matching password/secret/token/key are
redacted.  Nothing is contacted over the network.
"""

from __future__ import annotations

import json
from pathlib import Path

_SECRET = ("password", "passwd", "secret", "token", "api_key", "apikey",
           "private_key", "credential", "auth")
_SUBDIRS = {
    "bmc": ("bmc", "redfish", "ipmi"),
    "switches": ("switches", "switch", "sonic", "cumulus", "fabric"),
    "tpm": ("tpm", "attestation"),
}


def _clean(raw: dict) -> dict:
    out = {}
    for key, value in raw.items():
        low = str(key).lower()
        if any(s in low for s in _SECRET):
            out[key] = "<redacted>"
        elif isinstance(value, (str, int, float, bool)) or value is None:
            out[key] = value
        elif isinstance(value, list):
            out[key] = [v for v in value if isinstance(v, (str, int, float, bool))][:50]
        elif isinstance(value, dict):
            out[key] = _clean(value)
    return out


def _read_docs(directory: Path) -> tuple[list[dict], list[str]]:
    docs: list[dict] = []
    errors: list[str] = []
    if not directory.exists():
        return docs, errors
    for path in sorted(directory.glob("*.json")):
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            errors.append(f"{path.name}: {type(exc).__name__}: {exc}")
            continue
        items = raw if isinstance(raw, list) else [raw]
        for item in items:
            if not isinstance(item, dict):
                continue
            item = _clean(item)
            item.setdefault("id", item.get("name") or item.get("host") or path.stem)
            item["file"] = path.name
            item["source"] = "collection:hardware"
            docs.append(item)
    return docs, errors


def collect(root: str | Path) -> dict:
    base = Path(root)
    if not base.exists():
        return {"schema": "trident-hardware-collection-v1", "status": "unavailable",
                "root": str(base), "bmc": [], "switches": [], "tpm": [],
                "errors": [f"not found: {base}"]}
    bmc: list[dict] = []
    switches: list[dict] = []
    tpm: list[dict] = []
    errors: list[str] = []
    for kind, names in _SUBDIRS.items():
        found = False
        for name in names:
            directory = base / name
            if directory.is_dir():
                found = True
                docs, errs = _read_docs(directory)
                errors.extend(errs)
                {"bmc": bmc, "switches": switches, "tpm": tpm}[kind].extend(docs)
        if not found:
            continue
    inventory = base / "inventory.json"
    if inventory.is_file():
        try:
            raw = json.loads(inventory.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                for key, target in (("bmc", bmc), ("switches", switches), ("tpm", tpm)):
                    for item in raw.get(key) or []:
                        if isinstance(item, dict):
                            item = _clean(item)
                            item.setdefault("id", item.get("name") or key)
                            item["source"] = "collection:hardware"
                            target.append(item)
        except (OSError, ValueError) as exc:
            errors.append(f"inventory.json: {type(exc).__name__}: {exc}")
    status = "ok" if (bmc or switches or tpm) else "unavailable"
    return {
        "schema": "trident-hardware-collection-v1",
        "status": status,
        "root": str(base),
        "bmc": bmc,
        "switches": switches,
        "tpm": tpm,
        "errors": errors[:50],
    }
