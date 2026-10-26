# -*- coding: utf-8 -*-
"""Generate ``inkblade/profiles/surface-map.json`` from module metadata.

Run after adding a module: ``python tools/gen-surface-map.py``.
Explicit ``surfaces`` / ``required_surfaces`` in a module.json always wins;
otherwise the heuristic in ``core.surface.derive_surfaces`` bootstraps a
declaration that a maintainer can review and tighten.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from inkblade.core.surface import derive_surfaces  # noqa: E402

MODULES = ROOT / "inkblade" / "modules"
OUT = ROOT / "inkblade" / "profiles" / "surface-map.json"

# Selectors where the generic keyword heuristic is too coarse.  These are
# reviewed declarations, not guesses.
OVERRIDES: dict[str, list[dict]] = {
    "sglang-route-poison": [
        {"type": "http-endpoint", "selector": "/route"},
        {"type": "http-endpoint", "selector": "/register_dp_rank"},
        {"type": "config-file", "selector": "sglang"},
    ],
    "sglang-admin-failopen": [
        {"type": "http-endpoint", "selector": "/admin"},
        {"type": "config-file", "selector": "sglang"},
    ],
    "sglang-weight-exfil": [
        {"type": "http-endpoint", "selector": "/v1/models"},
        {"type": "model-file", "selector": "model"},
    ],
    "vllm-pickle-pipe-rce": [
        {"type": "config-file", "selector": "vllm"},
        {"type": "model-file", "selector": "model"},
    ],
    "vllm-plugin-auth-bypass": [
        {"type": "http-endpoint", "selector": "/v1/models"},
        {"type": "config-file", "selector": "vllm"},
    ],
    "storage-protocol-csi": [
        {"type": "k8s-object", "selector": "CSIDriver"},
        {"type": "runtime-agent", "selector": "csi"},
    ],
    "api-server-flood-surface": [
        {"type": "k8s-object", "selector": "APIService"},
        {"type": "k8s-object", "selector": "Pod"},
        {"type": "http-endpoint", "selector": "/healthz"},
    ],
    "aigateway-guardrail-bypass": [
        {"type": "http-endpoint", "selector": "/v1/models"},
        {"type": "config-file", "selector": "litellm"},
    ],
    "data-provenance-audit": [
        {"type": "http-endpoint", "selector": "/provenance/attestation"},
    ],
}


def main() -> int:
    modules: dict[str, list[dict]] = {}
    for directory in sorted(p for p in MODULES.iterdir() if p.is_dir()):
        manifest = directory / "module.json"
        if not manifest.is_file():
            continue
        raw = json.loads(manifest.read_text(encoding="utf-8"))
        explicit = raw.get("surfaces") or raw.get("required_surfaces") or []
        modules[raw["key"]] = list(explicit) if explicit else OVERRIDES.get(
            raw["key"]) or derive_surfaces(
            raw["key"], raw.get("description", ""), raw.get("series", ""))
    doc = {
        "schema": "inkblade-surface-map-v1",
        "description": "Declared deployment surfaces per module. Explicit module.json surfaces win; this map covers legacy modules.",
        "modules": modules,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"surface-map: {len(modules)} modules -> {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
