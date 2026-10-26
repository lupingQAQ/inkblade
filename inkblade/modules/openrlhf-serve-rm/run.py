"""Weapon pack openrlhf-serve-rm: OpenRLHF Reward-Model Score Forgery."""
from __future__ import annotations

import importlib.util
from pathlib import Path

KEY = "openrlhf-serve-rm"
ROUTES = [
        {
                "name": "reward health",
                "method": "GET",
                "path": "/health",
                "expect": 200,
                "sev": "medium",
                "fix": "Bind --serve-rm to 127.0.0.1 or add an auth proxy."
        },
        {
                "name": "reward score",
                "method": "POST",
                "path": "/v1/score",
                "body": {
                        "prompt": "INKBLADE benign probe",
                        "response": "ok"
                },
                "expect": 200,
                "sev": "high",
                "fix": "Require a bearer token on the reward server."
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
