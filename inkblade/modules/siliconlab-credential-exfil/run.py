"""Weapon pack siliconlab-credential-exfil: OpenJev-SiliconLab Credential Exfiltration."""
from __future__ import annotations

import importlib.util
from pathlib import Path

KEY = "siliconlab-credential-exfil"
ROUTES = [
        {
                "name": "service health",
                "method": "GET",
                "path": "/",
                "expect": 200,
                "sev": "medium",
                "fix": "Require auth on the evaluation API."
        },
        {
                "name": "attacker base_url",
                "method": "POST",
                "path": "/api/evaluate",
                "body": {
                        "base_url": "http://127.0.0.1:9/inkblade",
                        "prompt": "probe"
                },
                "expect": 200,
                "sev": "high",
                "fix": "Pin provider endpoints server-side and reject caller-supplied base_url."
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
