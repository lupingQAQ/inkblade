"""Weapon pack llm2jev-file-read: llm2jev image_url Local File Read."""
from __future__ import annotations

import importlib.util
from pathlib import Path

KEY = "llm2jev-file-read"
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
                "name": "file image read",
                "method": "POST",
                "path": "/v1/chat/completions",
                "body": {
                        "model": "llm2jev",
                        "messages": [
                                {
                                        "role": "user",
                                        "content": [
                                                {
                                                        "type": "image_url",
                                                        "image_url": {
                                                                "url": "file:///etc/hostname"
                                                        }
                                                }
                                        ]
                                }
                        ]
                },
                "expect": 200,
                "sev": "high",
                "fix": "Allow only http(s) URLs with an allow-list; never open local paths."
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
