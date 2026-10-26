"""Weapon pack msswift-trust-remote-code: ms-swift trust_remote_code Model Load (function-level, read-only probe)."""
from __future__ import annotations

import importlib.util
from pathlib import Path

KEY = "msswift-trust-remote-code"
READER = 'transformers.AutoModel.from_pretrained(trust_remote_code=True)'


def _load_common():
    path = Path(__file__).resolve().parent.parent / "_reserve-common.py"
    spec = importlib.util.spec_from_file_location(f"_reserve_common_{KEY.replace('-', '_')}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_COMMON = _load_common()


def run(ctx: dict, params: dict) -> dict:
    return _COMMON.read_file_probe(ctx, KEY, params, reader=READER,
                                   payload=str(params.get("payload") or ""))
