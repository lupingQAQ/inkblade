"""Weapon pack openjev-clef-release-module: OpenJEV clef Release-Module Load (function-level, read-only probe)."""
from __future__ import annotations

import importlib.util
from pathlib import Path

KEY = "openjev-clef-release-module"
READER = 'importlib exec_module(joint_schema_model.py)'


def _load_common():
    path = Path(__file__).resolve().parent.parent / "_exploit-common.py"
    spec = importlib.util.spec_from_file_location(f"_exploit_common_{KEY.replace('-', '_')}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_COMMON = _load_common()


def run(ctx: dict, params: dict) -> dict:
    return _COMMON.read_file_probe(ctx, KEY, params, reader=READER,
                                   payload=str(params.get("payload") or ""))
