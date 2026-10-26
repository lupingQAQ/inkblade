"""Weapon pack msswift-eval-escape: ms-swift ranks Expression Sandbox Escape (parameter-driven)."""
from __future__ import annotations

import importlib.util
from pathlib import Path

KEY = "msswift-eval-escape"


def _load_common():
    path = Path(__file__).resolve().parent.parent / "_exploit-common.py"
    spec = importlib.util.spec_from_file_location(f"_exploit_common_{KEY.replace('-', '_')}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_COMMON = _load_common()


def run(ctx: dict, params: dict) -> dict:
    payload = str(params.get("payload") or "")
    if not payload:
        return _COMMON.needs_target(KEY, params.get("variants") or [],
                                    "parameter/expression payload")
    return _COMMON.result(
        f"{KEY}: payload '{payload}' is applied to the training configuration",
        [_COMMON.finding("high", f"{KEY}: attacker-controlled parameter",
                         {"payload": payload},
                         evidence="params")],
    )
