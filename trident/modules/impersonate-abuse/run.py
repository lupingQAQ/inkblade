"""impersonate-abuse — impersonate 冒充。"""

from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_privesc_common", _PARENT / "_privesc-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)


def run(ctx: dict, params: dict) -> dict:
    return _COMMON.run_detect(ctx, params, "impersonate-abuse", "impersonate 冒充")
