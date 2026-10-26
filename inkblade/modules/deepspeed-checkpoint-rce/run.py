"""DeepSpeed 检查点 RCE ? CVE ????????? _cve-specs.py??"""
from __future__ import annotations

import importlib.util
from pathlib import Path

KEY = "deepspeed-checkpoint-rce"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_PARENT = Path(__file__).resolve().parent.parent
_C = _load(f"_cve_common_{KEY.replace('-', '_')}", _PARENT / "_cve-common.py")
_S = _load(f"_cve_specs_{KEY.replace('-', '_')}", _PARENT / "_cve-specs.py")
SPEC = _S.ALL[KEY]


def run(ctx: dict, params: dict) -> dict:
    if "analyze" in SPEC:
        return _C.run_snapshot(ctx, params, SPEC, SPEC["analyze"])
    return _C.run_http(ctx, params, SPEC)
