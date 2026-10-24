"""Tetragon/eBPF 盲区：指纹 + 良性覆盖探针两态评估（benign-only，无恶意载荷）。"""
from __future__ import annotations


def _engine():
    try:
        from trident.core import defenseprobe
        return defenseprobe
    except Exception:  # 直接文件加载回退（runner 场景）
        import importlib.util
        from pathlib import Path
        core = Path(__file__).resolve().parents[2] / "core" / "defenseprobe.py"
        spec = importlib.util.spec_from_file_location("trident_core_defenseprobe", core)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod


def run(ctx, params):
    return _engine().run_module_assessment("tetragon", ctx, params)
