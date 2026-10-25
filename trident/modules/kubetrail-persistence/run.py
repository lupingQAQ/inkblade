"""kubetrail-persistence — KubeTrail 权限维持七模板检测侧（只读，不生成植入模板）。"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_surface_common", _PARENT / "_surface-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

finding, run_surface = _C.finding, _C.run_surface


def analyze(snapshot: dict, params: dict) -> list[dict]:
    from trident.kubetrail.persistence import detect

    report = detect(snapshot)
    return [finding(
        f["sev"], f["title"], f["detail"], evidence=f.get("evidence", ""),
        mapping_text=f.get("mapping", "KubeTrail 权限维持检测（K8）"),
        fix=f.get("fix", ""),
    ) for f in report["findings"]]


def extra(snapshot: dict, findings: list[dict]) -> dict:
    from trident.kubetrail.persistence import detect

    report = detect(snapshot)
    return {"indicators": report["indicators"], "findings": len(findings),
            "templates_detected": len([k for k, v in report["indicators"].items() if v])}


def run(ctx: dict, params: dict) -> dict:
    return run_surface(ctx, params, analyze, family="KubeTrail 持久化检测", extra=extra)
