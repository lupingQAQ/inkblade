"""kubetrail-collector — KubeTrail in-pod 采集最小闭环（13 bucket，只读）。"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_surface_common", _PARENT / "_surface-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

finding, run_surface = _C.finding, _C.run_surface


def analyze(snapshot: dict, params: dict) -> list[dict]:
    from trident.kubetrail.collector import collect

    view = snapshot.get("inpod") or snapshot
    report = collect(view, root=params.get("root"))
    findings = report["findings"]
    return [finding(
        f["sev"], f["title"], f["detail"], evidence=f.get("evidence", ""),
        mapping_text=f.get("mapping", "KubeTrail in-pod 采集（CM-22）"),
        fix=f.get("fix", ""), source="kubetrail-collector",
    ) for f in findings]


def extra(snapshot: dict, findings: list[dict]) -> dict:
    from trident.kubetrail.collector import COLLECTORS

    return {"collectors": len(COLLECTORS), "exposures": len(findings),
            "critical": sum(1 for f in findings if f.get("sev") == "critical"),
            "inputs": "inpod" if snapshot.get("inpod") else "snapshot"}


def run(ctx: dict, params: dict) -> dict:
    return run_surface(ctx, params, analyze, family="KubeTrail in-pod 采集", extra=extra)
