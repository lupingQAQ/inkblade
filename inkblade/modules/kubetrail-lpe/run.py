"""kubetrail-lpe — 16 条内核 LPE CVE + 逃逸原语启发式（只判定，不利用）。"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_surface_common", _PARENT / "_surface-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

finding, run_surface = _C.finding, _C.run_surface
section = _C.section


def _view(snapshot: dict) -> dict:
    view = dict(snapshot.get("inpod") or {})
    nodes = section(snapshot, "nodes")
    node = view.get("node") or (nodes[0] if nodes else {})
    if node:
        view.setdefault("node", node)
    runtime = dict(view.get("runtime") or {})
    if not runtime.get("runc"):
        for candidate in nodes:
            if candidate.get("runc"):
                runtime["runc"] = candidate["runc"]
                break
    if runtime:
        view["runtime"] = runtime
    return view


def analyze(snapshot: dict, params: dict) -> list[dict]:
    from inkblade.kubetrail.lpe import assess, findings

    report = assess(_view(snapshot))
    return [finding(
        f["sev"], f["title"], f["detail"], evidence=f.get("evidence", ""),
        mapping_text=f.get("mapping", "KubeTrail LPE 启发式"),
        fix=f.get("fix", ""), cve=f.get("cve", ""), confidence=f.get("confidence", ""),
    ) for f in findings(report)]


def extra(snapshot: dict, findings: list[dict]) -> dict:
    from inkblade.kubetrail.lpe import RULES

    cves = sorted({f.get("cve") for f in findings if f.get("cve")})
    return {"rules": len(RULES), "cves_at_risk": len(cves), "cves": cves,
            "confidence": "heuristic（版本区间 + 配置前置，未执行利用）"}


def run(ctx: dict, params: dict) -> dict:
    return run_surface(ctx, params, analyze, family="KubeTrail LPE 启发式", extra=extra)
