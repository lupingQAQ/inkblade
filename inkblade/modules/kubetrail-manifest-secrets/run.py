"""kubetrail-manifest-secrets — manifest/configmap 云密钥扫描（三态脱敏，raw 不落证据）。"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_surface_common", _PARENT / "_surface-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

finding, run_surface = _C.finding, _C.run_surface
section = _C.section


def analyze(snapshot: dict, params: dict) -> list[dict]:
    from inkblade.kubetrail.manifestscan import scan_configmaps, scan_manifests

    out: list[dict] = []
    report = scan_manifests(section(snapshot, "manifests"))
    out += report["findings"]
    for hit in scan_configmaps(section(snapshot, "configmaps"))["findings"]:
        out.append({**hit, "title": "ConfigMap " + hit["title"]})
    return out


def extra(snapshot: dict, findings: list[dict]) -> dict:
    kinds: dict[str, int] = {}
    for item in findings:
        kind = item.get("secret_kind") or "unknown"
        kinds[kind] = kinds.get(kind, 0) + 1
    return {"manifests": len(section(snapshot, "manifests")),
            "configmaps": len(section(snapshot, "configmaps")),
            "by_kind": kinds, "tri_state": "redact+metadata（raw 需显式 TriStore）"}


def run(ctx: dict, params: dict) -> dict:
    return run_surface(ctx, params, analyze, family="KubeTrail manifest 密钥扫描", extra=extra)
