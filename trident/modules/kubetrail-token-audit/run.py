"""kubetrail-token-audit — legacy ServiceAccount token 逐 token 审计（CM-05）。"""
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
    from trident.kubetrail.token_audit import audit_tokens, findings

    tokens = section(snapshot, "tokens")
    report = audit_tokens(tokens)
    out = []
    for item in findings(report):
        out.append(finding(
            item["sev"], item["title"], item["detail"], evidence=item["evidence"],
            mapping_text=item["mapping"], fix=item["fix"],
        ))
    return out


def extra(snapshot: dict, findings: list[dict]) -> dict:
    from trident.kubetrail.token_audit import audit_tokens

    report = audit_tokens(section(snapshot, "tokens"))
    return {"tokens": report["summary"]["total"], "legacy": report["summary"]["legacy"],
            "critical": report["summary"]["critical"], "high": report["summary"]["high"]}


def run(ctx: dict, params: dict) -> dict:
    return run_surface(ctx, params, analyze, family="KubeTrail token 审计", extra=extra)
