# -*- coding: utf-8 -*-
"""cis-benchmark-audit — CIS Kubernetes v1.8.x + 节点/发行版加固 + ML 部署基线。

输入：fixture snapshot（dict 或 JSON 路径）；输出 pass/fail/manual 矩阵 + findings。
判定只读：不访问集群、不执行 kube-bench，也不写入任何对象。
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

from inkblade.cis.catalog import CATALOG
from inkblade.cis.engine import assess, findings as cis_findings
from inkblade.cis.ml import assess_ml, findings as ml_findings

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_surface_common", _PARENT / "_surface-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

load_snapshot = _C.load_snapshot


def run(ctx: dict, params: dict) -> dict:
    snapshot = load_snapshot(params)
    include_ml = bool(params.get("include_ml", True))

    report = assess(snapshot)
    summary = dict(report["summary"])
    summary["matrix"] = report["matrix"]
    summary["detection"] = "fixture-read-only"

    fs = cis_findings(report)
    if include_ml:
        ml_report = assess_ml(snapshot)
        summary["ml"] = ml_report["summary"]
        summary["ml_matrix"] = ml_report["matrix"]
        fs += ml_findings(ml_report)
    else:
        summary["ml"] = {"total": 0, "pass": 0, "fail": 0, "manual": 0,
                         "skipped": True}

    src = params.get("snapshot")
    summary["source"] = src if isinstance(src, str) else "<inline snapshot>"
    summary["rules_total"] = len(CATALOG)
    return {
        "summary": json.dumps(summary, ensure_ascii=False),
        "findings": fs,
        "artifacts": [],
    }
