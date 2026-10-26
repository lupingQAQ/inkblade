# -*- coding: utf-8 -*-
"""kernel-lpe-audit — 内核/容器运行时 LPE 检测（版本区间 + 前置面，detection-only）。

输入：多节点内核/组件快照（dict 或 JSON 路径），例如 lab/fixtures/lpe/kernels.json。
输出：每节点命中 CVE（含受影响区间、修复版本、前置面）+ 汇总；绝不执行利用。
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

from trident.lpe.catalog import CATALOG
from trident.lpe.engine import assess

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_surface_common", _PARENT / "_surface-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

load_snapshot = _C.load_snapshot
finding = _C.finding


def _findings(report: dict) -> list[dict]:
    out = []
    for node_name, node in report["nodes"].items():
        for hit in node["hits"] + node["component_hits"]:
            comp = "kernel" if hit["component"] == "kernel" else hit["component"]
            out.append(finding(
                hit["sev"],
                f"LPE 面：{hit['cve']} {hit['name']}（detection-only）",
                (f"{hit['note']}；confidence=detection-only；未执行利用；"
                 f"node={node_name} kernel={node['kernel']} {comp}={hit.get('installed', node['kernel'])} "
                 f"fixed_in={hit['fixed_in']}；检测逻辑：{hit['logic']}"),
                evidence=hit["evidence"],
                mapping_text="内核 LPE 检测库（trident/lpe，仅判定不利用）",
                fix=("升级内核/运行时到 fixed_in；seccomp + 最小能力 + userns 隔离作为补偿控制"),
                cve=hit["cve"], confidence="detection-only", fixed_in=hit["fixed_in"],
                node=node_name, component=comp, logic=hit["logic"],
            ))
    return out


def run(ctx: dict, params: dict) -> dict:
    snapshot = load_snapshot(params)
    report = assess(snapshot)
    aggregate = report["aggregate"]
    fs = _findings(report)
    summary = {
        "family": "kernel-lpe-audit",
        "rules": len(CATALOG),
        "kernel_rules": aggregate["kernel_rules"],
        "userspace_rules": aggregate["userspace_rules"],
        "nodes": aggregate["nodes"],
        "hits": aggregate["hits"],
        "hit_cves": aggregate["hit_cves"],
        "cves": aggregate["cves"],
        "by_category": aggregate["by_category"],
        "by_component": aggregate["by_component"],
        "detection_only": True,
        "source": params.get("snapshot") if isinstance(params.get("snapshot"), str) else "<inline snapshot>",
    }
    return {"summary": json.dumps(summary, ensure_ascii=False),
            "findings": fs, "artifacts": []}
