# -*- coding: utf-8 -*-
"""PCIe/IOMMU passthrough isolation audit (read-only)."""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_emerging_common", _PARENT / "_emerging-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "pcie-iommu-audit"


def run(ctx: dict, params: dict) -> dict:
    doc = _C.collection(params)
    state = _C.surface_state(ctx.get("meta") or {}, params, doc)
    if state.get("status") != "deployed":
        return _C.not_deployed(ctx, KEY, state)

    findings: list[dict] = []
    nodes = _C.objects(doc, "Node")
    observed = params.get("iommu") or {}
    if observed:
        if not observed.get("enabled", True):
            findings.append(_C.finding(
                "high", "节点 IOMMU 关闭，PCIe 直通设备无法按租户隔离",
                {"iommu": observed}, evidence="params iommu.enabled=false"))
        if observed.get("acs_enabled") is False:
            findings.append(_C.finding(
                "high", "PCIe ACS 关闭，同组设备可绕过 IOMMU 分组",
                {"iommu": observed}, evidence="params iommu.acs_enabled=false"))
        groups = observed.get("groups") or []
        shared = [g for g in groups if isinstance(g, dict)
                  and len(g.get("devices") or []) > 1 and g.get("passthrough_to")]
        if shared:
            findings.append(_C.finding(
                "medium", "多个设备共享 IOMMU 组并整组直通到单一租户",
                {"groups": shared[:20]}, evidence="IOMMU group has multiple devices"))
    elif nodes:
        findings.append(_C.finding(
            "info", "节点已采集但 IOMMU 运行态未验证，需补采 /sys/kernel/iommu_groups 与内核参数",
            {"nodes": [n.get("name") for n in nodes][:50]},
            evidence="config export present; no iommu observation"))

    return _C.result(ctx, KEY, state, findings,
                     f"nodes={len(nodes)} observed={bool(observed)} findings={len(findings)}",
                     {"nodes": [n.get("name") for n in nodes][:50], "iommu": observed})
