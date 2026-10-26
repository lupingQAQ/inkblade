# -*- coding: utf-8 -*-
"""PCIe IOMMU/DMA 隔离面（只读侦察）。

GET /iommu/groups：
- IOMMU 未启用 → high；
- 多设备共享 IOMMU 组且 passthrough → high；
- ACS 未启用/ATS 无保护/内核 DMA 保护关闭 → medium。

只读：不绑定 vfio、不写 sysfs、不重置设备。
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_infra2026_common", _PARENT / "_infra2026-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "pcie-iommu-dma"


def run(ctx: dict, params: dict) -> dict:
    target = str(params.get("target") or "").rstrip("/")
    if not target:
        return _C.no_target()
    t = _C.Trace(ctx, KEY)
    entry = t.get(f"{target}/iommu/groups")
    doc = _C.resp(entry)
    groups = [g for g in _C.as_list(doc.get("groups")) if isinstance(g, dict)]
    findings: list[dict] = []

    enabled = bool(doc.get("iommu_enabled"))
    acs = bool(doc.get("acs_enabled"))
    dma = bool(doc.get("kernel_dma_protection"))
    ats = bool(doc.get("ats_enabled"))
    ats_protected = bool(doc.get("ats_protected"))
    shared_passthrough = [g for g in groups
                          if len(_C.as_list(g.get("devices"))) > 1
                          and bool(g.get("passthrough"))]

    if not enabled:
        findings.append(_C.finding(
            "high", "IOMMU 未启用（DMA 直通风险）",
            {"detected": True, "iommu_enabled": enabled,
             "kernel_dma_protection": dma},
            evidence="iommu_enabled=false",
            mapping="Intel VT-d / AMD-Vi / kernel DMA protection",
            fix="BIOS 与内核启用 IOMMU；开启 kernel DMA protection",
        ))
    if shared_passthrough:
        findings.append(_C.finding(
            "high", "PCIe 设备共享 IOMMU 组且启用 passthrough",
            {"detected": True,
             "groups": [{"id": g.get("id"), "devices": g.get("devices"),
                         "functions": g.get("functions")} for g in shared_passthrough]},
            evidence=f"passthrough_groups={len(shared_passthrough)}",
            mapping="IOMMU group / VFIO passthrough / ACS",
            fix="启用 ACS 拆分 IOMMU 组；禁止把多设备组整体 passthrough 给不可信负载",
        ))
    if not acs or not dma or (ats and not ats_protected):
        findings.append(_C.finding(
            "medium", "ACS 未启用或 ATS 无保护",
            {"detected": True, "acs_enabled": acs, "kernel_dma_protection": dma,
             "ats_enabled": ats, "ats_protected": ats_protected},
            evidence=f"acs={acs} dma_protection={dma} ats_protected={ats_protected}",
            mapping="PCIe ACS / ATS / DMA remapping",
            fix="启用 ACS 与 DMA remapping；对 ATS 设备启用 IOMMU 保护",
        ))

    extra = {
        "iommu_enabled": enabled,
        "acs_enabled": acs,
        "groups": len(groups),
        "passthrough_groups": len(shared_passthrough),
        "kernel_dma_protection": dma,
        "ats_enabled": ats,
        "status": entry.get("status"),
    }
    summary = _C.summary_json("PCIe IOMMU/DMA 隔离面", findings, extra=extra, source=target)
    artifact = _C.write_artifact(ctx, f"{KEY}.json", {
        "summary": json.loads(summary), "iommu": doc, "findings": findings,
    })
    trace = t.dump()
    artifacts = ([str(trace)] if trace else []) + artifact
    return {"summary": summary, "artifacts": artifacts, "findings": findings}
