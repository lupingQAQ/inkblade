# -*- coding: utf-8 -*-
"""DPU/IPU 卸载与隔离面（主动探测，只读）。

GET /dpu/offload：
- DPU 未接管基础设施服务 → high；
- 未启用 IOMMU/switchdev 隔离 → high；
- 固件未验证/数据面未隔离 → medium。

与 dpu-smartnic-surface 互补：后者看服务/凭据，本模块看 offload 数据面与隔离。
只读：不登录 DPU、不改交换机/固件。
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_infra2026_common", _PARENT / "_infra2026-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "dpu-ipu-offload"


def run(ctx: dict, params: dict) -> dict:
    target = str(params.get("target") or "").rstrip("/")
    if not target:
        return _C.no_target()
    t = _C.Trace(ctx, KEY)
    entry = t.get(f"{target}/dpu/offload")
    doc = _C.resp(entry).get("dpu") or {}
    findings: list[dict] = []

    offload = bool(doc.get("host_offload"))
    host_services = [str(x) for x in _C.as_list(doc.get("services_on_host"))]
    iommu = bool(doc.get("iommu_enabled"))
    switchdev = bool(doc.get("switchdev"))
    isolated = bool(doc.get("isolated"))
    verified = bool(doc.get("firmware_verified"))

    if not offload or host_services:
        findings.append(_C.finding(
            "high", "DPU 未接管基础设施服务",
            {"detected": True, "host_offload": offload, "services_on_host": host_services,
             "model": doc.get("model")},
            evidence=f"host_offload={offload} services_on_host={host_services}",
            mapping="BlueField DPU / OVS-kube-proxy offload",
            fix="将 OVN/kube-proxy/storage 数据面迁移到 DPU；宿主仅保留管理面",
        ))
    if not iommu or not switchdev or not isolated:
        findings.append(_C.finding(
            "high", "DPU 未启用 IOMMU/switchdev 隔离",
            {"detected": True, "iommu_enabled": iommu, "switchdev": switchdev,
             "isolated": isolated},
            evidence=f"iommu_enabled={iommu} switchdev={switchdev} isolated={isolated}",
            mapping="DPU switchdev / IOMMU / 数据面隔离",
            fix="启用 IOMMU 与 switchdev；DPU 数据面与宿主管理面隔离",
        ))
    if not verified:
        findings.append(_C.finding(
            "medium", "DPU 固件未验证",
            {"detected": True, "firmware_verified": verified, "model": doc.get("model")},
            evidence="firmware_verified=false",
            mapping="DPU 固件供应链 / BMC 证明",
            fix="校验 DPU 固件签名与版本，纳入固件清单与轮换",
        ))

    extra = {
        "model": doc.get("model"),
        "host_offload": offload,
        "host_services": len(host_services),
        "iommu_enabled": iommu,
        "switchdev": switchdev,
        "isolated": isolated,
        "firmware_verified": verified,
        "status": entry.get("status"),
    }
    summary = _C.summary_json("DPU/IPU 卸载面", findings, extra=extra, source=target)
    artifact = _C.write_artifact(ctx, f"{KEY}.json", {
        "summary": json.loads(summary), "dpu": doc, "findings": findings,
    })
    trace = t.dump()
    artifacts = ([str(trace)] if trace else []) + artifact
    return {"summary": summary, "artifacts": artifacts, "findings": findings}
