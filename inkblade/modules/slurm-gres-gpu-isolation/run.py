# -*- coding: utf-8 -*-
"""Slurm GRES/GPU 设备隔离审计（只读）。"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_slurm_common", _PARENT / "_slurm-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "slurm-gres-gpu-isolation"


def run(ctx: dict, params: dict) -> dict:
    snap = _C.load_snapshot(params)
    doc = _C.json_file(snap, "gres.json", default={})
    cgroup = _C.conf(snap, "cgroup.conf")
    findings: list[dict] = []

    gres_types = str(doc.get("GresTypes") or "").lower()
    auto = str(doc.get("AutoDetect") or "").lower()
    constrain = _C.as_bool(doc.get("ConstrainDevices"), False)
    gres = [g for g in (doc.get("gres") or []) if isinstance(g, dict)]
    allows = [str(a) for a in (doc.get("device_allow") or [])]

    if "gpu" not in gres_types:
        findings.append(_C.finding(
            "high", "未声明 GPU GRES 类型",
            {"GresTypes": gres_types or "<missing>"},
            evidence=f"GresTypes={gres_types or '<missing>'}",
            mapping="GPU 调度清点",
            fix="GresTypes=gpu；节点 gres.conf 声明 GPU 型号/数量",
        ))
    if not constrain:
        findings.append(_C.finding(
            "high", "GRES 未约束设备（ConstrainDevices=no）",
            {"ConstrainDevices": constrain},
            evidence="ConstrainDevices=no",
            mapping="GPU 设备越界",
            fix="ConstrainDevices=yes + cgroup device allowlist",
        ))
    if auto in ("", "none", "off"):
        findings.append(_C.finding(
            "medium", "GRES AutoDetect 未启用",
            {"AutoDetect": auto or "<missing>"},
            evidence=f"AutoDetect={auto or '<missing>'}",
            mapping="GPU 拓扑准确性",
            fix="AutoDetect=nvml（NVIDIA）或相应厂商探测",
        ))
    for g in gres:
        binding = str(g.get("binding") or "none").lower()
        if binding in ("", "none"):
            findings.append(_C.finding(
                "high", f"GRES {g.get('name')} 未设置 GPU 绑定策略",
                {"gres": g},
                evidence=f"gres={g.get('name')} binding={binding}",
                mapping="GPU/NVLink 亲和",
                fix="binding=closest（或按拓扑显式绑定）",
            ))
        if _C.as_int(g.get("count"), 0) <= 0:
            findings.append(_C.finding(
                "medium", f"GRES {g.get('name')} 数量为 0",
                {"gres": g},
                evidence=f"count={g.get('count')}",
                mapping="GPU 容量清点",
                fix="核对 gres.conf 与 nvidia-smi；修复后重新注册节点",
            ))
        if not bool(g.get("mig", False)) and g.get("tenant_shared"):
            findings.append(_C.finding(
                "medium", "多租户共享 GPU 但未启用 MIG 隔离",
                {"gres": g},
                evidence="tenant_shared=true mig=false",
                mapping="GPU 显存/计算隔离",
                fix="启用 MIG 或独占 GPU 分配",
            ))
        allow = [str(x) for x in (g.get("device_cgroup_allow") or [])]
        if any(x in ("*:*", "a *:* rwm", "a *:*") for x in allow):
            findings.append(_C.finding(
                "high", "GRES 设备 cgroup allowlist 放行所有设备",
                {"allow": allow, "gres": g.get("name")},
                evidence=f"device_allow={allow}",
                mapping="设备 cgroup 全放行",
                fix="只放行 GPU char 设备（如 c 195:* / c 511:*），禁止 a *:*",
            ))
    if any(x in ("*:*", "a *:* rwm", "a *:*") for x in allows):
        findings.append(_C.finding(
            "high", "device_allow 全局放行所有设备",
            {"device_allow": allows},
            evidence=f"device_allow={allows}",
            mapping="设备 cgroup 全放行",
            fix="按 GRES 生成最小 device allowlist",
        ))
    cg_devices = _C.as_bool(_C.get(cgroup, "ConstrainDevices"), False)
    if cgroup and not cg_devices:
        findings.append(_C.finding(
            "high", "cgroup.conf ConstrainDevices=no（GRES 约束不生效）",
            {"ConstrainDevices": cg_devices},
            evidence="cgroup.conf ConstrainDevices=no",
            mapping="GRES 与 cgroup 联动",
            fix="cgroup.conf ConstrainDevices=yes",
        ))
    if not gres:
        findings.append(_C.finding(
            "medium", "未发现 GRES 配置",
            {"gres": gres},
            evidence="gres=0",
            mapping="GPU 调度面清点",
            fix="补充 gres.conf / scontrol show node 的 GresUsed 导出",
        ))

    extra = {
        "gres_types": gres_types or "missing",
        "auto_detect": auto or "missing",
        "constrain_devices": constrain,
        "gres": len(gres),
        "global_device_allow": any(x in ("*:*", "a *:* rwm", "a *:*") for x in allows),
        "finding_count": len(findings),
    }
    return _C.result(ctx, KEY, "Slurm GRES/GPU 设备隔离审计", findings, extra=extra,
                     source=str(params.get("snapshot") or "<inline snapshot>"))
