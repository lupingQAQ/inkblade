# -*- coding: utf-8 -*-
"""Slurm cgroup 资源与设备约束审计（只读）。"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_slurm_common", _PARENT / "_slurm-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "slurm-cgroup-constraint-audit"


def run(ctx: dict, params: dict) -> dict:
    snap = _C.load_snapshot(params)
    conf = _C.conf(snap, "cgroup.conf")
    slurm_conf = _C.conf(snap, "slurm.conf")
    findings: list[dict] = []

    plugin = _C.get(conf, "CgroupPlugin", "autodetect").lower()
    cores = _C.as_bool(_C.get(conf, "ConstrainCores"), False)
    ram = _C.as_bool(_C.get(conf, "ConstrainRAMSpace"), False)
    swap = _C.as_bool(_C.get(conf, "ConstrainSwapSpace"), False)
    devices = _C.as_bool(_C.get(conf, "ConstrainDevices"), False)
    affinity = _C.as_bool(_C.get(conf, "TaskAffinity"), False)
    enforce = _C.get(conf, "MemoryLimitEnforcement", "none").lower()
    allowed_ram = _C.as_int(_C.get(conf, "AllowedRAMSpace"), 100)
    allowed_swap = _C.as_int(_C.get(conf, "AllowedSwapSpace"), 0)
    max_ram = _C.as_int(_C.get(conf, "MaxRAMPercent"), 100)
    max_swap = _C.as_int(_C.get(conf, "MaxSwapPercent"), 100)

    if plugin in ("disabled", "none", ""):
        findings.append(_C.finding(
            "high", "cgroup 插件被禁用",
            {"CgroupPlugin": plugin or "<missing>"},
            evidence=f"CgroupPlugin={plugin or '<missing>'}",
            mapping="Slurm cgroup 边界",
            fix="CgroupPlugin=autodetect 或 cgroup/v2；确认节点 cgroup v2 已挂载",
        ))
    if not cores:
        findings.append(_C.finding(
            "high", "未限制作业 CPU 核集（ConstrainCores=no）",
            {"ConstrainCores": cores},
            evidence="ConstrainCores=no",
            mapping="CPU 隔离 / 跨作业抢占",
            fix="ConstrainCores=yes + TaskAffinity=yes",
        ))
    if not ram:
        findings.append(_C.finding(
            "high", "未限制作业内存（ConstrainRAMSpace=no）",
            {"ConstrainRAMSpace": ram},
            evidence="ConstrainRAMSpace=no",
            mapping="内存隔离 / OOM 影响他租户",
            fix="ConstrainRAMSpace=yes；AllowedRAMSpace<=100",
        ))
    if not swap:
        findings.append(_C.finding(
            "medium", "未限制 swap（ConstrainSwapSpace=no）",
            {"ConstrainSwapSpace": swap, "AllowedSwapSpace": allowed_swap},
            evidence=f"ConstrainSwapSpace=no AllowedSwapSpace={allowed_swap}",
            mapping="swap 放大约束",
            fix="ConstrainSwapSpace=yes + AllowedSwapSpace=0",
        ))
    if not devices:
        findings.append(_C.finding(
            "high", "未限制设备访问（ConstrainDevices=no）",
            {"ConstrainDevices": devices},
            evidence="ConstrainDevices=no",
            mapping="GPU/NVLink/加速器设备越界",
            fix="ConstrainDevices=yes；device allowlist 只放 GRES 对应设备",
        ))
    if allowed_ram > 100:
        findings.append(_C.finding(
            "medium", "AllowedRAMSpace 超过分配量",
            {"AllowedRAMSpace": allowed_ram},
            evidence=f"AllowedRAMSpace={allowed_ram}",
            mapping="内存超用",
            fix="AllowedRAMSpace=100（或按业务实测收紧）",
        ))
    if allowed_swap > 0 or max_swap > 0:
        findings.append(_C.finding(
            "medium", "允许 swap 超用",
            {"AllowedSwapSpace": allowed_swap, "MaxSwapPercent": max_swap},
            evidence=f"AllowedSwapSpace={allowed_swap} MaxSwapPercent={max_swap}",
            mapping="swap 侧信道/资源争用",
            fix="AllowedSwapSpace=0、MaxSwapPercent=0",
        ))
    if not affinity:
        findings.append(_C.finding(
            "medium", "TaskAffinity 未启用",
            {"TaskAffinity": affinity},
            evidence="TaskAffinity=no",
            mapping="CPU 亲和 / NUMA 性能隔离",
            fix="TaskAffinity=yes；与 ConstrainCores 联动",
        ))
    if enforce in ("none", "no", "off", ""):
        findings.append(_C.finding(
            "high", "MemoryLimitEnforcement 未启用",
            {"MemoryLimitEnforcement": enforce or "<missing>"},
            evidence=f"MemoryLimitEnforcement={enforce or '<missing>'}",
            mapping="内存上限执行点",
            fix="MemoryLimitEnforcement=yes（cgroup v2）",
        ))
    if max_ram > 100:
        findings.append(_C.finding(
            "medium", "MaxRAMPercent 超过 100%",
            {"MaxRAMPercent": max_ram},
            evidence=f"MaxRAMPercent={max_ram}",
            mapping="cgroup 内存上限",
            fix="MaxRAMPercent<=100",
        ))
    meta = _C.meta(snap, "cgroup.conf")
    if meta and _C.world_writable(meta.get("mode")):
        findings.append(_C.finding(
            "high", "cgroup.conf 全局可写",
            {"meta": meta},
            evidence=f"cgroup.conf mode={meta.get('mode')}",
            mapping="cgroup 配置完整性",
            fix="cgroup.conf root:root 0644；纳入基线",
        ))
    task_plugin = _C.get(slurm_conf, "TaskPlugin").lower()
    if slurm_conf and "task/cgroup" not in task_plugin:
        findings.append(_C.finding(
            "high", "slurm.conf TaskPlugin 未加载 task/cgroup（cgroup.conf 不生效）",
            {"TaskPlugin": task_plugin or "<missing>"},
            evidence=f"TaskPlugin={task_plugin or '<missing>'}",
            mapping="cgroup 配置生效链路",
            fix="TaskPlugin=task/cgroup,task/affinity",
        ))
    if "cgroupv2" not in _C.get(conf, "CgroupPlugin").lower() and plugin != "autodetect":
        findings.append(_C.finding(
            "low", "未显式启用 cgroup v2 插件",
            {"CgroupPlugin": plugin},
            evidence=f"CgroupPlugin={plugin}",
            mapping="cgroup v1 弃用",
            fix="CgroupPlugin=cgroup/v2（或 autodetect + 节点 cgroup v2）",
        ))

    extra = {
        "cgroup_plugin": plugin,
        "constrain_cores": cores,
        "constrain_ram": ram,
        "constrain_swap": swap,
        "constrain_devices": devices,
        "allowed_ram_space": allowed_ram,
        "allowed_swap_space": allowed_swap,
        "task_affinity": affinity,
        "memory_enforcement": enforce,
        "finding_count": len(findings),
    }
    return _C.result(ctx, KEY, "Slurm cgroup 资源与设备约束审计", findings, extra=extra,
                     source=str(params.get("snapshot") or "<inline snapshot>"))
