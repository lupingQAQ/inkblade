# -*- coding: utf-8 -*-
"""GPU 驱动/固件暴露面 — 解析 nvidia-smi / NVML 导出，不执行 nvidia-smi。

输入（任选其一）：
- params.snapshot = {"nvidia_smi": CSV 文本或路径, "nvml": JSON 路径/dict,
                     "xid_events": [...]}
- params.snapshot 为 JSON 文件路径（同上字段）

判定：
- 驱动版本低于只读基线（默认 570.0）→ high；
- 同池驱动版本不一致 / 同型号 VBIOS 不一致 → medium；
- ECC 未启用 → medium；持久化模式未启用 → low；
- Xid 复位族（48/63/79/94/119）→ high。

只读：不执行 nvidia-smi、不调用 NVML、不写设备。
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_hardware_common", _PARENT / "_hardware-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "gpu-driver-firmware-surface"
BASELINE = (570, 0)
RESET_XIDS = {48, 63, 79, 94, 119}


def _parse_csv(text: str) -> list[dict]:
    lines = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    if not lines:
        return []
    header = [c.strip().lower() for c in lines[0].split(",")]
    has_header = "driver_version" in header or "name" in header
    rows = lines[1:] if has_header else lines
    if not has_header:
        header = ["index", "name", "driver_version", "vbios_version", "memory.total",
                  "ecc.mode.current", "pstate", "temperature.gpu", "persistence_mode"]
    devices: list[dict] = []
    for line in rows:
        cells = [c.strip() for c in line.split(",")]
        if len(cells) < 3:
            continue
        row = dict(zip(header, cells))
        devices.append({
            "index": _C.first_int(row.get("index", "")) or len(devices),
            "name": row.get("name", ""),
            "driver_version": row.get("driver_version", ""),
            "vbios_version": row.get("vbios_version", ""),
            "memory_total_mib": _C.first_int(row.get("memory.total", "")),
            "ecc_mode": row.get("ecc.mode.current", row.get("ecc_mode", "")),
            "pstate": row.get("pstate", ""),
            "temperature_c": _C.first_int(row.get("temperature.gpu", "")),
            "persistence_mode": row.get("persistence_mode", ""),
        })
    return devices


def _load_inputs(params: dict):
    snap = params.get("snapshot")
    if snap is None:
        raise ValueError("缺少 params.snapshot（nvidia-smi CSV / NVML JSON / fixture 路径）")
    if isinstance(snap, dict):
        doc, source = snap, "<inline fixture>"
    else:
        doc, source = _C.load_json_ref(snap), str(snap)
    csv_ref = doc.get("nvidia_smi") or doc.get("nvidia_smi_csv")
    nvml_ref = doc.get("nvml")
    devices = _parse_csv(_C.read_text_ref(csv_ref)) if csv_ref else []
    nvml = _C.load_json_ref(nvml_ref) if nvml_ref else {}
    nvml_devices = nvml.get("devices") or doc.get("devices") or []
    if not devices:
        devices = [{
            "index": _C.int_of(d.get("index"), i),
            "name": d.get("name", ""),
            "driver_version": str(d.get("driver_version") or nvml.get("driver_version") or ""),
            "vbios_version": d.get("vbios_version", ""),
            "memory_total_mib": d.get("memory_total_mib"),
            "ecc_mode": (d.get("ecc") or {}).get("mode", d.get("ecc_mode", "")),
            "pstate": d.get("pstate", ""),
            "temperature_c": d.get("temperature_c"),
            "persistence_mode": d.get("persistence_mode", ""),
        } for i, d in enumerate(nvml_devices)]
    by_index = {_C.int_of(d.get("index"), -1): d for d in nvml_devices}
    for dev in devices:
        extra = by_index.get(dev["index"], {})
        if not dev.get("vbios_version"):
            dev["vbios_version"] = extra.get("vbios_version", "")
        if not dev.get("ecc_mode"):
            dev["ecc_mode"] = (extra.get("ecc") or {}).get("mode", extra.get("ecc_mode", ""))
        if not dev.get("persistence_mode"):
            dev["persistence_mode"] = extra.get("persistence_mode", "")
    xid_events = nvml.get("xid_events") or doc.get("xid_events") or []
    cuda_version = str(nvml.get("cuda_version") or doc.get("cuda_version") or "")
    return devices, xid_events, cuda_version, source


def run(ctx: dict, params: dict) -> dict:
    devices, xid_events, cuda_version, source = _load_inputs(params)
    if not devices:
        raise ValueError("nvidia-smi/NVML 输入未解析到任何 GPU")
    findings: list[dict] = []

    versions = sorted({str(d.get("driver_version")) for d in devices if d.get("driver_version")})
    old_versions = [v for v in versions if _C.version_lt(v, BASELINE)]
    if old_versions:
        findings.append(_C.finding(
            "high", "GPU 驱动版本低于只读基线",
            {"detected": True, "baseline": ".".join(map(str, BASELINE)),
             "driver_versions": old_versions, "device_count": len(devices)},
            evidence=f"driver_versions={old_versions} baseline={BASELINE}",
            mapping="GPU 驱动/固件基线（fixture 规则，非 CVE 结论）",
            fix="升级到厂商支持的稳定分支并回归 ECC/Xid/训练步时；先在实验环境验证",
        ))
    if len(versions) > 1:
        findings.append(_C.finding(
            "medium", "同池 GPU 驱动版本不一致",
            {"detected": True, "driver_versions": versions, "device_count": len(devices)},
            evidence=f"driver_versions={versions}",
            fix="同池统一驱动/固件版本，避免 NCCL 与 Xid 行为差异",
        ))

    by_name: dict[str, set[str]] = {}
    for dev in devices:
        if dev.get("name") and dev.get("vbios_version"):
            by_name.setdefault(str(dev["name"]), set()).add(str(dev["vbios_version"]))
    mismatched_vbios = {name: sorted(values) for name, values in by_name.items() if len(values) > 1}
    if mismatched_vbios:
        findings.append(_C.finding(
            "medium", "同型号 GPU VBIOS 版本不一致",
            {"detected": True, "models": mismatched_vbios},
            evidence=f"models={mismatched_vbios}",
            fix="按厂商矩阵统一 VBIOS，变更窗口内逐台升级并保留回滚",
        ))

    ecc_disabled = [d for d in devices
                    if str(d.get("ecc_mode", "")).strip().lower() in ("disabled", "disable", "off")]
    if ecc_disabled:
        findings.append(_C.finding(
            "medium", "GPU ECC 未启用",
            {"detected": True, "devices": [d["index"] for d in ecc_disabled],
             "count": len(ecc_disabled)},
            evidence=f"ecc_disabled={[d['index'] for d in ecc_disabled]}",
            fix="在训练节点启用 ECC 并核对性能预算；ECC 关闭会放大静默数据损坏",
        ))

    reset_events = [e for e in xid_events if _C.int_of(e.get("xid"), -1) in RESET_XIDS]
    if reset_events:
        findings.append(_C.finding(
            "high", "Xid 复位族事件",
            {"detected": True, "events": reset_events, "xid_events": len(reset_events),
             "reset_xids": sorted(RESET_XIDS)},
            evidence=f"xid_events={len(reset_events)}",
            mapping="GPU Xid 复位族（48/63/79/94/119）",
            fix="保留 Xid 原始日志，按厂商 Xid 表定位硬件/驱动/链路；不要在未取证前复位",
        ))

    persistence_disabled = [d for d in devices
                            if str(d.get("persistence_mode", "")).strip().lower()
                            in ("disabled", "disable", "off")]
    if persistence_disabled:
        findings.append(_C.finding(
            "low", "GPU 持久化模式未启用",
            {"detected": True, "devices": [d["index"] for d in persistence_disabled]},
            fix="训练节点启用 persistence mode，减少驱动初始化抖动（按厂商建议）",
        ))

    extra = {
        "devices": len(devices),
        "driver_versions": versions,
        "cuda_version": cuda_version,
        "vbios_versions": sorted({str(d.get("vbios_version")) for d in devices if d.get("vbios_version")}),
        "ecc_disabled": len(ecc_disabled),
        "xid_events": len(reset_events),
        "persistence_disabled": len(persistence_disabled),
        "baseline": ".".join(map(str, BASELINE)),
    }
    summary = _C.summary_json("GPU 驱动/固件暴露面", findings, extra=extra, source=source)
    artifact = _C.write_artifact(ctx, f"{KEY}.json", {
        "summary": json.loads(summary), "devices": devices,
        "xid_events": xid_events, "findings": findings,
    })
    return {"summary": summary, "artifacts": artifact, "findings": findings}
