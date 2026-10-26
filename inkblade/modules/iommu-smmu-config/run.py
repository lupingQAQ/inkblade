# -*- coding: utf-8 -*-
"""IOMMU / ARM SMMU 配置与直通风险（只读导出解析）。

输入（params.snapshot）：
```
{
  "arch": "x86_64|arm64",
  "kernel_cmdline": "intel_iommu=on iommu.passthrough=0 iommu.strict=1",
  "iommu": {"enabled": true, "passthrough": false, "strict": true, "smmu": false},
  "dma_protection": true,
  "groups": [{"id": 1, "devices": ["0000:01:00.0", "0000:01:00.1"],
              "acs": true, "ats": false, "ats_protected": true,
              "identity": false, "passthrough": false, "untrusted": false}]
}
```

判定：
- `iommu=off` / `intel_iommu=off` / `amd_iommu=off` / enabled=false → high；
- `iommu=pt` / `iommu.passthrough=1` → high（全局直通）；
- 多设备/不可信设备处于 identity/passthrough 组 → high；
- arm64 无 SMMU → high；
- ACS 未启用、ATS 无保护、kernel DMA protection 关闭、strict=0 → medium。

边界：iOSMMU 配置只从客户导出读取；不绑定 vfio、不写 sysfs、不重置设备。
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_chip_common", _PARENT / "_chip-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "iommu-smmu-config"


def _cmdline_tokens(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for token in str(text or "").split():
        if "=" in token:
            key, value = token.split("=", 1)
            out[key.strip()] = value.strip()
        else:
            out[token.strip()] = "1"
    return out


def run(ctx: dict, params: dict) -> dict:
    doc, source = _C.load_snapshot(params)
    cmdline = str(doc.get("kernel_cmdline") or doc.get("cmdline") or "")
    tokens = _cmdline_tokens(cmdline)
    iommu = doc.get("iommu") if isinstance(doc.get("iommu"), dict) else {}
    groups = [g for g in doc.get("groups") or [] if isinstance(g, dict)]
    arch = str(doc.get("arch") or "x86_64").lower()

    disabled = (
        iommu.get("enabled") is False
        or tokens.get("iommu") == "off"
        or tokens.get("intel_iommu") == "off"
        or tokens.get("amd_iommu") == "off"
    )
    passthrough = (
        bool(iommu.get("passthrough"))
        or tokens.get("iommu") == "pt"
        or tokens.get("intel_iommu") == "pt"
        or tokens.get("iommu.passthrough") in ("1", "on", "true")
        or tokens.get("iommu.passthrough") == "1"
    )
    strict = iommu.get("strict")
    if strict is None:
        strict = tokens.get("iommu.strict") not in ("0", "off", "false")
    smmu = bool(iommu.get("smmu") or doc.get("smmu"))

    findings: list[dict] = []
    risky_groups: list[dict] = []
    acs_disabled: list[dict] = []
    ats_unprotected: list[dict] = []
    for group in groups:
        devices = [str(d) for d in group.get("devices") or []]
        identity = bool(group.get("identity") or group.get("passthrough"))
        untrusted = bool(group.get("untrusted"))
        if identity and (len(devices) > 1 or untrusted):
            risky_groups.append({
                "id": group.get("id"), "devices": devices,
                "untrusted": untrusted,
                "functions": group.get("functions"),
            })
        if group.get("acs") is False and len(devices) > 1:
            acs_disabled.append({"id": group.get("id"), "devices": devices})
        if group.get("ats") and group.get("ats_protected") is False:
            ats_unprotected.append({"id": group.get("id"), "devices": devices})

    if disabled:
        findings.append(_C.finding(
            "high", "IOMMU 未启用（DMA 直通风险）",
            {"detected": True, "iommu_enabled": False,
             "kernel_dma_protection": doc.get("dma_protection"),
             "kernel_cmdline": cmdline},
            evidence=f"kernel_cmdline={cmdline!r}",
            mapping="Intel VT-d / AMD-Vi / kernel DMA remapping",
            fix="BIOS 与内核启用 IOMMU；禁止 iommu=off/intel_iommu=off/amd_iommu=off",
        ))
    elif passthrough:
        findings.append(_C.finding(
            "high", "IOMMU 全局直通模式",
            {"detected": True, "iommu_enabled": True, "passthrough": True,
             "strict": strict, "kernel_cmdline": cmdline},
            evidence=f"kernel_cmdline={cmdline!r}",
            mapping="Linux iommu=pt / iommu.passthrough=1",
            fix="改为 iommu.passthrough=0；对不可信设备使用 translated mode",
        ))

    if arch.startswith("arm") and not smmu:
        findings.append(_C.finding(
            "high", "ARM SMMU 未启用",
            {"detected": True, "arch": arch, "smmu": smmu},
            mapping="Arm SMMUv3 (IHI 0070) / DMA remapping",
            fix="启用 arm-smmu-v3 并在固件/ACPI 中声明 IORT；核对 bypass 属性",
        ))

    if risky_groups:
        findings.append(_C.finding(
            "high", "IOMMU 组直通给多设备/不可信设备",
            {"detected": True, "groups": risky_groups,
             "count": len(risky_groups)},
            evidence=f"risky_groups={len(risky_groups)}",
            mapping="IOMMU group / VFIO passthrough / ACS",
            fix="启用 ACS 拆分组；禁止把多设备组整体 passthrough 给不可信负载",
        ))
    if acs_disabled:
        findings.append(_C.finding(
            "medium", "ACS 未启用（IOMMU 组无法隔离）",
            {"detected": True, "groups": acs_disabled, "count": len(acs_disabled)},
            mapping="PCIe Access Control Services",
            fix="在根端口/交换机启用 ACS；确认上游端口支持 ACS",
        ))
    if ats_unprotected:
        findings.append(_C.finding(
            "medium", "ATS 无 IOMMU 保护",
            {"detected": True, "groups": ats_unprotected, "count": len(ats_unprotected)},
            mapping="PCIe ATS / IOMMU remapping",
            fix="对 ATS 设备启用 IOMMU 保护；禁止 ATS 绕过翻译",
        ))
    if doc.get("dma_protection") is False:
        findings.append(_C.finding(
            "medium", "内核 DMA 保护未启用",
            {"detected": True, "kernel_dma_protection": False},
            fix="启用 kernel DMA protection / Thunderbolt/PCIe 热插 DMA 防护",
        ))
    if strict is False:
        findings.append(_C.finding(
            "medium", "IOMMU strict 模式关闭（延迟失效）",
            {"detected": True, "strict": strict},
            fix="高风险多租户节点使用 iommu.strict=1，避免延迟失效窗口",
        ))

    extra = {
        "arch": arch,
        "kernel_cmdline": cmdline,
        "iommu_enabled": not disabled,
        "passthrough": passthrough,
        "strict": strict,
        "smmu": smmu,
        "groups": len(groups),
        "risky_groups": len(risky_groups),
        "acs_disabled": len(acs_disabled),
        "ats_unprotected": len(ats_unprotected),
        "kernel_dma_protection": doc.get("dma_protection"),
    }
    summary = _C.summary_json("IOMMU/SMMU 姿态", findings, extra=extra, source=source)
    artifact = _C.write_artifact(ctx, f"{KEY}.json", {
        "summary": json.loads(summary), "groups": groups, "findings": findings,
    })
    return {"summary": summary, "artifacts": artifact, "findings": findings}
