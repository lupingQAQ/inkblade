# -*- coding: utf-8 -*-
"""CXL 内存安全（C 级 research-only，有面才启用）。

输入（params.snapshot）：
```
{
  "host": {"cxl_version": "3.2", "ide": true, "tsp": true},
  "devices": [{
    "id": "cxl0", "cxl_version": "3.2",
    "ide": {"enabled": true, "keys_programmed": true},
    "tsp": {"supported": true, "enabled": true, "te_state": "CONFIG_LOCKED"},
    "mailbox": {"auth": true},
    "firmware": {"signed": true},
    "attestation": {"trust_anchor": "vendor-root"},
    "decoder": {"tenants": ["tenant-a"], "interleave": ["cxl0"]}
  }]
}
```

判定：CXL 链路未启用 IDE、TSP 未启用、解码区域跨租户、版本过低、mailbox/CCI
未鉴权、固件未签名、设备未绑定信任锚。

边界：C 级 research-only；六个主流画像均无 CXL 面，默认关闭；只有客户实际部署
CXL 时显式 --probe。只读导出解析；不写 CXL 寄存器/不解锁 TSP。
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_chip_common", _PARENT / "_chip-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "cxl-memory-security"


def run(ctx: dict, params: dict) -> dict:
    doc, source = _C.load_snapshot(params)
    host = doc.get("host") if isinstance(doc.get("host"), dict) else {}
    devices = [d for d in doc.get("devices") or [] if isinstance(d, dict)]
    host_version = str(host.get("cxl_version") or "")
    findings: list[dict] = []
    ide_all = bool(devices)
    tsp_all = bool(devices)
    cross_regions = 0
    mailbox_open = 0
    unsigned = 0
    unpinned = 0
    versions: set[str] = set()

    for dev in devices:
        name = str(dev.get("id") or "cxl?")
        version = str(dev.get("cxl_version") or host_version)
        if version:
            versions.add(version)
        ide = dev.get("ide") if isinstance(dev.get("ide"), dict) else {}
        tsp = dev.get("tsp") if isinstance(dev.get("tsp"), dict) else {}
        mailbox = dev.get("mailbox") if isinstance(dev.get("mailbox"), dict) else {}
        firmware = dev.get("firmware") if isinstance(dev.get("firmware"), dict) else {}
        attest = dev.get("attestation") if isinstance(dev.get("attestation"), dict) else {}
        decoder = dev.get("decoder") if isinstance(dev.get("decoder"), dict) else {}

        if not ide.get("enabled"):
            ide_all = False
            findings.append(_C.finding(
                "high", "CXL 链路未启用 IDE",
                {"detected": True, "device": name, "ide": ide},
                mapping="CXL 2.0 Integrity and Data Encryption (IDE)",
                fix="启用 CXL IDE 并完成密钥编程；拒绝明文 CXL 链路承载租户数据",
            ))
        if tsp.get("supported") and not tsp.get("enabled"):
            tsp_all = False
            findings.append(_C.finding(
                "high", "CXL TSP 未启用",
                {"detected": True, "device": name, "tsp": tsp},
                mapping="CXL 3.0 Trusted Security Protocol (TSP)",
                fix="机密 VM/多租户场景启用 TSP 并锁定 CONFIG_LOCKED 状态",
            ))
        elif tsp.get("enabled"):
            if str(tsp.get("te_state") or "").upper() not in ("CONFIG_LOCKED", "LOCKED"):
                tsp_all = False
                findings.append(_C.finding(
                    "medium", "CXL TSP 未锁定",
                    {"detected": True, "device": name, "te_state": tsp.get("te_state")},
                    fix="把 TSP TE state 锁定到 CONFIG_LOCKED；禁止运行时回退",
                ))
        elif not tsp.get("supported"):
            tsp_all = False

        tenants = {str(t) for t in decoder.get("tenants") or [] if t}
        if len(tenants) > 1:
            cross_regions += 1
            findings.append(_C.finding(
                "high", "CXL 解码区域跨租户共享",
                {"detected": True, "device": name, "tenants": sorted(tenants),
                 "interleave": decoder.get("interleave")},
                mapping="CXL decoder / HDM region isolation",
                fix="按租户划分 decoder/interleave set；拒绝跨租户共享 HDM 区域",
            ))
        if mailbox.get("auth") is False:
            mailbox_open += 1
            findings.append(_C.finding(
                "medium", "CXL 邮箱/CCI 未鉴权",
                {"detected": True, "device": name, "mailbox": mailbox},
                mapping="CXL Mailbox / Component Command Interface",
                fix="限制 CXL mailbox 到特权管理面；启用访问控制与审计",
            ))
        if firmware.get("signed") is False:
            unsigned += 1
            findings.append(_C.finding(
                "medium", "CXL 设备固件未签名",
                {"detected": True, "device": name},
                mapping="CXL firmware update / NIST SP 800-193",
                fix="只允许厂商签名固件；校验设备固件版本与签名",
            ))
        if not attest.get("trust_anchor"):
            unpinned += 1
            findings.append(_C.finding(
                "high", "CXL 设备未绑定信任锚",
                {"detected": True, "device": name, "attestation": attest},
                mapping="CXL device attestation / CMA-SPDM",
                fix="把设备证书链固定到厂商根；拒绝动态信任任意设备",
            ))

    if host_version and _C.version_lt(host_version, (2, 0)):
        findings.append(_C.finding(
            "medium", "CXL 版本过低（无 IDE）",
            {"detected": True, "version": host_version},
            mapping="CXL 2.0 IDE",
            fix="升级到 CXL 2.0+；低版本链路不得承载敏感租户数据",
        ))
    elif host_version and _C.version_lt(host_version, (3, 0)):
        findings.append(_C.finding(
            "medium", "CXL 版本低于 3.0（无 TSP）",
            {"detected": True, "version": host_version},
            mapping="CXL 3.0 TSP",
            fix="机密计算场景升级到 CXL 3.0+ 或使用 CPU TEE 的内存加密",
        ))

    extra = {
        "cxl_version": host_version,
        "versions": sorted(versions),
        "devices": len(devices),
        "ide_all_enabled": ide_all,
        "tsp_all_enabled": tsp_all,
        "cross_tenant_regions": cross_regions,
        "mailbox_unauthenticated": mailbox_open,
        "firmware_unsigned": unsigned,
        "unpinned_devices": unpinned,
        "host_ide": host.get("ide"),
        "host_tsp": host.get("tsp"),
    }
    summary = _C.summary_json("CXL 内存安全", findings, extra=extra, source=source)
    artifact = _C.write_artifact(ctx, f"{KEY}.json", {
        "summary": json.loads(summary), "devices": devices, "findings": findings,
    })
    return {"summary": summary, "artifacts": artifact, "findings": findings}
