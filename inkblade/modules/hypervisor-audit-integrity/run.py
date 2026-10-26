# -*- coding: utf-8 -*-
"""R01 Hypervisor 侧可信审计完整性检查（只读快照）。"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_residual_common", _PARENT / "_residual2026-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "hypervisor-audit-integrity"


def run(ctx: dict, params: dict) -> dict:
    doc = _C.load_snapshot(params)
    audit = _C.section(doc, "hypervisor_audit", "audit", default={})
    collector = audit.get("collector") or {}
    log_path = audit.get("log_path") or {}
    hyper = audit.get("hypervisor") or {}
    race = _C.as_int(audit.get("race_window_ms"), 0)
    findings: list[dict] = []

    location = str(collector.get("location") or "guest").lower()
    if location != "hypervisor":
        findings.append(_C.finding(
            "high", "审计采集器运行在 guest 内核内",
            {"location": location, "collector": collector},
            evidence=f"collector.location={location}",
            mapping="HyperAudit I01 / 采集器信任边界",
            source="USENIX Security 2026 I01",
            fix="在 hypervisor/host 侧独立采集；guest 内仅保留非权威遥测",
        ))
    if not _C.as_bool(collector.get("integrity_verified")):
        findings.append(_C.finding(
            "high", "采集器完整性未校验",
            {"integrity_verified": collector.get("integrity_verified"),
             "signature": collector.get("signature")},
            evidence="collector.integrity_verified=false",
            mapping="采集器供应链/运行态完整性",
            source="USENIX Security 2026 I01",
            fix="采集器镜像/二进制签名验证 + 运行时度量/证明",
        ))
    if _C.as_bool(log_path.get("write_from_guest")):
        findings.append(_C.finding(
            "critical", "审计日志可被 guest 写入",
            {"log_path": log_path},
            evidence="log_path.write_from_guest=true",
            mapping="日志竞态篡改",
            source="USENIX Security 2026 I01",
            fix="日志走 hypervisor 侧只写通道/远端不可变存储；guest 只读",
        ))
    if not _C.as_bool(log_path.get("append_only")):
        findings.append(_C.finding(
            "high", "审计日志非 append-only",
            {"log_path": log_path},
            evidence="log_path.append_only=false",
            mapping="日志完整性",
            source="USENIX Security 2026 I01",
            fix="WORM/append-only 存储 + 定期锚定哈希",
        ))
    if not _C.as_bool(log_path.get("immutable_storage")):
        findings.append(_C.finding(
            "medium", "审计日志未落不可变存储",
            {"log_path": log_path},
            evidence="log_path.immutable_storage=false",
            mapping="证据保留",
            source="USENIX Security 2026 I01",
            fix="对象锁/WORM 桶或外部 SIEM 只写副本",
        ))
    if _C.as_bool(log_path.get("remote_forward")) and not _C.as_bool(log_path.get("mtls")):
        findings.append(_C.finding(
            "medium", "审计日志远程转发未启用 mTLS",
            {"remote_forward": True, "mtls": False},
            evidence="remote_forward=true mtls=false",
            mapping="传输完整性/身份",
            source="USENIX Security 2026 I01",
            fix="mTLS + 接收端签名回执",
        ))
    if race > 0:
        findings.append(_C.finding(
            "high", "存在 guest 启动到采集器就绪的竞态窗口",
            {"race_window_ms": race, "started_before_guest": collector.get("started_before_guest")},
            evidence=f"race_window_ms={race}",
            mapping="rootkit 竞态",
            source="USENIX Security 2026 I01",
            fix="采集器先于 guest 启动；hypervisor 侧记录启动事件",
        ))
    if not (_C.as_bool(hyper.get("audit_stream")) or _C.as_bool(hyper.get("host_agent"))):
        findings.append(_C.finding(
            "high", "无 hypervisor 侧审计流/宿主代理",
            {"hypervisor": hyper},
            evidence="hypervisor.audit_stream=false host_agent=false",
            mapping="宿主侧可信采集",
            source="USENIX Security 2026 I01",
            fix="启用 libvirt audit/qemu trace 或宿主 eBPF/审计代理，并与 guest 流交叉校验",
        ))
    if not _C.as_bool(hyper.get("attestation")):
        findings.append(_C.finding(
            "medium", "采集器/宿主未做证明",
            {"hypervisor": hyper},
            evidence="hypervisor.attestation=false",
            mapping="远程证明",
            source="USENIX Security 2026 I01",
            fix="TPM/SEV-SNP/TDX 证明采集器与宿主基线",
        ))

    extra = {
        "collector_location": location,
        "integrity_verified": _C.as_bool(collector.get("integrity_verified")),
        "guest_writable_log": _C.as_bool(log_path.get("write_from_guest")),
        "hypervisor_stream": _C.as_bool(hyper.get("audit_stream")) or _C.as_bool(hyper.get("host_agent")),
        "race_window_ms": race,
        "finding_count": len(findings),
    }
    return _C.result(ctx, KEY, "Hypervisor 侧可信审计完整性", findings, extra=extra,
                     source=str(params.get("snapshot") or "<inline snapshot>"))
