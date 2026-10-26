# -*- coding: utf-8 -*-
"""NVSwitch/NVLink/IMEX 拓扑只读审计。

输入：params.snapshot = NVSwitch 拓扑 JSON（switches/links/partitions/imex）。
判定：
- 同一 GPU 出现在多个租户分区 / 分区跨租户 → high；
- IMEX 通道成员跨租户 → high；
- 多租户分区共享同一 NVSwitch → medium；
- 链路 down/degraded、NVSwitch 固件不一致 → medium。

只读：不连接 NVSwitch、不写分区/路由。
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_hardware_common", _PARENT / "_hardware-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "nvswitch-nvlink-topology"


def _member_tenant(member: str) -> str:
    text = str(member)
    return text.split("/", 1)[0] if "/" in text else ""


def run(ctx: dict, params: dict) -> dict:
    doc = _C.load_snapshot(params)
    switches = doc.get("switches") or []
    links = doc.get("links") or []
    partitions = doc.get("partitions") or []
    channels = (doc.get("imex") or {}).get("channels") or []
    findings: list[dict] = []

    gpu_tenants: dict[str, set[str]] = {}
    for part in partitions:
        tenant = str(part.get("tenant") or "")
        for gpu in part.get("gpus") or []:
            gpu_tenants.setdefault(str(gpu), set())
            if tenant:
                gpu_tenants[str(gpu)].add(tenant)
    cross_gpus = sorted(gpu for gpu, tenants in gpu_tenants.items() if len(tenants) > 1)
    if cross_gpus:
        findings.append(_C.finding(
            "high", "NVLink 分区跨越租户",
            {"detected": True, "gpus": cross_gpus,
             "owners": {gpu: sorted(gpu_tenants[gpu]) for gpu in cross_gpus}},
            evidence=f"cross_tenant_gpus={cross_gpus}",
            mapping="NVSwitch/NVLink 分区隔离（GPU 直连域不受 NetworkPolicy 覆盖）",
            fix="按租户重做 NVLink 分区/IMEX 绑定，变更窗口内验证分区生效与 NCCL 步时",
        ))

    switch_tenants: dict[str, set[str]] = {}
    for part in partitions:
        tenant = str(part.get("tenant") or "")
        if not tenant:
            continue
        for sw in part.get("switches") or []:
            switch_tenants.setdefault(str(sw), set()).add(tenant)
    shared = sorted(sw for sw, tenants in switch_tenants.items() if len(tenants) > 1)
    if shared:
        findings.append(_C.finding(
            "medium", "NVSwitch 分区共享交换机",
            {"detected": True, "switches": shared,
             "tenants": {sw: sorted(switch_tenants[sw]) for sw in shared}},
            evidence=f"shared_switches={shared}",
            fix="按租户独占 NVSwitch 分区；共享交换机需确认 IMEX/路由隔离",
        ))

    firmware = sorted({str(sw.get("firmware")) for sw in switches if sw.get("firmware")})
    if len(firmware) > 1:
        findings.append(_C.finding(
            "medium", "NVSwitch 固件版本不一致",
            {"detected": True, "firmware_versions": firmware,
             "switches": {sw.get("id"): sw.get("firmware") for sw in switches}},
            evidence=f"firmware_versions={firmware}",
            fix="按厂商矩阵统一 NVSwitch 固件，保留备件与回滚路径",
        ))

    bad_links = [link for link in links if str(link.get("state", "up")).lower() != "up"]
    if bad_links:
        findings.append(_C.finding(
            "medium", "NVLink 链路非 up",
            {"detected": True, "links": bad_links,
             "down": sum(1 for link in bad_links if str(link.get("state")).lower() == "down"),
             "degraded": sum(1 for link in bad_links if str(link.get("state")).lower() == "degraded")},
            evidence=f"bad_links={len(bad_links)}",
            fix="检查光模块/线缆/端口，按 NVLink 拓扑复核带宽与 rail 局部性",
        ))

    cross_imex: list[dict] = []
    for channel in channels:
        channel_tenant = str(channel.get("tenant") or "")
        member_tenants = sorted({_member_tenant(m) for m in channel.get("members") or []
                                if _member_tenant(m)})
        if len(member_tenants) > 1 or (channel_tenant and any(t != channel_tenant for t in member_tenants)):
            cross_imex.append({"id": channel.get("id"), "channel_tenant": channel_tenant,
                               "member_tenants": member_tenants})
    if cross_imex:
        findings.append(_C.finding(
            "high", "IMEX 通道成员跨租户",
            {"detected": True, "channels": cross_imex},
            evidence=f"cross_tenant_imex={[c['id'] for c in cross_imex]}",
            mapping="NVIDIA IMEX/ComputeDomain 租户隔离",
            fix="按 ComputeDomain/租户重建 IMEX channel，核对成员与 import 权限",
        ))

    extra = {
        "switches": len(switches),
        "links": len(links),
        "partitions": len(partitions),
        "imex_channels": len(channels),
        "firmware_versions": firmware,
        "down_links": sum(1 for link in links if str(link.get("state")).lower() == "down"),
        "degraded_links": sum(1 for link in links if str(link.get("state")).lower() == "degraded"),
        "cross_tenant_partitions": len(cross_gpus),
        "cross_tenant_imex": len(cross_imex),
        "shared_switches": shared,
    }
    source = params.get("snapshot") if isinstance(params.get("snapshot"), str) else "<inline fixture>"
    summary = _C.summary_json("NVSwitch/NVLink 拓扑", findings, extra=extra, source=source)
    artifact = _C.write_artifact(ctx, f"{KEY}.json", {
        "summary": json.loads(summary), "findings": findings,
    })
    return {"summary": summary, "artifacts": artifact, "findings": findings}
