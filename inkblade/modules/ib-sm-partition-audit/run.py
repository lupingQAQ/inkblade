# -*- coding: utf-8 -*-
"""IB Subnet Manager / Partition 配置审计（只读）。

输入：params.snapshot = SM/Partition/节点导出 JSON。
判定：
- 无 secondary SM → high（单 SM 控制整个 fabric 信任域）；
- 默认分区 0x7fff 成员为 * / 覆盖全部 HCA → high；
- 同一 Partition 成员来自多个租户 → high；
- IPoIB 在默认/跨租户分区启用 → medium；
- SM 运行在计算节点 → medium。

只读：不连接 OpenSM/UFM、不改 Partition/成员。
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_hardware_common", _PARENT / "_hardware-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "ib-sm-partition-audit"


def _partition_list(value) -> list[dict]:
    if isinstance(value, dict):
        out = []
        for pkey, item in value.items():
            if isinstance(item, dict):
                out.append({**item, "pkey": item.get("pkey", pkey)})
        return out
    return [p for p in value or [] if isinstance(p, dict)]


def run(ctx: dict, params: dict) -> dict:
    doc = _C.load_snapshot(params)
    sm = doc.get("sm") or {}
    partitions = _partition_list(doc.get("partitions"))
    nodes = [n for n in doc.get("nodes") or [] if isinstance(n, dict)]
    node_tenant = {str(n.get("guid")): str(n.get("tenant") or "") for n in nodes}
    compute_hosts = {str(n.get("host")) for n in nodes
                     if str(n.get("type", "")).upper() == "HCA" and n.get("host")}
    compute_guids = {str(n.get("guid")) for n in nodes
                     if str(n.get("type", "")).upper() == "HCA"}
    findings: list[dict] = []

    sm_count = 1 + (1 if sm.get("secondary") else 0)
    if sm_count < 2:
        findings.append(_C.finding(
            "high", "IB SM 无冗余",
            {"detected": True, "sm_count": sm_count, "primary": sm.get("primary"),
             "host": sm.get("host")},
            evidence=f"subnet_manager primary={sm.get('primary')} secondary={sm.get('secondary')}",
            mapping="InfiniBand Subnet Manager 信任域",
            fix="部署主备 SM（不同主机/网络路径），核对优先级与故障切换",
        ))
    if sm.get("host") and str(sm.get("host")) in compute_hosts:
        findings.append(_C.finding(
            "medium", "IB SM 运行在计算节点",
            {"detected": True, "sm_host": sm.get("host"),
             "compute_hosts": sorted(compute_hosts)},
            evidence=f"sm.host={sm.get('host')} is a compute HCA host",
            fix="SM 迁移到独立管理节点/交换机，限制计算面到 SM 的写权限",
        ))

    wildcard = []
    cross = []
    ipoib = []
    for part in partitions:
        members = [str(m) for m in part.get("members") or []]
        is_default = bool(part.get("default")) or str(part.get("pkey")) == "0x7fff"
        if is_default and ("*" in members or (compute_guids and compute_guids <= set(members))):
            wildcard.append(part.get("pkey") or part.get("name"))
        tenants = {node_tenant.get(m, "") for m in members if node_tenant.get(m, "")}
        if len(tenants) > 1:
            cross.append({"pkey": part.get("pkey"), "name": part.get("name"),
                          "tenant": part.get("tenant"), "member_tenants": sorted(tenants)})
        if bool(part.get("ipoib")) and (is_default or len(tenants) > 1):
            ipoib.append({"pkey": part.get("pkey"), "name": part.get("name"),
                          "default": is_default, "member_tenants": sorted(tenants)})

    if wildcard:
        findings.append(_C.finding(
            "high", "IB 默认分区覆盖全部 HCA",
            {"detected": True, "partitions": wildcard, "members": "*",
             "compute_hcas": sorted(compute_guids)},
            evidence=f"default_partition_wildcard={wildcard}",
            mapping="IB Partition 0x7fff 默认信任域",
            fix="默认分区仅保留 SM/管理口；业务 HCA 移入按租户划分的 PKey",
        ))
    if cross:
        findings.append(_C.finding(
            "high", "IB Partition 跨越租户",
            {"detected": True, "partitions": cross},
            evidence=f"cross_tenant_partitions={[p['pkey'] for p in cross]}",
            mapping="IB Partition/PKey 租户隔离",
            fix="按租户重建 PKey 与成员；核对 SM 配置与节点端口 membership",
        ))
    if ipoib:
        findings.append(_C.finding(
            "medium", "IB IPoIB 在默认/跨租户分区启用",
            {"detected": True, "partitions": ipoib},
            fix="IPoIB 仅用于管理/存储 VLAN，禁止跨租户承载业务流量",
        ))

    extra = {
        "partitions": len(partitions),
        "nodes": len(nodes),
        "hca_nodes": len(compute_guids),
        "sm_count": sm_count,
        "default_partition_wildcard": bool(wildcard),
        "cross_tenant_partitions": len(cross),
        "ipoib_partitions": len(ipoib),
        "sm_host": sm.get("host", ""),
        "routing_engine": sm.get("routing_engine", ""),
    }
    source = params.get("snapshot") if isinstance(params.get("snapshot"), str) else "<inline fixture>"
    summary = _C.summary_json("IB SM/Partition 审计", findings, extra=extra, source=source)
    artifact = _C.write_artifact(ctx, f"{KEY}.json", {
        "summary": json.loads(summary), "sm": sm, "findings": findings,
    })
    return {"summary": summary, "artifacts": artifact, "findings": findings}
