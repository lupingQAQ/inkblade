# -*- coding: utf-8 -*-
"""NVLink/IMEX 域与分区隔离（C 级 research-only 配置审计）。

输入（params.snapshot）：
```
{
  "imex": {"enabled": true, "tls": true, "auth": true, "bind": "127.0.0.1"},
  "domains": [{"id": "imex-0", "tenant": "tenant-a",
               "members": [{"gpu": "gpu-a0", "tenant": "tenant-a"}],
               "permissions": {"export": ["gpu-a0"], "import": ["gpu-a1"]},
               "channels": [{"path": "/dev/nvidia-imex-0", "mode": "0600",
                             "tenants": ["tenant-a"]}]}],
  "partitions": [{"id": 1, "tenant": "tenant-a", "gpus": ["gpu-a0"],
                  "default": false}],
  "fabric_manager": {"running": true, "partitioning": true, "bind": "127.0.0.1"}
}
```

判定：域成员跨租户、导入导出通配、通道全局可读写、默认分区/任一分区跨租户、
Fabric Manager 未启用分区隔离或绑定 0.0.0.0、IMEX gRPC 未 TLS/鉴权。

边界：C 级 research-only；仅 GB200/NVL 或明确使用多节点 NVLink 的客户按需启用。
只读导出解析；不启动 IMEX、不改 NVLSM/FM、不写分区。
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_chip_common", _PARENT / "_chip-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "nvlink-imex-isolation"


def _member_tenants(members) -> set[str]:
    out: set[str] = set()
    for item in members or []:
        if isinstance(item, dict):
            if item.get("tenant"):
                out.add(str(item["tenant"]))
        elif isinstance(item, str) and "/" in item:
            out.add(item.split("/", 1)[0])
    return out


def _wildcard(values) -> bool:
    if not isinstance(values, list):
        return False
    return any(str(v).strip() in ("*", "all", "any", "0.0.0.0/0") for v in values)


def run(ctx: dict, params: dict) -> dict:
    doc, source = _C.load_snapshot(params)
    imex = doc.get("imex") if isinstance(doc.get("imex"), dict) else {}
    domains = [d for d in doc.get("domains") or [] if isinstance(d, dict)]
    partitions = [p for p in doc.get("partitions") or [] if isinstance(p, dict)]
    fm = doc.get("fabric_manager") if isinstance(doc.get("fabric_manager"), dict) else {}

    findings: list[dict] = []
    cross_domains = []
    wildcard_domains = []
    shared_channels = []
    for domain in domains:
        tenants = _member_tenants(domain.get("members"))
        if domain.get("tenant"):
            tenants.add(str(domain["tenant"]))
        if len(tenants) > 1:
            cross_domains.append({"id": domain.get("id"), "tenants": sorted(tenants),
                                  "members": domain.get("members")})
        perms = domain.get("permissions") if isinstance(domain.get("permissions"), dict) else {}
        if _wildcard(perms.get("export")) or _wildcard(perms.get("import")):
            wildcard_domains.append({"id": domain.get("id"), "permissions": perms})
        for channel in domain.get("channels") or []:
            if not isinstance(channel, dict):
                continue
            mode = str(channel.get("mode") or "")
            ch_tenants = set(str(t) for t in channel.get("tenants") or [])
            if mode in ("0666", "0777", "666", "777") or len(ch_tenants) > 1:
                shared_channels.append({"domain": domain.get("id"),
                                        "path": channel.get("path"),
                                        "mode": mode,
                                        "tenants": sorted(ch_tenants)})

    if cross_domains:
        findings.append(_C.finding(
            "high", "IMEX 域成员跨租户",
            {"detected": True, "domains": cross_domains},
            mapping="NVIDIA IMEX domain (nodes_config.cfg)",
            fix="按租户拆分 IMEX 域；节点配置只包含同租户成员",
        ))
    if wildcard_domains:
        findings.append(_C.finding(
            "high", "IMEX 权限通配（任意主机可导入/导出）",
            {"detected": True, "domains": wildcard_domains},
            mapping="IMEX import/export permissions",
            fix="把 import/export 白名单收敛到域内 GPU/节点；拒绝 *",
        ))
    if shared_channels:
        findings.append(_C.finding(
            "high", "IMEX 通道跨租户共享/全局可读写",
            {"detected": True, "channels": shared_channels},
            mapping="IMEX channel /dev permissions",
            fix="通道 per-tenant 创建，mode 0600，并绑定租户 cgroup/设备策略",
        ))

    default_multi = []
    cross_partitions = []
    for part in partitions:
        tenants = {str(t) for t in part.get("tenants") or []}
        if part.get("tenant"):
            tenants.add(str(part["tenant"]))
        if len(tenants) > 1:
            cross_partitions.append({"id": part.get("id"), "tenants": sorted(tenants),
                                     "gpus": part.get("gpus")})
            if part.get("default"):
                default_multi.append({"id": part.get("id"), "tenants": sorted(tenants),
                                      "gpus": part.get("gpus")})
    if default_multi:
        findings.append(_C.finding(
            "high", "NVLink 默认分区包含多租户 GPU",
            {"detected": True, "partitions": default_multi},
            mapping="NVLink default partition / NVLSM PKEY",
            fix="默认分区只保留同租户 GPU；为租户创建独立 user partition",
        ))
    if cross_partitions:
        findings.append(_C.finding(
            "high", "NVLink 分区跨越租户",
            {"detected": True, "partitions": cross_partitions},
            mapping="NVLink partition / Fabric Manager",
            fix="按租户创建分区并核对 FM/NVLSM 访问控制位",
        ))

    if fm:
        if fm.get("partitioning") is False or fm.get("running") is False:
            findings.append(_C.finding(
                "medium", "Fabric Manager 未启用分区隔离",
                {"detected": True, "fabric_manager": fm},
                mapping="NVIDIA Fabric Manager / NVLSM",
                fix="启用 FM 分区管理；多租户时禁止共享默认分区",
            ))
        if str(fm.get("bind") or "") in ("0.0.0.0", "::", "*"):
            findings.append(_C.finding(
                "medium", "Fabric Manager 管理面绑定 0.0.0.0",
                {"detected": True, "bind": fm.get("bind")},
                fix="FM/NVLSM 管理面绑定回环或带外管理网，并启用鉴权",
            ))
    if imex.get("tls") is False or imex.get("auth") is False:
        findings.append(_C.finding(
            "medium", "IMEX gRPC 未启用 TLS/鉴权",
            {"detected": True, "imex": imex},
            mapping="IMEX TCP/IP + gRPC control plane",
            fix="IMEX 控制面启用 TLS/mTLS 与节点白名单；限制到带内管理网",
        ))

    extra = {
        "domains": len(domains),
        "cross_tenant_domains": len(cross_domains),
        "wildcard_permissions": len(wildcard_domains),
        "shared_channels": len(shared_channels),
        "partitions": len(partitions),
        "cross_tenant_partitions": len(cross_partitions),
        "default_partition_multi_tenant": len(default_multi),
        "fabric_manager": fm,
        "imex_enabled": imex.get("enabled"),
    }
    summary = _C.summary_json("NVLink/IMEX 隔离", findings, extra=extra, source=source)
    artifact = _C.write_artifact(ctx, f"{KEY}.json", {
        "summary": json.loads(summary), "domains": domains, "partitions": partitions,
        "findings": findings,
    })
    return {"summary": summary, "artifacts": artifact, "findings": findings}
