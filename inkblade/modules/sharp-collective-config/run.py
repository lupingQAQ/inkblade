# -*- coding: utf-8 -*-
"""SHARP 在网聚合会话/聚合配置审计（只读）。

输入：params.snapshot = SHARP 会话/AM/collective 导出 JSON。
判定：
- 会话 auth=none/缺失 → high；
- 聚合节点被不同租户会话共享 → high；
- 会话成员租户与 session.tenant 不一致 → high；
- 聚合缓冲未隔离 / AM tenant_sharing=true → medium。

只读：不加入会话、不提交 reduce、不改 AM。
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_hardware_common", _PARENT / "_hardware-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "sharp-collective-config"


def _member_tenant(member: str) -> str:
    text = str(member)
    return text.split("/", 1)[0] if "/" in text else ""


def run(ctx: dict, params: dict) -> dict:
    doc = _C.load_snapshot(params)
    sharp = doc.get("sharp") or {}
    sessions = [s for s in doc.get("sessions") or [] if isinstance(s, dict)]
    collectives = [c for c in doc.get("collectives") or [] if isinstance(c, dict)]
    findings: list[dict] = []

    unauth = [s for s in sessions if str(s.get("auth", "none")).lower() in ("", "none", "false", "off")]
    if unauth:
        findings.append(_C.finding(
            "high", "SHARP 会话无鉴权",
            {"detected": True, "sessions": [s.get("id") for s in unauth],
             "count": len(unauth)},
            evidence=f"unauth_sessions={[s.get('id') for s in unauth]}",
            mapping="SHARP/SHARPv3 在网聚合会话面",
            fix="会话入组启用 mTLS/作业令牌，成员与作业 rank 绑定",
        ))

    cross_members = []
    for session in sessions:
        tenant = str(session.get("tenant") or "")
        member_tenants = sorted({_member_tenant(m) for m in session.get("members") or []
                                 if _member_tenant(m)})
        if tenant and any(t != tenant for t in member_tenants):
            cross_members.append({"id": session.get("id"), "tenant": tenant,
                                  "member_tenants": member_tenants})
    if cross_members:
        findings.append(_C.finding(
            "high", "SHARP 会话成员跨租户",
            {"detected": True, "sessions": cross_members},
            evidence=f"cross_tenant_sessions={[s['id'] for s in cross_members]}",
            fix="按作业/租户重建 SHARP 会话，拒绝外部 rank 入组",
        ))

    node_tenants: dict[str, set[str]] = {}
    for session in sessions:
        tenant = str(session.get("tenant") or "")
        if not tenant:
            continue
        for node in session.get("aggregation_nodes") or []:
            node_tenants.setdefault(str(node), set()).add(tenant)
    shared = sorted(node for node, tenants in node_tenants.items() if len(tenants) > 1)
    if shared:
        findings.append(_C.finding(
            "high", "SHARP 聚合节点跨租户共享",
            {"detected": True, "nodes": shared,
             "tenants": {node: sorted(node_tenants[node]) for node in shared}},
            evidence=f"shared_aggregation_nodes={shared}",
            fix="按租户分配聚合节点/AM 资源；共享节点需确认缓冲与会话隔离",
        ))

    unisolated = []
    for session in sessions:
        if session.get("buffer_isolation") is False:
            unisolated.append(f"session:{session.get('id')}")
    for collective in collectives:
        if collective.get("buffer_isolation") is False:
            unisolated.append(f"collective:{collective.get('name')}")
    if unisolated:
        findings.append(_C.finding(
            "medium", "SHARP 聚合缓冲未隔离",
            {"detected": True, "items": unisolated},
            fix="启用 per-session/per-tenant 聚合缓冲隔离，核对 AM 内存分区",
        ))

    if bool(sharp.get("tenant_sharing")):
        findings.append(_C.finding(
            "medium", "SHARP AM 租户共享启用",
            {"detected": True, "sharp": sharp},
            fix="关闭 AM 租户共享；按租户独占 AM/聚合资源",
        ))

    extra = {
        "sessions": len(sessions),
        "collectives": len(collectives),
        "unauth_sessions": len(unauth),
        "cross_tenant_sessions": len(cross_members),
        "shared_aggregation_nodes": shared,
        "buffer_isolation_off": len(unisolated),
        "sharp_version": sharp.get("version", ""),
        "am_enabled": bool(sharp.get("am_enabled")),
    }
    source = params.get("snapshot") if isinstance(params.get("snapshot"), str) else "<inline fixture>"
    summary = _C.summary_json("SHARP 集合通信配置", findings, extra=extra, source=source)
    artifact = _C.write_artifact(ctx, f"{KEY}.json", {
        "summary": json.loads(summary), "sharp": sharp, "findings": findings,
    })
    return {"summary": summary, "artifacts": artifact, "findings": findings}
