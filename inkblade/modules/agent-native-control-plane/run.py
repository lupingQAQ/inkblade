# -*- coding: utf-8 -*-
"""R07 Agent 原生控制面（MaaS/Agent 运行时）检查（只读快照）。"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_residual_common", _PARENT / "_residual2026-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "agent-native-control-plane"


def run(ctx: dict, params: dict) -> dict:
    doc = _C.load_snapshot(params)
    plane = _C.section(doc, "agent_control_plane", "agent_native_control_plane", default={})
    runtime = plane.get("runtime") or {} if isinstance(plane, dict) else {}
    maas = plane.get("maas") or {} if isinstance(plane, dict) else {}
    agents = [a for a in (plane.get("agents") or []) if isinstance(a, dict)] \
        if isinstance(plane, dict) else []
    findings: list[dict] = []

    checks = [
        ("agent_identity", True, "high", "Agent 无独立工作负载身份",
         "Agent 身份 / 最小权限", "为每个 agent 分配 SPIFFE/服务账号身份"),
        ("approval_gate", True, "high", "写/高风险工具有调用无人工审批",
         "Agent 工具审批", "写操作/凭据访问进入双签或 lead 审批"),
        ("sandbox", True, "high", "Agent 工具执行无沙箱",
         "Agent 进程隔离", "工具在 gVisor/Firecracker/WASM 沙箱内执行"),
        ("audit", True, "medium", "Agent 控制面未开启审计",
         "Agent 审计", "记录 agent/工具/参数/结果/审批人"),
    ]
    for key, good, sev, title, mapping, fix in checks:
        value = _C.as_bool(runtime.get(key), default=not good)
        if value != good:
            findings.append(_C.finding(
                sev, title, {"field": key, "value": value, "expected": good},
                evidence=f"runtime.{key}={value} expected={good}",
                mapping=mapping, source="云栖 2026 I60", fix=fix,
            ))
    egress = runtime.get("tool_egress") or []
    if _C.wildcard(egress):
        findings.append(_C.finding(
            "high", "Agent 工具出网/调用范围无 allowlist",
            {"tool_egress": egress},
            evidence=f"tool_egress={egress}",
            mapping="工具出网治理",
            source="云栖 2026 I60",
            fix="按 agent 角色配置工具 allowlist 与目标域名 allowlist",
        ))
    memory = str(runtime.get("memory_store") or "").lower()
    if memory in ("", "shared", "global"):
        findings.append(_C.finding(
            "high", "Agent 记忆存储跨 agent 共享",
            {"memory_store": memory or "<missing>"},
            evidence=f"memory_store={memory or '<missing>'}",
            mapping="记忆/上下文隔离",
            source="云栖 2026 I60",
            fix="每个 agent/租户独立 memory namespace + 访问控制",
        ))
    max_agents = _C.as_int(runtime.get("max_agents"), 0)
    if max_agents <= 0:
        findings.append(_C.finding(
            "medium", "Agent 并发/实例数无上限",
            {"max_agents": max_agents},
            evidence=f"max_agents={max_agents}",
            mapping="资源/成本治理",
            source="云栖 2026 I60",
            fix="设置每租户 agent 并发与总量上限",
        ))
    for field, title, sev in (("tenant_scoped_keys", "MaaS API key 未按租户隔离", "high"),
                              ("api_key_rotation", "MaaS API key 无轮换", "high"),
                              ("audit", "MaaS 控制面未审计", "medium")):
        value = _C.as_bool(maas.get(field), default=False)
        if not value:
            findings.append(_C.finding(
                sev, title, {"field": field, "value": value},
                evidence=f"maas.{field}=false",
                mapping="MaaS 控制面治理", source="云栖 2026 I60",
                fix="租户级 key + 90 天轮换 + 调用审计",
            ))
    if str(maas.get("bind") or "") in ("0.0.0.0", "::", "") or not _C.as_bool(maas.get("tls")):
        findings.append(_C.finding(
            "high", "MaaS 控制面全网监听或未启用 TLS",
            {"bind": maas.get("bind"), "tls": maas.get("tls")},
            evidence=f"bind={maas.get('bind')} tls={maas.get('tls')}",
            mapping="MaaS 管理面暴露",
            source="云栖 2026 I60",
            fix="loopback/管理网 + TLS + 网关鉴权",
        ))
    for agent in agents:
        if _C.wildcard(agent.get("tools")) or _C.wildcard(agent.get("secrets")):
            findings.append(_C.finding(
                "high", f"Agent {agent.get('name')} 工具/凭据范围通配",
                {"agent": agent},
                evidence=f"agent={agent.get('name')} tools/secrets wildcard",
                mapping="Agent 最小权限",
                source="云栖 2026 I60",
                fix="按任务裁剪工具与凭据；禁止 * 通配",
            ))
    if not plane:
        findings.append(_C.finding(
            "high", "未提供 Agent 原生控制面导出",
            {"snapshot": params.get("snapshot")},
            evidence="agent_control_plane missing",
            mapping="控制面清点",
            source="云栖 2026 I60",
            fix="导出 runtime/maas/agents 配置后复测",
        ))

    extra = {
        "agents": len(agents),
        "agent_identity": _C.as_bool(runtime.get("agent_identity")),
        "approval_gate": _C.as_bool(runtime.get("approval_gate")),
        "sandbox": _C.as_bool(runtime.get("sandbox")),
        "memory_store": memory or "missing",
        "max_agents": max_agents,
        "finding_count": len(findings),
    }
    return _C.result(ctx, KEY, "Agent 原生控制面检查", findings, extra=extra,
                     source=str(params.get("snapshot") or "<inline snapshot>"))
