# -*- coding: utf-8 -*-
"""R04 MCP 控制面与工具权限治理检查（只读快照）。"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_residual_common", _PARENT / "_residual2026-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "mcp-control-plane-governance"


def run(ctx: dict, params: dict) -> dict:
    doc = _C.load_snapshot(params)
    plane = _C.section(doc, "mcp_control_plane", "mcp", default={})
    reg = plane.get("registry") or {} if isinstance(plane, dict) else {}
    servers = [s for s in (plane.get("servers") or []) if isinstance(s, dict)] \
        if isinstance(plane, dict) else _C.items(doc, "servers")
    findings: list[dict] = []

    if not _C.as_bool(reg.get("signature_required")):
        findings.append(_C.finding(
            "high", "MCP 注册表未强制 server/工具清单签名",
            {"registry": reg},
            evidence="registry.signature_required=false",
            mapping="MCP 供应链 / rug pull",
            source="IEEE S&P 2026 I21",
            fix="注册表签名 + 工具清单哈希钉住；安装前验签",
        ))
    if not [str(x) for x in (reg.get("publisher_allowlist") or [])]:
        findings.append(_C.finding(
            "medium", "MCP 注册表未配置发布者 allowlist",
            {"registry": reg},
            evidence="publisher_allowlist empty",
            mapping="MCP 发布者信任",
            source="DEF CON 34 I37",
            fix="维护内部 MCP server 白名单",
        ))
    for server in servers:
        name = str(server.get("name") or "?")
        auth = str(server.get("auth") or "none").lower()
        bind = str(server.get("bind") or "")
        tools = [t for t in (server.get("tools") or []) if isinstance(t, dict)]
        issues = []
        if auth in ("", "none", "no", "disabled"):
            issues.append("no-auth")
        if bind in ("0.0.0.0", "::", "[::]", ""):
            issues.append("all-interfaces")
        if not _C.as_bool(server.get("tls")):
            issues.append("no-tls")
        if not _C.as_bool(server.get("signed")):
            issues.append("unsigned")
        if not _C.as_bool(server.get("sandbox")) and any(_C.as_bool(t.get("writes")) for t in tools):
            issues.append("write-tool-without-sandbox")
        if not [str(x) for x in (server.get("allowlist") or [])]:
            issues.append("no-tool-allowlist")
        if str(server.get("previous_manifest_sha256") or "") \
                and str(server.get("previous_manifest_sha256")) != str(server.get("manifest_sha256")):
            issues.append("manifest-changed-rug-pull")
        for tool in tools:
            scopes = tool.get("scopes") or []
            if _C.wildcard(scopes):
                issues.append(f"tool-wildcard-scope:{tool.get('name')}")
            if _C.as_bool(tool.get("writes")) and not _C.as_bool(tool.get("approval")):
                issues.append(f"write-tool-no-approval:{tool.get('name')}")
        if issues:
            sev = "critical" if "no-auth" in issues and "all-interfaces" in issues else "high"
            findings.append(_C.finding(
                sev, f"MCP server {name} 控制面风险",
                {"server": server, "issues": issues},
                evidence=f"server={name} issues={','.join(issues)}",
                mapping="MCP 工具权限治理",
                source="IEEE S&P 2026 I21 / DEF CON 34 I37",
                fix="JWT/mTLS + loopback/管理网 + 工具 allowlist + 写工具人工审批 + 沙箱 + 签名",
            ))

    extra = {
        "servers": len(servers),
        "signed_registry": _C.as_bool(reg.get("signature_required")),
        "critical": sum(1 for f in findings if f["sev"] == "critical"),
        "finding_count": len(findings),
    }
    return _C.result(ctx, KEY, "MCP 控制面与工具权限治理", findings, extra=extra,
                     source=str(params.get("snapshot") or "<inline snapshot>"))
