# -*- coding: utf-8 -*-
"""SPIFFE/SPIRE identity surface audit (read-only)."""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_emerging_common", _PARENT / "_emerging-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "spiffe-spire-audit"


def run(ctx: dict, params: dict) -> dict:
    doc = _C.collection(params)
    state = _C.surface_state(ctx.get("meta") or {}, params, doc)
    if state.get("status") != "deployed":
        return _C.not_deployed(ctx, KEY, state)

    findings: list[dict] = []
    servers = [o for o in _C.objects(doc) if "spire-server" in str(o.get("name", "")).lower()]
    agents = [o for o in _C.objects(doc) if "spire-agent" in str(o.get("name", "")).lower()]
    reg = _C.endpoint_hit(doc, "registration")
    if reg:
        findings.append(_C.finding(
            "high", "SPIRE 注册 API 未授权可达",
            {"endpoint": reg.get("url"), "status": reg.get("status")},
            evidence="registration endpoint returned 2xx"))
    server = servers[0] if servers else {}
    if server.get("hostNetwork"):
        findings.append(_C.finding(
            "medium", "SPIRE Server 使用 hostNetwork，身份控制面直接暴露在节点网络",
            {"server": server.get("name"), "namespace": server.get("namespace")},
            evidence="hostNetwork=true"))
    trust_domain = str(params.get("trust_domain") or "")
    if trust_domain.lower() in ("example.org", "spiffe://example.org", "default"):
        findings.append(_C.finding(
            "medium", "SPIRE 使用示例/默认 trust domain",
            {"trust_domain": trust_domain}, evidence="params trust_domain is default"))

    return _C.result(ctx, KEY, state, findings,
                     f"servers={len(servers)} agents={len(agents)} "
                     f"registration_api={'open' if reg else 'absent'}",
                     {"servers": [o.get("name") for o in servers],
                      "agents": [o.get("name") for o in agents]})
