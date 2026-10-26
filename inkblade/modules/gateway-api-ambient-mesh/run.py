# -*- coding: utf-8 -*-
"""Gateway API/Ambient Mesh 策略面（只读侦察）。

GET /mesh/policies：
- Gateway listener 明文 HTTP/通配主机 → high；
- HTTPRoute 跨命名空间或 allowedRoutes.from=All → high；
- ambient waypoint 未强制 L7 授权 / mTLS permissive → high；
- ztunnel bypass / L7 策略为空 → medium。

只读：不创建/修改 Gateway、HTTPRoute、AuthorizationPolicy。
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_infra2026_common", _PARENT / "_infra2026-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "gateway-api-ambient-mesh"


def run(ctx: dict, params: dict) -> dict:
    target = str(params.get("target") or "").rstrip("/")
    if not target:
        return _C.no_target()
    t = _C.Trace(ctx, KEY)
    entry = t.get(f"{target}/mesh/policies")
    doc = _C.resp(entry)
    gateways = [g for g in _C.as_list(doc.get("gateways")) if isinstance(g, dict)]
    routes = [r for r in _C.as_list(doc.get("httproutes")) if isinstance(r, dict)]
    waypoint = doc.get("waypoint") or {}
    peer = doc.get("peer_auth") or {}
    findings: list[dict] = []

    plaintext: list[dict] = []
    for gw in gateways:
        for listener in _C.as_list(gw.get("listeners")):
            if not isinstance(listener, dict):
                continue
            if (str(listener.get("protocol")).upper() != "HTTPS"
                    or not listener.get("tls")
                    or str(listener.get("hostname")) == "*"):
                plaintext.append({"gateway": gw.get("name"),
                                  "namespace": gw.get("namespace"),
                                  "port": listener.get("port"),
                                  "protocol": listener.get("protocol"),
                                  "hostname": listener.get("hostname")})
    gw_ns = {str(g.get("name")): str(g.get("namespace")) for g in gateways}
    cross = [r for r in routes
             if bool(r.get("allowed_routes_from_all"))
             or (gw_ns and str(r.get("namespace")) not in set(gw_ns.values()))]
    authz = bool(waypoint.get("authz_enforced"))
    mtls = str(peer.get("mtls") or "")
    bypass = [str(x) for x in _C.as_list(doc.get("ztunnel_bypass"))]
    l7 = _C.as_list(doc.get("l7_policy"))

    if plaintext:
        findings.append(_C.finding(
            "high", "Gateway 监听器明文 HTTP 或通配主机",
            {"detected": True, "listeners": plaintext},
            evidence=f"plaintext_listeners={len(plaintext)}",
            mapping="Gateway API Listener / TLS 终止",
            fix="listener 强制 HTTPS + TLS 证书；hostname 精确到域名，禁止 *",
        ))
    if cross:
        findings.append(_C.finding(
            "high", "HTTPRoute 跨命名空间或全来源放行",
            {"detected": True,
             "routes": [{"name": r.get("name"), "namespace": r.get("namespace"),
                         "hostnames": r.get("hostnames"),
                         "allowed_routes_from_all": r.get("allowed_routes_from_all")}
                        for r in cross]},
            evidence=f"cross_namespace_routes={len(cross)}",
            mapping="Gateway API allowedRoutes / ReferenceGrant",
            fix="限制 allowedRoutes.namespaces.from=Same；跨 ns 必须显式 ReferenceGrant",
        ))
    if not authz or mtls != "strict":
        findings.append(_C.finding(
            "high", "Ambient waypoint 未强制 L7 授权",
            {"detected": True, "authz_enforced": authz, "mtls": mtls,
             "waypoint": waypoint, "l7_policy_count": len(l7)},
            evidence=f"authz_enforced={authz} mtls={mtls} l7_policy={len(l7)}",
            mapping="Istio ambient waypoint / AuthorizationPolicy / PeerAuthentication",
            fix="waypoint 启用 L7 AuthorizationPolicy；PeerAuthentication STRICT",
        ))
    if bypass or not l7:
        findings.append(_C.finding(
            "medium", "Ambient 存在 ztunnel 旁路或 L7 策略缺失",
            {"detected": True, "ztunnel_bypass": bypass, "l7_policy_count": len(l7),
             "excluded_namespaces": doc.get("ambient_redirection_excluded")},
            evidence=f"ztunnel_bypass={bypass} l7_policy={len(l7)}",
            mapping="ztunnel redirection / ambient dataplane bypass",
            fix="将 hostNetwork/VM 流量纳入策略或隔离；为敏感 ns 配置 L7 deny-all",
        ))

    extra = {
        "mode": doc.get("mode"),
        "gateways": len(gateways),
        "routes": len(routes),
        "plaintext_listeners": len(plaintext),
        "cross_namespace_routes": len(cross),
        "authz_enforced": authz,
        "mtls": mtls,
        "status": entry.get("status"),
    }
    summary = _C.summary_json("Gateway API/Ambient Mesh", findings, extra=extra,
                              source=target)
    artifact = _C.write_artifact(ctx, f"{KEY}.json", {
        "summary": json.loads(summary), "mesh": doc, "findings": findings,
    })
    trace = t.dump()
    artifacts = ([str(trace)] if trace else []) + artifact
    return {"summary": summary, "artifacts": artifacts, "findings": findings}
