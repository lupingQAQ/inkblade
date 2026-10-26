# -*- coding: utf-8 -*-
"""Ambient mesh (ztunnel) surface audit (read-only)."""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_emerging_common", _PARENT / "_emerging-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "ambient-mesh-audit"


def run(ctx: dict, params: dict) -> dict:
    doc = _C.collection(params)
    state = _C.surface_state(ctx.get("meta") or {}, params, doc)
    if state.get("status") != "deployed":
        return _C.not_deployed(ctx, KEY, state)

    findings: list[dict] = []
    ztunnels = [o for o in _C.objects(doc) if "ztunnel" in str(o.get("name", "")).lower()]
    istio_cni = [o for o in _C.objects(doc) if "istio-cni" in str(o.get("name", "")).lower()]
    ready = _C.endpoint_hit(doc, "healthz/ready")
    host_net = [o.get("name") for o in ztunnels if o.get("hostNetwork")]
    if host_net:
        findings.append(_C.finding(
            "high", "ztunnel 使用 hostNetwork，mesh 数据面绕开 Pod 网络隔离",
            {"ztunnel": host_net}, evidence="ztunnel hostNetwork=true"))
    if ready:
        findings.append(_C.finding(
            "low", "ztunnel 健康端点未授权可达（版本与就绪信息泄露）",
            {"endpoint": ready.get("url"), "status": ready.get("status"),
             "product": ready.get("product"), "version": ready.get("version")},
            evidence="GET /healthz/ready -> 2xx"))
    namespaces = set(params.get("mesh_namespaces") or [])
    uncovered = [ns for ns in namespaces if not any(
        str(o.get("namespace", "")) == ns and str(o.get("kind")) == "Namespace"
        and str((o.get("labels") or {}).get("istio.io/dataplane-mode", "")) == "ambient"
        for o in _C.objects(doc))]
    if uncovered:
        findings.append(_C.finding(
            "medium", "命名空间未加入 ambient mesh，东西向流量不受 ztunnel 策略约束",
            {"namespaces": uncovered}, evidence="istio.io/dataplane-mode != ambient"))

    return _C.result(ctx, KEY, state, findings,
                     f"ztunnel={len(ztunnels)} istio_cni={len(istio_cni)} "
                     f"host_network={len(host_net)} findings={len(findings)}",
                     {"ztunnel": [o.get("name") for o in ztunnels],
                      "ready_endpoint": ready.get("url") if ready else ""})
