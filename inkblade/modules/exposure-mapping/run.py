"""exposure-mapping — 暴露面测绘：Service/Ingress/NodePort/LoadBalancer/Gateway API。"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_recon_common", _PARENT / "_recon-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

finding, run_recon = _COMMON.finding, _COMMON.run_recon


def analyze(snapshot: dict, params: dict) -> list[dict]:
    findings: list[dict] = []
    for svc in snapshot.get("services", []):
        ns = svc.get("namespace", "default")
        name = svc.get("name", "?")
        typ = svc.get("type", "ClusterIP")
        ports = ", ".join(str(p.get("port")) for p in svc.get("ports", [])) or "-"
        ext = svc.get("externalIPs") or []
        if typ == "LoadBalancer":
            findings.append(finding(
                "high", f"LoadBalancer 服务暴露：{ns}/{name}（端口 {ports}）",
                detail=f"Service {ns}/{name} 类型 LoadBalancer，经云 LB 对外转发；externalIPs={ext}，无源限制即全网可达。",
                evidence=f"type=LoadBalancer ports={ports} externalIPs={ext}",
                mapping="暴露面测绘；供 framework-port-matching / observability-exposure 交叉定位",
                fix="按域收敛：仅网关命名空间允许 LoadBalancer；云安全组白名单限源；管理端口不得对外",
            ))
        elif typ == "NodePort":
            findings.append(finding(
                "medium", f"NodePort 服务暴露：{ns}/{name}（端口 {ports}）",
                detail=f"NodePort 在全部节点对外开放（含宿主网络边界），绕过 Ingress 层治理。",
                evidence=f"type=NodePort ports={ports} nodePorts="
                         + ",".join(str(p.get("nodePort")) for p in svc.get("ports", []) if p.get("nodePort")),
                mapping="暴露面测绘",
                fix="收敛 NodePort 使用；必须使用时以防火墙/安全组限源并登记端口归属",
            ))
        elif ext:
            findings.append(finding(
                "high", f"externalIPs 直接暴露：{ns}/{name}（{ext}）",
                detail="ClusterIP 挂 externalIPs 直接暴露，等价绕过服务层治理。",
                evidence=f"externalIPs={ext}",
                mapping="暴露面测绘",
                fix="移除 externalIPs，统一经 Ingress/网关暴露",
            ))
    for ing in snapshot.get("ingresses", []):
        findings.append(finding(
            "low", f"Ingress 暴露：{ing.get('host', '?')} → {ing.get('namespace', 'default')}/{ing.get('service', '?')}:{ing.get('port', '?')}",
            detail="经 Ingress 七层暴露；需核对鉴权、TLS 与路径级访问控制。",
            evidence=f"ingress={ing.get('name')} host={ing.get('host')}",
            mapping="暴露面测绘",
            fix="Ingress 层统一鉴权/限速；内部工具域名仅内网解析并加访问控制",
        ))
    for route in snapshot.get("httproutes", []):
        findings.append(finding(
            "medium", f"Gateway API HTTPRoute 暴露：{route.get('hostname', '?')} → {route.get('namespace', 'default')}/{route.get('service', '?')}:{route.get('port', '?')}",
            detail="Gateway API 路由暴露推理入口面（llm-d/router/EPP 语义），是未授权入口与配额绕过的首要核对点。",
            evidence=f"httproute={route.get('name')} hostname={route.get('hostname')}",
            mapping="暴露面测绘；推理网关与预填充-解码分离（网络架构族）",
            fix="网关层强制鉴权与配额；HTTPRoute 按 API 语义最小化暴露路径",
        ))
        pool = route.get("inferencePool") or {}
        if pool.get("failureMode") == "FailOpen":
            findings.append(finding(
                "medium", f"InferencePool failureMode=FailOpen：{pool.get('name', '?')}（故障域放大）",
                detail="EPP 故障时 FailOpen 放行流量，端到端策略（鉴权/路由约束）在故障期失效。",
                evidence=f"inferencePool={pool.get('name')} failureMode=FailOpen",
                mapping="网络组合签名：InferencePool failureMode=FailOpen → 网关故障域放大",
                fix="评估 FailClosed；至少对 FailOpen 池叠加后端鉴权与监控告警",
            ))
    return findings


def run(ctx: dict, params: dict) -> dict:
    return run_recon(ctx, params, analyze, family="暴露面测绘")
