"""kubelet-api-surface — KubeletCTL 15 API 组 + 只读 10255 面判定（检测/取证，不执行）。"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_surface_common", _PARENT / "_surface-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

finding, run_surface = _C.finding, _C.run_surface
section = _C.section

API_GROUPS = ("stats", "metrics", "logs", "spec", "pods", "healthz", "configz",
              "containerLogs", "run", "exec", "cri", "attach", "portForward",
              "runningpods", "debug")
SEV = {
    "exec": "critical", "run": "critical", "cri": "critical", "debug": "high",
    "attach": "high", "portForward": "high", "logs": "medium", "containerLogs": "medium",
    "configz": "medium", "spec": "medium", "pods": "low", "runningpods": "low",
    "stats": "info", "metrics": "info", "healthz": "info",
}
HINT = {
    "exec": "在容器内执行任意命令（RCE 通道）", "run": "拉起新容器（宿主执行面）",
    "cri": "CRI 执行通道", "debug": "调试通道（可读内存/进程）",
    "attach": "附加容器 stdin/stdout", "portForward": "端口转发进容器",
    "logs": "读取容器日志（常含凭据）", "containerLogs": "读取容器日志文件",
    "configz": "kubelet 配置泄露", "spec": "Pod spec 泄露（含 env/volume）",
    "pods": "Pod 清单泄露", "runningpods": "运行中 Pod 清单",
}


def analyze(snapshot: dict, params: dict) -> list[dict]:
    out = []
    for node in section(snapshot, "kubelet"):
        name = node.get("node", "?")
        endpoints = list(node.get("endpoints") or [])
        if node.get("anonymous_auth"):
            out.append(finding(
                "critical", f"kubelet {name}：匿名认证开启（任意 API 组可达）",
                "anonymous-auth=true 时 10250 全 API 面无需凭据。",
                evidence=f"node={name} anonymous_auth=true",
                mapping_text="KubeletCTL 10250 全 API 面（CM-08）",
                fix="anonymous-auth=false + authorization-mode=Webhook",
                node=name, endpoint="auth",
            ))
        if str(node.get("read_only_port", "0")) not in ("0", "", "None"):
            out.append(finding(
                "high", f"kubelet {name}：只读端口 {node.get('read_only_port')} 开放",
                "10255 只读面泄露 Pod/指标/健康信息（kube-hunter 交叉印证）。",
                evidence=f"node={name} read_only_port={node.get('read_only_port')}",
                mapping_text="KubeletCTL / kube-hunter 10255（CM-08）",
                fix="read-only-port=0", node=name, endpoint="readonly",
            ))
        for endpoint in API_GROUPS:
            if endpoint not in endpoints:
                continue
            sev = SEV[endpoint]
            out.append(finding(
                sev, f"kubelet {name}：API 组 {endpoint} 可达",
                f"{HINT.get(endpoint, 'API 面可达')}（仅检测，不发起执行）。",
                evidence=f"node={name} endpoint={endpoint}",
                mapping_text="KubeletCTL API_TABLE.md（15 组）",
                fix="关闭非必要端点 + 认证/授权 + 网络策略仅放行控制面",
                node=name, endpoint=endpoint,
            ))
        if node.get("authorization_mode") and str(node["authorization_mode"]).lower() != "webhook":
            out.append(finding(
                "high", f"kubelet {name}：授权模式 {node['authorization_mode']}",
                "非 Webhook 授权使匿名/低权主体可通过 kubelet 面绕过 API Server RBAC。",
                evidence=f"node={name} authorization_mode={node['authorization_mode']}",
                mapping_text="KubeletCTL（CM-08）", fix="authorization-mode=Webhook",
                node=name, endpoint="authz",
            ))
    return out


def extra(snapshot: dict, findings: list[dict]) -> dict:
    nodes = section(snapshot, "kubelet")
    enabled = {n.get("node", "?"): len(n.get("endpoints") or []) for n in nodes}
    rce = sorted({f.get("endpoint") for f in findings
                  if f.get("endpoint") in ("exec", "run", "cri")})
    return {"api_groups": len(API_GROUPS), "nodes": len(nodes),
            "endpoints_enabled": enabled, "rce_channels": rce,
            "readonly_ports": [n.get("read_only_port") for n in nodes if n.get("read_only_port")]}


def run(ctx: dict, params: dict) -> dict:
    return run_surface(ctx, params, analyze, family="Kubelet API 面", extra=extra)
