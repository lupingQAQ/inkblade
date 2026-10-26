"""kubelet 10250 暴露面：只读快照分析（不主动扫描，采集由授权工具完成）。"""
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
    kubelets = snapshot.get("kubelets") or []
    for k in kubelets:
        addr = k.get("addr") or k.get("host") or "?"
        port = k.get("port") or 10250
        base = f"{addr}:{port}"
        if k.get("anonymous_auth"):
            findings.append(finding(
                "critical", f"kubelet 匿名鉴权开启：{base}",
                detail="匿名请求可读取 Pod 列表/日志，结合 exec 可进入容器；"
                       "SA token 可能被挂载读取。",
                evidence=f"anonymous_auth=true {base}",
                mapping="资产发现 → 权限链（SA token 收割）",
                fix="关闭 --anonymous-auth，启用 Webhook 授权并限制 10250 到控制面网段",
            ))
        if k.get("read_only_port"):
            findings.append(finding(
                "high", f"kubelet read-only port 开启：{base}",
                detail="只读端口通常无需鉴权，暴露 Pod/节点信息。",
                evidence=f"read_only_port=true {base}",
                mapping="资产发现", fix="关闭 --read-only-port",
            ))
        if k.get("running_pods_exposed"):
            findings.append(finding(
                "medium", f"kubelet /runningpods 可枚举：{base}",
                detail="可枚举运行中 Pod 名称与命名空间，为横向移动提供目标清单。",
                evidence=f"runningpods={len(k.get('running_pods') or [])}",
                mapping="资产发现", fix="关闭匿名读接口",
            ))
        if k.get("logs_allowed"):
            findings.append(finding(
                "high", f"kubelet 日志接口可读：{base}",
                detail="日志可能包含模型路径、token、上游凭据等敏感信息。",
                evidence=f"logs_allowed=true {base}",
                mapping="窃取与数据泄露", fix="鉴权并最小化日志暴露",
            ))
        if k.get("token_harvestable"):
            findings.append(finding(
                "critical", f"kubelet 面可收割 SA token：{base}",
                detail="通过 Pod 详情/exec 读取挂载的 serviceaccount token，可横向到 API Server。",
                evidence=f"token_harvestable=true {base}",
                mapping="权限链（SA token）", fix="禁用 automount，轮换 token，限制 kubelet 读面",
            ))
        if k.get("exec_allowed"):
            findings.append(finding(
                "critical", f"kubelet exec 接口可进入容器：{base}",
                detail="未授权 exec 等价于容器内命令执行，可直接读取权重/凭据。",
                evidence=f"exec_allowed=true {base}",
                mapping="权限链 → 数据泄露", fix="关闭匿名 exec，启用鉴权与审计",
            ))
        if not any(k.get(x) for x in ("anonymous_auth", "read_only_port", "running_pods_exposed",
                                      "logs_allowed", "token_harvestable", "exec_allowed")):
            findings.append(finding(
                "info", f"kubelet 未发现未授权读面：{base}",
                detail="快照声明各读接口均需鉴权，建议持续监测配置漂移。",
                evidence=f"addr={base}", mapping="资产发现", fix="保持 Webhook 授权与最小暴露",
            ))
    return findings


def run(ctx: dict, params: dict) -> dict:
    return run_recon(ctx, params, analyze, family="kubelet 暴露面")
