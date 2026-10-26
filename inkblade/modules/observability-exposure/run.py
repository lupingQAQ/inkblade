"""observability-exposure — 观测面暴露测绘：DCGM/Prometheus/Grafana/MLflow/Jupyter/TensorBoard。"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_recon_common", _PARENT / "_recon-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

finding, run_recon = _COMMON.finding, _COMMON.run_recon

OBSERVABILITY_PORTS = {
    9400: "DCGM exporter",
    9090: "Prometheus",
    3000: "Grafana",
    5000: "MLflow",
    8888: "Jupyter",
    6006: "TensorBoard",
}


def analyze(snapshot: dict, params: dict) -> list[dict]:
    findings: list[dict] = []
    ingress_by_service = {ing.get("service"): ing.get("host") for ing in snapshot.get("ingresses", [])}
    for svc in snapshot.get("services", []):
        ns = svc.get("namespace", "default")
        name = svc.get("name", "?")
        typ = svc.get("type", "ClusterIP")
        host = ingress_by_service.get(name)
        for port_entry in svc.get("ports", []):
            port = port_entry.get("port")
            component = OBSERVABILITY_PORTS.get(port)
            if not component:
                continue
            if typ in ("LoadBalancer", "NodePort"):
                sev, note = "high", f"{typ} 直接对外暴露"
            elif host:
                sev, note = "medium", f"经 Ingress {host} 暴露"
            else:
                sev, note = "info", "ClusterIP 集群内可达（平网内任意 Pod 可达）"
            findings.append(finding(
                sev, f"观测面暴露：{component} {ns}/{name}:{port}（{note}）",
                detail="观测面 = 资产地图与打点器：指标/面板/实验记录直接暴露 GPU 拓扑、训练任务、数据集与模型路径，"
                       "是「观测面 → 精准打点」链的起点；Jupyter/MLflow 类还可能直接提供执行/数据面。",
                evidence=f"service={ns}/{name} port={port} type={typ} ingress={host or '-'}",
                mapping="链「观测面 → 精准打点」",
                fix="观测栈独立命名空间 + 默认拒绝；对外一律经网关鉴权；训练日志/指标脱敏（不含样本与 prompt）",
            ))
    return findings


def run(ctx: dict, params: dict) -> dict:
    return run_recon(ctx, params, analyze, family="观测面暴露测绘")
