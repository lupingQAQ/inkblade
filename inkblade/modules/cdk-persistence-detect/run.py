"""cdk-persistence-detect — CDK/KubeTrail 持久化面检测（只读，不生成植入模板）。"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_surface_common", _PARENT / "_surface-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

finding, run_surface = _C.finding, _C.run_surface
section = _C.section


def analyze(snapshot: dict, params: dict) -> list[dict]:
    from inkblade.kubetrail.persistence import detect

    report = detect(snapshot)
    out = list(report["findings"])
    for service in section(snapshot, "services"):
        external = service.get("externalIPs") or []
        if external:
            out.append(finding(
                "high",
                f"externalIPs 劫持面：{service.get('namespace')}/{service.get('name')} → {external}",
                "externalIPs 可把集群内 Service 流量重定向到外部地址（MITM ClusterIP 持久化面）。",
                evidence=f"service={service.get('name')} externalIPs={external}",
                mapping_text="CDK Persistence（MITM ClusterIP）；KubeTrail K8 模板",
                fix="禁用 externalIPs（准入）+ Service 白名单",
            ))
    for path in (snapshot.get("persistence") or {}).get("static_pods") or []:
        out.append(finding(
            "medium", f"静态 Pod 清单：{path}",
            "静态 Pod 绕过 API Server 准入与审计，常被用于影子控制面/后门。",
            evidence=f"static_pod={path}",
            mapping_text="CDK Persistence（影子 apiserver/static pod）",
            fix="节点清单完整性监控 + 文件完整性（AIDE）",
        ))
    return out


def extra(snapshot: dict, findings: list[dict]) -> dict:
    persistence = snapshot.get("persistence") or {}
    return {"indicators": {k: len(v) if isinstance(v, list) else 0
                           for k, v in persistence.items()},
            "findings": len(findings)}


def run(ctx: dict, params: dict) -> dict:
    return run_surface(ctx, params, analyze, family="CDK 持久化检测", extra=extra)
