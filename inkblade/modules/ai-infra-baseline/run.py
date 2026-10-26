# -*- coding: utf-8 -*-
"""R05 AI 基础设施统一基线（Ray/Notebook/推理，只读快照）。"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_residual_common", _PARENT / "_residual2026-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "ai-infra-baseline"


def run(ctx: dict, params: dict) -> dict:
    doc = _C.load_snapshot(params)
    infra = _C.section(doc, "ai_infra", "ai-infrastructure", default={})
    services = [s for s in (infra.get("services") or []) if isinstance(s, dict)] \
        if isinstance(infra, dict) else _C.items(doc, "services")
    egress = infra.get("egress") or {} if isinstance(infra, dict) else {}
    known = [k for k in (infra.get("known_vulnerable") or []) if isinstance(k, dict)] \
        if isinstance(infra, dict) else []
    findings: list[dict] = []

    vulnerable = {}
    for item in known:
        vulnerable.setdefault(str(item.get("service") or "").lower(), set()).update(
            str(v) for v in (item.get("versions") or []))

    for service in services:
        name = str(service.get("name") or "?")
        kind = str(service.get("type") or "unknown").lower()
        auth = _C.as_bool(service.get("auth"))
        bind = str(service.get("bind") or "")
        tls = _C.as_bool(service.get("tls"))
        version = str(service.get("version") or "")
        issues = []
        if not auth:
            issues.append("no-auth")
        if bind in ("0.0.0.0", "::", "[::]", ""):
            issues.append("all-interfaces")
        if not tls:
            issues.append("no-tls")
        if _C.as_bool(service.get("admin_api")):
            issues.append("admin-api")
        if version and version in vulnerable.get(kind, set()):
            issues.append(f"known-vulnerable-{version}")
        if issues:
            sev = "critical" if "no-auth" in issues and "all-interfaces" in issues else "high"
            findings.append(_C.finding(
                sev, f"AI 服务 {name} 暴露且缺少基线控制",
                {"service": service, "issues": issues},
                evidence=f"service={name} type={kind} issues={','.join(issues)}",
                mapping="AI 基础设施统一基线",
                source="RSA 2026 I55",
                fix="认证 + TLS + 管理面仅内网 + 版本修复；Ray/Jupyter 关闭匿名 dashboard",
            ))
    if str(egress.get("allowed_hosts") or []) and _C.wildcard(egress.get("allowed_hosts")):
        findings.append(_C.finding(
            "high", "推理/训练进程允许任意出网",
            {"egress": egress},
            evidence=f"allowed_hosts={egress.get('allowed_hosts')}",
            mapping="模型服务出网 / 权重外传",
            source="RSA 2026 I55",
            fix="出网 allowlist（HF/镜像源/对象存储）；禁止推理 Pod 访问 IMDS",
        ))
    if _C.as_bool(egress.get("metadata")):
        findings.append(_C.finding(
            "critical", "AI 服务可触达云元数据/IMDS",
            {"egress": egress},
            evidence="egress.metadata=true",
            mapping="IMDS 凭据窃取",
            source="RSA 2026 I55",
            fix="网络策略阻断 169.254.169.254；使用 workload identity 短时凭据",
        ))
    if _C.as_bool(egress.get("internet")) and not services:
        findings.append(_C.finding(
            "medium", "AI 基础设施可访问互联网但无服务清单",
            {"egress": egress},
            evidence="internet=true services=0",
            mapping="基线清点缺口",
            source="RSA 2026 I55",
            fix="补齐服务清单后再评估暴露面",
        ))

    extra = {
        "services": len(services),
        "insecure": sum(1 for s in services if not _C.as_bool(s.get("auth"))),
        "known_vulnerable": sum(1 for s in services
                                if str(s.get("version")) in vulnerable.get(str(s.get("type")).lower(), set())),
        "egress_internet": _C.as_bool(egress.get("internet")),
        "egress_metadata": _C.as_bool(egress.get("metadata")),
        "finding_count": len(findings),
    }
    return _C.result(ctx, KEY, "AI 基础设施统一基线", findings, extra=extra,
                     source=str(params.get("snapshot") or "<inline snapshot>"))
