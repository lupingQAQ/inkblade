# -*- coding: utf-8 -*-
"""R03 Kubernetes Operator 跨 namespace 引用图检查（只读快照）。"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_residual_common", _PARENT / "_residual2026-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "operator-cross-namespace-reference"


def _ns(ref: str) -> str:
    parts = str(ref or "").split("/")
    return parts[0] if len(parts) > 1 else ""


def run(ctx: dict, params: dict) -> dict:
    doc = _C.load_snapshot(params)
    graph = _C.section(doc, "operator_references", "operators", default={})
    operators = [o for o in (graph.get("operators") or []) if isinstance(o, dict)] \
        if isinstance(graph, dict) else _C.items(doc, "operators")
    rbac = [r for r in (graph.get("rbac") or []) if isinstance(r, dict)] if isinstance(graph, dict) else []
    webhooks = [w for w in (graph.get("conversion_webhooks") or []) if isinstance(w, dict)] \
        if isinstance(graph, dict) else []
    findings: list[dict] = []

    for op in operators:
        name = str(op.get("name") or "?")
        watch = [str(x) for x in (op.get("watch_namespaces") or [])]
        role = str(op.get("cluster_role") or "")
        refs = [r for r in (op.get("references") or []) if isinstance(r, dict)]
        cross = [r for r in refs if _ns(r.get("from")) and _ns(r.get("to")) and _ns(r.get("from")) != _ns(r.get("to"))]
        if any(x in ("*", "all") for x in watch) and role in ("cluster-admin", "admin", "edit"):
            findings.append(_C.finding(
                "critical", f"Operator {name} 全 namespace watch 且持有高权限",
                {"operator": op, "watch_namespaces": watch, "cluster_role": role},
                evidence=f"operator={name} watch=* role={role}",
                mapping="Operator 跨 namespace 越权",
                source="NDSS 2026 I11",
                fix="Operator 只 watch 自身 namespace；cluster-scoped 逻辑拆分为最小 RBAC",
            ))
        if cross:
            findings.append(_C.finding(
                "high", f"Operator {name} CR 跨 namespace 引用他租户资源",
                {"operator": name, "references": cross},
                evidence=f"cross_ns_refs={len(cross)}",
                mapping="CR 引用图 / 凭据读取跳板",
                source="NDSS 2026 I11",
                fix="CR 引用限制在同 namespace；跨 ns 读取需显式审批与 RBAC 隔离",
            ))
        for ref in refs:
            if str(ref.get("kind") or "").lower() in ("secret", "serviceaccount", "rolebinding") \
                    and _ns(ref.get("from")) != _ns(ref.get("to")):
                findings.append(_C.finding(
                    "high", f"Operator {name} 跨 ns 引用敏感对象 {ref.get('kind')}",
                    {"reference": ref},
                    evidence=f"{ref.get('from')} -> {ref.get('to')}",
                    mapping="跨 namespace Secret 读取",
                    source="NDSS 2026 I11",
                    fix="使用同 ns Secret 或 external-secrets 的租户级 SecretStore",
                ))
    for entry in rbac:
        resources = [str(r) for r in (entry.get("resources") or [])]
        namespaces = [str(n) for n in (entry.get("namespaces") or [])]
        verbs = [str(v) for v in (entry.get("verbs") or [])]
        if any(r in ("secrets", "*") for r in resources) and any(n in ("*", "all") for n in namespaces) \
                and any(v in ("get", "list", "watch", "*") for v in verbs):
            findings.append(_C.finding(
                "high", "RBAC 允许全 namespace 读取 Secret",
                {"subject": entry.get("subject"), "entry": entry},
                evidence=f"subject={entry.get('subject')} verbs={verbs} ns=*",
                mapping="Operator 服务账号凭据面",
                source="NDSS 2026 I11",
                fix="Role/RoleBinding 限定 namespace；禁止 secrets list/watch 通配",
            ))
    for hook in webhooks:
        if not str(hook.get("ca_bundle") or "") or _C.as_bool(hook.get("insecure_skip_verify")):
            findings.append(_C.finding(
                "high", f"CRD conversion webhook {hook.get('name')} 未校验服务端证书",
                {"webhook": hook},
                evidence=f"ca_bundle={'missing' if not hook.get('ca_bundle') else 'present'} "
                         f"insecure_skip_verify={hook.get('insecure_skip_verify')}",
                mapping="CRD conversion 中间人",
                source="NDSS 2026 I11",
                fix="注入 CA bundle；禁止 insecureSkipVerify；轮换 webhook 证书",
            ))
    if not operators:
        findings.append(_C.finding(
            "info", "未发现 Operator 引用图（可能未部署 Operator）",
            {"operators": 0},
            evidence="operators=0",
            mapping="引用图清点",
            source="NDSS 2026 I11",
            fix="若部署 Operator，导出 CRD/CR/RBAC 引用关系后复测",
        ))

    extra = {
        "operators": len(operators),
        "cross_namespace_refs": sum(1 for op in operators for r in (op.get("references") or [])
                                    if _ns(r.get("from")) and _ns(r.get("to"))
                                    and _ns(r.get("from")) != _ns(r.get("to"))),
        "rbac_entries": len(rbac),
        "webhooks": len(webhooks),
        "finding_count": len(findings),
    }
    return _C.result(ctx, KEY, "Kubernetes Operator 跨 namespace 引用图", findings, extra=extra,
                     source=str(params.get("snapshot") or "<inline snapshot>"))
