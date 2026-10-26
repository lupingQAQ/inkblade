# -*- coding: utf-8 -*-
"""Karmada/Cluster API 多集群联邦面（只读侦察）。

GET /multicluster/federation：
- 通配传播到全部集群 → high；
- kubeconfig 共享或无审批 → high；
- 无自动故障转移或命名空间未隔离 → medium。

只读：不创建 PropagationPolicy、不接入/驱逐成员集群。
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_infra2026_common", _PARENT / "_infra2026-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "multi-cluster-federation"


def run(ctx: dict, params: dict) -> dict:
    target = str(params.get("target") or "").rstrip("/")
    if not target:
        return _C.no_target()
    t = _C.Trace(ctx, KEY)
    entry = t.get(f"{target}/multicluster/federation")
    doc = _C.resp(entry)
    propagation = doc.get("propagation") or {}
    policy = doc.get("policy") or {}
    findings: list[dict] = []

    wildcard = bool(propagation.get("wildcard")) or str(propagation.get("cluster_selector")) == "*"
    shared = bool(doc.get("kubeconfigs_shared"))
    approval = bool(policy.get("requires_approval"))
    failover = str(propagation.get("failover") or "none")
    isolated = bool(policy.get("namespace_isolation"))

    if wildcard:
        findings.append(_C.finding(
            "high", "Karmada 通配传播到全部集群",
            {"detected": True, "clusters": doc.get("clusters"),
             "cluster_selector": propagation.get("cluster_selector")},
            evidence=f"wildcard={propagation.get('wildcard')} selector={propagation.get('cluster_selector')}",
            mapping="Karmada PropagationPolicy / Cluster API placement",
            fix="按 clusterAffinity 精确放置；禁止 * 传播到 dev/生产混合集群",
        ))
    if shared or not approval:
        findings.append(_C.finding(
            "high", "多集群 kubeconfig 共享或无审批",
            {"detected": True, "kubeconfigs_shared": shared,
             "requires_approval": approval},
            evidence=f"kubeconfigs_shared={shared} requires_approval={approval}",
            mapping="多集群凭据隔离 / 变更审批",
            fix="每集群独立最小权限凭据；联邦变更走审批与审计",
        ))
    if failover == "none" or not isolated:
        findings.append(_C.finding(
            "medium", "多集群无自动故障转移或命名空间未隔离",
            {"detected": True, "failover": failover, "namespace_isolation": isolated},
            evidence=f"failover={failover} namespace_isolation={isolated}",
            mapping="Karmada failover / 多租户命名空间隔离",
            fix="配置自动 failover 与副本分布；按租户隔离 namespace 与凭据",
        ))

    extra = {
        "hub": doc.get("hub"),
        "clusters": len(_C.as_list(doc.get("clusters"))),
        "wildcard_propagation": wildcard,
        "kubeconfigs_shared": shared,
        "requires_approval": approval,
        "failover": failover,
        "namespace_isolation": isolated,
        "status": entry.get("status"),
    }
    summary = _C.summary_json("多集群联邦面", findings, extra=extra, source=target)
    artifact = _C.write_artifact(ctx, f"{KEY}.json", {
        "summary": json.loads(summary), "federation": doc, "findings": findings,
    })
    trace = t.dump()
    artifacts = ([str(trace)] if trace else []) + artifact
    return {"summary": summary, "artifacts": artifacts, "findings": findings}
