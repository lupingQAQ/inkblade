# -*- coding: utf-8 -*-
"""kube-audit-trail-analysis — K8s 审计轨迹分析（who-did-what 追溯，只读侦察）。

薄封装 inkblade/core/auditlog.py 引擎：
- params.auditlog：JSON Lines 文件路径或事件列表
- params.kubetrail_export：KubeTrail dbus.json 导出（路径或 dict）
- params.baseline_subjects / include_denied：白名单与拒绝尝试口径
"""
from __future__ import annotations

import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[3]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from inkblade.core.auditlog import (  # noqa: E402
    DEFAULT_BASELINE_SUBJECTS,
    analyze,
)

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def run(ctx: dict, params: dict) -> dict:
    baseline = params.get("baseline_subjects") or list(DEFAULT_BASELINE_SUBJECTS)
    if not (params.get("auditlog") or params.get("kubetrail_export")):
        raise ValueError("缺少输入：params.auditlog（JSON Lines 路径/事件列表）或 params.kubetrail_export 二者至少其一")

    result = analyze(
        params.get("auditlog"),
        baseline_subjects=baseline,
        kubetrail_export=params.get("kubetrail_export"),
        include_denied=bool(params.get("include_denied", False)),
    )
    findings = result["findings"]
    findings.sort(key=lambda f: _SEV_RANK.get(f.get("sev", "info"), 9))
    stats = result["stats"]
    top = next((f["sev"] for f in findings), None)
    by_detector: dict[str, int] = {}
    for f in findings:
        by_detector[f["detector"]] = by_detector.get(f["detector"], 0) + 1
    chains = sorted({c for f in findings for c in f.get("chains", [])})
    summary = (
        f"K8s 审计轨迹分析：{stats['events']} 事件 → {len(findings)} 条发现"
        f"（最高 {top or '-'}；检测器分布 {by_detector}；KubeTrail 适配 {stats['kubetrail_findings']} 条；"
        f"映射链 {'/'.join(chains) or '-'}）"
    )
    return {"summary": summary, "findings": findings, "artifacts": []}
