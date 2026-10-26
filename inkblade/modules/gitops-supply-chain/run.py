# -*- coding: utf-8 -*-
"""GitOps 密钥与漂移面（只读侦察）。

GET /gitops/secrets：
- 仓库存在明文密钥/未加密 → high；
- 漂移未阻断或自动同步未签名 → high；
- 未启用 prune/签名提交/external-secrets → medium。

只读：不 clone 写回、不 sync、不读取密钥值（仅统计与名称）。
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_infra2026_common", _PARENT / "_infra2026-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "gitops-supply-chain"


def run(ctx: dict, params: dict) -> dict:
    target = str(params.get("target") or "").rstrip("/")
    if not target:
        return _C.no_target()
    t = _C.Trace(ctx, KEY)
    entry = t.get(f"{target}/gitops/secrets")
    doc = _C.resp(entry)
    findings: list[dict] = []

    plaintext = _C.as_int(doc.get("plaintext_secrets"))
    encrypted = bool(doc.get("encrypted"))
    names = [str(x) for x in _C.as_list(doc.get("secret_names"))]
    drift = _C.as_int(doc.get("drift_entries"))
    auto_sync = bool(doc.get("auto_sync"))
    signed = bool(doc.get("signed_commits"))
    prune = bool(doc.get("prune"))

    if plaintext > 0 or not encrypted:
        findings.append(_C.finding(
            "high", "GitOps 仓库存在明文密钥",
            {"detected": True, "plaintext_secrets": plaintext, "encrypted": encrypted,
             "secret_names": names, "external_secrets": bool(doc.get("external_secrets"))},
            evidence=f"plaintext_secrets={plaintext} encrypted={encrypted}",
            mapping="Argo CD/Flux + SOPS/SealedSecrets/External Secrets",
            fix="迁移到 External Secrets/SOPS；轮换已泄露密钥；仓库开启 secret scanning",
        ))
    if drift > 0 or (auto_sync and not signed):
        findings.append(_C.finding(
            "high", "GitOps 漂移未阻断或自动同步未签名",
            {"detected": True, "drift_entries": drift, "auto_sync": auto_sync,
             "signed_commits": signed},
            evidence=f"drift_entries={drift} auto_sync={auto_sync} signed={signed}",
            mapping="GitOps reconciliation / commit signature / drift detection",
            fix="启用 drift detection 并阻断自动 sync；要求签名提交与策略校验",
        ))
    if not prune or not signed:
        findings.append(_C.finding(
            "medium", "GitOps 未启用 prune 或签名提交",
            {"detected": True, "prune": prune, "signed_commits": signed,
             "external_secrets": bool(doc.get("external_secrets"))},
            evidence=f"prune={prune} signed_commits={signed}",
            mapping="GitOps 生命周期 / 供应链完整性",
            fix="启用 prune 防残留；启用 commit 签名与部署密钥最小权限",
        ))

    extra = {
        "tool": doc.get("tool"),
        "repo": doc.get("repo"),
        "plaintext_secrets": plaintext,
        "drift_entries": drift,
        "encrypted": encrypted,
        "signed_commits": signed,
        "prune": prune,
        "status": entry.get("status"),
    }
    summary = _C.summary_json("GitOps 密钥与漂移", findings, extra=extra, source=target)
    artifact = _C.write_artifact(ctx, f"{KEY}.json", {
        "summary": json.loads(summary), "gitops": doc, "findings": findings,
    })
    trace = t.dump()
    artifacts = ([str(trace)] if trace else []) + artifact
    return {"summary": summary, "artifacts": artifacts, "findings": findings}
