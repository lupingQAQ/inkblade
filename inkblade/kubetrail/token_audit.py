# -*- coding: utf-8 -*-
# Portions derived from KubeTrail (https://github.com/ekkoo-z/KubeTrail),
# Copyright the KubeTrail Authors, licensed under Apache-2.0. This file is an
# independent Python reimplementation; see NOTICE and docs/KUBETRAIL-PORT.md.
"""legacy ServiceAccount token 审计：JWT 解析（仅解码，不验签）+ 风险分级。

检查项（逐 token）：
- ``legacy``：kubernetes.io/service-account-token 型长期 token（无 bound object）；
- 过期时间：无 exp / exp 超过 365 天 / 已过期；
- audience：缺失（旧 token 无受众约束）；
- 权限：``allowed`` 命中通配符 / secrets / pods-exec / impersonate；
- 身份：default SA（命名空间默认）、跨命名空间使用。

输出 ``{tokens: [...], summary: {...}}``；不含原始 token（仅 sha256 前 16 + 长度）。
"""

from __future__ import annotations

import base64
import hashlib
import json
import time

DANGEROUS_PERMS = ("secrets", "pods/exec", "impersonate", "create pods", "rolebindings",
                   "nodes/proxy", "tokenreviews")
LEGACY_MAX_DAYS = 365


class TokenAuditError(ValueError):
    """token 记录/编码非法。"""


def _b64url_decode(segment: str) -> bytes:
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


def decode_jwt(token: str) -> dict:
    """仅解码 JWT payload（**不验签**，绝不用于认证判定）。"""
    parts = str(token).split(".")
    if len(parts) < 2:
        raise TokenAuditError("JWT 段数不足（需 header.payload[.sig]）")
    try:
        claims = json.loads(_b64url_decode(parts[1]).decode("utf-8"))
    except Exception as exc:
        raise TokenAuditError(f"JWT payload 解码失败: {exc}") from exc
    if not isinstance(claims, dict):
        raise TokenAuditError("JWT payload 非对象")
    return claims


def _risk_reasons(record: dict, claims: dict, now: float) -> list[str]:
    reasons: list[str] = []
    allowed = [str(a).lower() for a in (record.get("allowed") or [])]
    exp = record.get("exp", claims.get("exp"))
    if record.get("legacy") or "kubernetes.io/service-account-token" == record.get("type"):
        reasons.append("legacy 长期 token（无 bound object 约束）")
    if exp is None:
        reasons.append("无 exp（永不过期）")
    else:
        days = (float(exp) - now) / 86400
        if days < 0:
            reasons.append("已过期（仍在使用说明轮换失效）")
        elif days > LEGACY_MAX_DAYS:
            reasons.append(f"有效期 {int(days)} 天（> {LEGACY_MAX_DAYS} 天）")
    audience = record.get("audience") or claims.get("aud") or []
    if not audience:
        reasons.append("无 audience（旧 token 无受众约束）")
    if any(a == "*" or a.startswith("* ") for a in allowed):
        reasons.append("绑定通配符权限")
    if any(d in a for a in allowed for d in DANGEROUS_PERMS):
        reasons.append("绑定高价值权限（secrets/exec/impersonate 等）")
    subject = str(record.get("subject") or claims.get("sub") or "")
    if subject.endswith(":default"):
        reasons.append("使用命名空间 default SA")
    if not reasons:
        reasons.append("未命中高风险规则（仍建议轮换）")
    return reasons


def audit_token(record: dict, *, now: float | None = None) -> dict:
    if not isinstance(record, dict) or not record.get("name"):
        raise TokenAuditError("token 记录缺 name")
    now = time.time() if now is None else now
    claims: dict = {}
    jwt = record.get("jwt")
    if jwt:
        try:
            claims = decode_jwt(str(jwt))
        except TokenAuditError:
            claims = {}
    reasons = _risk_reasons(record, claims, now)
    sev = "critical" if any("通配符" in r or "高价值" in r for r in reasons) else (
        "high" if any("legacy" in r or "永不过期" in r for r in reasons) else "medium")
    exp = record.get("exp", claims.get("exp"))
    sha = hashlib.sha256(str(jwt or record.get("name", "")).encode("utf-8")).hexdigest()[:16]
    return {
        "name": record["name"],
        "namespace": record.get("namespace", ""),
        "subject": record.get("subject") or claims.get("sub", ""),
        "issuer": claims.get("iss", ""),
        "legacy": bool(record.get("legacy")),
        "expires_in_days": (int((float(exp) - now) / 86400) if exp is not None else None),
        "audience": record.get("audience") or claims.get("aud") or [],
        "permissions": list(record.get("allowed") or []),
        "sev": sev,
        "reasons": reasons,
        "token_sha256": sha,
        "token_length": len(str(jwt or "")),
    }


def audit_tokens(tokens: list[dict], *, now: float | None = None) -> dict:
    audited = [audit_token(t, now=now) for t in tokens or []]
    counts = {sev: sum(1 for t in audited if t["sev"] == sev)
              for sev in ("critical", "high", "medium", "low")}
    return {"tokens": audited, "summary": {"total": len(audited), **counts,
                                           "legacy": sum(1 for t in audited if t["legacy"])}}


def findings(audit: dict) -> list[dict]:
    out = []
    for token in audit.get("tokens", []):
        out.append({
            "sev": token["sev"],
            "title": f"SA token 审计：{token['namespace']}/{token['name']}（{token['sev']}）",
            "detail": ("风险：" + "；".join(token["reasons"]) +
                       f"；subject={token['subject']}；有效期={token['expires_in_days']} 天；"
                       f"sha256={token['token_sha256']}"),
            "evidence": f"token={token['namespace']}/{token['name']} legacy={token['legacy']}",
            "mapping": "KubeTrail token 审计（CM-05）；KubeHound TOKEN_STEAL/LIST/BRUTEFORCE",
            "fix": "轮换为 bound token（TokenRequest 短有效期 + audience）；收敛 default SA 权限",
        })
    return out
