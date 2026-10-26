# -*- coding: utf-8 -*-
"""legacy SA token 逐 token 权限审计（CM-05，SSRR/SSAR 等价，离线）。

输入（fixture 或由采集器导入的 JSON）：
- tokens: [{name, namespace, jti, legacy, expires_at, rules:[{verbs,resources,apiGroups,
  resourceNames,namespaces}]}]
- requests: [{verb, resource, subresource, apiGroup, namespace, name}]

对每个 token 的 RBAC 规则并集逐请求判定（K8s RBAC 语义子集：verbs/resources/
apiGroups/resourceNames/namespaces 与 ``*`` 通配），输出：
- 每 token 的 allow/deny 明细；
- 风险 finding：legacy+写权限、过期 token 仍可解析权限、通配规则、Secret 读取、
  pods/exec 等敏感动词、jti 重复；
- 不访问集群、不执行 SSAR 网络调用：调用方把 API Server 的 SSAR 结果导入即可。
"""

from __future__ import annotations

import time
from typing import Any

WRITE_VERBS = {"create", "update", "patch", "delete", "deletecollection",
               "impersonate", "bind", "escalate"}
READ_VERBS = {"get", "list", "watch"}
SENSITIVE_RESOURCES = {"secrets", "serviceaccounts/token", "pods/exec",
                       "pods/attach", "pods/portforward", "clusterrolebindings",
                       "rolebindings", "nodes/proxy"}


class TokenAuditError(ValueError):
    """token/请求 fixture 非法。"""


def _list(value: Any) -> list:
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple, set)) else [value]


def _match_rule(rule: dict, req: dict) -> bool:
    verb = str(req.get("verb") or "").lower()
    verbs = [str(v).lower() for v in _list(rule.get("verbs"))]
    if not verbs or ("*" not in verbs and verb not in verbs):
        return False
    group = str(req.get("apiGroup") or "")
    groups = [str(g) for g in _list(rule.get("apiGroups"))]
    if groups and "*" not in groups and group not in groups:
        return False
    resource = str(req.get("resource") or "").lower()
    sub = str(req.get("subresource") or "").lower()
    wanted = f"{resource}/{sub}" if sub else resource
    rules_res = [str(r).lower() for r in _list(rule.get("resources"))]
    if not rules_res or ("*" not in rules_res and resource not in rules_res
                         and wanted not in rules_res):
        return False
    names = [str(n) for n in _list(rule.get("resourceNames"))]
    if names and str(req.get("name") or "") not in names:
        return False
    namespaces = [str(n) for n in _list(rule.get("namespaces"))]
    if namespaces and str(req.get("namespace") or "") not in namespaces:
        return False
    return True


def _decide(token: dict, req: dict) -> tuple[bool, str]:
    for i, rule in enumerate(token.get("rules") or []):
        if _match_rule(rule, req):
            return True, f"rule[{i}]"
    return False, "no-rule"


def audit_token(token: dict, requests: list[dict], *, now: float | None = None) -> dict:
    if not token.get("name"):
        raise TokenAuditError("token.name 必填")
    now = time.time() if now is None else now
    rules = token.get("rules") or []
    if not isinstance(rules, list):
        raise TokenAuditError(f"{token['name']}: rules 必须是列表")
    allowed, denied = [], []
    for req in requests or []:
        ok, reason = _decide(token, req)
        row = {**req, "allowed": ok, "reason": reason}
        (allowed if ok else denied).append(row)
    write_allowed = [r for r in allowed if str(r.get("verb", "")).lower() in WRITE_VERBS]
    sensitive = [r for r in allowed
                 if f"{r.get('resource')}/{r.get('subresource')}" in SENSITIVE_RESOURCES
                 or str(r.get("resource")) in SENSITIVE_RESOURCES]
    findings = []
    legacy = bool(token.get("legacy"))
    expires = token.get("expires_at")
    expired = bool(expires) and float(expires) < now
    if legacy and write_allowed:
        findings.append({"sev": "high", "title": f"legacy SA token 具备写权限：{token['name']}",
                         "detail": f"旧式长期 token 可写：{', '.join(sorted({str(r.get('verb')) for r in write_allowed}))}"})
    if expired and allowed:
        findings.append({"sev": "high", "title": f"过期 token 仍解析出权限：{token['name']}",
                         "detail": f"expires_at={expires} 已过期，但规则仍允许 {len(allowed)} 个请求（须吊销/轮换）"})
    if any("*" in [str(v) for v in _list(r.get("verbs"))] or "*" in [str(x) for x in _list(r.get("resources"))]
           for r in rules):
        findings.append({"sev": "medium", "title": f"token 绑定通配规则：{token['name']}",
                         "detail": "verbs/resources 含 *，违背最小权限；按实际调用收敛"})
    if sensitive:
        findings.append({"sev": "high", "title": f"token 可达敏感资源：{token['name']}",
                         "detail": "; ".join(sorted({f"{r.get('verb')} {r.get('resource')}/{r.get('subresource', '')}".strip() for r in sensitive}))})
    return {
        "token": token["name"], "namespace": token.get("namespace", ""),
        "legacy": legacy, "expired": expired, "jti": token.get("jti", ""),
        "summary": {"requests": len(requests or []), "allowed": len(allowed),
                    "denied": len(denied), "write_allowed": len(write_allowed),
                    "sensitive_allowed": len(sensitive)},
        "allowed": allowed, "denied": denied, "findings": findings,
        "risk": ("high" if any(f["sev"] == "high" for f in findings)
                 else "medium" if findings else "low"),
    }


def audit_tokens(tokens: list[dict], requests: list[dict], *,
                 now: float | None = None) -> dict:
    if not isinstance(tokens, list) or not tokens:
        raise TokenAuditError("tokens 不能为空")
    now = time.time() if now is None else now
    per_token = []
    findings: list[dict] = []
    seen_jti: dict[str, str] = {}
    for token in tokens:
        reqs = token.get("requests") if isinstance(token.get("requests"), list) else requests
        result = audit_token(token, reqs, now=now)
        per_token.append(result)
        for f in result["findings"]:
            findings.append({**f, "token": result["token"]})
        jti = str(token.get("jti") or "")
        if jti:
            if jti in seen_jti:
                findings.append({"sev": "medium", "token": result["token"],
                                 "title": f"重复 jti：{jti}",
                                 "detail": f"{seen_jti[jti]} 与 {result['token']} 共用 jti，疑复制 token"})
            else:
                seen_jti[jti] = result["token"]
    return {
        "tokens": len(tokens), "requests": len(requests or []),
        "per_token": per_token, "findings": findings,
        "summary": {
            "legacy": sum(1 for t in per_token if t["legacy"]),
            "expired": sum(1 for t in per_token if t["expired"]),
            "high_risk": sum(1 for t in per_token if t["risk"] == "high"),
            "allowed": sum(t["summary"]["allowed"] for t in per_token),
        },
        "checked_at": now,
    }
