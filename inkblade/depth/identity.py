# -*- coding: utf-8 -*-
"""IRSA/RRSA/EKS Pod Identity/GCP/Azure workload identity trust evaluator.

Models the condition-key semantics that create cross-tenant federation:
wildcard principals, missing or wildcard sub/aud/iss, vacuous ForAllValues,
Null misuse, absent SourceAccount/SourceArn, optional ExternalId, OIDC issuer
confusion and Pod Identity namespace/service-account wildcards.
"""

from __future__ import annotations

import copy
import fnmatch
from typing import Any

from .common import finding, hash_payload, summary_json

KEY = "identity-federation-trust"

LEGIT = {
    "account": "111122223333",
    "issuer": "https://token.actions.githubusercontent.com",
    "sub": "repo:org/repo:ref:refs/heads/main",
    "aud": "sts.amazonaws.com",
    "namespace": "tenant-a",
    "service_account": "sa",
    "external_id": "expected-external-id",
    "source_account": "111122223333",
    "source_arn": "arn:aws:iam::111122223333:role/weight-reader",
    "principal_set": "principalSet://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/tenant-a",
    "principal_arn": "arn:aws:iam::111122223333:role/weight-reader",
}
ATTACK = {
    **LEGIT,
    "account": "999999999999",
    # Keep issuer/audience legitimate unless a case is specifically about
    # confusion; otherwise the exact-principal check would mask the finding.
    "sub": "repo:org/evil-repo:ref:refs/heads/main",
    "namespace": "tenant-b",
    "service_account": "admin",
    "external_id": "attacker-external-id",
    "source_account": "999999999999",
    "source_arn": "arn:aws:iam::999999999999:role/evil",
    "principal_set": "principalSet://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/attacker",
    "principal_arn": "arn:aws:iam::999999999999:role/evil",
}

OIDC = "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"
SUB = "token.actions.githubusercontent.com:sub"
AUD = "token.actions.githubusercontent.com:aud"
ISS = "token.actions.githubusercontent.com:iss"


def _stmt(principal, condition=None, action="sts:AssumeRoleWithWebIdentity") -> dict:
    item = {"Effect": "Allow", "Principal": principal, "Action": action}
    if condition:
        item["Condition"] = condition
    return {"Version": "2012-10-17", "Statement": [item]}


def _hardened_aws() -> dict:
    return _stmt({"Federated": OIDC}, {
        "StringEquals": {SUB: LEGIT["sub"], AUD: LEGIT["aud"], ISS: LEGIT["issuer"],
                         "aws:SourceAccount": LEGIT["source_account"],
                         "aws:SourceArn": LEGIT["source_arn"],
                         "sts:ExternalId": LEGIT["external_id"]},
    })


def _hardened_gcp() -> dict:
    return {
        "principalSet": "principalSet://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/tenant-a",
        "attributeCondition": f"assertion.sub == '{LEGIT['sub']}'",
        "audience": "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/github",
    }


def _hardened_azure() -> dict:
    return {
        "issuer": LEGIT["issuer"],
        "subject": LEGIT["sub"],
        "audiences": ["api://AzureADTokenExchange"],
    }


def _hardened_pod_identity() -> dict:
    return {"namespace": "tenant-a", "service_account": "sa"}


def _aws_case(cid, category, title, trust, *, attack=None, hardened=None) -> dict:
    return {
        "id": cid, "provider": "aws-irsa" if "rrssa" not in cid else "aws-rrssa",
        "category": category, "title": title,
        "trust": trust,
        "hardened_trust": hardened or _hardened_aws(),
        "request": {**ATTACK, **(attack or {})},
        "legit_request": dict(LEGIT),
    }


def _cases() -> list[dict]:
    cases: list[dict] = []
    cases.append(_aws_case(
        "irsa-wildcard-principal", "wildcard-principal",
        "IRSA trust Principal=\"*\"，任意账户可 AssumeRoleWithWebIdentity",
        _stmt("*")))
    cases.append(_aws_case(
        "irsa-account-root-wildcard", "wildcard-principal",
        "Principal 为 arn:aws:iam::*:root，跨账户根主体可假定",
        _stmt({"AWS": "arn:aws:iam::*:root"}),
        attack={"principal_arn": "arn:aws:iam::999999999999:root"}))
    cases.append(_aws_case(
        "irsa-subject-wildcard", "subject-wildcard",
        "sub 使用 StringLike repo:org/*，同组织任意仓库可假定",
        _stmt({"Federated": OIDC}, {
            "StringLike": {SUB: "repo:org/*", AUD: LEGIT["aud"]}}),
        attack={"sub": "repo:org/evil-repo:ref:refs/heads/main"}))
    cases.append(_aws_case(
        "rrssa-subject-wildcard", "subject-wildcard",
        "ACK RRSA trust 的 sub 使用 repo:org/*，同组织任意仓库可假定",
        _stmt({"Federated": OIDC}, {
            "StringLike": {SUB: "repo:org/*", AUD: LEGIT["aud"]}}),
        attack={"sub": "repo:org/evil-repo:ref:refs/heads/main"}))
    cases.append(_aws_case(
        "irsa-subject-missing", "missing-condition",
        "trust 未约束 sub，任意 OIDC subject 可假定",
        _stmt({"Federated": OIDC}, {"StringEquals": {AUD: LEGIT["aud"]}})))
    cases.append(_aws_case(
        "irsa-audience-missing", "audience-wildcard",
        "trust 未约束 aud，其他 OIDC 客户端 audience 可复用",
        _stmt({"Federated": OIDC}, {"StringEquals": {SUB: LEGIT["sub"]}}),
        attack={"sub": LEGIT["sub"], "aud": "evil-audience"}))
    cases.append(_aws_case(
        "irsa-issuer-confusion", "oidc-confusion",
        "Principal Federated=* 且无 iss 条件，攻击者 OIDC issuer 可冒充",
        _stmt({"Federated": "*"}, {"StringEquals": {SUB: LEGIT["sub"]}}),
        attack={"issuer": "https://token.evil.example", "sub": LEGIT["sub"]}))
    cases.append(_aws_case(
        "irsa-source-account-missing", "source-account-missing",
        "跨账户 trust 未约束 aws:SourceAccount，其他账户可代填",
        _stmt({"Federated": OIDC}, {
            "StringEquals": {SUB: LEGIT["sub"], AUD: LEGIT["aud"]}}),
        attack={"sub": LEGIT["sub"], "source_account": "999999999999"}))
    cases.append(_aws_case(
        "irsa-source-arn-wildcard", "source-account-missing",
        "aws:SourceArn 使用 arn:aws:iam::*:role/* 通配",
        _stmt({"Federated": OIDC}, {
            "StringEquals": {SUB: LEGIT["sub"], AUD: LEGIT["aud"]},
            "StringLike": {"aws:SourceArn": "arn:aws:iam::*:role/*"}}),
        attack={"sub": LEGIT["sub"], "source_arn": "arn:aws:iam::999999999999:role/evil"}))
    cases.append(_aws_case(
        "irsa-external-id-optional", "external-id-optional",
        "trust 未要求 sts:ExternalId， confused-deputy 可跨租户假定",
        _stmt({"Federated": OIDC}, {
            "StringEquals": {SUB: LEGIT["sub"], AUD: LEGIT["aud"]}}),
        attack={"sub": LEGIT["sub"], "external_id": "attacker-external-id"}))
    cases.append(_aws_case(
        "irsa-foranyvalue-wildcard", "subject-wildcard",
        "ForAnyValue:StringLike 对 sub 列表中的 repo:org/* 放行",
        _stmt({"Federated": OIDC}, {
            "ForAnyValue:StringLike": {SUB: ["repo:org/*"]},
            "StringEquals": {AUD: LEGIT["aud"]}}),
        attack={"sub": "repo:org/evil-repo:ref:refs/heads/main"}))
    cases.append(_aws_case(
        "irsa-null-sub", "missing-condition",
        "Null:{sub:true} 允许 subject 缺失的 token",
        _stmt({"Federated": OIDC}, {
            "Null": {SUB: "true"}, "StringEquals": {AUD: LEGIT["aud"]}}),
        attack={"sub": ""}))
    cases.append(_aws_case(
        "irsa-forallvalues-empty", "empty-set",
        "ForAllValues:StringLike 在 subject 空集上 vacuously true",
        _stmt({"Federated": OIDC}, {
            "ForAllValues:StringLike": {SUB: ["repo:org/*"]},
            "StringEquals": {AUD: LEGIT["aud"]}}),
        attack={"sub": ""}))
    # GCP workload identity
    cases.append({
        "id": "gcp-principal-set-wildcard", "provider": "gcp-wi",
        "category": "subject-wildcard",
        "title": "GCP principalSet 以 pool/* 放行任意 service account",
        "trust": {"principalSet": "principalSet://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/*"},
        "hardened_trust": _hardened_gcp(),
        "request": {**ATTACK, "principal_set": "principalSet://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/attacker"},
        "legit_request": dict(LEGIT),
    })
    cases.append({
        "id": "gcp-attribute-wildcard", "provider": "gcp-wi",
        "category": "subject-wildcard",
        "title": "GCP attributeCondition assertion.sub == '*'",
        "trust": {"principalSet": "principalSet://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/tenant-a",
                  "attributeCondition": "assertion.sub == '*'"},
        "hardened_trust": _hardened_gcp(),
        "request": {**ATTACK, "principal_set": "principalSet://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/tenant-a"},
        "legit_request": dict(LEGIT),
    })
    cases.append({
        "id": "gcp-missing-condition", "provider": "gcp-wi",
        "category": "missing-condition",
        "title": "GCP provider 未配置 attributeCondition",
        "trust": {"principalSet": "principalSet://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/tenant-a"},
        "hardened_trust": _hardened_gcp(),
        "request": {**ATTACK, "principal_set": "principalSet://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/tenant-a"},
        "legit_request": dict(LEGIT),
    })
    # Azure workload identity
    cases.append({
        "id": "azure-subject-wildcard", "provider": "azure-wi",
        "category": "subject-wildcard",
        "title": "Azure federated credential subject=repo:org/*",
        "trust": {"issuer": LEGIT["issuer"], "subject": "repo:org/*",
                  "audiences": ["api://AzureADTokenExchange"]},
        "hardened_trust": _hardened_azure(),
        "request": {**ATTACK, "issuer": LEGIT["issuer"],
                    "sub": "repo:org/evil-repo:ref:refs/heads/main",
                    "aud": "api://AzureADTokenExchange"},
        "legit_request": {**LEGIT, "aud": "api://AzureADTokenExchange"},
    })
    cases.append({
        "id": "azure-audience-missing", "provider": "azure-wi",
        "category": "audience-wildcard",
        "title": "Azure federated credential 未约束 audiences",
        "trust": {"issuer": LEGIT["issuer"], "subject": LEGIT["sub"]},
        "hardened_trust": _hardened_azure(),
        "request": {**ATTACK, "aud": "evil-audience", "sub": LEGIT["sub"],
                    "issuer": LEGIT["issuer"]},
        "legit_request": {**LEGIT, "aud": "api://AzureADTokenExchange"},
    })
    cases.append({
        "id": "azure-issuer-wildcard", "provider": "azure-wi",
        "category": "oidc-confusion",
        "title": "Azure issuer 使用 https://* 通配",
        "trust": {"issuer": "https://*", "subject": LEGIT["sub"],
                  "audiences": ["api://AzureADTokenExchange"]},
        "hardened_trust": _hardened_azure(),
        "request": {**ATTACK, "issuer": "https://token.evil.example",
                    "sub": LEGIT["sub"], "aud": "api://AzureADTokenExchange"},
        "legit_request": {**LEGIT, "aud": "api://AzureADTokenExchange"},
    })
    # EKS Pod Identity associations
    cases.append({
        "id": "podidentity-namespace-wildcard", "provider": "aws-pod-identity",
        "category": "wildcard-principal",
        "title": "EKS Pod Identity association namespace='*'",
        "trust": {"namespace": "*", "service_account": "*"},
        "hardened_trust": _hardened_pod_identity(),
        "request": {**ATTACK, "namespace": "tenant-b", "service_account": "sa"},
        "legit_request": dict(LEGIT),
    })
    cases.append({
        "id": "podidentity-sa-wildcard", "provider": "aws-pod-identity",
        "category": "subject-wildcard",
        "title": "EKS Pod Identity association serviceAccount='*'",
        "trust": {"namespace": "tenant-a", "service_account": "*"},
        "hardened_trust": _hardened_pod_identity(),
        "request": {**ATTACK, "namespace": "tenant-a", "service_account": "admin"},
        "legit_request": dict(LEGIT),
    })
    return cases


_CASES_CACHE: list[dict] | None = None


def cases() -> list[dict]:
    global _CASES_CACHE
    if _CASES_CACHE is None:
        _CASES_CACHE = _cases()
    return copy.deepcopy(_CASES_CACHE)


def _pattern_match(pattern: str, value: Any) -> bool:
    return fnmatch.fnmatchcase(str(value or ""), str(pattern))


def _principal_match(principal: Any, request: dict) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, str):
        return _pattern_match(principal, request.get("principal_arn"))
    if not isinstance(principal, dict):
        return False
    if "*" in (principal.get("AWS"), principal.get("Federated")):
        return True
    if principal.get("Federated"):
        fed = str(principal["Federated"])
        issuer = str(request.get("issuer") or "")
        provider = fed.split("oidc-provider/", 1)[-1]
        bare_issuer = issuer.replace("https://", "").replace("http://", "").rstrip("/")
        return (_pattern_match(fed, issuer) or _pattern_match(provider, bare_issuer)
                or _pattern_match(provider, issuer))
    if principal.get("AWS"):
        return _pattern_match(principal["AWS"], request.get("principal_arn")) \
            or _pattern_match(principal["AWS"], request.get("account"))
    return False


def _request_value(request: dict, key: str):
    mapping = {
        SUB: "sub", AUD: "aud", ISS: "issuer",
        "aws:SourceAccount": "source_account",
        "aws:SourceArn": "source_arn",
        "sts:ExternalId": "external_id",
        "aws:PrincipalArn": "principal_arn",
    }
    return request.get(mapping.get(key, key))


def _conditions_match(conditions: dict, request: dict, reasons: list[str]) -> bool:
    for op, entries in (conditions or {}).items():
        if not isinstance(entries, dict):
            continue
        for key, expected in entries.items():
            actual = _request_value(request, key)
            values = expected if isinstance(expected, list) else [expected]
            if op == "Null":
                wants_absent = str(expected).lower() == "true"
                present = actual not in (None, "")
                if present == wants_absent:
                    reasons.append(f"null-condition:{key}")
                    return False
                continue
            if op in ("ForAllValues:StringLike", "ForAllValues:StringEquals"):
                vals = actual if isinstance(actual, list) else ([actual] if actual else [])
                if not vals:
                    reasons.append(f"vacuous-{op}:{key}")
                    continue
                for value in vals:
                    if not any(_pattern_match(p, value) for p in values):
                        return False
                continue
            if op in ("ForAnyValue:StringLike", "StringLike"):
                vals = actual if isinstance(actual, list) else [actual]
                if not any(_pattern_match(p, value) for p in values for value in vals):
                    return False
                continue
            if op in ("StringEquals", "StringEqualsIgnoreCase"):
                vals = actual if isinstance(actual, list) else [actual]
                if op == "StringEqualsIgnoreCase":
                    if not any(str(p).lower() == str(value).lower()
                               for p in values for value in vals):
                        return False
                elif not any(str(p) == str(value) for p in values for value in vals):
                    return False
                continue
            # Unknown operators are ignored by this model, which mirrors a
            # trust document whose condition is not enforced by the caller.
            reasons.append(f"unknown-operator:{op}")
    return True


def _aws_eval(trust: dict, request: dict, reasons: list[str]) -> bool:
    for statement in trust.get("Statement") or []:
        if statement.get("Effect") != "Allow":
            continue
        actions = statement.get("Action")
        actions = actions if isinstance(actions, list) else [actions]
        if not any(str(a).endswith("AssumeRoleWithWebIdentity") or a == "*" for a in actions):
            continue
        if not _principal_match(statement.get("Principal"), request):
            reasons.append("principal-no-match")
            continue
        if _conditions_match(statement.get("Condition") or {}, request, reasons):
            return True
    return False


def _gcp_eval(trust: dict, request: dict, reasons: list[str]) -> bool:
    principal = trust.get("principalSet")
    if principal and not _pattern_match(principal, request.get("principal_set")):
        reasons.append("principal-set-no-match")
        return False
    condition = str(trust.get("attributeCondition") or "").strip()
    if not condition:
        reasons.append("missing-attribute-condition")
        return True
    # Supports the common assertion.sub == 'x' / assertion.repository_owner == 'x'.
    import re
    match = re.match(r"assertion\.(\w+)\s*==\s*['\"](.*)['\"]$", condition)
    if not match:
        reasons.append("unparsed-attribute-condition")
        return True
    field, expected = match.group(1), match.group(2)
    actual = request.get("sub") if field == "sub" else request.get(field)
    if expected == "*" or _pattern_match(expected, actual):
        if expected == "*":
            reasons.append("wildcard-attribute-condition")
        return True
    return False


def _azure_eval(trust: dict, request: dict, reasons: list[str]) -> bool:
    issuer = trust.get("issuer")
    if issuer and not _pattern_match(issuer, request.get("issuer")):
        reasons.append("issuer-no-match")
        return False
    subject = trust.get("subject")
    if subject and not _pattern_match(subject, request.get("sub")):
        reasons.append("subject-no-match")
        return False
    audiences = trust.get("audiences")
    if audiences and request.get("aud") not in audiences:
        reasons.append("audience-no-match")
        return False
    if "*" in str(subject or "") or "*" in str(issuer or ""):
        reasons.append("wildcard-trust-field")
    if not subject:
        reasons.append("missing-subject")
    if not audiences:
        reasons.append("missing-audience")
    return True


def _pod_identity_eval(trust: dict, request: dict, reasons: list[str]) -> bool:
    ns = trust.get("namespace")
    sa = trust.get("service_account")
    if ns and not _pattern_match(ns, request.get("namespace")):
        reasons.append("namespace-no-match")
        return False
    if sa and not _pattern_match(sa, request.get("service_account")):
        reasons.append("service-account-no-match")
        return False
    if "*" in str(ns or "") or "*" in str(sa or ""):
        reasons.append("wildcard-association")
    if not ns:
        reasons.append("missing-namespace")
    if not sa:
        reasons.append("missing-service-account")
    return True


def evaluate(case: dict, *, hardened: bool = False, request: dict | None = None) -> dict:
    trust = case["hardened_trust"] if hardened else case["trust"]
    req = dict(request or case["request"])
    reasons: list[str] = []
    provider = case["provider"]
    if provider in ("aws-irsa", "aws-rrssa"):
        allowed = _aws_eval(trust, req, reasons)
    elif provider == "gcp-wi":
        allowed = _gcp_eval(trust, req, reasons)
    elif provider == "azure-wi":
        allowed = _azure_eval(trust, req, reasons)
    elif provider == "aws-pod-identity":
        allowed = _pod_identity_eval(trust, req, reasons)
    else:
        allowed = False
        reasons.append("unknown-provider")
    return {
        "id": case["id"], "provider": provider, "category": case["category"],
        "allowed": bool(allowed), "reasons": reasons,
        "request": {k: req.get(k) for k in ("account", "issuer", "sub", "aud",
                                            "namespace", "service_account",
                                            "external_id", "source_account",
                                            "source_arn", "principal_set")},
        "result_sha256": hash_payload({"id": case["id"], "hardened": hardened,
                                       "allowed": allowed, "reasons": reasons}),
    }


def audit(cases_in: list[dict] | None = None) -> dict:
    rows = cases_in if cases_in is not None else cases()
    results = []
    findings = []
    allowed = 0
    hardened_allowed = 0
    for case in rows:
        vuln = evaluate(case, hardened=False)
        hard = evaluate(case, hardened=True)
        legit = evaluate(case, hardened=True, request=case["legit_request"])
        allowed += int(vuln["allowed"])
        hardened_allowed += int(hard["allowed"])
        results.append({"id": case["id"], "provider": case["provider"],
                        "category": case["category"], "title": case["title"],
                        "vulnerable": vuln, "hardened": hard, "legit": legit})
        if vuln["allowed"] and not hard["allowed"] and legit["allowed"]:
            findings.append(finding(
                "critical",
                f"身份联邦信任绕过（{case['provider']}/{case['category']}）：{case['title']}",
                {"case": case["id"], "provider": case["provider"],
                 "category": case["category"], "reasons": vuln["reasons"],
                 "request": vuln["request"], "legit_allowed": True},
                fix="Principal 精确到 role/provider；强制 sub/aud/iss、SourceAccount/SourceArn、ExternalId；"
                    "禁止 * 与空条件；Pod Identity namespace/serviceAccount 精确绑定。",
            ))
    return {
        "total": len(rows),
        "allowed": allowed,
        "hardened_allowed": hardened_allowed,
        "findings": len(findings),
        "results": results,
        "finding_items": findings,
        "results_sha256": hash_payload(results),
    }


def bypass_categories() -> set[str]:
    return {c["category"] for c in cases()}


def summary(report: dict) -> str:
    return summary_json("identity-federation-trust", [], extra={
        "total": report["total"], "allowed": report["allowed"],
        "hardened_allowed": report["hardened_allowed"],
    })


def load_cases(path) -> list[dict]:
    import json
    from pathlib import Path
    return json.loads(Path(path).read_text(encoding="utf-8"))["cases"]
