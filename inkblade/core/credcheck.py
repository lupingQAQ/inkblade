# -*- coding: utf-8 -*-
"""泄露凭据有效性验证面（CM-21）：fixture 驱动的凭据→租户内有效性判定。

输入：
- credentials: [{id, kind, tenant, expected_tenant, secret_ref, scope}]
- probes: [{credential_id, ok, tenant, permissions:[...], error}]

输出：
- 每个凭据 valid / tenant_match / cross_tenant / permissions / risk；
- findings：跨租户可用（critical）、有效且具写权限（high）、无效/未探测（info）；
- ``probe_plan``：给出在授权租户内应执行的只读校验清单（不包含 secret 值），
  由人工/采集器执行后回填 probes。

本模块不做网络请求、不读取真实云 API：live 有效性验证必须在授权租户内由独立采集器完成。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

WRITE_WORDS = ("write", "delete", "create", "put", "post", "admin", "*", "manage",
               "assume", "sts:assumerole", "iam:passrole")


class CredCheckError(ValueError):
    """fixture 非法。"""


def _risk(valid: bool, cross: bool, perms: list[str]) -> str:
    if cross:
        return "critical"
    write = any(any(w in str(p).lower() for w in WRITE_WORDS) for p in perms)
    if valid and write:
        return "high"
    if valid:
        return "medium"
    return "info"


def validate(fixture: dict) -> dict:
    if not isinstance(fixture, dict):
        raise CredCheckError("fixture 必须是对象")
    creds = fixture.get("credentials") or []
    probes = {p.get("credential_id"): p for p in fixture.get("probes") or []}
    if not isinstance(creds, list) or not creds:
        raise CredCheckError("credentials 不能为空")
    rows, findings = [], []
    for c in creds:
        cid = c.get("id")
        if not cid:
            raise CredCheckError("credential.id 必填")
        p = probes.get(cid) or {}
        valid = bool(p.get("ok"))
        expected = str(c.get("expected_tenant") or c.get("tenant") or "")
        actual = str(p.get("tenant") or "")
        cross = bool(valid and expected and actual and actual != expected)
        perms = [str(x) for x in (p.get("permissions") or [])]
        risk = _risk(valid, cross, perms)
        row = {"id": cid, "kind": c.get("kind", ""), "expected_tenant": expected,
               "actual_tenant": actual, "valid": valid, "tenant_match": (expected == actual),
               "cross_tenant": cross, "permissions": perms, "risk": risk,
               "probed": bool(p), "error": p.get("error", "")}
        rows.append(row)
        if cross:
            findings.append({"sev": "critical", "credential": cid,
                             "title": f"凭据跨租户有效：{cid}",
                             "detail": f"期望租户 {expected}，实际 {actual}；权限 {len(perms)} 项"})
        elif valid and risk == "high":
            findings.append({"sev": "high", "credential": cid,
                             "title": f"有效凭据具备写权限：{cid}",
                             "detail": "权限：" + ", ".join(perms[:10])})
        elif not p:
            findings.append({"sev": "info", "credential": cid,
                             "title": f"凭据未探测：{cid}",
                             "detail": "未提供 probe 结果；live 校验须在授权租户内执行"})
    return {"credentials": len(creds), "probed": sum(1 for r in rows if r["probed"]),
            "rows": rows, "findings": findings,
            "summary": {"valid": sum(1 for r in rows if r["valid"]),
                        "cross_tenant": sum(1 for r in rows if r["cross_tenant"]),
                        "high_risk": sum(1 for r in rows if r["risk"] == "high"),
                        "unprobed": sum(1 for r in rows if not r["probed"])}}


def probe_plan(fixture: dict) -> dict:
    """只读校验计划（不含 secret）；由授权采集器执行后回填 probes。"""
    if not isinstance(fixture, dict):
        raise CredCheckError("fixture 必须是对象")
    plan = []
    for c in fixture.get("credentials") or []:
        plan.append({"credential_id": c.get("id"), "kind": c.get("kind", ""),
                     "tenant": c.get("expected_tenant") or c.get("tenant", ""),
                     "checks": ["sts:GetCallerIdentity", "list-readable-scope",
                                "write-deny-probe"],
                     "secret_ref": c.get("secret_ref", ""),
                     "network": False})
    return {"plan": plan, "count": len(plan), "network": False,
            "note": "probe_plan 仅描述校验动作；live 执行须在授权租户内由人工/采集器完成"}


def validate_file(path: Path | str) -> dict:
    p = Path(path)
    if not p.is_file():
        raise CredCheckError(f"fixture 不存在：{p}")
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise CredCheckError(f"fixture JSON 非法：{exc}") from exc
    return validate(doc)


def render_md(result: dict) -> str:
    lines = ["# 凭据有效性验证", "",
             f"- 凭据 {result.get('credentials', 0)}；已探测 {result.get('probed', 0)}；"
             f"跨租户 {result.get('summary', {}).get('cross_tenant', 0)}", "",
             "| ID | 类型 | 有效 | 期望租户 | 实际租户 | 风险 |", "|---|---|---|---|---|---|"]
    for r in result.get("rows", []):
        lines.append(f"| {r['id']} | {r['kind']} | {r['valid']} | {r['expected_tenant']} "
                     f"| {r['actual_tenant']} | {r['risk']} |")
    return "\n".join(lines) + "\n"
