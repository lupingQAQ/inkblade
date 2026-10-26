"""aigateway-log-pii-leak — 网关请求日志明文 prompt/PII/Authorization。

Ruling：finding 只记录命中模式计数与租户集合，绝不复述原始 PII 或完整凭据。
"""
from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_aigateway_common", _PARENT / "_aigateway-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

KEY = "aigateway-log-pii-leak"
WRITES = False
Trace, finding = _COMMON.Trace, _COMMON.finding
bearer, tenant_key, target = _COMMON.bearer, _COMMON.tenant_key, _COMMON.target
ok, resp, status = _COMMON.ok, _COMMON.resp, _COMMON.status

EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
PHONE_RE = re.compile(r"\+?\d{1,3}[- ]\d{3}[- ]\d{4}\b")
CARD_RE = re.compile(r"\b(?:\d[ -]?){13,16}\b")


def run(ctx: dict, params: dict) -> dict:
    base = target(params)
    if not base:
        return {"summary": "no-target", "artifacts": [], "findings": []}
    tenant = str(params.get("tenant") or "tenant-a")
    t = Trace(ctx, KEY)
    logs = t.call("GET", f"{base}/logs",
                  headers={**bearer(tenant_key(params)), "X-Tenant": tenant})
    payload = resp(logs)
    entries = payload.get("entries") or []
    text = json.dumps(entries, ensure_ascii=False)
    email_count = len(EMAIL_RE.findall(text))
    phone_count = len(PHONE_RE.findall(text))
    card_count = len(CARD_RE.findall(text))
    auth_plaintext = sum(
        1 for entry in entries
        if str((entry or {}).get("authorization") or "").startswith("Bearer MOCK-")
    )
    redaction_markers = text.count("<email>") + text.count("<phone>") + text.count("<card>")
    tenants = sorted({str((entry or {}).get("tenant")) for entry in entries})

    findings: list[dict] = []
    if ok(logs) and (email_count or phone_count or card_count or auth_plaintext):
        detail = {
            "route": "/logs",
            "http_status": status(logs),
            "entry_count": len(entries),
            "tenants_visible": tenants,
            "email_count": email_count,
            "phone_count": phone_count,
            "card_count": card_count,
            "authorization_plaintext": auth_plaintext,
            "redaction_markers": redaction_markers,
            "tenant_scoped": payload.get("tenant_scoped"),
            "redacted": payload.get("redacted"),
            "note": "网关日志保留明文 prompt 与鉴权头：PII/凭据二次泄露；finding 仅记录计数不回显原文",
        }
        findings.append(finding(
            "high", f"AI 网关日志 PII 泄露：{len(tenants)} 租户明文 prompt（邮箱 {email_count} / 卡号 {card_count}）",
            detail))

    artifact = t.dump()
    summary = (f"status={status(logs)} entries={len(entries)} tenants={len(tenants)} "
               f"email={email_count} card={card_count} auth_plain={auth_plaintext}")
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
