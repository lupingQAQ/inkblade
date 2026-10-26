"""云身份联邦 trust policy 通配 — IRSA/RRSA/WorkloadIdentity 注解 + 跨账户 AssumeRole。

检测面：
1) GET /cloud/identity?role=weight-reader 返回 trust policy Principal="*"、无 ExternalId、
   cross_account_allowed=true；
2) POST /cloud/identity/assume-role 以外部账户（999999999999）模拟 STS → 200 即跨账户角色假定成功。
凭据输出一律 MOCK 前缀脱敏（尾 4 位），全文仅存证据 trace。
fixed：仅同账户 Principal + sts:ExternalId（403）。
"""
from __future__ import annotations

import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[3]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from trident.modules._gpu_cloud_common import (  # noqa: E402
    Trace, base_url, detail, mask, ok, read_headers, resolve_mode, resp,
)

KEY = "cloud-irsa-trust-wildcard"
WRITES = False


def run(ctx: dict, params: dict) -> dict:
    base = base_url(params)
    mode, note = resolve_mode(params, WRITES)
    if not base:
        return {"summary": "no-target", "artifacts": [], "findings": []}
    role = str(params.get("role") or "weight-reader")
    source_account = str(params.get("source_account") or "999999999999")
    t = Trace(ctx, KEY)
    findings: list[dict] = []

    identity = t.call("GET", f"{base}/cloud/identity?role={role}", headers=read_headers(params))
    payload = resp(identity)
    wildcard = bool(payload.get("wildcard_principal"))
    if ok(identity) and wildcard:
        findings.append({
            "sev": "high",
            "title": "IRSA/RRSA trust policy 通配 Principal（跨账户可 AssumeRole）",
            "detail": detail({
                "route": "/cloud/identity",
                "http_status": identity.get("status"),
                "role": payload.get("role", ""),
                "role_arn": payload.get("role_arn", ""),
                "account": payload.get("account", ""),
                "wildcard_principal": True,
                "external_id_required": bool(payload.get("external_id_required")),
                "cross_account_allowed": bool(payload.get("cross_account_allowed")),
                "trust_policy": payload.get("trust_policy"),
                "annotations": payload.get("annotations"),
                "note": "trust policy Principal='*' 且无 ExternalId/Condition：任意云账户可假定额度桶读角色",
            }),
        })

    assume = t.call("POST", f"{base}/cloud/identity/assume-role", {
        "role": role,
        "source_account": source_account,
        "session_name": f"trident-{params.get('tenant') or 'tenant-a'}",
    })
    assumed = resp(assume)
    if ok(assume) and assumed.get("assumed"):
        creds = assumed.get("credentials") or {}
        findings.append({
            "sev": "high",
            "title": "通配 trust policy 跨账户 AssumeRole 成功（权重桶读角色被外部账户假定）",
            "detail": detail({
                "route": "/cloud/identity/assume-role",
                "assume_role_status": assume.get("status"),
                "assumed": True,
                "role": assumed.get("role", ""),
                "role_arn": assumed.get("role_arn", ""),
                "source_account": assumed.get("source_account", source_account),
                "cross_account": bool(assumed.get("cross_account")),
                "trust_policy_wildcard": wildcard,
                "session_name": assumed.get("session_name", ""),
                "credentials": {
                    "AccessKeyId": mask(creds.get("AccessKeyId")),
                    "SecretAccessKey": mask(creds.get("SecretAccessKey")),
                    "SessionToken": mask(creds.get("SessionToken")),
                },
                "note": "跨账户角色假定成功：后续可直接读取 victim 账户权重桶/快照/KMS",
            }),
        })

    artifact = t.dump()
    summary = (f"identity={identity.get('status')} assume_role={assume.get('status')} "
               f"wildcard={str(wildcard).lower()} findings={len(findings)} mode={mode}")
    if note:
        summary += f"；{note}"
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
