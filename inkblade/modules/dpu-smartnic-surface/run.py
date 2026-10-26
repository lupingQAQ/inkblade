# -*- coding: utf-8 -*-
"""BlueField/DPU 服务与凭据面（授权主动级，只读）。

GET：
- /dpu/health      健康/固件版本
- /dpu/services    服务清单（端口/协议/是否管理面/是否需要鉴权）
- /dpu/credentials 凭据面（仅 vulnerable mock 暴露；fixed 404）

判定：
- 管理服务 auth_required=false → high；
- 凭据面 200 且含 password/secret/token 字段 → high（finding 不回显密码值）；
- SSH 密码认证、rshim 暴露 → medium。

只读：不登录 SSH/gRPC/Redfish，不修改 DPU 服务。
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_hardware_common", _PARENT / "_hardware-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "dpu-smartnic-surface"
SECRET_FIELDS = ("password", "secret", "token", "private_key", "api_key")


def run(ctx: dict, params: dict) -> dict:
    target = str(params.get("target") or "").rstrip("/")
    if not target:
        return _C.no_target()
    t = _C.Trace(ctx, KEY)
    findings: list[dict] = []

    health = t.get(f"{target}/dpu/health")
    services_entry = t.get(f"{target}/dpu/services")
    credentials_entry = t.get(f"{target}/dpu/credentials")

    services_doc = _C.resp(services_entry)
    services = [s for s in services_doc.get("services") or [] if isinstance(s, dict)]
    unauth = [s for s in services if not bool(s.get("auth_required", True))]
    mgmt_unauth = [s for s in unauth if bool(s.get("management"))]
    ssh = next((s for s in services if str(s.get("name", "")).lower() == "ssh"), {})
    rshim = services_doc.get("rshim") or {}
    credentials_doc = _C.resp(credentials_entry)
    secret_fields = sorted(k for k in credentials_doc if str(k).lower() in SECRET_FIELDS)
    credentials_exposed = credentials_entry.get("status") == 200 and bool(secret_fields)
    ssh_password_auth = bool(ssh.get("password_auth"))
    rshim_exposed = bool(rshim.get("enabled"))

    if mgmt_unauth:
        findings.append(_C.finding(
            "high", "DPU 管理服务未鉴权暴露",
            {"detected": True,
             "services": [{"name": s.get("name"), "port": s.get("port"),
                           "protocol": s.get("protocol")} for s in mgmt_unauth]},
            evidence=f"unauth_management_services={[s.get('name') for s in mgmt_unauth]}",
            mapping="BlueField/DPU 管理面（Redfish/gRPC-DOCA/rshim）",
            fix="DPU 管理服务启用 mTLS/证书鉴权并限制到带外管理网；关闭未使用服务",
        ))
    if credentials_exposed:
        findings.append(_C.finding(
            "high", "DPU 工厂/默认凭据明文暴露",
            {"detected": True, "credentials_status": credentials_entry.get("status"),
             "credential_fields": secret_fields,
             "username": credentials_doc.get("username", ""),
             "source": credentials_doc.get("source", ""),
             "rotation_required": bool(credentials_doc.get("rotation_required"))},
            evidence=f"GET /dpu/credentials -> 200 fields={secret_fields}",
            mapping="DPU 工厂默认凭据/凭据面",
            fix="立即轮换 DPU 默认凭据，删除未鉴权凭据端点，纳入密钥管理",
        ))
    if ssh_password_auth:
        findings.append(_C.finding(
            "medium", "DPU SSH 密码认证启用",
            {"ssh_port": ssh.get("port"), "password_auth": True},
            evidence="services.ssh.password_auth=true",
            fix="DPU SSH 改为密钥/证书认证，限制来源并审计登录",
        ))
    if rshim_exposed:
        findings.append(_C.finding(
            "medium", "DPU rshim 暴露",
            {"rshim": rshim},
            evidence=f"services.rshim.enabled={rshim_exposed}",
            mapping="BlueField rshim 主机- DPU 通道",
            fix="生产默认关闭 rshim；调试时必须限制宿主 root 与物理/带外访问",
        ))

    extra = {
        "health_status": health.get("status"),
        "services_status": services_entry.get("status"),
        "services": len(services),
        "unauth_services": len(unauth),
        "management_unauth": len(mgmt_unauth),
        "credentials_status": credentials_entry.get("status"),
        "credentials_exposed": credentials_exposed,
        "credential_fields": secret_fields,
        "ssh_password_auth": ssh_password_auth,
        "rshim_exposed": rshim_exposed,
    }
    summary = _C.summary_json("DPU/BlueField 暴露面", findings, extra=extra, source=target)
    artifact = _C.write_artifact(ctx, f"{KEY}.json", {
        "summary": json.loads(summary), "services": services_doc, "findings": findings,
    })
    trace = t.dump()
    artifacts = ([str(trace)] if trace else []) + artifact
    return {"summary": summary, "artifacts": artifacts, "findings": findings}
