# -*- coding: utf-8 -*-
"""BMC/IPMI 暴露面 — Redfish 只读指纹 + 单次厂商默认凭据验证（授权主动级）。

GET 路由（不写）：
- /redfish/v1/                              服务根/版本
- /redfish/v1/Managers/BMC                  管理详情（匿名可读？）
- /redfish/v1/Managers/BMC/NetworkProtocol  IPMI over LAN / SSH / SNMP
- /redfish/v1/Managers/BMC/Accounts         账号与 DefaultCredential 标记
- /redfish/v1/Systems/1                     Basic 认证（默认凭据是否可登录）

默认凭据仅尝试 root/calvin 与 admin/admin（最多 2 次、命中即停），不爆破、不改密。
finding 不输出密码；凭据值只留在 trace 的 Basic 头中（报告/证据按需脱敏）。
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_hardware_common", _PARENT / "_hardware-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "bmc-ipmi-exposure"
DEFAULT_CREDENTIALS = (("root", "calvin"), ("admin", "admin"))


def run(ctx: dict, params: dict) -> dict:
    target = str(params.get("target") or "").rstrip("/")
    if not target:
        return _C.no_target()
    t = _C.Trace(ctx, KEY)
    findings: list[dict] = []

    root = t.get(f"{target}/redfish/v1/")
    manager = t.get(f"{target}/redfish/v1/Managers/BMC")
    protocol = t.get(f"{target}/redfish/v1/Managers/BMC/NetworkProtocol")
    accounts = t.get(f"{target}/redfish/v1/Managers/BMC/Accounts")

    protocol_doc = _C.resp(protocol)
    ipmi = protocol_doc.get("IPMI") or {}
    ssh = protocol_doc.get("SSH") or {}
    accounts_doc = _C.resp(accounts)
    members = accounts_doc.get("Members") or []
    default_accounts = [a for a in members if isinstance(a, dict) and a.get("DefaultCredential")]

    login_status = 0
    login_user = ""
    check_defaults = params.get("check_default_credentials", True)
    if check_defaults:
        for user, password in DEFAULT_CREDENTIALS:
            entry = t.get(f"{target}/redfish/v1/Systems/1", _C.basic_auth(user, password))
            if entry.get("status") == 200:
                login_status, login_user = 200, user
                break

    anonymous_manager_read = manager.get("status") == 200
    accounts_exposed = accounts.get("status") == 200
    ipmi_over_lan = bool(ipmi.get("ProtocolEnabled"))
    ssh_password_auth = bool(ssh.get("PasswordAuthentication"))
    detail = {
        "target": target,
        "service_root_status": root.get("status"),
        "redfish_version": _C.resp(root).get("RedfishVersion", ""),
        "vendor": _C.resp(root).get("Vendor", ""),
        "manager_status": manager.get("status"),
        "network_protocol_status": protocol.get("status"),
        "accounts_status": accounts.get("status"),
        "anonymous_manager_read": anonymous_manager_read,
        "accounts_exposed": accounts_exposed,
        "default_account_count": len(default_accounts),
        "default_login_status": login_status,
        "default_username": login_user,
        "credential_class": "vendor-default" if login_user else "",
        "ipmi_over_lan": ipmi_over_lan,
        "ipmi_port": _C.int_of(ipmi.get("Port")),
        "ssh_enabled": bool(ssh.get("ProtocolEnabled")),
        "ssh_password_auth": ssh_password_auth,
        "detected": bool(login_status == 200 or default_accounts or ipmi_over_lan),
    }

    if login_status == 200:
        findings.append(_C.finding(
            "high", "BMC 默认凭据可登录 Redfish",
            detail,
            evidence=f"GET /redfish/v1/Systems/1 -> 200 user={login_user}",
            mapping="BMC/Redfish 默认凭据面（带外管理面失陷 = 绕过 K8s）",
            fix="立即改密/禁用默认账号，限制 Redfish/IPMI 到带外管理网，启用 MFA/审计",
        ))
    if anonymous_manager_read:
        findings.append(_C.finding(
            "medium", "BMC 管理详情匿名可读",
            {"manager_status": manager.get("status"), "vendor": detail["vendor"],
             "firmware": _C.resp(manager).get("FirmwareVersion", "")},
            evidence="GET /redfish/v1/Managers/BMC -> 200 without auth",
            fix="Redfish 管理详情要求认证；仅暴露服务根与健康检查",
        ))
    if ipmi_over_lan:
        findings.append(_C.finding(
            "medium", "IPMI over LAN 启用",
            {"ipmi_over_lan": True, "ipmi_port": detail["ipmi_port"]},
            evidence=f"NetworkProtocol.IPMI.ProtocolEnabled=true port={detail['ipmi_port']}",
            mapping="IPMI/RMCP+ 带外管理面",
            fix="关闭未使用的 IPMI over LAN；必须使用时限制管理网 + 强口令 + 审计",
        ))
    if ssh_password_auth:
        findings.append(_C.finding(
            "medium", "BMC SSH 密码认证启用",
            {"ssh_enabled": detail["ssh_enabled"], "ssh_password_auth": True},
            evidence="NetworkProtocol.SSH.PasswordAuthentication=true",
            fix="BMC SSH 改为密钥/证书认证，关闭密码登录并限制来源",
        ))
    if default_accounts and login_status != 200:
        findings.append(_C.finding(
            "medium", "BMC 默认凭据账号仍启用",
            {"default_account_count": len(default_accounts),
             "usernames": [a.get("UserName") for a in default_accounts]},
            evidence=f"Accounts.DefaultCredential count={len(default_accounts)}",
            fix="禁用/改密默认账号并核对账号锁定与审计策略",
        ))

    extra = {
        "service_root_status": detail["service_root_status"],
        "manager_status": detail["manager_status"],
        "network_protocol_status": detail["network_protocol_status"],
        "accounts_status": detail["accounts_status"],
        "default_login_status": login_status,
        "default_username": login_user,
        "credential_class": detail["credential_class"],
        "default_account_count": len(default_accounts),
        "ipmi_over_lan": ipmi_over_lan,
        "ipmi_port": detail["ipmi_port"],
        "ssh_password_auth": ssh_password_auth,
        "anonymous_manager_read": anonymous_manager_read,
        "detected": detail["detected"],
    }
    summary = _C.summary_json("BMC/IPMI 暴露面", findings, extra=extra, source=target)
    artifact = _C.write_artifact(ctx, f"{KEY}.json", {
        "summary": json.loads(summary), "detail": detail, "findings": findings,
    })
    trace = t.dump()
    artifacts = ([str(trace)] if trace else []) + artifact
    return {"summary": summary, "artifacts": artifacts, "findings": findings}
