# -*- coding: utf-8 -*-
"""SONiC / Cumulus 配置导出只读解析（不登录设备）。

输入：params.config = JSON 导出路径或 dict；也接受 params.snapshot。
支持两类形状：
- SONiC config_db：PFC_WATCHDOG / WRED_PROFILE / ACL_RULE / MGMT_INTERFACE / SNMP /
  NTP_SERVER / AAA；
- Cumulus/NVUE：interfaces[*].pfc/ecn、acl.mgmt.rules、snmp、ntp.servers、aaa。

判定：
- PFC watchdog 未启用（false）→ high；ECN/WRED 未启用 → medium；
- 管理 ACL 放行任意来源 → high；缺失 → medium；
- SNMP public/private → medium；缺少远程 AAA → medium；无 NTP → low。

只读：只解析客户提供的配置，不 SSH/NETCONF/gNMI 登录设备，不下发任何配置。
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_hardware_common", _PARENT / "_hardware-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "switch-os-config-surface"
OPEN_SOURCES = ("0.0.0.0/0", "any", "*", "")


def _cfg(params: dict) -> tuple[dict, str]:
    value = params.get("config")
    if value is None:
        value = params.get("snapshot")
    if value is None:
        raise ValueError("缺少 params.config（SONiC/Cumulus JSON 导出）")
    source = value if isinstance(value, str) else "<inline fixture>"
    return _C.load_json_ref(value), source


def _sonic_acl(rules: dict) -> str:
    if not isinstance(rules, dict) or not rules:
        return "missing"
    has_deny = False
    for key, rule in rules.items():
        if not isinstance(rule, dict):
            continue
        label = f"{key} {rule.get('TABLE', '')}".upper()
        if "MGMT" not in label and "MANAGEMENT" not in label:
            continue
        action = str(rule.get("PACKET_ACTION") or rule.get("action") or "").upper()
        src = str(rule.get("SRC_IP") or rule.get("src") or "").strip().lower()
        if action in ("ACCEPT", "PERMIT", "ALLOW") and src in OPEN_SOURCES:
            return "open"
        if action in ("DROP", "DENY", "REJECT"):
            has_deny = True
    return "deny" if has_deny else "missing"


def _cumulus_acl(rules: list) -> str:
    if not rules:
        return "missing"
    has_deny = False
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        action = str(rule.get("action") or rule.get("ACTION") or "").upper()
        src = str(rule.get("src") or rule.get("source") or "").strip().lower()
        if action in ("PERMIT", "ACCEPT", "ALLOW") and src in OPEN_SOURCES:
            return "open"
        if action in ("DENY", "DROP", "REJECT"):
            has_deny = True
    return "deny" if has_deny else "missing"


def _snmp_public(doc) -> bool:
    if isinstance(doc, dict):
        for key, value in doc.items():
            if str(key).lower() in ("public", "private"):
                return True
            if isinstance(value, str) and value.lower() in ("public", "private"):
                return True
            if _snmp_public(value):
                return True
    elif isinstance(doc, list):
        return any(_snmp_public(item) for item in doc)
    return False


def _sonic_facts(cfg: dict) -> dict:
    metadata = (cfg.get("DEVICE_METADATA") or {}).get("localhost") or {}
    pfc = cfg.get("PFC_WATCHDOG") or {}
    pfc_modes = [str(v.get("mode", "")).lower() for v in pfc.values() if isinstance(v, dict)]
    pfc_watchdog = any(_C.is_truthy(mode) for mode in pfc_modes) if pfc_modes else None

    wred = cfg.get("WRED_PROFILE") or {}
    ecn_enabled = None
    if wred:
        ecn_enabled = any(
            _C.is_truthy(v.get("wred_enabled"))
            and str(v.get("ecn", "")).lower() not in ("", "none", "disable", "disabled")
            for v in wred.values() if isinstance(v, dict)
        )

    snmp = cfg.get("SNMP") or {}
    aaa = cfg.get("AAA") or {}
    aaa_remote = bool(
        any(("TACACS" in str(k).upper() or "RADIUS" in str(k).upper()) and bool(v)
            for k, v in aaa.items())
    ) or bool(cfg.get("TACPLUS")) or bool(cfg.get("RADIUS"))
    ntp = cfg.get("NTP_SERVER")
    if ntp is None:
        ntp = (cfg.get("NTP") or {}).get("servers")
    ntp_servers = len(ntp) if isinstance(ntp, (dict, list)) else 0
    return {
        "format": "sonic",
        "hostname": str(metadata.get("hostname") or ""),
        "pfc_watchdog": pfc_watchdog,
        "ecn_enabled": ecn_enabled,
        "mgmt_acl": _sonic_acl(cfg.get("ACL_RULE") or {}),
        "snmp_public": _snmp_public(snmp),
        "snmp_v3": "SNMP_V3" in snmp or str(snmp.get("version", "")).lower() in ("3", "v3"),
        "ntp_servers": ntp_servers,
        "aaa_remote": aaa_remote,
    }


def _cumulus_facts(cfg: dict) -> dict:
    interfaces = cfg.get("interfaces") or {}
    pfc_entries = [v.get("pfc") for v in interfaces.values()
                   if isinstance(v, dict) and isinstance(v.get("pfc"), dict)]
    ecn_entries = [v.get("ecn") for v in interfaces.values()
                   if isinstance(v, dict) and isinstance(v.get("ecn"), dict)]
    pfc_watchdog = (all(_C.is_truthy(p.get("watchdog")) for p in pfc_entries)
                    if pfc_entries else None)
    ecn_enabled = (all(_C.is_truthy(e.get("enabled")) for e in ecn_entries)
                   if ecn_entries else None)
    acl = cfg.get("acl") or {}
    aaa = cfg.get("aaa") or {}
    aaa_remote = any(
        (isinstance(v, list) and bool(v)) or (isinstance(v, dict) and bool(v))
        for v in aaa.values()
    )
    snmp = cfg.get("snmp") or {}
    return {
        "format": "cumulus",
        "hostname": str((cfg.get("system") or {}).get("hostname") or ""),
        "pfc_watchdog": pfc_watchdog,
        "ecn_enabled": ecn_enabled,
        "mgmt_acl": _cumulus_acl(((acl.get("mgmt") or {}).get("rules") or [])),
        "snmp_public": _snmp_public(snmp),
        "snmp_v3": str(snmp.get("version", "")).lower() in ("3", "v3"),
        "ntp_servers": len(((cfg.get("ntp") or {}).get("servers") or [])),
        "aaa_remote": aaa_remote,
    }


def _facts(cfg: dict) -> dict:
    if "DEVICE_METADATA" in cfg or "PFC_WATCHDOG" in cfg or "ACL_RULE" in cfg:
        return _sonic_facts(cfg)
    if "interfaces" in cfg or "acl" in cfg:
        return _cumulus_facts(cfg)
    raise ValueError("无法识别配置格式（需要 SONiC config_db 或 Cumulus/NVUE 导出）")


def run(ctx: dict, params: dict) -> dict:
    cfg, source = _cfg(params)
    facts = _facts(cfg)
    findings: list[dict] = []
    if facts["pfc_watchdog"] is False:
        findings.append(_C.finding(
            "high", "PFC watchdog 未启用",
            {"detected": True, "format": facts["format"]},
            evidence="PFC watchdog disabled (no automatic storm protection)",
            mapping="RoCE PFC 风暴保护（交换机 OS 配置面）",
            fix="启用 PFC watchdog 的 detect/recover 档并演练 pause storm 告警",
        ))
    if facts["ecn_enabled"] is False:
        findings.append(_C.finding(
            "medium", "ECN/WRED 未在无损队列启用",
            {"detected": True, "format": facts["format"]},
            evidence="WRED/ECN disabled on lossless profile",
            fix="在无损队列启用 ECN/WRED 并核对阈值与 PFC 协同",
        ))
    if facts["mgmt_acl"] == "open":
        findings.append(_C.finding(
            "high", "管理面 ACL 允许任意来源",
            {"detected": True, "mgmt_acl": "open", "format": facts["format"]},
            evidence="management ACL permits 0.0.0.0/0",
            mapping="交换机管理面 ACL",
            fix="管理面 ACL 仅放行带外管理网/堡垒机；默认拒绝",
        ))
    elif facts["mgmt_acl"] == "missing":
        findings.append(_C.finding(
            "medium", "管理面 ACL 缺失",
            {"detected": True, "mgmt_acl": "missing", "format": facts["format"]},
            fix="为管理 VRF/接口增加显式 deny-all + 白名单 ACL",
        ))
    if facts["snmp_public"]:
        findings.append(_C.finding(
            "medium", "SNMP 弱团体名",
            {"detected": True, "format": facts["format"]},
            evidence="SNMP community public/private present",
            fix="禁用 SNMP v1/v2c；使用 SNMPv3 authPriv + 最小视图 + ACL",
        ))
    if facts["aaa_remote"] is False:
        findings.append(_C.finding(
            "medium", "缺少远程 AAA",
            {"detected": True, "format": facts["format"]},
            fix="接入 TACACS+/RADIUS，禁用本地共享账号并审计命令",
        ))
    if facts["ntp_servers"] == 0:
        findings.append(_C.finding(
            "low", "未配置 NTP 服务器",
            {"detected": True, "format": facts["format"]},
            fix="配置受控 NTP，保证日志/审计时间线可关联",
        ))

    extra = dict(facts)
    extra["ntp_servers"] = facts["ntp_servers"]
    summary = _C.summary_json("交换机 OS 配置面", findings, extra=extra, source=source)
    artifact = _C.write_artifact(ctx, f"{KEY}.json", {
        "summary": json.loads(summary), "facts": facts, "findings": findings,
    })
    return {"summary": summary, "artifacts": artifact, "findings": findings}
