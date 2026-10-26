# -*- coding: utf-8 -*-
"""SONiC / InfiniBand / SHARP fabric configuration depth audit.

28 checks over PFC/ECN/buffer/ACL/telemetry/AAA on SONiC, SM/partition/QoS on
IB, and session trust/reduction-tree isolation on SHARP.  The bridge to
``lab.fabric_sim`` maps the audit findings to the simulator scenario that
reproduces the same failure mode (PFC pause storm / ECN congestion).
"""

from __future__ import annotations

import copy
from typing import Any, Callable

from .common import finding, hash_payload, summary_json

KEY = "sonic-fabric-config"

DOMAINS = ("sonic", "ib", "sharp")


def _get(doc: dict, dotted: str, default=None):
    cur: Any = doc
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return default
        cur = cur.get(part, default)
    return cur


def _partitions(doc: dict) -> list[dict]:
    return [p for p in _get(doc, "ib.partitions", []) or [] if isinstance(p, dict)]


def _vulnerable_fixture() -> dict:
    return {
        "sonic": {
            "pfc_watchdog": "disabled", "pfc_storm_threshold": 100,
            "ecn_wred": "disabled", "buffer_pool_oversubscription": 3.5,
            "acl_any_any": True, "telemetry_gnmi_tls": False,
            "telemetry_gnmi_auth": False, "snmp_v2c_public": True,
            "ssh_root_login": True, "aaa_local_only": True,
            "rsyslog_welf_injection": True, "ztp_enabled": True,
            "image_signature_verified": False, "mgmt_vrf_isolated": False,
            "pfc_pause_frames": 120000, "ecn_marks": 0,
        },
        "ib": {
            "sm": {"primary": "sm-1", "secondary": None, "host": "gpu-01",
                   "routing_engine": "minhop"},
            "partitions": [
                {"pkey": "0x7fff", "name": "default", "default": True,
                 "members": ["*"], "ipoib": True, "tenants": ["tenant-a", "tenant-b"]},
                {"pkey": "0x8001", "name": "train-a", "default": False,
                 "members": ["gpu-01", "gpu-02"], "ipoib": False,
                 "tenants": ["tenant-a", "tenant-b"]},
            ],
            "nodes": [
                {"guid": "gpu-01", "type": "HCA", "host": "gpu-01", "tenant": "tenant-a"},
                {"guid": "gpu-02", "type": "HCA", "host": "gpu-02", "tenant": "tenant-b"},
            ],
            "qos": {"vl_arbitration": "default", "adaptive_routing": False},
            "sharp_enabled": True, "sharp_partition_isolated": False,
            "rail_binding": "cross",
        },
        "sharp": {
            "session_auth": False, "shared_sessions": True, "reduce_acl": False,
            "tree_members": ["gpu-01", "gpu-02", "gpu-99"],
            "job_members": ["gpu-01", "gpu-02"],
            "telemetry_exposes_session": True, "version_mismatch": True,
        },
    }


def _hardened_fixture() -> dict:
    return {
        "sonic": {
            "pfc_watchdog": "detect", "pfc_storm_threshold": 10000,
            "ecn_wred": "enabled", "buffer_pool_oversubscription": 1.2,
            "acl_any_any": False, "telemetry_gnmi_tls": True,
            "telemetry_gnmi_auth": True, "snmp_v2c_public": False,
            "ssh_root_login": False, "aaa_local_only": False,
            "rsyslog_welf_injection": False, "ztp_enabled": False,
            "image_signature_verified": True, "mgmt_vrf_isolated": True,
            "pfc_pause_frames": 0, "ecn_marks": 42,
        },
        "ib": {
            "sm": {"primary": "sm-1", "secondary": "sm-2", "host": "oob-sm-1",
                   "routing_engine": "adaptive"},
            "partitions": [
                {"pkey": "0x7fff", "name": "default", "default": True,
                 "members": ["sm-1"], "ipoib": False, "tenants": ["platform"]},
                {"pkey": "0x8001", "name": "train-a", "default": False,
                 "members": ["gpu-01", "gpu-02"], "ipoib": False,
                 "tenants": ["tenant-a"]},
            ],
            "nodes": [
                {"guid": "gpu-01", "type": "HCA", "host": "gpu-01", "tenant": "tenant-a"},
                {"guid": "gpu-02", "type": "HCA", "host": "gpu-02", "tenant": "tenant-a"},
            ],
            "qos": {"vl_arbitration": "strict", "adaptive_routing": True},
            "sharp_enabled": True, "sharp_partition_isolated": True,
            "rail_binding": "rail",
        },
        "sharp": {
            "session_auth": True, "shared_sessions": False, "reduce_acl": True,
            "tree_members": ["gpu-01", "gpu-02"], "job_members": ["gpu-01", "gpu-02"],
            "telemetry_exposes_session": False, "version_mismatch": False,
        },
    }


def fixture(state: str = "vulnerable") -> dict:
    return _vulnerable_fixture() if state == "vulnerable" else _hardened_fixture()


Check = tuple[str, str, str, str, Callable[[dict], bool]]


def _checks() -> list[Check]:
    return [
        # SONiC 14
        ("sonic-pfc-watchdog", "sonic", "high", "PFC watchdog 关闭",
         lambda d: str(_get(d, "sonic.pfc_watchdog")) != "detect"),
        ("sonic-pfc-threshold", "sonic", "high", "PFC storm 阈值过低",
         lambda d: int(_get(d, "sonic.pfc_storm_threshold", 0)) < 1000),
        ("sonic-ecn-wred", "sonic", "high", "ECN/WRED 未启用",
         lambda d: str(_get(d, "sonic.ecn_wred")) != "enabled"),
        ("sonic-buffer-pool", "sonic", "medium", "buffer pool 超额订阅 >2x",
         lambda d: float(_get(d, "sonic.buffer_pool_oversubscription", 0)) > 2.0),
        ("sonic-acl-any-any", "sonic", "high", "ACL 存在 any-any permit",
         lambda d: bool(_get(d, "sonic.acl_any_any"))),
        ("sonic-telemetry-tls", "sonic", "high", "gNMI telemetry 未启用 TLS",
         lambda d: not bool(_get(d, "sonic.telemetry_gnmi_tls"))),
        ("sonic-telemetry-auth", "sonic", "high", "gNMI telemetry 未鉴权",
         lambda d: not bool(_get(d, "sonic.telemetry_gnmi_auth"))),
        ("sonic-snmp-v2c", "sonic", "medium", "SNMP v2c public 团体字",
         lambda d: bool(_get(d, "sonic.snmp_v2c_public"))),
        ("sonic-ssh-root", "sonic", "medium", "SSH 允许 root 登录",
         lambda d: bool(_get(d, "sonic.ssh_root_login"))),
        ("sonic-aaa-local", "sonic", "medium", "AAA 仅本地账号",
         lambda d: bool(_get(d, "sonic.aaa_local_only"))),
        ("sonic-rsyslog-injection", "sonic", "high", "rsyslog welf 名称可注入",
         lambda d: bool(_get(d, "sonic.rsyslog_welf_injection"))),
        ("sonic-ztp", "sonic", "medium", "ZTP 未关闭（可被 DHCP 选项劫持）",
         lambda d: bool(_get(d, "sonic.ztp_enabled"))),
        ("sonic-image-signature", "sonic", "high", "SONiC 镜像未验签",
         lambda d: not bool(_get(d, "sonic.image_signature_verified"))),
        ("sonic-mgmt-vrf", "sonic", "medium", "管理面未隔离 VRF",
         lambda d: not bool(_get(d, "sonic.mgmt_vrf_isolated"))),
        # IB 8
        ("ib-sm-redundancy", "ib", "high", "IB SM 无主备冗余",
         lambda d: not bool(_get(d, "ib.sm.secondary"))),
        ("ib-default-wildcard", "ib", "high", "默认分区 0x7fff 成员为 *",
         lambda d: any(bool(p.get("default")) and ("*" in (p.get("members") or []))
                       for p in _partitions(d))),
        ("ib-cross-tenant", "ib", "high", "IB Partition 跨租户",
         lambda d: any(len(set(p.get("tenants") or [])) > 1 for p in _partitions(d))),
        ("ib-ipoib-default", "ib", "medium", "默认/跨租户分区启用 IPoIB",
         lambda d: any(bool(p.get("ipoib")) and (bool(p.get("default"))
                                                 or len(set(p.get("tenants") or [])) > 1)
                       for p in _partitions(d))),
        ("ib-sm-on-compute", "ib", "medium", "SM 运行在计算节点",
         lambda d: str(_get(d, "ib.sm.host")) in {
             str(n.get("host")) for n in _get(d, "ib.nodes", []) or []
             if str(n.get("type", "")).upper() == "HCA"}),
        ("ib-routing-minhop", "ib", "medium", "路由引擎仅 minhop，无自适应",
         lambda d: str(_get(d, "ib.sm.routing_engine")) == "minhop"
         or not bool(_get(d, "ib.qos.adaptive_routing"))),
        ("ib-qos-default", "ib", "medium", "VL arbitration 使用 default",
         lambda d: str(_get(d, "ib.qos.vl_arbitration")) == "default"),
        ("ib-sharp-partition", "ib", "high", "SHARP 开启但未按 Partition 隔离",
         lambda d: bool(_get(d, "ib.sharp_enabled"))
         and not bool(_get(d, "ib.sharp_partition_isolated"))),
        # SHARP 6
        ("sharp-session-auth", "sharp", "critical", "SHARP 会话建立无鉴权",
         lambda d: not bool(_get(d, "sharp.session_auth"))),
        ("sharp-shared-session", "sharp", "high", "SHARP 会话跨租户复用",
         lambda d: bool(_get(d, "sharp.shared_sessions"))),
        ("sharp-reduce-acl", "sharp", "critical", "SHARP reduce 无成员 ACL",
         lambda d: not bool(_get(d, "sharp.reduce_acl"))),
        ("sharp-tree-outside-job", "sharp", "critical", "聚合树包含非作业成员",
         lambda d: bool(set(_get(d, "sharp.tree_members", []) or [])
                        - set(_get(d, "sharp.job_members", []) or []))),
        ("sharp-telemetry-session", "sharp", "medium", "遥测暴露 SHARP 会话标识",
         lambda d: bool(_get(d, "sharp.telemetry_exposes_session"))),
        ("sharp-version-mismatch", "sharp", "high", "SHARP 版本不一致（v3/v4 混跑）",
         lambda d: bool(_get(d, "sharp.version_mismatch"))),
    ]


def checks() -> list[Check]:
    return _checks()


def audit(snapshot: dict | None = None) -> dict:
    doc = copy.deepcopy(snapshot or _vulnerable_fixture())
    failed: list[dict] = []
    passed: list[str] = []
    for cid, domain, sev, title, predicate in _checks():
        try:
            bad = bool(predicate(doc))
        except Exception:  # noqa: BLE001
            bad = True
        if bad:
            failed.append({"id": cid, "domain": domain, "sev": sev, "title": title})
        else:
            passed.append(cid)
    counts: dict[str, int] = {}
    for item in failed:
        counts[item["sev"]] = counts.get(item["sev"], 0) + 1
    findings = [finding(
        item["sev"], f"{item['domain'].upper()} 配置风险：{item['title']}",
        {"check": item["id"], "domain": item["domain"], "checks": len(_checks()),
         "failed": len(failed), "domains": sorted({c[1] for c in _checks()}),
         "snapshot_sha256": hash_payload(doc)},
        fix="启用 PFC watchdog/ECN；关闭 any-any ACL 与明文 telemetry；IB SM 主备、默认分区最小成员、"
            "按租户 PKey；SHARP 会话鉴权 + reduce ACL + 作业成员树。",
    ) for item in failed]
    return {
        "checks": len(_checks()),
        "failed": len(failed),
        "passed": len(passed),
        "findings": len(failed),
        "severity": counts,
        "domains": sorted({c[1] for c in _checks()}),
        "failed_ids": [f["id"] for f in failed],
        "results": failed,
        "finding_items": findings,
        "snapshot_sha256": hash_payload(doc),
    }


def fabric_sim_plan(snapshot: dict | None = None) -> dict:
    doc = copy.deepcopy(snapshot or _vulnerable_fixture())
    scenarios: list[str] = []
    evidence: dict[str, Any] = {}
    pfc_off = str(_get(doc, "sonic.pfc_watchdog")) != "detect"
    low_threshold = int(_get(doc, "sonic.pfc_storm_threshold", 0)) < 1000
    if pfc_off or low_threshold:
        scenarios.append("pfc-storm")
        evidence["pfc-storm"] = {"watchdog": _get(doc, "sonic.pfc_watchdog"),
                                 "threshold": _get(doc, "sonic.pfc_storm_threshold")}
    if str(_get(doc, "sonic.ecn_wred")) != "enabled":
        scenarios.append("ecn")
        evidence["ecn"] = {"ecn_wred": _get(doc, "sonic.ecn_wred"),
                           "ecn_marks": _get(doc, "sonic.ecn_marks")}
    if str(_get(doc, "ib.rail_binding", "rail")) != "rail":
        scenarios.append("rail-mismatch")
        evidence["rail-mismatch"] = {"rail_binding": _get(doc, "ib.rail_binding")}
    return {"scenarios": scenarios, "evidence": evidence,
            "snapshot_sha256": hash_payload(doc)}


def summary(report: dict) -> str:
    return summary_json("sonic-fabric-config", [], extra={
        "checks": report["checks"], "failed": report["failed"],
        "domains": report["domains"],
    })


def load_snapshot(value) -> dict:
    if value is None:
        return fixture("vulnerable")
    if isinstance(value, dict):
        return value
    import json
    from pathlib import Path
    return json.loads(Path(str(value)).read_text(encoding="utf-8"))
