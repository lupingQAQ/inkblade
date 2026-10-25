# -*- coding: utf-8 -*-
"""fabric 遥测暴露面（gNMI/SNMP/TSDB，授权主动级只读）。

GET：
- /telemetry/v1/config   gNMI TLS/鉴权、SNMP 版本/团体名、TSDB 保留期
- /telemetry/v1/metrics  指标与标签（tenant/serial）

判定：
- metrics 匿名 200 且带 tenant/serial 标签 → high；
- gNMI 未启用 TLS / 未启用认证 → medium；
- SNMP v1/v2c public/private → medium。

只读：不写 gNMI、不 SET SNMP、不改订阅。
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_hardware_common", _PARENT / "_hardware-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "fabric-telemetry-exposure"


def run(ctx: dict, params: dict) -> dict:
    target = str(params.get("target") or "").rstrip("/")
    if not target:
        return _C.no_target()
    t = _C.Trace(ctx, KEY)
    findings: list[dict] = []

    config_entry = t.get(f"{target}/telemetry/v1/config")
    metrics_entry = t.get(f"{target}/telemetry/v1/metrics")
    cfg = _C.resp(config_entry)
    metrics_doc = _C.resp(metrics_entry)
    gnmi = cfg.get("gnmi") or {}
    snmp = cfg.get("snmp") or {}
    metric_items = [m for m in metrics_doc.get("metrics") or [] if isinstance(m, dict)]
    labels = [m.get("labels") or {} for m in metric_items]
    tenant_labels = any("tenant" in item for item in labels)
    serial_labels = any("serial" in item for item in labels)
    anonymous_metrics = metrics_entry.get("status") == 200 and (tenant_labels or serial_labels)
    snmp_version = str(snmp.get("version") or "")
    snmp_community = str(snmp.get("community") or "")

    if anonymous_metrics:
        findings.append(_C.finding(
            "high", "fabric 遥测匿名暴露跨租户标签",
            {"detected": True, "metrics_status": metrics_entry.get("status"),
             "tenant_labels": tenant_labels, "serial_labels": serial_labels,
             "metric_count": len(metric_items),
             "tenants": metrics_doc.get("tenants") or []},
            evidence="GET /telemetry/v1/metrics -> 200 with tenant/serial labels",
            mapping="fabric telemetry/gNMI 多租户标签",
            fix="遥测端点启用认证；指标按租户聚合或删除 tenant/serial 标签",
        ))
    if bool(gnmi.get("enabled")) and not bool(gnmi.get("tls")):
        findings.append(_C.finding(
            "medium", "gNMI 未启用 TLS",
            {"detected": True, "gnmi": gnmi},
            evidence=f"gnmi.port={gnmi.get('port')} tls=false",
            fix="gNMI 启用 TLS（mTLS），关闭明文 6030",
        ))
    if bool(gnmi.get("enabled")) and not bool(gnmi.get("auth")):
        findings.append(_C.finding(
            "medium", "gNMI 未启用认证",
            {"detected": True, "gnmi": gnmi},
            evidence=f"gnmi.port={gnmi.get('port')} auth=false",
            fix="gNMI 启用证书/账号鉴权与最小 RPC 权限",
        ))
    if snmp_version.lower() in ("1", "2c", "v2c") and snmp_community.lower() in ("public", "private", ""):
        findings.append(_C.finding(
            "medium", "SNMP v2c 弱团体名",
            {"detected": True, "snmp_version": snmp_version,
             "community_present": bool(snmp_community)},
            evidence=f"snmp.version={snmp_version} community={snmp_community or '<empty>'}",
            fix="禁用 SNMP v1/v2c；使用 SNMPv3 authPriv + ACL + 最小视图",
        ))

    extra = {
        "config_status": config_entry.get("status"),
        "metrics_status": metrics_entry.get("status"),
        "gnmi_tls": bool(gnmi.get("tls")),
        "gnmi_auth": bool(gnmi.get("auth")),
        "gnmi_enabled": bool(gnmi.get("enabled")),
        "snmp_version": snmp_version,
        "snmp_community": snmp_community,
        "tenant_labels": tenant_labels,
        "serial_labels": serial_labels,
        "metric_count": len(metric_items),
        "anonymous_metrics": anonymous_metrics,
        "retention_days": _C.int_of((cfg.get("tsdb") or {}).get("retention_days")),
    }
    summary = _C.summary_json("fabric 遥测暴露面", findings, extra=extra, source=target)
    artifact = _C.write_artifact(ctx, f"{KEY}.json", {
        "summary": json.loads(summary), "config": cfg, "metrics": metrics_doc,
        "findings": findings,
    })
    trace = t.dump()
    artifacts = ([str(trace)] if trace else []) + artifact
    return {"summary": summary, "artifacts": artifacts, "findings": findings}
