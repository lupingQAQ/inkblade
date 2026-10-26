# -*- coding: utf-8 -*-
"""SPIFFE/SPIRE 工作负载身份面（主动探测，只读）。

GET /spire/entries：
- 通配 SPIFFE ID → high；
- 条目无选择器或 TTL=0/超长 → high；
- admin socket 无 ACL 或监听 0.0.0.0 → high。

只读：不注册/删除 entry，不调用 SPIRE admin API 写操作。
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_infra2026_common", _PARENT / "_infra2026-common.py")
_C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_C)

KEY = "spiffe-spire-surface"


def run(ctx: dict, params: dict) -> dict:
    target = str(params.get("target") or "").rstrip("/")
    if not target:
        return _C.no_target()
    t = _C.Trace(ctx, KEY)
    entry = t.get(f"{target}/spire/entries")
    doc = _C.resp(entry)
    entries = [e for e in _C.as_list(doc.get("entries")) if isinstance(e, dict)]
    server = doc.get("server") or {}
    findings: list[dict] = []

    wildcard = [e for e in entries if _C.wildcard_id(e.get("spiffe_id"))]
    weak = [e for e in entries
            if not _C.as_list(e.get("selectors"))
            or _C.as_int(e.get("ttl"), -1) == 0
            or _C.as_int(e.get("ttl"), 0) > 86400]
    admin_acl = bool(server.get("admin_acl"))
    bind = str(server.get("bind") or "")
    exposed_admin = (not admin_acl) or bind.startswith("0.0.0.0")

    if wildcard:
        findings.append(_C.finding(
            "high", "SPIRE 通配 SPIFFE ID 条目",
            {"detected": True,
             "entries": [{"spiffe_id": e.get("spiffe_id"), "ttl": e.get("ttl")}
                         for e in wildcard]},
            evidence=f"wildcard_entries={[e.get('spiffe_id') for e in wildcard]}",
            mapping="SPIFFE ID / SPIRE registration entry",
            fix="删除通配 entry；按 ns/sa/节点选择器签发最小身份",
        ))
    if weak:
        findings.append(_C.finding(
            "high", "SPIRE 条目缺少选择器或 TTL 异常",
            {"detected": True,
             "entries": [{"spiffe_id": e.get("spiffe_id"),
                          "selectors": e.get("selectors"), "ttl": e.get("ttl")}
                         for e in weak]},
            evidence=f"weak_entries={[e.get('spiffe_id') for e in weak]}",
            mapping="SPIRE selector attestation / SVID TTL",
            fix="每个 entry 必须绑定可证明选择器；TTL 限制在 1h 内并启用轮换",
        ))
    if exposed_admin:
        findings.append(_C.finding(
            "high", "SPIRE 管理接口无 ACL 或监听 0.0.0.0",
            {"detected": True, "admin_acl": admin_acl, "bind": bind,
             "admin_socket": server.get("admin_socket")},
            evidence=f"admin_acl={admin_acl} bind={bind}",
            mapping="SPIRE server admin socket / registration API",
            fix="admin socket 仅 root 可写并启用 ACL；server 绑定到内网地址",
        ))

    extra = {
        "trust_domain": doc.get("trust_domain"),
        "entries": len(entries),
        "wildcard_entries": len(wildcard),
        "weak_entries": len(weak),
        "admin_acl": admin_acl,
        "bind": bind,
        "status": entry.get("status"),
    }
    summary = _C.summary_json("SPIFFE/SPIRE 身份面", findings, extra=extra, source=target)
    artifact = _C.write_artifact(ctx, f"{KEY}.json", {
        "summary": json.loads(summary), "spire": doc, "findings": findings,
    })
    trace = t.dump()
    artifacts = ([str(trace)] if trace else []) + artifact
    return {"summary": summary, "artifacts": artifacts, "findings": findings}
