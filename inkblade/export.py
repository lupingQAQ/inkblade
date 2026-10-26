# -*- coding: utf-8 -*-
"""机器可读导出：SARIF 2.1.0 / OCSF 1.x Detection Finding / OpenVEX 风格 JSON。

设计口径：
- finding UID 稳定（run + step_key + title + ordinal），便于跨报告去重与工单关联；
- SARIF 以 step_key 聚合成 rule，结果携带 severity / 零日标记 / 证据 SHA256 / 合规映射；
- OCSF 用 Detection Finding（class_uid=2004, category_uid=2, type_uid=200401）；
- VEX 默认 ``affected``，中低危标 ``under_investigation``（需复现/修复确认），CVE 标题直通。
"""

from __future__ import annotations

import calendar
import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any

from . import VERSION
from .reports import compliance

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
OCSF_VERSION = "1.5.0"
VEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"
FORMATS = ("sarif", "ocsf", "vex")

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
                "low": "note", "info": "note"}
_SECURITY_SEVERITY = {"critical": "9.8", "high": "8.1", "medium": "5.5",
                      "low": "2.5", "info": "0.0"}
_OCSF_SEVERITY = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
_OCSF_SEVERITY_NAME = {5: "Critical", 4: "High", 3: "Medium", 2: "Low", 1: "Informational"}


def _sha16(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def finding_uid(finding: dict, meta: dict, ordinal: int = 0) -> str:
    seed = "|".join([
        str(meta.get("workspace", "")), str(meta.get("run", "")),
        str(finding.get("step_key", "")), str(finding.get("title", "")), str(ordinal),
    ])
    return f"inkblade-{_sha16(seed)}"


def _evidence_sha(finding: dict, meta: dict) -> str:
    path = str(finding.get("evidence_path") or "")
    return str((meta.get("evidence_sha") or {}).get(path, ""))


def _rfc3339(meta: dict) -> str:
    value = str(meta.get("generated_at") or "").strip()
    if re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", value):
        return value
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _epoch_ms(meta: dict) -> int:
    value = str(meta.get("generated_at") or "")
    if re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", value):
        try:
            return int(calendar.timegm(time.strptime(value, "%Y-%m-%dT%H:%M:%SZ")) * 1000)
        except ValueError:
            pass
    return int(time.time() * 1000)


# ---------------------------------------------------------------- SARIF 2.1.0

def build_sarif(findings: list[dict], meta: dict) -> dict:
    rules: list[dict] = []
    index: dict[str, int] = {}
    for finding in findings or []:
        step = str(finding.get("step_key") or "general")
        if step in index:
            continue
        rule_id = f"INKBLADE.{step}"
        index[step] = len(rules)
        severity = str(finding.get("severity") or "info").lower()
        rules.append({
            "id": rule_id,
            "name": step,
            "shortDescription": {"text": str(finding.get("title") or step)},
            "fullDescription": {"text": str(finding.get("detail") or finding.get("title") or step)},
            "defaultConfiguration": {"level": _SARIF_LEVEL.get(severity, "note")},
            "properties": {
                "tags": ["security", "ml-cluster", severity],
                "severity": severity,
                "security-severity": _SECURITY_SEVERITY.get(severity, "0.0"),
            },
        })

    results: list[dict] = []
    for ordinal, finding in enumerate(findings or []):
        step = str(finding.get("step_key") or "general")
        severity = str(finding.get("severity") or "info").lower()
        uid = finding_uid(finding, meta, ordinal)
        uri = str(finding.get("evidence_path") or f"steps/{step}.tar.gz").replace("\\", "/")
        evidence_sha = _evidence_sha(finding, meta)
        results.append({
            "ruleId": f"INKBLADE.{step}",
            "ruleIndex": index[step],
            "level": _SARIF_LEVEL.get(severity, "note"),
            "message": {"text": f"{finding.get('title', '')}: {finding.get('detail', '')}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": 1, "startColumn": 1},
                },
                "logicalLocations": [{"fullyQualifiedName": step, "kind": "module"}],
            }],
            "partialFingerprints": {"inkbladeFindingHash/v1": _sha16(uid + uri)},
            "properties": {
                "inkblade_uid": uid,
                "severity": severity,
                "is_zeroday": bool(finding.get("is_zeroday")),
                "evidence_path": uri,
                "evidence_sha256": evidence_sha,
                "compliance": compliance.map_finding(finding),
            },
        })

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {"driver": {
                "name": "InkBlade",
                "version": str(meta.get("tool_version") or VERSION),
                "rules": rules,
            }},
            "automationDetails": {"id": f"inkblade/{meta.get('workspace', '')}/{meta.get('run', '')}"},
            "invocations": [{"executionSuccessful": True,
                             "endTimeUtc": _rfc3339(meta)}],
            "results": results,
        }],
    }


# ---------------------------------------------------------------- OCSF 1.x

def _ocsf_event(finding: dict, meta: dict, ordinal: int) -> dict:
    severity = str(finding.get("severity") or "info").lower()
    sev_id = _OCSF_SEVERITY.get(severity, 1)
    uid = finding_uid(finding, meta, ordinal)
    types = ["ML Cluster Security Finding", f"severity:{severity}"]
    if finding.get("is_zeroday"):
        types.insert(0, "Zero-Day")
    evidence_path = str(finding.get("evidence_path") or "").replace("\\", "/")
    resource = str(meta.get("workspace") or "workspace")
    return {
        "class_uid": 2004,
        "class_name": "Detection Finding",
        "category_uid": 2,
        "category_name": "Findings",
        "activity_id": 1,
        "activity_name": "Create",
        "type_uid": 200401,
        "severity_id": sev_id,
        "severity": _OCSF_SEVERITY_NAME[sev_id],
        "status_id": 1,
        "status": "New",
        "time": _epoch_ms(meta),
        "metadata": {
            "version": OCSF_VERSION,
            "product": {
                "vendor_name": "InkBlade",
                "name": "InkBlade",
                "version": str(meta.get("tool_version") or VERSION),
            },
            "original_time": _rfc3339(meta),
            "profiles": ["security_control"],
        },
        "finding_info": {
            "uid": uid,
            "title": str(finding.get("title") or ""),
            "desc": str(finding.get("detail") or ""),
            "created_time_ms": _epoch_ms(meta),
            "types": types,
            "analytic": {
                "name": "inkblade.chain-module",
                "type_id": 1,
                "type": "Rule",
                "uid": str(finding.get("step_key") or ""),
            },
        },
        "resources": [{
            "type": "Kubernetes Cluster",
            "name": resource,
            "uid": resource,
        }],
        "evidences": [{
            "uid": _evidence_sha(finding, meta) or evidence_path or str(finding.get("step_key") or ""),
            "data": {
                "path": evidence_path,
                "sha256": _evidence_sha(finding, meta),
                "step_key": str(finding.get("step_key") or ""),
            },
        }],
    }


def build_ocsf(findings: list[dict], meta: dict) -> dict:
    events = [_ocsf_event(f, meta, i) for i, f in enumerate(findings or [])]
    return {
        "schema": "inkblade-ocsf-export/2026-10",
        "ocsf_version": OCSF_VERSION,
        "count": len(events),
        "generated_at": _rfc3339(meta),
        "workspace": meta.get("workspace", ""),
        "run": meta.get("run", ""),
        "events": events,
    }


# ---------------------------------------------------------------- VEX

def _vex_status(severity: str) -> str:
    return "under_investigation" if severity in ("medium", "low", "info") else "affected"


def build_vex(findings: list[dict], meta: dict) -> dict:
    statements: list[dict] = []
    timestamp = _rfc3339(meta)
    product = "pkg:generic/inkblade/{}/{}".format(
        meta.get("workspace", "workspace"), meta.get("run", "run"))
    seed = "|".join([
        str(meta.get("workspace", "")), str(meta.get("run", "")),
        *[str(f.get("title", "")) for f in findings or []],
    ])
    for ordinal, finding in enumerate(findings or []):
        title = str(finding.get("title") or "")
        m = _CVE_RE.search(title)
        cve = m.group(0).upper() if m else ""
        uid = finding_uid(finding, meta, ordinal)
        severity = str(finding.get("severity") or "info").lower()
        step = str(finding.get("step_key") or "general")
        statements.append({
            "vulnerability": {
                "name": cve or f"INKBLADE-{uid[8:].upper()}",
                "aliases": [cve] if cve else [],
                "description": title,
            },
            "products": [{
                "@id": product,
                "subcomponents": [{"@id": f"pkg:generic/inkblade-module/{step}"}],
            }],
            "status": _vex_status(severity),
            "status_notes": f"severity={severity}; evidence={finding.get('evidence_path') or 'n/a'}; "
                            f"automatic VEX from InkBlade run {meta.get('run', '')}",
            "action_statement": f"Apply remediation for {title or step} and retest with InkBlade.",
            "timestamp": timestamp,
        })
    return {
        "@context": VEX_CONTEXT,
        "@id": f"https://inkblade.local/vex/{_sha16(seed)}",
        "author": "InkBlade <inkblade@localhost>",
        "timestamp": timestamp,
        "version": 1,
        "tooling": f"inkblade/{meta.get('tool_version') or VERSION}",
        "statements": statements,
    }


# ---------------------------------------------------------------- 统一入口

def _manifest_sha_map(run) -> dict[str, str]:
    path = run.dir / "manifest.sha256"
    out: dict[str, str] = {}
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        sha, _, rel = line.partition("  ")
        if rel:
            out[rel.strip()] = sha.strip()
    return out


def build(fmt: str, findings: list[dict], meta: dict) -> dict:
    if fmt == "sarif":
        return build_sarif(findings, meta)
    if fmt == "ocsf":
        return build_ocsf(findings, meta)
    if fmt == "vex":
        return build_vex(findings, meta)
    raise ValueError(f"未知导出格式 {fmt!r}（支持 {', '.join(FORMATS)}）")


def export_run(store, run_name: str, fmt: str) -> dict:
    if fmt not in FORMATS:
        raise ValueError(f"未知导出格式 {fmt!r}（支持 {', '.join(FORMATS)}）")
    run = store.open_run(run_name)
    meta = {
        "workspace": store.workspace,
        "run": run_name,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tool_version": VERSION,
        "evidence_sha": _manifest_sha_map(run),
    }
    return build(fmt, run.findings, meta)


def write_export(doc: dict, out: Path | str | None) -> None:
    if out is None:
        return
    p = Path(out)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
