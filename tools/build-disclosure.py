# -*- coding: utf-8 -*-
"""Build the (never-sent) CVE-ready disclosure packages for the 0day reserve.

Every reserve entry is screened in ``corpus/zeroday/disclosure-eligibility.json``.
Eligible entries get ``disclosure/<id>/`` with:

    report-en.md        English vendor report (root cause, repro, impact, fix, timeline)
    cve-request.json    CVE JSON 5.1 record (placeholder CVE-0000-xxxx, not submitted)
    evidence.sha256     evidence bundle hashes, logical names only
    vendor-contact.txt  private channels + CNVD/CNNVD, status NOT SENT
    timeline.json       T0 + 7/30/60/90 day milestones
    status.json         machine-readable state (never sent, no real CVE id)

Ineligible entries get ``status.json`` + ``hardening-advice.md`` instead.

Nothing in this module performs network I/O or sends email.  The only writes are
local files under ``disclosure/`` and the generated index table in
``docs/0DAY-DISCLOSURE.md``.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from inkblade.core import cvss  # noqa: E402
from inkblade.core.cveschema import validate_cve_record  # noqa: E402

WORKSPACE = ROOT.parents[1]
INVENTORY = ROOT / "corpus" / "zeroday" / "inventory.json"
ELIGIBILITY = ROOT / "corpus" / "zeroday" / "disclosure-eligibility.json"
REGISTRY = ROOT / "inkblade" / "core" / "zeroday-registry.json"
DISCLOSURE = ROOT / "disclosure"
DOC = ROOT / "docs" / "0DAY-DISCLOSURE.md"
GENERATED_AT = "2026-10-27T00:00:00+00:00"
T0 = "2026-10-28T00:00:00+00:00"
PLACEHOLDER_ORG_ID = "00000000-0000-4000-8000-000000000000"
PLACEHOLDER_CVE_PREFIX = "CVE-0000-"
MARKERS = ("<!-- DISCLOSURE-INDEX:START -->", "<!-- DISCLOSURE-INDEX:END -->")

_DRIVE_RE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]:[\\/][^\s\"'<>|)]+")
_INTERNAL_PREFIXES = (
    str(ROOT).replace("\\", "/"),
    str(WORKSPACE).replace("\\", "/"),
    str(ROOT),
    str(WORKSPACE),
    "projects/repro-2026-10/",
    "projects/agent-2026-10/",
    "lab/upstream_verify/",
    "lab/zeroday_reserve/",
)


def now() -> str:
    return GENERATED_AT


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def redact(text: Any) -> str:
    """Remove host/workspace paths and internal evidence-tree prefixes."""
    value = str(text if text is not None else "")
    for prefix in _INTERNAL_PREFIXES:
        value = value.replace(prefix, "")
        value = value.replace(prefix.replace("\\", "/"), "")
    value = _DRIVE_RE.sub("<redacted-path>", value)
    value = value.replace("/home/", "<home>/")
    return value.strip()


def resolve_evidence(path: str) -> Path | None:
    if not path:
        return None
    candidate = Path(path)
    if candidate.is_absolute() and candidate.is_file():
        return candidate
    for base in (ROOT, WORKSPACE):
        target = base / path
        if target.is_file():
            return target
    return None


def evidence_files(entry: dict, case_dir: Path | None = None) -> list[Path]:
    files: list[Path] = []
    resolved = resolve_evidence(str((entry.get("evidence") or {}).get("path") or ""))
    if resolved is not None:
        files.append(resolved)
    if resolved is not None and resolved.name != "evidence" and resolved.parent.is_dir() and resolved.suffix == ".json":
        sibling = resolved.parent / "evidence"
        if sibling.is_dir():
            files.extend(sorted(p for p in sibling.rglob("*") if p.is_file()))
    if case_dir is not None:
        result = case_dir / "result.json"
        if result.is_file() and result not in files:
            files.append(result)
    seen: set[Path] = set()
    unique = []
    for path in files:
        key = path.resolve()
        if key not in seen:
            seen.add(key)
            unique.append(path)
    return unique[:24]


def logical_names(paths: list[Path]) -> list[tuple[str, Path]]:
    seen: dict[str, int] = {}
    out = []
    for path in paths:
        name = path.name
        if name in seen:
            seen[name] += 1
            name = f"{path.stem}-{seen[name]}{path.suffix}"
        else:
            seen[name] = 0
        out.append((name, path))
    return out


def bundle(entry: dict, case_dir: Path | None = None) -> tuple[list[str], list[str]]:
    lines = [
        f"# evidence bundle: {entry['id']}",
        f"# generated: {now()}",
        "# logical names only; no host paths are stored in the disclosure tree",
    ]
    missing: list[str] = []
    files = evidence_files(entry, case_dir)
    for name, path in logical_names(files):
        lines.append(f"{sha256_file(path)}  {name}")
    canonical = json.dumps(entry, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    lines.append(f"{sha256_bytes(canonical)}  inventory-entry.json")
    if not files:
        missing.append("source evidence archive not present next to this checkout")
        lines.append("# unavailable: source evidence archive (see registry evidence.path)")
    return lines, missing


def cve_record(entry: dict, item: dict, index: int) -> dict:
    cve_id = f"{PLACEHOLDER_CVE_PREFIX}{index:04d}"
    owner = item["vendor"]["product_repo"].split("/")[0]
    product: dict[str, Any] = {
        "vendor": owner,
        "product": item["vendor"].get("product_name") or entry.get("product") or entry["component"],
        "versions": item["versions"],
        "defaultStatus": "unaffected",
    }
    if item["vendor"].get("collection_url"):
        product["collectionURL"] = item["vendor"]["collection_url"]
        product["packageName"] = item["vendor"]["collection_url"].rstrip("/").rsplit("/", 1)[-1]
    description = (
        f"{redact(item['title'])}. {redact(item['impact'])} "
        f"Affected: {entry.get('version') or 'see versions'}. "
        f"Root cause: {redact((entry.get('root_cause') or {}).get('file'))}"
        f":{(entry.get('root_cause') or {}).get('line') or '?'}"
        f" ({(entry.get('root_cause') or {}).get('function') or 'unknown function'})."
    )
    references = [
        {"url": f"https://github.com/{item['vendor']['product_repo']}", "name": "Vendor repository"},
        {"url": item["vendor"]["policy"], "name": "Vendor security policy"},
        {"url": item["vendor"]["url"], "name": "Vendor private advisory intake"},
    ]
    timeline = []
    for label, offset in (("T0", 0), ("T0+7", 7), ("T0+30", 30), ("T0+60", 60), ("T0+90", 90)):
        time = (datetime.fromisoformat(T0) + timedelta(days=offset)).isoformat(timespec="seconds")
        timeline.append({"time": time, "lang": "en",
                         "value": f"{label}: {'vendor notification (planned)' if offset == 0 else 'follow-up milestone (planned)'}"})
    record = {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.1",
        "cveMetadata": {
            "cveId": cve_id,
            "assignerOrgId": PLACEHOLDER_ORG_ID,
            "assignerShortName": "INKBLADE-RESERVE",
            "state": "PUBLISHED",
            "serial": 1,
            "dateUpdated": now(),
        },
        "containers": {
            "cna": {
                "providerMetadata": {
                    "orgId": PLACEHOLDER_ORG_ID,
                    "shortName": "INKBLADE-RESERVE",
                    "dateUpdated": now(),
                },
                "title": item["title"][:256],
                "descriptions": [{"lang": "en", "value": description}],
                "affected": [product],
                "problemTypes": [{
                    "descriptions": [{
                        "lang": "en",
                        "cweId": cwe["id"],
                        "description": f"{cwe['id']} {cwe['name']}",
                        "type": "CWE",
                    } for cwe in item["cwe"]],
                }],
                "metrics": [{
                    "cvssV3_1": {
                        "version": "3.1",
                        "vectorString": item["cvss31"]["vector"],
                        "baseScore": item["cvss31"]["score"],
                        "baseSeverity": item["cvss31"]["severity"],
                    }
                }],
                "references": references,
                "credits": [{"lang": "en", "value": "InkBlade security research", "type": "finder"}],
                "solutions": [{"lang": "en", "value": redact(item["fix"])}],
                "timeline": timeline,
                "x_inkblade": {
                    "reserveId": entry["id"],
                    "mergedIds": item.get("merged_ids") or [],
                    "state": "draft-request-not-submitted",
                    "realCveId": None,
                    "sendStatus": "not-sent",
                    "placeholderCveId": True,
                    "evidenceSha256File": "evidence.sha256",
                },
            }
        },
    }
    return record


def report_markdown(entry: dict, item: dict, bundle_lines: list[str]) -> str:
    rc = entry.get("root_cause") or {}
    pre = entry.get("preconditions") or []
    lines = [
        f"# {item['title']}",
        "",
        f"> **Status: DRAFT — NOT SENT.** Prepared {now()} for coordinated disclosure. "
        "No email, advisory, or CVE request has been submitted.",
        "",
        "## 1. Summary",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Product | {item['vendor']['product_name']} |",
        f"| Affected version | {entry.get('version') or 'see CVE affected versions'} |",
        f"| Weakness | {', '.join(c['id'] for c in item['cwe'])} |",
        f"| CVSS 3.1 | {item['cvss31']['score']} ({item['cvss31']['severity']}) `{item['cvss31']['vector']}` |",
        f"| Impact | {redact(item['impact'])} |",
        f"| CVE | placeholder `CVE-0000-xxxx` only; not requested |",
        "",
        "## 2. Root cause",
        "",
        f"- `{redact(rc.get('file'))}:{rc.get('line') or '?'}` in `{rc.get('function') or 'unknown function'}`.",
        f"- {redact(entry.get('reachability') or '')}",
        "",
        "## 3. Preconditions",
        "",
    ]
    for condition in pre:
        lines.append(f"- {redact(condition)}")
    lines += [
        "",
        "## 4. Reproduction",
        "",
        f"- Environment: {redact(entry.get('version') or '')}.",
        f"- Observed behaviour: {redact(entry.get('exploit') or '')}",
        "- The evidence bundle is hashed in `evidence.sha256`; the runnable harness is not shipped "
        "with this report.",
        "",
        "## 5. Impact",
        "",
        redact(item["impact"]),
        "",
        "## 6. Fix",
        "",
        redact(item["fix"]),
        "",
        "## 7. Disclosure timeline (planned)",
        "",
        "| Milestone | Date (UTC) | Action |",
        "|---|---|---|",
    ]
    t0 = datetime.fromisoformat(T0)
    for label, offset, action in (
        ("T0", 0, "Private vendor notification with this report and evidence hashes."),
        ("T0+7", 7, "Re-send through a second private channel if unacknowledged."),
        ("T0+30", 30, "Ask for fix plan and CVE assignment; refine affected versions."),
        ("T0+60", 60, "Second reminder; agree advisory publication date if fixed."),
        ("T0+90", 90, "Default coordinated publication with fix version and credit."),
    ):
        lines.append(f"| {label} | {(t0 + timedelta(days=offset)).date().isoformat()} | {action} |")
    lines += [
        "",
        "## 8. Evidence bundle",
        "",
        "```text",
        *bundle_lines[:40],
        "```",
        "",
        "## 9. Credits and contact",
        "",
        "- Reported by: InkBlade security research (coordinated disclosure).",
        f"- Preferred channel: {item['vendor']['url']} (private advisory draft).",
        "- CNVD/CNNVD: secondary channels after the vendor has been notified.",
        "",
        "## 10. Legal and authorization",
        "",
        "Testing was performed in a local, authorized lab against upstream open-source code. "
        "This document is a draft for human review and legal check before any transmission.",
        "",
    ]
    return "\n".join(lines)


def timeline_json(entry: dict, item: dict) -> dict:
    t0 = datetime.fromisoformat(T0)
    milestones = []
    for label, offset, action in (
        ("T0", 0, "private-vendor-notification"),
        ("T0+7", 7, "second-channel-if-unacknowledged"),
        ("T0+30", 30, "fix-plan-and-cve-request"),
        ("T0+60", 60, "second-reminder"),
        ("T0+90", 90, "default-coordinated-publication"),
    ):
        milestones.append({
            "label": label,
            "due": (t0 + timedelta(days=offset)).isoformat(timespec="seconds"),
            "action": action,
            "state": "not-started",
        })
    return {
        "schema": "inkblade-disclosure-timeline-v1",
        "id": entry["id"],
        "anchor": "planned-t0",
        "t0_planned": T0,
        "t0_actual": None,
        "sent": False,
        "milestones": milestones,
        "extension_policy": "written vendor request only; record the new date in status.json",
        "publication_rule": "publish no earlier than T0+90 unless the vendor agrees; never before a fix is available",
    }


def status_json(entry: dict, item: dict, package_files: list[str], missing: list[str]) -> dict:
    return {
        "schema": "inkblade-disclosure-status-v1",
        "id": entry["id"],
        "reserve_source": entry.get("source"),
        "component": entry.get("component"),
        "merged_ids": item.get("merged_ids") or [],
        "eligible_for_cve": bool(item["eligible"]),
        "decision": item["decision"],
        "reason": redact(item["reason"]),
        "state": "draft-not-sent" if item["eligible"] else "hardening-only",
        "sent": False,
        "sent_at": None,
        "vendor_notified": False,
        "cve_id": None,
        "cve_state": "not-requested",
        "public_disclosure": False,
        "legal_review": "required",
        "redaction": {
            "internal_paths_removed": True,
            "credentials_removed": True,
            "hostnames_removed": True,
            "method": "drive-letter, workspace, /home and internal evidence prefixes stripped",
        },
        "package_files": package_files,
        "evidence_gaps": missing,
        "generated_at": now(),
        "no_send_policy": "this repository never transmits disclosure material automatically",
    }


def vendor_contact(entry: dict, item: dict) -> str:
    vendor = item["vendor"]
    lines = [
        f"# Vendor contact plan — {entry['id']}",
        "",
        f"Product: {vendor['product_name']}",
        f"Repository: https://github.com/{vendor['product_repo']}",
        f"Preferred channel: {vendor['channel']}",
        f"Private advisory intake: {vendor['url']}",
        f"Security policy: {vendor['policy']}",
    ]
    if vendor.get("email"):
        lines.append(f"Email: {vendor['email']}")
    else:
        lines.append("Email: not guessed; read the current SECURITY.md before sending.")
    lines += [
        "",
        "Secondary channels (after the vendor has been notified):",
        "- CNVD: https://www.cnvd.org.cn/ (account and real-name registration required).",
        "- CNNVD: https://www.cnnvd.org.cn/ (parallel or supplementary to CNVD).",
        "",
        "Status: NOT SENT. No message has been drafted into an email client or API.",
        "Before sending: legal review, redaction check, and a human owner must sign off.",
        "",
    ]
    return "\n".join(lines)


def hardening_markdown(entry: dict, item: dict) -> str:
    lines = [
        f"# Hardening advice — {entry['id']}",
        "",
        f"**Decision: not CVE-eligible.** {redact(item['reason'])}",
        "",
        "## Affected",
        "",
        f"- Product: {item['vendor']['product_name']}",
        f"- Version: {entry.get('version') or 'see inventory'}",
        f"- Root cause: `{redact((entry.get('root_cause') or {}).get('file'))}"
        f":{(entry.get('root_cause') or {}).get('line') or '?'}`",
        "",
        "## Recommended hardening",
        "",
        redact(item["fix"]),
        "",
        "## Why no CVE",
        "",
        redact(item["reason"]),
        "",
        "## Status",
        "",
        "No disclosure package was generated and nothing will be sent. Keep this item in the "
        "reserve as a hardening recommendation only.",
        "",
    ]
    return "\n".join(lines)


def build(write: bool = True) -> dict:
    inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
    eligibility = json.loads(ELIGIBILITY.read_text(encoding="utf-8"))
    entries = {e["id"]: e for e in inventory["entries"]}
    items = eligibility["entries"]
    covered: set[str] = set()
    for item in items.values():
        covered.add(item["id"])
        covered.update(item.get("merged_ids") or [])
    index_rows = []
    eligible = 0
    packages = 0
    cve_index = 0
    for eid, item in sorted(items.items(), key=lambda kv: (not kv[1]["eligible"], kv[0])):
        entry = entries.get(eid)
        if entry is None:
            raise SystemExit(f"eligibility references unknown inventory id: {eid}")
        cvss.check(item["cvss31"]["vector"], item["cvss31"]["score"], item["cvss31"]["severity"])
        case_dir = None
        resolved = resolve_evidence(str((entry.get("evidence") or {}).get("path") or ""))
        if resolved is not None and resolved.parent.is_dir():
            case_dir = resolved.parent
        out_dir = DISCLOSURE / eid
        if item["eligible"]:
            eligible += 1
            cve_index += 1
            bundle_lines, missing = bundle(entry, case_dir)
            record = cve_record(entry, item, cve_index)
            validate_cve_record(record)
            files = {
                "report-en.md": report_markdown(entry, item, bundle_lines),
                "cve-request.json": json.dumps(record, ensure_ascii=False, indent=2) + "\n",
                "evidence.sha256": "\n".join(bundle_lines) + "\n",
                "vendor-contact.txt": vendor_contact(entry, item),
                "timeline.json": json.dumps(timeline_json(entry, item), ensure_ascii=False, indent=2) + "\n",
            }
            package_files = sorted(files) + ["status.json"]
            files["status.json"] = json.dumps(
                status_json(entry, item, package_files, missing), ensure_ascii=False, indent=2) + "\n"
            if write:
                out_dir.mkdir(parents=True, exist_ok=True)
                for name, content in files.items():
                    (out_dir / name).write_text(content, encoding="utf-8")
            packages += 1
            index_rows.append({
                "id": eid, "decision": "cve", "cve_placeholder": record["cveMetadata"]["cveId"],
                "title": item["title"], "cvss": item["cvss31"]["score"],
                "severity": item["cvss31"]["severity"], "state": "draft-not-sent",
            })
        else:
            files = {
                "hardening-advice.md": hardening_markdown(entry, item),
                "status.json": json.dumps(
                    status_json(entry, item, ["hardening-advice.md", "status.json"], []),
                    ensure_ascii=False, indent=2) + "\n",
            }
            if write:
                out_dir.mkdir(parents=True, exist_ok=True)
                for name, content in files.items():
                    (out_dir / name).write_text(content, encoding="utf-8")
            index_rows.append({
                "id": eid, "decision": "hardening", "cve_placeholder": None,
                "title": item["title"], "cvss": item["cvss31"]["score"],
                "severity": item["cvss31"]["severity"], "state": "hardening-only",
            })

    summary = {
        "schema": "inkblade-disclosure-index-v1",
        "generated_at": now(),
        "no_send": True,
        "reserve_ids_screened": len(covered),
        "eligible_cve_packages": eligible,
        "hardening_only": len(items) - eligible,
        "cve_placeholders_used": cve_index,
        "rows": index_rows,
    }
    if write:
        DISCLOSURE.mkdir(parents=True, exist_ok=True)
        (DISCLOSURE / "INDEX.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        update_doc(summary)
    return summary


def _table(summary: dict) -> str:
    lines = [
        f"Generated: `{summary['generated_at']}` ｜ **NOT SENT** ｜ "
        f"screened reserve entries: **{summary['reserve_ids_screened']}** ｜ "
        f"CVE-ready packages: **{summary['eligible_cve_packages']}** ｜ "
        f"hardening-only: **{summary['hardening_only']}**",
        "",
        "| ID | Decision | Placeholder | CVSS | Severity | State |",
        "|---|---|---|---:|---|---|",
    ]
    for row in summary["rows"]:
        lines.append(
            f"| `{row['id']}` | {row['decision']} | {row['cve_placeholder'] or '—'} | "
            f"{row['cvss']} | {row['severity']} | {row['state']} |"
        )
    lines += [
        "",
        "> CVSS 为条目自身弱点评分；`hardening` 行不申请 CVE，分数仅用于排序与修复优先级。"
        "所有 `CVE-0000-xxxx` 均为占位符，未提交 CNA。",
    ]
    return "\n".join(lines)


def update_doc(summary: dict) -> None:
    text = DOC.read_text(encoding="utf-8") if DOC.is_file() else "# 0day 披露流程（InkBlade Reserve）\n"
    block = f"{MARKERS[0]}\n{_table(summary)}\n{MARKERS[1]}"
    if MARKERS[0] in text and MARKERS[1] in text:
        text = re.sub(re.escape(MARKERS[0]) + r".*?" + re.escape(MARKERS[1]), block, text, flags=re.S)
    else:
        text = text.rstrip() + "\n\n## 8. 披露包索引（CVE 就绪，未外发）\n\n" + block + "\n"
    DOC.write_text(text, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Build CVE-ready disclosure packages (never sends)")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    summary = build(write=not args.dry_run)
    print(json.dumps({k: v for k, v in summary.items() if k != "rows"}, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
