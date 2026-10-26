#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate a baseline declarative template from a module contract + source.

This is a migration aid, not the runtime.  It extracts the module's input kind
(target/snapshot/fixture/collection), HTTP paths, finding titles/severities and
CVE/version metadata, then emits a valid ``template.json`` that agents refine.
Baseline templates are marked ``fidelity: reduced`` until every check and the
two-state expectation are verified.
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from inkblade.tpl.schema import validate  # noqa: E402

SEV_RE = re.compile(r'["\'](critical|high|medium|low|info)["\']\s*,\s*(f?["\'][^"\']{3,160}["\'])')
DICT_RE = re.compile(r'["\']sev["\']\s*:\s*["\'](critical|high|medium|low|info)["\']'
                     r'[^}]{0,400}?["\']title["\']\s*:\s*(f?["\'][^"\']{3,160}["\'])', re.S)
PATH_RE = re.compile(r'["\']((?:/[A-Za-z0-9_.~{}$:-]+){1,6})["\']')
WRITE_HINT = re.compile(r"\b(POST|PUT|PATCH|DELETE)\b")
WRITE_PATH_HINT = re.compile(r"(config|update|write|job|run|submit|create|delete|apply|"
                             r"inject|poison|flood|token|upload|exec)", re.I)


def _literal_title(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith("f"):
        raw = raw[1:]
    try:
        return str(ast.literal_eval(raw))
    except (ValueError, SyntaxError):
        return raw.strip("'\"{} ")


def extract(source: str) -> dict:
    findings = []
    seen = set()
    for sev, raw in SEV_RE.findall(source):
        title = _literal_title(raw)
        if title and title not in seen:
            seen.add(title)
            findings.append({"sev": sev, "title": title})
    for sev, raw in DICT_RE.findall(source):
        title = _literal_title(raw)
        if title and title not in seen:
            seen.add(title)
            findings.append({"sev": sev, "title": title})
    paths = []
    for hit in PATH_RE.findall(source):
        if any(token in hit for token in ("{", "$", "}", "..")):
            continue
        if len(hit) < 2 or hit.startswith("//"):
            continue
        if hit not in paths:
            paths.append(hit)
    return {"findings": findings[:12], "paths": paths[:10]}


def _step_for_path(index: int, path: str, writes: bool) -> dict:
    method = "GET"
    if writes and WRITE_PATH_HINT.search(path):
        method = "POST"
    step = {
        "id": f"probe{index}",
        "op": "http",
        "method": method,
        "url": "{{input.target}}" + path,
        "headers": {},
        "save": f"probe{index}",
        "allow_failure": True,
        "timeout_ms": 8000,
    }
    if method == "POST":
        step["body"] = {"marker": "{{ctx.marker}}", "benign": True}
        step["write"] = True
    return step


def build(module_dir: Path) -> dict:
    raw = json.loads((module_dir / "module.json").read_text(encoding="utf-8"))
    source = ""
    run_py = module_dir / "run.py"
    if run_py.is_file():
        source = run_py.read_text(encoding="utf-8-sig", errors="replace")
    extracted = extract(source)
    params = raw.get("params_schema") or {}
    writes = bool(raw.get("writes"))
    inputs: dict = {}
    steps: list[dict] = []
    checks: list[dict] = []
    condition = "true"

    if "target" in params:
        inputs["target"] = {"from": "params.target", "required": True,
                            "description": "Target base URL"}
        steps.append({"id": "surface", "op": "http", "method": "GET",
                      "url": "{{input.target}}/healthz", "save": "surface",
                      "allow_failure": True, "timeout_ms": 8000})
        for index, path in enumerate(extracted["paths"], start=1):
            steps.append(_step_for_path(index, path, writes))
        if len(steps) > 1:
            condition = f"steps.probe1.status == 200 or steps.probe1.status == 201"
        else:
            condition = "steps.surface.ok == true"
        checks.append({"id": "surface-reachable",
                       "when": "steps.surface.status != null",
                       "message": "target did not answer the surface probe"})
    snapshot_key = next((key for key in ("snapshot", "fixture", "collection", "deploy_snapshot",
                                         "posture", "manifest", "inventory")
                         if key in params), "")
    if snapshot_key:
        inputs[snapshot_key] = {"from": f"params.{snapshot_key}", "required": True,
                                "description": "Collected snapshot / fixture path"}
        steps.append({"id": "snapshot", "op": "fs", "action": "read",
                      "path": f"{{{{input.{snapshot_key}}}}}", "json": True,
                      "save": "snapshot", "allow_failure": False})
        checks.append({"id": "snapshot-readable",
                       "when": "steps.snapshot.ok == true", "fatal": True,
                       "message": "snapshot is not readable JSON"})
        if not condition.startswith("steps."):
            condition = "steps.snapshot.exists == true"
    if not steps:
        steps.append({"id": "host", "op": "fs", "action": "stat", "path": "/",
                      "save": "host", "allow_failure": True})
        checks.append({"id": "host-readable", "when": "steps.host.exists == true",
                       "message": "probe filesystem is not readable"})

    findings = []
    for index, item in enumerate(extracted["findings"][:6], start=1):
        finding = {
            "id": f"f{index}",
            "when": condition,
            "sev": item["sev"],
            "title": item["title"],
            "detail": "Declarative probe assertion (baseline migrated from the module rule).",
            "evidence": "{{steps.probe1.status}}" if "probe1" in {s["id"] for s in steps}
            else "{{steps.snapshot.path}}",
            "mapping": str(raw.get("knowledge") or ""),
            "fix": "",
        }
        if raw.get("verification_cves") and index == 1:
            finding["cves"] = list(raw["verification_cves"])
            finding["version_matrix"] = {
                "product": str(raw.get("key", "")).split("-")[0],
                "source": "steps.snapshot.json.version",
                "vulnerable": ["<*"],
                "note": "version matrix declared by module metadata; refine during migration",
            }
        findings.append(finding)
    if not findings:
        findings.append({
            "id": "observed",
            "when": condition,
            "sev": "info",
            "title": f"{raw.get('name', {}).get('zh') or raw['key']}：部署面已观测",
            "detail": "Template executed and the declared surface responded; no exploitable condition asserted.",
            "evidence": "steps",
        })

    template = {
        "schema": "inkblade-probe-template-v1",
        "key": raw["key"],
        "version": "1.0.0",
        "meta": {
            "name": raw["name"],
            "series": raw["series"],
            "min_level": raw["min_level"],
            "writes": writes,
            "requires": list(raw.get("requires") or []),
            "surfaces": [str(s) for s in (raw.get("surfaces") or [])],
            "cves": list(raw.get("verification_cves") or []),
            "fidelity": "reduced",
        },
        "inputs": inputs,
        "defaults": {"timeout_ms": 8000, "tls_verify": False},
        "steps": steps,
        "checks": checks,
        "findings": findings,
        "artifacts": [{"name": f"{raw['key']}-probe.json", "from": "steps", "kind": "json"}],
        "payloads": {
            "benign": {"marker": "INKBLADE-BENIGN", "note": "no exploit payload"},
        },
        "limits": {"timeout_ms": 60000, "max_http_requests": 64},
    }
    if writes:
        template["modes"] = {"probe_only": True, "backup_write": True,
                             "requires_backup": True}
        template["payloads"]["attack"] = {"marker": "{{ctx.marker}}",
                                          "note": "write-surface demo; requires backup receipt"}
    return template


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--modules", default=str(ROOT / "inkblade" / "modules"))
    parser.add_argument("--keys", nargs="*", default=[])
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    modules_dir = Path(args.modules)
    written, skipped, errors = 0, 0, []
    for module_dir in sorted(p for p in modules_dir.iterdir()
                             if p.is_dir() and (p / "module.json").exists()):
        raw = json.loads((module_dir / "module.json").read_text(encoding="utf-8"))
        key = raw.get("key") or module_dir.name
        if args.keys and key not in args.keys:
            continue
        if str(raw.get("execution") or "template") == "bootstrap":
            continue
        target = module_dir / "template.json"
        if target.exists() and not args.force:
            skipped += 1
            continue
        doc = build(module_dir)
        problems = validate(doc, module_dir=module_dir, module_meta=raw)
        if problems:
            errors.extend(f"{key}: {problem}" for problem in problems)
            continue
        if not args.check:
            target.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n",
                              encoding="utf-8")
        written += 1
    print(f"written={written} skipped={skipped} errors={len(errors)}")
    for error in errors:
        print("ERROR", error)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
