#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate the module coverage table (module / execution / template / dynamic-tested / evidence).

Inputs:
  * every ``inkblade/modules/*/module.json`` and ``template.json``
  * ``reports/probe-coverage/evidence.json`` written by dynamic template tests
    (``tests/test_probe_templates_dynamic.py`` and per-batch suites)

Outputs (with ``--write``):
  * ``docs/PROBE-COVERAGE.md``
  * ``reports/probe-coverage/coverage.json``
"""
from __future__ import annotations

import argparse
import collections
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from inkblade.tpl.probe import bootstrap_modules  # noqa: E402
from inkblade.tpl.schema import describe, load_template  # noqa: E402

EVIDENCE_PATH = ROOT / "reports" / "probe-coverage" / "evidence.json"
DOC_PATH = ROOT / "docs" / "PROBE-COVERAGE.md"
JSON_PATH = ROOT / "reports" / "probe-coverage" / "coverage.json"
DEFENSE = [
    "defense-bypass-elkeid", "defense-bypass-agentsmith", "defense-bypass-veinmind",
    "defense-bypass-falco", "defense-bypass-tetragon", "defense-bypass-kubearmor",
    "defense-bypass-admission", "defense-bypass-imagescan", "defense-bypass-hostagent",
    "defense-bypass-waf-inference", "defense-bypass-netobserv",
]


def load_evidence() -> dict:
    try:
        return json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def collect(modules_dir: Path) -> list[dict]:
    rows = []
    for module_dir in sorted(p for p in modules_dir.iterdir()
                             if p.is_dir() and (p / "module.json").exists()):
        raw = json.loads((module_dir / "module.json").read_text(encoding="utf-8"))
        key = raw.get("key") or module_dir.name
        execution = str(raw.get("execution") or "template")
        row = {
            "module": key,
            "series": raw.get("series"),
            "execution": execution,
            "template": False,
            "steps": 0,
            "checks": 0,
            "findings": 0,
            "fidelity": "n/a",
            "writes": bool(raw.get("writes")),
            "min_level": raw.get("min_level"),
        }
        if execution == "template" and (module_dir / "template.json").is_file():
            try:
                doc = load_template(module_dir, module_meta=raw)
                meta = describe(doc, module_dir)
                row.update(template=True, steps=meta.steps, checks=meta.checks,
                           findings=meta.findings, fidelity=meta.fidelity)
                from inkblade.tpl.lower import compile_template

                compilation = compile_template(doc, {"mode": "backup-write", "target": ""},
                                               {"marker": "INKBLADE-COVERAGE"})
                row["native_ready"] = compilation.native_ready
                row["native_gaps"] = len(compilation.gaps)
                row["gap_reasons"] = sorted({g["reason"] for g in compilation.gaps})
            except Exception as exc:  # noqa: BLE001 - invalid templates stay visible
                row["error"] = f"{type(exc).__name__}: {exc}"
        rows.append(row)
    return rows


def build(rows: list[dict], evidence: dict) -> dict:
    entries = []
    evidence_entries = evidence.get("entries") or {}
    native_meta = evidence.get("native_runtime") or {}
    for row in rows:
        ev = evidence_entries.get(row["module"]) or {}
        entries.append({
            **row,
            "dynamic_tested": bool(ev.get("tested")),
            "dynamic_mode": ev.get("mode", ""),
            "evidence": ev.get("evidence", ""),
            "evidence_at": ev.get("at", ""),
            "evidence_runtime": ev.get("runtime", ""),
            "probe_version": ev.get("probe_version", ""),
            "repeat": ev.get("repeat", 0),
            "consistent": bool(ev.get("consistent")),
            "negative_status": ev.get("negative_status", ""),
            "same_finding": bool(ev.get("same_finding")),
            "binary_sha256": ev.get("binary_sha256", ""),
            "source_commit": ev.get("source_commit", ""),
            "defense_matrix": ev.get("defense_matrix") or {},
            "evidence_note": ev.get("note", ""),
        })
    templates = [e for e in entries if e["execution"] == "template"]
    dynamic = [e for e in templates if e["dynamic_tested"]]
    native = [e for e in templates if e["dynamic_tested"]
              and str(e.get("evidence_runtime") or "").startswith("rust")]
    summary = {
        "schema": "inkblade-probe-coverage-v1",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "modules": len(entries),
        "templates": len(templates),
        "bootstrap": sum(1 for e in entries if e["execution"] == "bootstrap"),
        "dynamic_tested": len(dynamic),
        "native_tested": len(native),
        "native_binary_sha256": next((e.get("binary_sha256") for e in native
                                      if e.get("binary_sha256")), ""),
        "native_source_commit": next((e.get("source_commit") for e in native
                                      if e.get("source_commit")), ""),
        "probe_version": next((e.get("probe_version") for e in native
                               if e.get("probe_version")), ""),
        "repeat": max((e.get("repeat") or 0) for e in native) if native else 0,
        "consistent": sum(1 for e in native if e.get("consistent")),
        "negative_clean": sum(1 for e in native if not e.get("same_finding")),
        "fixed_status_ok": sum(1 for e in native if e.get("negative_status") == "ok"),
        "native_duration_s": int(native_meta.get("duration_s") or 0),
        "coverage_pct": round(100.0 * len(dynamic) / len(templates), 2) if templates else 0.0,
        "equivalent": sum(1 for e in templates if e["fidelity"] == "equivalent"),
        "reduced": sum(1 for e in templates if e["fidelity"] == "reduced"),
        "native_ready": sum(1 for e in templates if e.get("native_ready")),
        "native_gaps": sum(e.get("native_gaps", 0) for e in templates),
        "writes": sum(1 for e in templates if e["writes"]),
        "series": dict(collections.Counter(e["series"] for e in entries)),
        "evidence_file": str(EVIDENCE_PATH.relative_to(ROOT)).replace("\\", "/"),
        "bootstrap_modules": [m.get("key") for m in bootstrap_modules()],
        "host_execution": "probe-bootstrap only (Rust probe drop); no adapter/host fallback",
    }
    return {"summary": summary, "entries": entries}


def render(result: dict) -> str:
    s = result["summary"]
    lines = [
        "# Probe coverage — 全量模块模板化与动态验证",
        "",
        f"> Generated by `tools/template-coverage.py` at {s['generated_at']}. "
        "Evidence: `" + s["evidence_file"] + "`.",
        "",
        "## 1. Summary",
        "",
        f"- Modules: **{s['modules']}** (templates **{s['templates']}**, "
        f"bootstrap **{s['bootstrap']}**)",
        f"- Dynamic template verification: **{s['dynamic_tested']}/{s['templates']} "
        f"({s['coverage_pct']}%)** — Rust-native **{s['native_tested']}** "
        f"(binary `{s['native_binary_sha256'][:12]}…`, source `{s['native_source_commit']}`, "
        f"probe `{s['probe_version']}`)",
        f"- Fidelity: equivalent **{s['equivalent']}**, reduced **{s['reduced']}**",
        f"- Repeat consistency: **{s['consistent']}/{s['templates']}** identical over "
        f"{s['repeat']} runs per state (canonical digest; volatile port/date/order masked)",
        f"- Negative control: fixed state without the same finding "
        f"**{s['negative_clean']}/{s['templates']}**; fixed `status=ok` "
        f"**{s['fixed_status_ok']}/{s['templates']}** (fixture-bound templates share inputs "
        "across both states — see §6)",
        f"- Native sweep duration: **{s['native_duration_s']}s** over the SSH framed protocol "
        "(QEMU TCG guest)",
        f"- Rust-native readiness (static compile): **{s['native_ready']}/{s['templates']}** "
        f"(gaps: {s['native_gaps']} op(s))",
        f"- Write-capable templates: **{s['writes']}** (RoE + backup + audit unchanged)",
        f"- Host execution: **{s['host_execution']}**",
        f"- Bootstrap registry: {', '.join('`'+k+'`' for k in s['bootstrap_modules'])}",
        "",
        "## 2. By series",
        "",
        "| Series | Modules |",
        "|---|---:|",
    ]
    for name, count in sorted(s["series"].items(), key=lambda kv: -kv[1]):
        lines.append(f"| {name} | {count} |")
    lines += ["", "## 3. Defense bypass (11) — detection / blindspot / hardening", "",
              "| Module | Dynamic | Mode | Detected | Blindspots | Hardening | Evidence |",
              "|---|---|---|---:|---:|---:|---|"]
    by_key = {e["module"]: e for e in result["entries"]}
    for key in DEFENSE:
        e = by_key.get(key)
        if not e:
            lines.append(f"| `{key}` | missing | — | — | — | — | — |")
            continue
        m = e.get("defense_matrix") or {}
        lines.append(f"| `{key}` | {'yes' if e['dynamic_tested'] else 'no'} | "
                     f"{e['dynamic_mode'] or '—'} | {m.get('detected', '—')} | "
                     f"{m.get('blindspots', '—')} | {m.get('hardening', '—')} | "
                     f"`{(e['evidence'] or '')[:16]}` |")
    lines += ["", "## 4. Full module table", "",
              "| Module | Series | Execution | Steps | Checks | Findings | Fidelity | Native | Runtime | Dynamic-tested | Evidence |",
              "|---|---|---|---:|---:|---:|---|---|---|---|---|"]
    for e in result["entries"]:
        lines.append(
            f"| `{e['module']}` | {e['series']} | {e['execution']} | {e['steps']} | "
            f"{e['checks']} | {e['findings']} | {e['fidelity']} | "
            f"{'yes' if e.get('native_ready') else 'gap' if e['execution'] == 'template' else '—'} | "
            f"{e.get('evidence_runtime') or '—'} | "
            f"{'yes' if e['dynamic_tested'] else 'no'} | "
            f"`{(e['evidence'] or '')[:16]}` |")
    lines += ["", "## 5. Contract", "",
              "- Every module is a declarative template (`template.json`), executed natively by "
              "the Rust probe (`inkblade-probe run-template`/`task`).",
              "- No Python, shell interpreter or module code is dropped into the target Pod.",
              "- `probe-bootstrap` is the only host-executed module and only drops the Rust binary.",
              "- Missing probe / missing target surface fails explicitly; there is no adapter or "
              "host fallback.",
              "- Legacy per-family Python tests for `run.py` internals were retired with the "
              "execution path; `tests/test_probe_*.py` replace them with two-state template "
              "execution and evidence digests.",
              "",
              "## 6. What the native sweep does and does not prove",
              "",
              "- Proves: every template lowers to the Rust template engine, runs in a real Linux "
              "guest through the framed SSH protocol, returns a non-error result in the "
              "`vulnerable` state, and repeats identically (canonical digest) over "
              f"{s['repeat']} runs per state.",
              "- Does not prove: a true negative control for every template. Templates whose "
              "inputs come from a fixture file (not from the mock target) receive the same input "
              "in both states, so the `fixed` run can still report the same finding. "
              f"**{s['templates'] - s['negative_clean']}/{s['templates']}** templates report the same "
              "finding in both states and are execution-verified only; "
              f"**{s['negative_clean']}/{s['templates']}** report no identical finding, and "
              f"**{s['fixed_status_ok']}/{s['templates']}** return `status=ok` in the fixed state — only "
              "that last group meets the strict `verified` definition in `DYNAMIC-VERIFICATION.md` §8.",
              "- The target is a local mock range (`lab/template_range.py`), not a production "
              "cluster; findings demonstrate detection logic, not live exposure.",
              ""]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--modules", default=str(ROOT / "inkblade" / "modules"))
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    rows = collect(Path(args.modules))
    result = build(rows, load_evidence())
    if args.write:
        DOC_PATH.parent.mkdir(parents=True, exist_ok=True)
        JSON_PATH.parent.mkdir(parents=True, exist_ok=True)
        DOC_PATH.write_text(render(result), encoding="utf-8")
        JSON_PATH.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n",
                             encoding="utf-8")
    if args.json:
        print(json.dumps(result["summary"], ensure_ascii=False, indent=2))
    else:
        print(json.dumps(result["summary"], ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
