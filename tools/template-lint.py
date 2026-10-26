#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Lint every declarative probe template against the contract.

Checks:
  * module.json <-> template.json metadata equality
  * schema + expression syntax (inkblade/tpl/schema.py)
  * no run.py / no Python execution path remains
  * every module declares execution=template except the bootstrap registry
  * findings/checks/steps/artifact ids are unique and complete

Exit code 0 only when every module passes.
"""
from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from inkblade.tpl.probe import is_bootstrap  # noqa: E402
from inkblade.tpl.schema import describe, load_template, validate  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--modules", default=str(ROOT / "inkblade" / "modules"))
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--strict", action="store_true",
                        help="fail when run.py is still present (release gate)")
    args = parser.parse_args()
    modules_dir = Path(args.modules)
    errors: list[str] = []
    warnings: list[str] = []
    rows: list[dict] = []
    series: collections.Counter = collections.Counter()

    dirs = sorted(p for p in modules_dir.iterdir() if p.is_dir() and (p / "module.json").exists())
    for module_dir in dirs:
        raw = json.loads((module_dir / "module.json").read_text(encoding="utf-8"))
        key = raw.get("key") or module_dir.name
        execution = str(raw.get("execution") or "template")
        if (module_dir / "run.py").exists():
            message = f"{key}: run.py 仍存在（Python 模块执行路径必须删除）"
            if args.strict:
                errors.append(message)
            else:
                warnings.append(message)
        if execution == "bootstrap":
            if not is_bootstrap(key):
                errors.append(f"{key}: bootstrap 未登记于 probe-bootstrap.json")
            if not (module_dir / "bootstrap.py").exists():
                errors.append(f"{key}: bootstrap 模块缺 bootstrap.py")
            rows.append({"module": key, "execution": "bootstrap", "series": raw.get("series"),
                         "steps": 0, "findings": 0, "checks": 0, "fidelity": "n/a"})
            series[raw.get("series")] += 1
            continue
        if execution != "template":
            errors.append(f"{key}: 未知 execution={execution!r}")
            continue
        if not (module_dir / "template.json").is_file():
            errors.append(f"{key}: 缺 template.json")
            continue
        try:
            doc = json.loads((module_dir / "template.json").read_text(encoding="utf-8"))
            problems = validate(doc, module_dir=module_dir, module_meta=raw)
        except (ValueError, OSError) as exc:
            errors.append(f"{key}: {exc}")
            continue
        if problems:
            errors.extend(f"{key}: {problem}" for problem in problems)
            continue
        meta = describe(doc, module_dir)
        for field_name in ("requires",):
            if list(raw.get(field_name) or []) != list(meta.requires):
                errors.append(f"{key}: {field_name} 与 module.json 不一致")
        rows.append({"module": key, "execution": "template", "series": raw.get("series"),
                     "steps": meta.steps, "findings": meta.findings, "checks": meta.checks,
                     "fidelity": meta.fidelity})
        series[raw.get("series")] += 1

    summary = {
        "modules": len(rows),
        "templates": sum(1 for r in rows if r["execution"] == "template"),
        "bootstrap": sum(1 for r in rows if r["execution"] == "bootstrap"),
        "findings": sum(r["findings"] for r in rows),
        "steps": sum(r["steps"] for r in rows),
        "checks": sum(r["checks"] for r in rows),
        "series": dict(series),
        "errors": errors,
        "warnings": warnings,
    }
    if args.json:
        print(json.dumps({"summary": summary, "rows": rows}, ensure_ascii=False, indent=2))
    elif not args.quiet:
        print(f"modules={summary['modules']} templates={summary['templates']} "
              f"bootstrap={summary['bootstrap']} steps={summary['steps']} "
              f"checks={summary['checks']} findings={summary['findings']}")
        for name, count in sorted(series.items()):
            print(f"  {name}: {count}")
        for warning in warnings[:3]:
            print(f"WARN {warning}")
        for error in errors:
            print(f"ERROR {error}")
    if errors:
        print(f"\n{len(errors)} error(s)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
