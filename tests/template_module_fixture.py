# -*- coding: utf-8 -*-
"""Helpers that build declarative template fixtures for tests.

Production modules have no run.py; tests that need a synthetic module create
module.json + template.json here.
"""
from __future__ import annotations

import json
from pathlib import Path


def write_template_module(root: Path, key: str, *, series: str = "横向利用",
                          min_level: str = "只读侦察", writes: bool = False,
                          requires=None, fail: bool = False, touch: str = "",
                          expect_first: str = "", sleep: float = 0.0,
                          finding: bool = True, finding_title: str = "step-done",
                          finding_sev: str = "info", target_write: str = "",
                          content: str = "INKBLADE-{{ctx.marker}}",
                          flat: bool = False) -> Path:
    d = (Path(root) if flat else Path(root) / "modules") / key
    d.mkdir(parents=True, exist_ok=True)
    meta = {"key": key, "name": {"zh": key, "en": key}, "series": series,
            "description": "template fixture", "min_level": min_level,
            "writes": bool(writes), "requires": list(requires or [])}
    (d / "module.json").write_text(json.dumps(meta, ensure_ascii=False), encoding="utf-8")
    steps = []
    checks = []
    if fail:
        steps.append({"id": "boom", "op": "fs", "action": "read",
                      "path": str(Path(root) / "missing-boom.txt"), "save": "boom"})
    elif expect_first:
        steps.append({"id": "read", "op": "fs", "action": "read",
                      "path": expect_first, "save": "read"})
        checks.append({"id": "expect-first", "fatal": True,
                       "when": "steps.read.text == 'probe-first-done'",
                       "message": "dependency output mismatch"})
    elif target_write:
        steps.append({"id": "write", "op": "fs", "action": "write",
                      "path": target_write, "content": content, "save": "write",
                      "write": bool(writes)})
    else:
        steps.append({"id": "noop", "op": "fs", "action": "stat", "path": "/",
                      "save": "noop"})
    if touch and not target_write:
        steps.append({"id": "touch", "op": "fs", "action": "write",
                      "path": touch, "content": f"{key}-done", "save": "touch"})
    template = {
        "schema": "inkblade-probe-template-v1", "key": key, "version": "1.0.0",
        "meta": {"name": meta["name"], "series": series, "min_level": min_level,
                 "writes": bool(writes), "requires": list(requires or []),
                 "surfaces": ["test-fixture"], "cves": [], "fidelity": "equivalent"},
        "steps": steps, "checks": checks,
        "findings": ([{"id": "f", "sev": finding_sev, "title": finding_title,
                       "detail": "ok", "when": "true"}] if finding else []),
        "limits": {"timeout_ms": 5000},
    }
    if writes:
        template["modes"] = {"probe_only": True, "backup_write": True,
                             "requires_backup": True}
    (d / "template.json").write_text(json.dumps(template, ensure_ascii=False, indent=1),
                                     encoding="utf-8")
    return d
