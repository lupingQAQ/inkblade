#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Run one declarative template against a target or the mock range.

Examples::

    python tools/template-run.py --module cache-timing-sidechannel --range
    python tools/template-run.py --module defense-bypass-falco \
        --fixture lab/defense-deploy/fixtures/falco-deployed.json
    python tools/template-run.py --module kubelet-surface --target http://127.0.0.1:30080

Uses the reference conformance runtime (``INKBLADE_ALLOW_REFERENCE_PROBE=1``)
unless a real probe session is supplied through ``--probe-binary``.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from inkblade.tpl.execute import prepare_params  # noqa: E402
from inkblade.tpl.probe import RustProbe, local_executor, resolve_probe  # noqa: E402
from inkblade.tpl.schema import load_template  # noqa: E402


def _params(raw: str) -> dict:
    if not raw:
        return {}
    if raw.startswith("@"):
        return json.loads(Path(raw[1:]).read_text(encoding="utf-8"))
    return json.loads(raw)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--module", required=True)
    parser.add_argument("--modules", default=str(ROOT / "inkblade" / "modules"))
    parser.add_argument("--params", default="{}")
    parser.add_argument("--target", default="")
    parser.add_argument("--fixture", default="")
    parser.add_argument("--snapshot", default="")
    parser.add_argument("--collection", default="")
    parser.add_argument("--mode", default="")
    parser.add_argument("--payload-variant", default="")
    parser.add_argument("--range", action="store_true", help="start the mock range")
    parser.add_argument("--probe-binary", default="")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    module_dir = Path(args.modules) / args.module
    if not (module_dir / "module.json").is_file():
        print(f"unknown module: {args.module}", file=sys.stderr)
        return 2
    module_meta = json.loads((module_dir / "module.json").read_text(encoding="utf-8"))
    template = load_template(module_dir, module_meta=module_meta)
    params = prepare_params(template, _params(args.params))
    for key in ("target", "fixture", "snapshot", "collection", "mode", "payload_variant"):
        value = getattr(args, key)
        if value:
            params[key] = value

    range_obj = None
    if args.range:
        sys.path.insert(0, str(ROOT / "lab"))
        from template_range import Range

        range_obj = Range().start()
        params.setdefault("target", range_obj.url())
        params.setdefault("snapshot", range_obj.fixture("snapshot.json", {
            "nodes": [{"name": "node-1", "kubelet": {"anonymousAuth": True}}],
            "pods": [{"metadata": {"name": "lab", "namespace": "default"}}],
        }))
    try:
        probe = None
        if args.probe_binary:
            probe = RustProbe(args.probe_binary, local_executor(args.probe_binary))
            os.environ["INKBLADE_PROBE_BIN"] = args.probe_binary
        else:
            os.environ["INKBLADE_ALLOW_REFERENCE_PROBE"] = "1"
        backend = resolve_probe(None, probe)
        result = backend.run(template, params, {"marker": "INKBLADE-LAB",
                                                "run": "lab", "module": args.module})
    finally:
        if range_obj is not None:
            range_obj.stop()

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"{args.module}: status={result.get('status')} "
              f"runtime={result.get('runtime')} findings={len(result.get('findings') or [])}")
        for step in result.get("steps") or []:
            print(f"  step {step.get('id')}: ok={step.get('ok')} "
                  f"status={step.get('status')} error={step.get('error') or ''}")
        for finding in result.get("findings") or []:
            print(f"  [{finding.get('sev')}] {finding.get('title')}")
    return 0 if result.get("status") != "error" else 1


if __name__ == "__main__":
    raise SystemExit(main())
