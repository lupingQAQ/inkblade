"""``inkblade sdk`` - plugin authoring and validation commands.

    python -m inkblade.sdk lint  <plugin-dir> [<plugin-dir> ...]
    python -m inkblade.sdk new   <key> --dest plugins [--series recon]
    python -m inkblade.sdk trust <plugin-dir> --store trust.json
    python -m inkblade.sdk run   <plugin-dir> --params-json '{...}' [--store trust.json]
    python -m inkblade.sdk list  <plugins-root>

Exit codes: 0 success, 1 validation/runtime failure, 2 usage error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .loader import (
    PluginError,
    load_plugin,
    plugin_fingerprint,
    read_trust_store,
    run_plugin,
)
from .manifest import lint_manifest
from .scaffold import scaffold_plugin


def _cmd_lint(args: argparse.Namespace) -> int:
    failures = 0
    for target in args.paths:
        report = lint_manifest(target)
        key = report.get("key") or Path(target).name
        if report["errors"]:
            failures += 1
            print(f"FAIL {key}")
            for err in report["errors"]:
                print(f"  error: {err}")
        else:
            print(f"ok   {key}")
        for warning in report["warnings"]:
            print(f"  warn: {warning}")
    return 0 if failures == 0 else 1


def _cmd_new(args: argparse.Namespace) -> int:
    try:
        path = scaffold_plugin(
            args.dest,
            args.key,
            title=args.title,
            description=args.description or "",
            series=args.series,
            min_level=args.min_level,
            writes=args.writes,
            publisher=args.publisher or "",
            license=args.license,
            homepage=args.homepage or "",
            force=args.force,
        )
    except PluginError as exc:
        print(f"sdk new: {exc}", file=sys.stderr)
        return 1
    print(f"sdk new: {path}")
    print("next: inkblade sdk lint " + str(path))
    return 0


def _cmd_trust(args: argparse.Namespace) -> int:
    root = Path(args.path)
    try:
        fingerprint = plugin_fingerprint(root)
        store_path = Path(args.store)
        if store_path.exists():
            store = read_trust_store(store_path)
        else:
            store = {"version": 1, "plugins": {}}
        plugins = store.setdefault("plugins", {})
        key = root.name
        try:
            manifest_key = json.loads((root / "module.json").read_text(encoding="utf-8"))["key"]
            key = str(manifest_key)
        except (OSError, ValueError, KeyError):
            pass
        plugins[key] = {
            "fingerprint": fingerprint,
            "publisher": args.publisher or "",
            "allow": True,
        }
        store_path.parent.mkdir(parents=True, exist_ok=True)
        store_path.write_text(
            json.dumps(store, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
    except (PluginError, OSError) as exc:
        print(f"sdk trust: {exc}", file=sys.stderr)
        return 1
    print(f"sdk trust: {key} -> {fingerprint}")
    print(f"sdk trust: store {store_path}")
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    try:
        params = json.loads(args.params_json) if args.params_json else {}
    except ValueError as exc:
        print(f"sdk run: --params-json is not valid JSON: {exc}", file=sys.stderr)
        return 2
    if not isinstance(params, dict):
        print("sdk run: --params-json must be a JSON object", file=sys.stderr)
        return 2
    try:
        plugin = load_plugin(
            args.path,
            trust_store=args.store,
            allow_unsigned=args.allow_unsigned,
        )
        result = run_plugin(plugin, params, workspace=args.workspace, marker=args.marker)
    except PluginError as exc:
        print(f"sdk run: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 - plugin code, reported not swallowed
        print(f"sdk run: plugin raised {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"plugin   : {plugin.manifest.key} ({plugin.manifest.series} / "
              f"{plugin.manifest.min_level}, writes={plugin.manifest.writes})")
        print(f"fingerprint: {plugin.fingerprint}")
        print(f"trusted  : {plugin.trusted} ({plugin.trust_source or 'unsigned'})")
        print(f"summary  : {result['summary']}")
        for finding in result["findings"]:
            print(f"  [{finding['sev']}] {finding['title']}")
        for artifact in result["artifacts"]:
            print(f"  artifact: {artifact}")
        print(f"run dir  : {result['run_dir']}")
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    root = Path(args.plugins_root)
    if not root.is_dir():
        print(f"sdk list: not a directory: {root}", file=sys.stderr)
        return 2
    count = 0
    for child in sorted(root.iterdir()):
        if not (child / "module.json").is_file():
            continue
        report = lint_manifest(child)
        status = "ok" if not report["errors"] else "FAIL"
        series = report.get("series") or "-"
        print(f"{status:4} {child.name:32} {series}")
        count += 1
    print(f"sdk list: {count} plugin(s) under {root}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="inkblade sdk",
        description="InkBlade plugin SDK: scaffold, lint, trust and run plugins",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    lint = sub.add_parser("lint", help="validate one or more plugin directories")
    lint.add_argument("paths", nargs="+")
    lint.set_defaults(func=_cmd_lint)

    validate = sub.add_parser("validate", help="alias of lint (CI friendly)")
    validate.add_argument("paths", nargs="+")
    validate.set_defaults(func=_cmd_lint)

    new = sub.add_parser("new", help="scaffold a plugin from the module template")
    new.add_argument("key")
    new.add_argument("--dest", default="plugins")
    new.add_argument("--title", default=None)
    new.add_argument("--description", default="")
    new.add_argument("--series", default="recon")
    new.add_argument("--min-level", default="read-only", dest="min_level")
    new.add_argument("--writes", action="store_true")
    new.add_argument("--publisher", default="")
    new.add_argument("--license", default="Apache-2.0")
    new.add_argument("--homepage", default="")
    new.add_argument("--force", action="store_true")
    new.set_defaults(func=_cmd_new)

    trust = sub.add_parser("trust", help="pin a plugin fingerprint in a trust store")
    trust.add_argument("path")
    trust.add_argument("--store", default="trust.json")
    trust.add_argument("--publisher", default="")
    trust.set_defaults(func=_cmd_trust)

    run = sub.add_parser("run", help="load and execute a plugin")
    run.add_argument("path")
    run.add_argument("--params-json", default="{}")
    run.add_argument("--workspace", default=None)
    run.add_argument("--store", default=None)
    run.add_argument("--allow-unsigned", action="store_true")
    run.add_argument("--marker", default="INKBLADE")
    run.add_argument("--json", action="store_true")
    run.set_defaults(func=_cmd_run)

    listing = sub.add_parser("list", help="lint every plugin under a directory")
    listing.add_argument("plugins_root")
    listing.set_defaults(func=_cmd_list)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
