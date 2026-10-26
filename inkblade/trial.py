"""``inkblade trial`` - one command that proves the install works.

Runs the offline demo (mock lab on loopback, synthetic data, no cluster access),
then prints the produced artifacts, a machine-readable trial report and the next
steps for a real pilot. Intended as the first command a new evaluator runs after
``pip install inkblade``.

Nothing here touches a real cluster: the demo lab binds to 127.0.0.1 and is torn
down before the command returns.
"""

from __future__ import annotations

import contextlib
import io
import json
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import VERSION

SCHEMA = "inkblade-trial/1"

DOCS = {
    "trial": "docs/TRIAL.md",
    "pilot": "docs/PILOT-KIT.md",
    "feedback": "docs/FEEDBACK.md",
    "plugin_sdk": "docs/PLUGIN-SDK.md",
    "audit": "docs/AUDIT-PACKAGE.md",
    "security": "SECURITY.md",
}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def _inventory(out: Path) -> list[dict[str, Any]]:
    reports = out / "reports"
    workspace = out / "workspace"
    candidates = [
        ("pentest report", reports / "pentest-bi.md"),
        ("remediation report", reports / "remediation-bi.md"),
        ("demo summary", reports / "summary.json"),
        ("rules pack", out / "rules-pack"),
        ("static UI", out / "webui" / "index.html"),
        ("evidence workspace", workspace),
    ]
    items: list[dict[str, Any]] = []
    for label, path in candidates:
        if path.is_dir():
            files = sum(1 for p in path.rglob("*") if p.is_file())
            items.append({"label": label, "path": str(path.resolve()),
                          "kind": "dir", "files": files, "exists": True})
        else:
            items.append({"label": label, "path": str(path.resolve()),
                          "kind": "file", "bytes": _size(path), "exists": path.exists()})
    return items


def _print_card(report: dict[str, Any]) -> None:
    demo = report.get("demo") or {}
    print("")
    print("InkBlade trial" + (" (offline demo)" if demo else " (environment check only)"))
    print("=" * 62)
    print(f"version   : {report['version']}  python {report['python']}  {report['platform']}")
    print(f"mode      : {report['mode']}")
    if demo:
        print(f"chain     : {demo.get('chain', {}).get('id', '?')} "
              f"({demo.get('chain', {}).get('seconds', '?')}s)")
        findings = demo.get("findings") or {}
        print(f"findings  : {findings.get('total', 0)} total "
              f"{findings.get('by_severity', {})}")
        print(f"elapsed   : {demo.get('elapsed_seconds', '?')}s (mock lab on 127.0.0.1)")
    print("")
    print("Artifacts" + (" (expected)" if report["mode"] != "offline-demo" else ""))
    for item in report["artifacts"]:
        if item["exists"]:
            mark = "ok "
        elif report["mode"] == "offline-demo":
            mark = "MISSING"
        else:
            mark = "plan"
        print(f"  [{mark:<7}] {item['label']:<20} {item['path']}")
    print("")
    print("Report")
    print(f"  {report['report_path']}")
    print("")
    print("Next steps")
    for index, step in enumerate(report["next_steps"], 1):
        print(f"  {index}. {step}")
    print("")
    print("Docs")
    for label, path in DOCS.items():
        print(f"  {label:<12} {path}")
    print("")


def _next_steps(out: Path, report_path: Path, kubeconfig: str | None) -> list[str]:
    steps = [
        "read the trial report: " + str(report_path),
        "open the static UI: " + str((out / "webui" / "index.html").resolve()),
        "self-check: inkblade doctor --mode mock --json",
        "guided setup: inkblade quickstart",
    ]
    if kubeconfig:
        steps.append("read-only cluster pilot: inkblade pilot --kubeconfig <path> "
                     "--snapshot <snapshot.json> (see docs/PILOT-KIT.md)")
    else:
        steps.append("when you have authorization: inkblade pilot --kubeconfig <path> "
                     "(see docs/PILOT-KIT.md)")
    steps.append("author a plugin: inkblade sdk new my-check --dest plugins "
                 "(see docs/PLUGIN-SDK.md)")
    steps.append("send feedback: docs/FEEDBACK.md")
    return steps


def run_trial(
    out: str | Path = "demo-trial",
    *,
    no_demo: bool = False,
    json_out: bool = False,
    kubeconfig: str | None = None,
) -> int:
    """Public build: the offline synthetic trial is not shipped."""
    from .onboarding import PUBLIC_DEMO_MSG

    if json_out:
        print(json.dumps(
            {"schema": SCHEMA, "ok": False, "unsupported": "synthetic-range",
             "message": PUBLIC_DEMO_MSG},
            ensure_ascii=False, indent=2,
        ))
        return 2
    print("inkblade trial: " + PUBLIC_DEMO_MSG, file=sys.stderr)
    return 2

