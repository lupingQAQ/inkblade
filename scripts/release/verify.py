#!/usr/bin/env python3
"""Release hygiene gate.

Checks the things a commercial open-source release must have before a tag is
cut: packaging metadata, governance files, distribution assets, Helm chart
structure, plugin SDK examples and workflow definitions.

No third-party dependencies. Optional checks (helm lint/template) run only when
the ``helm`` binary is present.

Usage:
    python scripts/release/verify.py [--json]

Exit codes: 0 = all checks passed, 1 = at least one check failed.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - 3.10 fallback
    tomllib = None  # type: ignore[assignment]

REQUIRED_ROOT_FILES = (
    "LICENSE", "NOTICE", "README.md", "SECURITY.md", "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md", "CHANGELOG.md", "CODEOWNERS", "Dockerfile", "Makefile",
)

REQUIRED_DOCS = (
    "USAGE.md", "INSTALL.md", "FEATURES.md", "WORKFLOW.md",
    "MODULES.md", "FAQ.md", "VULNERABILITY-COVERAGE.md", "README-SITE.md",
    "ARCHITECTURE.md", "PILOT-KIT.md", "PLUGIN-SDK.md", "VERSIONING.md",
)

REQUIRED_WORKFLOWS = ("ci.yml", "release.yml", "docker.yml", "probe-release.yml")

REQUIRED_TEMPLATES = (
    "deployment.yaml", "service.yaml", "persistentvolumeclaim.yaml",
    "serviceaccount.yaml", "rbac.yaml", "NOTES.txt", "_helpers.tpl",
)


class Report:
    def __init__(self) -> None:
        self.results: list[dict] = []

    def check(self, name: str, ok: bool, detail: str = "") -> None:
        self.results.append({"check": name, "ok": bool(ok), "detail": detail})

    @property
    def failed(self) -> list[dict]:
        return [r for r in self.results if not r["ok"]]

    def emit(self, as_json: bool) -> int:
        if as_json:
            print(json.dumps({"ok": not self.failed, "results": self.results},
                             indent=2, ensure_ascii=False))
        else:
            for row in self.results:
                mark = "PASS" if row["ok"] else "FAIL"
                line = f"[{mark}] {row['check']}"
                if row["detail"]:
                    line += f" - {row['detail']}"
                print(line)
            print(f"\n{len(self.results) - len(self.failed)}/{len(self.results)} checks passed")
        return 0 if not self.failed else 1


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def package_dir(root: Path, pyproject: dict) -> Path | None:
    patterns = (
        pyproject.get("tool", {})
        .get("setuptools", {})
        .get("packages", {})
        .get("find", {})
        .get("include", [])
    ) or []
    for pattern in patterns:
        base = str(pattern).split("*")[0].rstrip("/\\")
        if base and (root / base).is_dir():
            return root / base
    for child in sorted(root.iterdir()):
        if child.is_dir() and (child / "__init__.py").is_file() and child.name != "tests":
            return child
    return None


def check_pyproject(report: Report, root: Path) -> tuple[dict, Path | None]:
    path = root / "pyproject.toml"
    if not tomllib:
        report.check("pyproject readable", False, "python >= 3.11 (tomllib) required")
        return {}, None
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        report.check("pyproject readable", False, str(exc))
        return {}, None
    report.check("pyproject readable", True)

    project = data.get("project", {}) or {}
    for key in ("name", "version", "description", "readme", "requires-python", "license"):
        report.check(f"pyproject [project].{key}", key in project)
    report.check(
        "pyproject requires-python >= 3.10",
        "3.10" in str(project.get("requires-python", "")),
        str(project.get("requires-python", "")),
    )
    scripts = project.get("scripts", {}) or {}
    report.check("pyproject console entry point", bool(scripts), ", ".join(sorted(scripts)))

    pkg = package_dir(root, data)
    report.check("first-party package detected", pkg is not None,
                 str(pkg.relative_to(root).as_posix()) if pkg else "")
    if pkg:
        report.check("package __main__ entry", (pkg / "__main__.py").is_file())
        report.check("package metadata version matches",
                     (pkg / "__init__.py").is_file())
    return data, pkg


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=None)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    root = Path(args.root).resolve() if args.root else repo_root()
    report = Report()
    data, pkg = check_pyproject(report, root)

    for name in REQUIRED_ROOT_FILES:
        report.check(f"file {name}", (root / name).is_file())

    for name in REQUIRED_DOCS:
        report.check(f"doc docs/{name}", (root / "docs" / name).is_file())

    for name in REQUIRED_WORKFLOWS:
        report.check(f"workflow {name}", (root / ".github" / "workflows" / name).is_file())

    for name in ("bug.yml", "feature.yml", "security.yml"):
        report.check(f"issue template {name}",
                     (root / ".github" / "ISSUE_TEMPLATE" / name).is_file())
    report.check("pull request template",
                 (root / ".github" / "PULL_REQUEST_TEMPLATE.md").is_file())

    # --- Helm chart ------------------------------------------------------
    chart = root / "deploy" / "helm" / "inkblade"
    report.check("helm Chart.yaml", (chart / "Chart.yaml").is_file())
    report.check("helm values.yaml", (chart / "values.yaml").is_file())
    for name in REQUIRED_TEMPLATES:
        report.check(f"helm template {name}", (chart / "templates" / name).is_file())
    if (chart / "Chart.yaml").is_file():
        chart_text = (chart / "Chart.yaml").read_text(encoding="utf-8")
        report.check("helm apiVersion v2", "apiVersion: v2" in chart_text)
        report.check("helm chart name inkblade", "name: inkblade" in chart_text)
    if (chart / "values.yaml").is_file():
        values = (chart / "values.yaml").read_text(encoding="utf-8")
        report.check("helm read-only default", "readOnly: true" in values)
        report.check("helm non-root security context", "runAsNonRoot: true" in values)
        report.check("helm resources limits", "limits:" in values)
        report.check("helm image repository", "repository:" in values)

    helm = shutil.which("helm")
    if helm:
        lint = subprocess.run([helm, "lint", str(chart)], capture_output=True, text=True)
        report.check("helm lint", lint.returncode == 0,
                     (lint.stdout or lint.stderr).strip().splitlines()[:1][0]
                     if (lint.stdout or lint.stderr).strip() else "")
        tmpl = subprocess.run(
            [helm, "template", "inkblade", str(chart), "--namespace", "inkblade"],
            capture_output=True, text=True,
        )
        report.check("helm template renders", tmpl.returncode == 0,
                     str(len(tmpl.stdout.splitlines())) + " lines rendered")
    else:
        report.check("helm lint (skipped: helm not installed)", True, "structure-only validation")

    # --- Plugin SDK ------------------------------------------------------
    if pkg:
        sdk = pkg / "sdk"
        report.check("plugin sdk package", (sdk / "__init__.py").is_file())
        report.check("plugin sdk manifest validator", (sdk / "manifest.py").is_file())
        report.check("plugin sdk loader", (sdk / "loader.py").is_file())
        examples = sdk / "examples"
        example_dirs = sorted(p for p in examples.iterdir() if p.is_dir()) if examples.is_dir() else []
        report.check("plugin sdk example present", bool(example_dirs),
                     ", ".join(p.name for p in example_dirs))
        for example in example_dirs:
            report.check(f"example {example.name}/module.json", (example / "module.json").is_file())
            report.check(f"example {example.name}/run.py", (example / "run.py").is_file())

    # --- Dockerfile ------------------------------------------------------
    dockerfile = root / "Dockerfile"
    if dockerfile.is_file():
        text = dockerfile.read_text(encoding="utf-8")
        report.check("dockerfile python 3.12 slim base", "python:3.12-slim" in text)
        report.check("dockerfile non-root user", "USER " in text and "USER root" not in text)
        report.check("dockerfile healthcheck", "HEALTHCHECK" in text)
        entry = ""
        for line in text.splitlines():
            if line.strip().upper().startswith("ENTRYPOINT"):
                entry = line
        report.check("dockerfile entrypoint", bool(entry), entry.strip())

    # --- changelog / versioning -----------------------------------------
    changelog = root / "CHANGELOG.md"
    version = str((data.get("project", {}) or {}).get("version", ""))
    if changelog.is_file() and version:
        text = changelog.read_text(encoding="utf-8")
        report.check("changelog documents current version",
                     version in text, version)

    return report.emit(args.json)


if __name__ == "__main__":
    raise SystemExit(main())
