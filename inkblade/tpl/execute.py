# -*- coding: utf-8 -*-
"""Execute one module template through a probe and fold the result into evidence.

Everything in this module is orchestration: load the declarative template, call
the probe, persist artifacts, normalise findings.  No module logic runs here.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .probe import (ProbeFailed, ProbeUnavailable, ProbeTransport, resolve_probe,
                    result_evidence)
from .schema import TemplateError, load_template

STATUS_SKIPPED = "skipped"


class TemplateExecutionError(RuntimeError):
    def __init__(self, message: str, result: dict | None = None):
        super().__init__(message)
        self.result = result or {}


def _module_meta_dict(meta) -> dict:
    return dict(meta.__dict__)


def prepare_params(template: dict, params: dict) -> dict:
    """Apply declared input defaults without overwriting explicit parameters."""
    out = dict(params or {})
    for name, spec in (template.get("inputs") or {}).items():
        if name in out:
            continue
        if "default" in spec:
            out[name] = spec["default"]
    return out


def _write_artifacts(run, module_key: str, artifacts: list[dict]) -> list[Path]:
    paths: list[Path] = []
    if not artifacts:
        return paths
    target_dir = Path(run.dir) / "artifacts" / module_key
    target_dir.mkdir(parents=True, exist_ok=True)
    for artifact in artifacts:
        name = str(artifact.get("name") or "artifact")
        safe = "".join(ch if ch.isalnum() or ch in "-_.@" else "_" for ch in name) or "artifact"
        path = target_dir / safe
        if artifact.get("b64") is not None:
            import base64
            data = base64.b64decode(artifact["b64"])
        else:
            text = artifact.get("text")
            data = (text if isinstance(text, str) else json.dumps(
                text, ensure_ascii=False, sort_keys=True, indent=1)).encode("utf-8")
        path.write_bytes(data)
        expected = artifact.get("sha256")
        actual = hashlib.sha256(data).hexdigest()
        if expected and expected != actual:
            raise TemplateExecutionError(
                f"artifact {name} sha256 mismatch: probe={expected} host={actual}")
        paths.append(path)
    return paths


def _write_trace(run, module_key: str, result: dict) -> None:
    """Persist http steps as traces/<key>.json so traffic replay keeps working."""
    if run is None:
        return
    entries = []
    for step in result.get("steps") or []:
        if step.get("op") != "http" or step.get("skipped"):
            continue
        entry = {"ts": 0, "method": step.get("method"), "url": step.get("url"),
                 "status": step.get("status"), "response": None,
                 "sha256": step.get("sha256"), "body": None}
        text = step.get("text")
        if isinstance(text, str):
            try:
                entry["response"] = json.loads(text)
            except ValueError:
                entry["response"] = text[:2048]
        entries.append(entry)
    if not entries:
        return
    traces = Path(run.dir) / "traces"
    traces.mkdir(parents=True, exist_ok=True)
    (traces / f"{module_key}.json").write_text(
        json.dumps({"module": module_key, "entries": entries}, ensure_ascii=False, indent=1),
        encoding="utf-8")


def execute_template(store, session, meta, params: dict[str, Any], *,
                     probe: ProbeTransport | None = None,
                     marker: str | None = None,
                     run=None) -> dict:
    """Run the module's template and return ``{summary, findings, artifacts, probe}``."""
    module_dir = Path(meta.path)
    template = load_template(module_dir, module_meta=_module_meta_dict(meta))
    params = prepare_params(template, params)
    backend = resolve_probe(session, probe)
    context = {
        "marker": marker or "",
        "run": getattr(run, "name", ""),
        "workspace": str(getattr(store, "workspace", "")),
        "module": meta.key,
        "actor": getattr(session, "name", ""),
        "probe_runtime": backend.runtime,
        "mode": params.get("mode") or "probe-only",
    }
    result = backend.run(template, params, context)
    result.setdefault("key", meta.key)

    if result.get("status") == "error":
        summary = f"探针执行失败：{result.get('error') or 'unknown'}"
        raise TemplateExecutionError(summary, result)
    if result.get("status") == STATUS_SKIPPED:
        return {"summary": f"跳过：{result.get('error') or 'no input'}",
                "findings": [], "artifacts": [], "probe": result, "skipped": True}

    artifacts = _write_artifacts(run, meta.key, result.get("artifacts") or []) if run else []
    _write_trace(run, meta.key, result)
    findings = []
    for finding in result.get("findings") or []:
        item = {
            "sev": finding.get("sev", "info"),
            "title": finding.get("title") or meta.key,
            "detail": finding.get("detail") or "",
        }
        for key in ("evidence", "mapping", "fix", "cves", "version_matrix", "is_zeroday"):
            if finding.get(key):
                item[key] = finding[key]
        if finding.get("id"):
            item["template_finding"] = finding["id"]
        if getattr(meta, "private", False):
            item["is_zeroday"] = True
        findings.append(item)

    executed = [s for s in result.get("steps") or [] if not s.get("skipped")]
    failed = [s for s in result.get("steps") or [] if s.get("ok") is False]
    summary = (f"probe[{result.get('runtime')}] {meta.key}: "
               f"{len(executed)} step(s), {len(findings)} finding(s), "
               f"{len(artifacts)} artifact(s)")
    if failed:
        summary += f", {len(failed)} step failure(s)"
    return {
        "summary": summary,
        "findings": findings,
        "artifacts": [str(p) for p in artifacts],
        "probe": result,
        "probe_evidence": result_evidence(result),
        "skipped": False,
    }


def coverage_entry(meta, probe_result: dict | None = None,
                   dynamic: bool = False, error: str | None = None) -> dict:
    entry = {
        "module": meta.key,
        "execution": getattr(meta, "execution", "template"),
        "template": bool((Path(meta.path) / "template.json").is_file()),
        "probe_tested": bool(dynamic),
        "evidence": "",
        "error": error or "",
    }
    if probe_result:
        entry["probe"] = {
            "runtime": probe_result.get("runtime"),
            "status": probe_result.get("status"),
            "steps": len(probe_result.get("steps") or []),
            "findings": len(probe_result.get("findings") or []),
            "artifacts": [a.get("sha256") for a in probe_result.get("artifacts") or []],
        }
        entry["evidence"] = hashlib.sha256(
            json.dumps(probe_result, ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest()
    return entry
