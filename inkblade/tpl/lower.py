# -*- coding: utf-8 -*-
"""Lower a canonical template to the Rust probe's native dialect.

The probe (``probe/src/template.rs``) executes a smaller dialect: steps with
``op`` + ``assert``/``extract``, flat ``vars`` rendered as ``{{name}}``, and
``steps.<id>`` lookups.  The controller keeps the canonical template (findings,
checks, artifacts, payload variants, version matrix) and folds the probe
evidence into the same result schema as the reference runtime.

This module is the single place where the two dialects meet.  Anything the
probe cannot execute natively is reported as a capability gap — never silently
rewritten into host execution.
"""
from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from typing import Any

from . import expr

# Native operations in probe/src/template.rs (as of inkblade-probe 0.1.0).
NATIVE_OPS = {"http", "tcp", "exec", "bypass", "fs", "spawn"}
NATIVE_K8S_ACTIONS = {"list", "get"}
NATIVE_FS_ACTIONS = {"read", "list", "stat", "write", "mkdir", "remove", "chmod"}
NATIVE_SOCKS_ACTIONS = {"serve"}

_PLACEHOLDER = re.compile(r"\{\{(.*?)\}\}", re.S)


@dataclass
class Compilation:
    template: dict
    params: dict
    context: dict
    native_template: dict
    step_map: dict[str, str] = field(default_factory=dict)
    gaps: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def native_ready(self) -> bool:
        return not self.gaps

    def as_dict(self) -> dict:
        return {
            "key": self.template.get("key"),
            "native_ready": self.native_ready,
            "steps": len(self.native_template.get("steps") or []),
            "gaps": self.gaps,
            "warnings": self.warnings,
        }


def _scope(template: dict, params: dict, context: dict) -> dict:
    payloads = template.get("payloads") or {}
    payload_name = str(params.get("payload_variant") or "")
    if not payload_name and payloads:
        payload_name = "benign" if "benign" in payloads else sorted(payloads)[0]
    scope: dict[str, Any] = {
        "params": params,
        "inputs": {},
        "input": {},
        "vars": {},
        "steps": {},
        "env": {},
        "ctx": {**context,
                "mode": params.get("mode") or "probe-only",
                "payload_variant": payload_name},
        "payload": payloads.get(payload_name) or {},
        "payloads": payloads,
    }
    for name, spec in (template.get("inputs") or {}).items():
        try:
            value = expr.evaluate(str(spec.get("from") or "null"), scope)
        except expr.ExprError:
            value = None
        if value in (None, "") and "default" in spec:
            value = spec["default"]
        scope["inputs"][name] = value
    scope["input"] = scope["inputs"]
    for name, raw in (template.get("vars") or {}).items():
        try:
            scope["vars"][name] = expr.render_value(raw, scope) if isinstance(raw, str) else raw
        except expr.ExprError:
            scope["vars"][name] = None
    return scope


def _rewrite(text: str, scope: dict, step_ids: set[str]) -> tuple[str, list[str]]:
    """Precompute every placeholder that does not depend on a step result."""
    problems: list[str] = []

    def replace(match: re.Match) -> str:
        token = match.group(1).strip()
        roots = {root for root in ("steps",) if root in token}
        if roots:
            # A step-dependent value must stay a runtime lookup. Probe supports
            # only direct paths, so complex expressions are a gap.
            if re.fullmatch(r"steps\.[a-z][a-z0-9_-]*(\.[A-Za-z0-9_]+)*", token):
                return "{{" + token + "}}"
            problems.append(f"runtime expression not supported by probe: {token}")
            return match.group(0)
        try:
            value = expr.evaluate(token, scope)
        except expr.ExprError as exc:
            problems.append(f"placeholder {token!r}: {exc}")
            return match.group(0)
        if isinstance(value, (dict, list, tuple)):
            return json.dumps(value, ensure_ascii=False, sort_keys=True)
        if value is None:
            return ""
        if value is True:
            return "true"
        if value is False:
            return "false"
        return str(value)

    return _PLACEHOLDER.sub(replace, text), problems


def _rewrite_value(value: Any, scope: dict, step_ids: set[str], problems: list[str]) -> Any:
    if isinstance(value, str):
        text, found = _rewrite(value, scope, step_ids)
        problems.extend(found)
        return text
    if isinstance(value, list):
        return [_rewrite_value(item, scope, step_ids, problems) for item in value]
    if isinstance(value, dict):
        return {key: _rewrite_value(item, scope, step_ids, problems) for key, item in value.items()}
    return value


def compile_template(template: dict, params: dict | None = None,
                     context: dict | None = None, *, mode: str | None = None) -> Compilation:
    params = dict(params or {})
    context = dict(context or {})
    mode = str(mode or params.get("mode") or "probe-only")
    params["mode"] = mode
    scope = _scope(template, params, context)
    step_ids = {str(s.get("id")) for s in template.get("steps") or []}
    native_steps: list[dict] = []
    step_map: dict[str, str] = {}
    gaps: list[dict] = []
    warnings: list[str] = []

    def gap(step_id: str, reason: str, detail: dict | None = None) -> None:
        gaps.append({"step": step_id, "reason": reason, **(detail or {})})

    for original in template.get("steps") or []:
        repeat = max(1, min(512, int(original.get("repeat") or 1)))
        for iter_index in range(repeat):
            step = dict(original)
            step.pop("repeat", None)
            step.pop("index_var", None)
            if repeat > 1:
                step["id"] = (str(original.get("id")) if iter_index == repeat - 1
                              else f"{original.get('id')}-{iter_index}")
            scope["i"] = iter_index
            scope[str(original.get("index_var") or "i")] = iter_index
            sid = str(step.get("id"))
            op = str(step.get("op"))
            if step.get("when") is not None:
                try:
                    if not expr.truthy(step["when"], scope):
                        continue
                except expr.ExprError as exc:
                    warnings.append(f"{sid}: when expression error: {exc}")
                    continue
            if step.get("write") and mode != "backup-write":
                continue
            problems: list[str] = []
            native = {"id": sid, "op": op}
            if op == "http":
                native["method"] = str(step.get("method") or "GET").upper()
                native["url"] = _rewrite_value(step.get("url") or "", scope, step_ids, problems)
                if step.get("headers"):
                    native["headers"] = _rewrite_value(step["headers"], scope, step_ids, problems)
                if step.get("body") is not None:
                    native["body"] = _rewrite_value(step["body"], scope, step_ids, problems)
                expect = step.get("expect") or {}
                if expect and not step.get("allow_failure"):
                    statuses = expect.get("status")
                    if isinstance(statuses, list) and statuses and \
                            not expect.get("body_contains") and not expect.get("header_contains"):
                        native["expect"] = {"status": statuses}
                    elif expect.get("body_contains") or expect.get("header_contains"):
                        warnings.append(f"{sid}: body/header expectations folded by controller")
            elif op == "tcp":
                native["host"] = _rewrite_value(step.get("host") or "", scope, step_ids, problems)
                native["port"] = int(step.get("port") or 0)
                if step.get("send"):
                    payload = _rewrite_value(step["send"], scope, step_ids, problems)
                    native["send_b64"] = base64.b64encode(str(payload).encode("utf-8")).decode("ascii")
                if step.get("send_b64"):
                    native["send_b64"] = step["send_b64"]
                native["read_bytes"] = int(step.get("read_bytes") or 65536)
            elif op == "exec":
                native["argv"] = [_rewrite_value(x, scope, step_ids, problems)
                                  for x in step.get("argv") or []]
                if step.get("stdin"):
                    warnings.append(f"{sid}: probe exec has no stdin; folded where possible")
            elif op == "bypass":
                # The probe interprets the same plan object the policy engine
                # emits.  Scripts are literal: no interpolation, so a template
                # can never splice host secrets into the memfd payload.
                techniques = step.get("techniques")
                if techniques is None and step.get("technique") is not None:
                    techniques = [step.get("technique")]
                native["techniques"] = list(techniques or [])
                for key in ("script", "script_b64", "workdir", "clean_env",
                            "target", "monitored_paths", "commands", "binaries",
                            "argv", "timeout_ms"):
                    if step.get(key) is not None:
                        native[key] = step[key]
            elif op == "fs":
                action = str(step.get("action"))
                if action == "hash":
                    gap(sid, "fs action hash is not implemented by the probe", {"action": action})
                    continue
                if action not in NATIVE_FS_ACTIONS:
                    gap(sid, f"fs action {action} is not native", {"action": action})
                    continue
                native["action"] = action
                if step.get("path"):
                    native["path"] = _rewrite_value(step["path"], scope, step_ids, problems)
                if step.get("glob"):
                    native["glob"] = _rewrite_value(step["glob"], scope, step_ids, problems)
                if action == "write" and step.get("content") is not None:
                    native["data"] = _rewrite_value(step["content"], scope, step_ids, problems)
            elif op == "k8s":
                verb = str(step.get("verb") or "")
                if verb not in ("get", "list"):
                    gap(sid, f"k8s verb {verb} is not implemented by the probe",
                        {"verb": verb, "resource": step.get("resource")})
                    continue
                native["action"] = verb
                native["resource"] = _rewrite_value(step.get("resource") or "", scope, step_ids, problems)
                if step.get("namespace") is not None:
                    native["namespace"] = _rewrite_value(step["namespace"], scope, step_ids, problems)
                if step.get("name"):
                    native["name"] = _rewrite_value(step["name"], scope, step_ids, problems)
                if step.get("api_version") not in (None, "", "v1"):
                    gap(sid, "probe k8s only supports core/v1 paths",
                        {"api_version": step.get("api_version")})
                    continue
                if step.get("label_selector"):
                    warnings.append(f"{sid}: probe k8s list has no label selector yet")
            elif op == "socks":
                gap(sid, "probe socks op is a server, not a Unix-socket client",
                    {"socket_path": step.get("socket_path")})
                continue
            elif op == "spawn":
                native["argv"] = [_rewrite_value(x, scope, step_ids, problems)
                                  for x in step.get("argv") or []]
                if step.get("detach"):
                    native["detach"] = True
            else:
                gap(sid, f"op {op} is not native", {"op": op})
                continue
            if int(step.get("timeout_ms") or 0) > 0:
                native["timeout_ms"] = int(step["timeout_ms"])
            if problems:
                gap(sid, "; ".join(problems[:3]))
                continue
            native_steps.append(native)
            step_map[sid] = sid

    native_template = {
        "name": template.get("key"),
        "budget": {
            "max_steps": max(64, len(native_steps) + 8,
                             int((template.get("limits") or {}).get("max_http_requests") or 64) + 8),
            "max_ms": int((template.get("limits") or {}).get("timeout_ms") or 60000),
            "max_bytes": int((template.get("defaults") or {}).get("max_bytes") or 1048576),
        },
        "steps": native_steps,
    }
    return Compilation(template=template, params=params, context=context,
                       native_template=native_template, step_map=step_map,
                       gaps=gaps, warnings=warnings)


def normalize_probe_result(native_result: dict, compilation: Compilation) -> dict:
    """Map the probe's ``task`` result into canonical step evidence.

    Probe result shape::

        {"ok": true, "steps": [{"step","op","ok","result"}], "vars": {"steps.x": ...}}

    HTTP bodies are base64-decoded/parsed here (controller-side, no module code).
    """
    steps: dict[str, dict] = {}
    raw_vars = native_result.get("vars") or {}
    for name, value in raw_vars.items():
        if isinstance(name, str) and name.startswith("steps.") and isinstance(value, dict):
            sid = name[len("steps."):]
            steps[sid] = _normalise_step(sid, value)
    for entry in native_result.get("steps") or []:
        sid = str(entry.get("step"))
        if sid in steps:
            steps[sid]["ok"] = bool(entry.get("ok", True))
            if entry.get("error"):
                steps[sid]["error"] = entry["error"]
    return {
        "schema": "inkblade-probe-result-v1",
        "key": compilation.template.get("key"),
        "template_version": compilation.template.get("version"),
        "runtime": "rust",
        "status": "ok",
        "duration_ms": int(native_result.get("duration_ms") or 0),
        "steps": [{"id": sid, **data} for sid, data in steps.items()],
        "checks": [],
        "findings": [],
        "artifacts": [],
        "extracts": steps,
    }


def _normalise_step(sid: str, value: dict) -> dict:
    out = {"op": "unknown", "ok": True, "skipped": False, **value}
    if "status" in value and ("body" in value or "headers" in value):
        text = value.get("body")
        if isinstance(text, str):
            out["text"] = text
            try:
                out["json"] = json.loads(text)
            except ValueError:
                out["json"] = None
        out["bytes"] = len(str(text or "").encode("utf-8", "ignore"))
    if "data_b64" in value:
        raw = base64.b64decode(value["data_b64"])
        text = raw.decode("utf-8", "replace")
        out["text"] = text
        try:
            out["json"] = json.loads(text)
        except ValueError:
            out["json"] = None
        out["bytes"] = len(raw)
    if "entries" in value:
        out["entries"] = value["entries"]
    if "exit_code" in value:
        out["rc"] = value["exit_code"]
        out["stdout"] = value.get("stdout") or ""
        out["stderr"] = value.get("stderr") or ""
    return out


def fold_result(compilation: Compilation, native_result: dict) -> dict:
    """Evaluate checks/findings/artifacts for a probe result (controller-side)."""
    from .engine import Engine, StepResult

    canonical_steps = normalize_probe_result(native_result, compilation)["steps"]
    engine = Engine(backend=None)  # only evaluation helpers are used
    scope = _scope(compilation.template, compilation.params, compilation.context)
    for step in canonical_steps:
        sid = step["id"]
        data = {key: value for key, value in step.items()
                if key not in ("id", "op", "ok", "skipped", "error")}
        result = StepResult(id=sid, op=str(step.get("op") or "unknown"),
                            ok=bool(step.get("ok", True)),
                            status=step.get("status"),
                            error=str(step.get("error") or ""),
                            skipped=bool(step.get("skipped")),
                            data=data)
        scope["steps"][sid] = engine._step_scope(result)  # noqa: SLF001 - shared fold
    scope["computed"] = {}
    for name, text in (compilation.template.get("computed") or {}).items():
        value = expr.evaluate(str(text), scope)
        scope["computed"][name] = value
        scope["vars"][name] = value
    checks = []
    error = None
    for check in compilation.template.get("checks") or []:
        ok = expr.truthy(check.get("when"), scope)
        checks.append({"id": check.get("id"), "ok": ok,
                       "severity": check.get("severity", "info"),
                       "message": check.get("message") or ""})
        if check.get("fatal") and not ok:
            error = f"check {check.get('id')} failed"
    findings = []
    if error is None:
        for spec in compilation.template.get("findings") or []:
            findings.extend(engine._findings(spec, scope))  # noqa: SLF001
    artifacts = []
    if error is None:
        defaults = {**{"max_bytes": 1048576}, **(compilation.template.get("defaults") or {})}
        for spec in compilation.template.get("artifacts") or []:
            artifacts.append(engine._artifact(spec, scope, defaults))  # noqa: SLF001
    result = normalize_probe_result(native_result, compilation)
    result.update(
        status="error" if error else ("findings" if findings else "ok"),
        error=error, checks=checks, findings=findings, artifacts=artifacts)
    return result
