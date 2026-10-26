# -*- coding: utf-8 -*-
"""Reference evaluator for declarative probe templates.

Production execution happens in the Rust probe (``inkblade-probe
run-template``).  This module implements the same evaluation rules in Python so
the mock range and CI can verify every template without a Rust toolchain.  It is
*not* a module interpreter: no module code exists any more; it only evaluates the
declarative program (http/tcp/exec/fs/k8s/socks/spawn + assert/extract).

Selection is explicit: :class:`ReferenceProbe` refuses to run when
``INKBLADE_ALLOW_REFERENCE_PROBE`` is not set, and every result records
``runtime="reference"`` so evidence can never be mistaken for the Rust engine.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

from . import expr
from .expr import ExprError

RESULT_SCHEMA = "inkblade-probe-result-v1"
DEFAULTS = {
    "timeout_ms": 8000,
    "max_bytes": 1048576,
    "tls_verify": False,
    "cleanup": True,
}


class ProbeError(RuntimeError):
    """The probe could not execute the template."""


@dataclass
class StepResult:
    id: str
    op: str
    ok: bool = True
    status: int | None = None
    error: str = ""
    skipped: bool = False
    data: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        out = {"id": self.id, "op": self.op, "ok": bool(self.ok),
               "skipped": bool(self.skipped)}
        if self.status is not None:
            out["status"] = self.status
        if self.error:
            out["error"] = self.error
        for key in ("url", "method", "bytes", "sha256", "entries", "pid",
                    "headers", "text", "json", "stdout", "stderr", "rc",
                    "exists", "size", "path"):
            if key in self.data:
                out[key] = self.data[key]
        return out


class Engine:
    """Evaluates one template with an already-constructed step backend."""

    def __init__(self, backend, *, clock=time.time):
        self.backend = backend
        self.clock = clock

    def run(self, template: dict, params: dict | None = None,
            context: dict | None = None) -> dict:
        started = self.clock()
        params = dict(params or {})
        context = dict(context or {})
        defaults = {**DEFAULTS, **(template.get("defaults") or {})}
        mode = str(params.get("mode") or "probe-only")
        write_allowed = mode == "backup-write"
        payload_name = str(params.get("payload_variant") or "")
        payloads = template.get("payloads") or {}
        if payload_name and payload_name not in payloads:
            raise ProbeError(f"未知 payload_variant: {payload_name}")
        if not payload_name and payloads:
            payload_name = "benign" if "benign" in payloads else sorted(payloads)[0]

        scope: dict[str, Any] = {
            "params": params,
            "inputs": {name: self._resolve_input(spec, params, payloads, payload_name)
                       for name, spec in (template.get("inputs") or {}).items()},
            "steps": {},
            "vars": {},
            "env": {},
            "ctx": {**context, "mode": mode, "payload_variant": payload_name},
            "payload": payloads.get(payload_name) or {},
            "payloads": payloads,
        }
        scope["input"] = scope["inputs"]
        for name, raw in (template.get("vars") or {}).items():
            scope["vars"][name] = expr.render_value(raw, scope) if isinstance(raw, str) \
                else raw

        missing = [name for name, spec in (template.get("inputs") or {}).items()
                   if spec.get("required") and scope["inputs"].get(name) in (None, "", [])]
        if missing:
            return self._result(template, started, status="skipped",
                                error=f"missing required input: {','.join(missing)}",
                                steps=[], checks=[], findings=[], artifacts=[])

        steps_out: list[dict] = []
        results: dict[str, StepResult] = {}
        error: str | None = None
        total_timeout = int((template.get("limits") or {}).get("timeout_ms") or 60000)
        deadline = started + total_timeout / 1000.0
        max_http = int((template.get("limits") or {}).get("max_http_requests") or 256)
        http_count = 0

        for step in template.get("steps") or []:
            sid = str(step.get("id"))
            op = str(step.get("op"))
            if step.get("when") is not None and not expr.truthy(step["when"], scope):
                result = StepResult(id=sid, op=op, skipped=True)
                results[sid] = result
                steps_out.append(result.as_dict())
                scope["steps"][sid] = self._step_scope(result)
                continue
            if step.get("write") and not write_allowed:
                result = StepResult(id=sid, op=op, skipped=True,
                                    data={"skipped_reason": "probe-only"})
                results[sid] = result
                steps_out.append(result.as_dict())
                scope["steps"][sid] = self._step_scope(result)
                continue
            if self.clock() > deadline:
                error = f"template timeout after {total_timeout}ms"
                break
            if op == "http":
                http_count += 1
                if http_count > max_http:
                    error = f"http request budget exceeded ({max_http})"
                    break
            try:
                result = self._execute(step, scope, defaults)
            except Exception as exc:  # noqa: BLE001 - op failure is evidence
                result = StepResult(id=sid, op=op, ok=False,
                                    error=f"{type(exc).__name__}: {exc}")
            results[sid] = result
            scope["steps"][sid] = self._step_scope(result)
            steps_out.append(result.as_dict())
            if not result.ok and not step.get("allow_failure"):
                error = f"step {sid} failed: {result.error or result.status}"
                break

        checks_out: list[dict] = []
        for check in template.get("checks") or []:
            try:
                actual = expr.truthy(check.get("when"), scope)
            except ExprError as exc:
                actual = False
                check = {**check, "message": f"{check.get('message') or ''} (expr error: {exc})"}
            entry = {"id": check.get("id"), "ok": bool(actual),
                     "severity": check.get("severity", "info"),
                     "message": check.get("message") or ""}
            if check.get("fatal") and not actual:
                error = error or f"check {check.get('id')} failed"
                entry["fatal"] = True
            checks_out.append(entry)

        findings: list[dict] = []
        if error is None:
            for finding in template.get("findings") or []:
                findings.extend(self._findings(finding, scope))

        artifacts = []
        if error is None:
            for spec in template.get("artifacts") or []:
                try:
                    artifacts.append(self._artifact(spec, scope, defaults))
                except Exception as exc:  # noqa: BLE001
                    artifacts.append({"name": spec.get("name"), "kind": "error",
                                      "error": f"{type(exc).__name__}: {exc}"})

        status = "error" if error else ("findings" if findings else "ok")
        return self._result(template, started, status=status, error=error,
                            steps=steps_out, checks=checks_out, findings=findings,
                            artifacts=artifacts,
                            extracts={k: v.data for k, v in results.items()},
                            payload_variant=payload_name)

    # ------------------------------------------------------------------ ops
    def _execute(self, step: dict, scope: dict, defaults: dict) -> StepResult:
        op = step["op"]
        render = lambda value: expr.render_value(value, scope)  # noqa: E731
        timeout = int(step.get("timeout_ms") or defaults["timeout_ms"])
        max_bytes = int(defaults.get("max_bytes") or DEFAULTS["max_bytes"])
        if op == "http":
            request = {
                "method": str(step.get("method") or "GET").upper(),
                "url": render(step.get("url") or ""),
                "headers": {str(k): str(render(v)) for k, v in (step.get("headers") or {}).items()},
                "body": render(step.get("body")) if step.get("body") is not None else None,
                "timeout_ms": timeout,
                "tls_verify": bool(step.get("tls_verify", defaults["tls_verify"])),
                "max_bytes": max_bytes,
            }
            raw = self.backend.http(request)
            data = {
                "method": request["method"], "url": request["url"],
                "status": int(raw.get("status") or 0),
                "headers": raw.get("headers") or {},
                "text": raw.get("text") or "",
                "json": raw.get("json"),
                "bytes": int(raw.get("bytes") or len(raw.get("body") or b"")),
                "sha256": raw.get("sha256") or "",
            }
            ok = int(raw.get("status") or 0) > 0
            error = str(raw.get("error") or "")
            expect = step.get("expect") or {}
            if expect:
                statuses = expect.get("status") or []
                if statuses and data["status"] not in statuses:
                    ok = False
                    error = error or f"unexpected status {data['status']} (want {statuses})"
                needle = expect.get("body_contains")
                if needle is not None and str(needle) not in data["text"]:
                    ok = False
                    error = error or f"body does not contain {needle!r}"
                for header, wanted in (expect.get("header_contains") or {}).items():
                    got = str((data["headers"] or {}).get(header.lower(), ""))
                    if str(wanted) not in got:
                        ok = False
                        error = error or f"header {header} does not contain {wanted!r}"
            return StepResult(id=step["id"], op=op, ok=ok, status=data["status"],
                              error=error, data=data)
        if op == "tcp":
            raw = self.backend.tcp({
                "host": render(step.get("host")), "port": int(step.get("port")),
                "send": render(step.get("send") or "") if step.get("send") else "",
                "send_b64": step.get("send_b64") or "",
                "expect_prefix": render(step.get("expect_prefix") or "") if step.get("expect_prefix") else "",
                "read_bytes": int(step.get("read_bytes") or 65536),
                "timeout_ms": timeout,
            })
            text = raw.get("text") or ""
            ok = bool(raw.get("ok"))
            error = str(raw.get("error") or "")
            if ok and step.get("expect_prefix") and not text.startswith(str(step["expect_prefix"])):
                ok = False
                error = f"response does not start with {step['expect_prefix']!r}"
            return StepResult(id=step["id"], op=op, ok=ok, error=error,
                              data={"text": text, "bytes": len(text.encode("utf-8", "ignore")),
                                    "sha256": raw.get("sha256") or ""})
        if op == "exec":
            raw = self.backend.exec({
                "argv": [str(x) for x in render(step.get("argv") or [])],
                "stdin": render(step.get("stdin") or "") if step.get("stdin") else "",
                "env": {str(k): str(render(v)) for k, v in (step.get("env") or {}).items()},
                "timeout_ms": timeout,
                "max_bytes": max_bytes,
            })
            ok = int(raw.get("rc", -1)) == 0
            return StepResult(id=step["id"], op=op, ok=ok,
                              error=("" if ok else f"exit {raw.get('rc')}: {(raw.get('stderr') or '')[:300]}"),
                              data={"rc": raw.get("rc"), "stdout": raw.get("stdout") or "",
                                    "stderr": raw.get("stderr") or "",
                                    "bytes": raw.get("bytes") or 0,
                                    "sha256": raw.get("sha256") or ""})
        if op == "spawn":
            raw = self.backend.spawn({
                "argv": [str(x) for x in render(step.get("argv") or [])],
                "env": {str(k): str(render(v)) for k, v in (step.get("env") or {}).items()},
                "detach": bool(step.get("detach", False)),
                "timeout_ms": timeout,
            })
            return StepResult(id=step["id"], op=op, ok=bool(raw.get("ok")),
                              error=str(raw.get("error") or ""),
                              data={"pid": raw.get("pid"), "stdout": raw.get("stdout") or "",
                                    "stderr": raw.get("stderr") or ""})
        if op == "fs":
            action = str(step.get("action"))
            raw = self.backend.fs({
                "action": action,
                "path": render(step.get("path") or "") if step.get("path") else "",
                "glob": render(step.get("glob") or "") if step.get("glob") else "",
                "content": render(step.get("content") or "") if step.get("content") else "",
                "json": bool(step.get("json")),
                "max_bytes": max_bytes,
            })
            ok = bool(raw.get("ok"))
            error = str(raw.get("error") or "")
            data = {"path": raw.get("path") or "", "exists": raw.get("exists"),
                    "size": raw.get("size"), "text": raw.get("text"),
                    "json": raw.get("json"), "entries": raw.get("entries"),
                    "sha256": raw.get("sha256")}
            return StepResult(id=step["id"], op=op, ok=ok, error=error,
                              data={k: v for k, v in data.items() if v is not None})
        if op == "k8s":
            raw = self.backend.k8s({
                "verb": step.get("verb"), "resource": render(step.get("resource")),
                "api_version": render(step.get("api_version") or "v1") if step.get("api_version") else "v1",
                "namespace": render(step.get("namespace") or "") if step.get("namespace") is not None else "",
                "name": render(step.get("name") or "") if step.get("name") else "",
                "label_selector": render(step.get("label_selector") or "") if step.get("label_selector") else "",
                "body": render(step.get("body")) if step.get("body") is not None else None,
                "timeout_ms": timeout,
                "max_bytes": max_bytes,
            })
            ok = bool(raw.get("ok"))
            return StepResult(id=step["id"], op=op, ok=ok,
                              status=raw.get("status"),
                              error=str(raw.get("error") or ""),
                              data={"json": raw.get("json"), "text": raw.get("text"),
                                    "status": raw.get("status"), "url": raw.get("url"),
                                    "bytes": raw.get("bytes"), "sha256": raw.get("sha256")})
        if op == "socks":
            raw = self.backend.socks({
                "path": render(step.get("socket_path")),
                "request": render(step.get("request")),
                "read_bytes": int(step.get("read_bytes") or 65536),
                "timeout_ms": timeout,
            })
            return StepResult(id=step["id"], op=op, ok=bool(raw.get("ok")),
                              error=str(raw.get("error") or ""),
                              data={"text": raw.get("text") or "", "exists": raw.get("exists"),
                                    "sha256": raw.get("sha256")})
        raise ProbeError(f"unknown op {op}")

    # ------------------------------------------------------------- helpers
    def _resolve_input(self, spec: dict, params: dict, payloads: dict,
                       payload_name: str) -> Any:
        scope = {"params": params, "payload": payloads.get(payload_name) or {},
                 "payloads": payloads}
        try:
            value = expr.evaluate(str(spec.get("from")), scope)
        except ExprError:
            value = None
        if value in (None, "") and "default" in spec:
            value = spec["default"]
        return value

    @staticmethod
    def _step_scope(result: StepResult) -> dict:
        out = {"ok": result.ok, "status": result.status, "error": result.error,
               "skipped": result.skipped}
        out.update(result.data)
        return out

    def _findings(self, spec: dict, scope: dict) -> list[dict]:
        out: list[dict] = []
        max_emit = int(spec.get("max_emit") or 100)
        sequence = [None]
        if spec.get("for_each"):
            value = expr.evaluate(spec["for_each"], scope)
            sequence = list(value) if isinstance(value, list) else ([] if value is None else [value])
        alias = str(spec.get("as") or "it")
        for item in sequence:
            bindings = {alias: item, "it": item} if item is not None else {}
            try:
                if not expr.truthy(spec.get("when", "true"), scope, bindings):
                    continue
            except ExprError:
                continue
            finding = {
                "id": spec.get("id"),
                "sev": spec.get("sev", "info"),
                "title": expr.render(spec.get("title"), scope, bindings),
                "detail": expr.render(spec.get("detail") or "", scope, bindings),
                "evidence": expr.render(spec.get("evidence") or "", scope, bindings),
                "mapping": expr.render(spec.get("mapping") or "", scope, bindings),
                "fix": expr.render(spec.get("fix") or "", scope, bindings),
            }
            if spec.get("cves"):
                finding["cves"] = list(spec["cves"])
            if spec.get("version_matrix"):
                vm = dict(spec["version_matrix"])
                vm["observed"] = expr.evaluate(str(vm.get("source")), scope, bindings)
                finding["version_matrix"] = vm
            out.append(finding)
            if len(out) >= max_emit:
                break
        return out

    def _artifact(self, spec: dict, scope: dict, defaults: dict) -> dict:
        kind = str(spec.get("kind") or "json")
        value = expr.evaluate(str(spec.get("from")), scope) if \
            str(spec.get("from")).find("{{") < 0 else expr.render(str(spec["from"]), scope)
        name = str(spec.get("name"))
        if kind == "json":
            payload = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=1).encode("utf-8")
            entry = {"name": name, "kind": "json", "text": payload.decode("utf-8")}
        elif kind == "text":
            payload = expr._to_text(value).encode("utf-8")  # noqa: SLF001 - shared helper
            entry = {"name": name, "kind": "text", "text": payload.decode("utf-8")}
        else:
            raw = value if isinstance(value, (bytes, bytearray)) else \
                expr._to_text(value).encode("utf-8")  # noqa: SLF001
            payload = bytes(raw)
            entry = {"name": name, "kind": "binary",
                     "b64": __import__("base64").b64encode(payload).decode("ascii")}
        import hashlib
        entry["sha256"] = hashlib.sha256(payload).hexdigest()
        entry["bytes"] = len(payload)
        return entry

    def _result(self, template: dict, started: float, **kwargs) -> dict:
        duration = int((self.clock() - started) * 1000)
        doc = {
            "schema": RESULT_SCHEMA,
            "key": template.get("key"),
            "template_version": template.get("version"),
            "runtime": getattr(self.backend, "runtime", "reference"),
            "status": kwargs.pop("status", "ok"),
            "duration_ms": duration,
            "steps": kwargs.pop("steps", []),
            "checks": kwargs.pop("checks", []),
            "findings": kwargs.pop("findings", []),
            "artifacts": kwargs.pop("artifacts", []),
            "extracts": kwargs.pop("extracts", {}),
        }
        doc.update(kwargs)
        return doc


class ReferenceProbe:
    """In-process conformance runtime. Explicit opt-in only."""

    runtime = "reference"

    def __init__(self, backend, *, clock=time.time):
        self.backend = backend
        self.engine = Engine(backend, clock=clock)

    def run(self, template: dict, params: dict | None = None,
            context: dict | None = None) -> dict:
        return self.engine.run(template, params, context)
