# -*- coding: utf-8 -*-
"""Shared probe helpers for the 0day-reserve weapon packs.

These modules are intentionally **probe-only by default**.  A weapon pack may
carry a destructive payload variant, but the module only executes it when the
operator passes an explicit target and (for write modules) a backup target;
the runner's backup gate is the second line of defence.

Every module returns the standard dict::

    {"summary": str, "findings": [...], "artifacts": [...]}

A module that has no target returns ``status="needs-target"`` and the payload
variants, so ``inkblade exploit <id> --dry-run`` stays side-effect free.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path

TIMEOUT = 5


def target_of(params: dict) -> str:
    return str(params.get("target") or "").rstrip("/")


class Trace:
    """Record every HTTP interaction as a run artifact (no secrets logged)."""

    def __init__(self, ctx: dict, key: str):
        run = ctx.get("run")
        self.path = None
        self.entries: list[dict] = []
        if run is not None:
            directory = Path(run.dir) / "traces"
            directory.mkdir(parents=True, exist_ok=True)
            self.path = directory / f"{key}.json"

    def call(self, method: str, url: str, body=None, headers: dict | None = None,
             timeout: int = TIMEOUT) -> dict:
        entry = {"ts": round(time.time(), 3), "method": method, "url": url,
                 "body": body, "headers": dict(headers or {})}
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(url, data=data, method=method)
        if data is not None:
            request.add_header("Content-Type", "application/json")
        for name, value in (headers or {}).items():
            request.add_header(name, value)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw, status = response.read(), response.status
        except urllib.error.HTTPError as exc:
            raw, status = exc.read(), exc.code
        except Exception as exc:  # connection refused, DNS, timeout
            entry.update(status=0, error=f"{type(exc).__name__}: {exc}")
            self.entries.append(entry)
            return entry
        text = raw.decode("utf-8", "replace")
        try:
            payload = json.loads(text)
        except ValueError:
            payload = text[:4000]
        entry.update(status=status, response=payload)
        self.entries.append(entry)
        return entry

    def dump(self) -> list[str]:
        if self.path is None:
            return []
        self.path.write_text(
            json.dumps({"entries": self.entries}, ensure_ascii=False, indent=1),
            encoding="utf-8",
        )
        return [str(self.path)]


def finding(sev: str, title: str, detail: dict | str, *, evidence: str = "",
            fix: str = "") -> dict:
    return {
        "sev": sev if sev in {"critical", "high", "medium", "low", "info"} else "info",
        "title": title,
        "detail": json.dumps(detail, ensure_ascii=False) if isinstance(detail, dict) else str(detail),
        **({"evidence": evidence} if evidence else {}),
        **({"fix": fix} if fix else {}),
    }


def result(summary: str, findings: list[dict] | None = None,
           artifacts: list[str] | None = None, status: str = "ok", **extra) -> dict:
    payload = {
        "summary": summary,
        "status": status,
        "findings": findings or [],
        "artifacts": artifacts or [],
    }
    payload.update(extra)
    return payload


def needs_target(key: str, variants: list[dict], note: str) -> dict:
    return result(
        f"{key}: no --target supplied; dry probe only ({note})",
        status="needs-target",
        variants=variants,
    )


def http_probe(ctx: dict, key: str, params: dict, *, routes: list[dict],
               headers: dict | None = None) -> dict:
    """Probe a list of ``{method, path, body, name, expect}`` routes.

    ``expect`` is the status code that proves the missing-auth/route behaviour.
    The probe is read-only: routes used here are GET/heartbeat/status calls or
    the least-destructive write named in the pack.
    """
    target = target_of(params)
    if not target:
        return needs_target(key, params.get("variants") or [], "HTTP service")
    trace = Trace(ctx, key)
    findings: list[dict] = []
    matched = 0
    for route in routes:
        url = target + str(route.get("path") or "/")
        entry = trace.call(str(route.get("method") or "GET"), url,
                           route.get("body"), headers or route.get("headers"))
        expect = route.get("expect")
        ok = entry.get("status") == expect if expect is not None else bool(entry.get("status"))
        if ok:
            matched += 1
            findings.append(finding(
                str(route.get("sev") or "high"),
                f"{key}: {route.get('name') or route.get('path')} reachable "
                f"(HTTP {entry.get('status')})",
                {"request": f"{entry['method']} {url}", "status": entry.get("status"),
                 "response": entry.get("response")},
                evidence=str(route.get("path")),
                fix=str(route.get("fix") or ""),
            ))
    artifacts = trace.dump()
    status = "ok" if matched else "no-match"
    return result(
        f"{key}: {matched}/{len(routes)} probe route(s) matched on {target}",
        findings, artifacts, status=status,
        http=[{k: e.get(k) for k in ("method", "url", "status", "error")}
              for e in trace.entries],
    )


def read_file_probe(ctx: dict, key: str, params: dict, *, reader: str,
                    payload: str, max_bytes: int = 4096) -> dict:
    """Read a caller-supplied local file without executing it.

    Used by function-level packs (checkpoint/media/package loaders) to prove
    that the path is attacker-controlled.  It never deserialises the payload;
    execution belongs to the isolated verification case, not a live engagement.
    """
    path = Path(str(params.get("local_path") or params.get("target") or ""))
    if not str(path) or not path.is_file():
        return needs_target(key, params.get("variants") or [], "local file/checkpoint")
    raw = path.read_bytes()[:max_bytes]
    trace_dir = Path(ctx["run"].dir) / "traces" if ctx.get("run") is not None else None
    artifacts: list[str] = []
    if trace_dir is not None:
        trace_dir.mkdir(parents=True, exist_ok=True)
        out = trace_dir / f"{key}.json"
        out.write_text(json.dumps({
            "path": str(path), "reader": reader, "payload": payload,
            "size": path.stat().st_size,
            "prefix_sha256": __import__("hashlib").sha256(raw).hexdigest(),
        }, ensure_ascii=False, indent=1), encoding="utf-8")
        artifacts.append(str(out))
    return result(
        f"{key}: {reader} consumes attacker-controlled {path.name} "
        f"({path.stat().st_size} bytes); no deserialisation performed in probe mode",
        [finding("high", f"{key}: attacker-controlled {reader} input",
                 {"path": str(path), "payload": payload,
                  "note": "probe only; the dynamic PoC exercises the sink in a sandbox"},
                 evidence=reader)],
        artifacts,
    )
