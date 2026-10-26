# -*- coding: utf-8 -*-
"""Probe task translation and dispatch.

The target accepts declarative template tasks only.  This module translates the
task vocabulary used by the controller (http / exec / fs upload/download /
spawn / template) into probe requests, records every task in the registry, and
refuses any request that would require an interpreter in the Pod.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from .probes import ProbeController, ProbeRegistry
from ..session import PentestSession


class ProbeTaskError(RuntimeError):
    pass


class UnsupportedTask(ProbeTaskError):
    pass


@dataclass
class ProbeTask:
    kind: str
    payload: dict[str, Any]
    task_id: str = field(default_factory=lambda: f"task-{uuid.uuid4().hex[:12]}")
    probe_id: str = ""
    session_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"task_id": self.task_id, "kind": self.kind, "probe_id": self.probe_id,
                "session_id": self.session_id, "payload": self.payload}


def task_id() -> str:
    return f"task-{uuid.uuid4().hex[:12]}"


def http_task(method: str, url: str, *, headers: dict[str, str] | None = None,
              body: Any = None, timeout_ms: int = 8000, write: bool = False) -> dict[str, Any]:
    step: dict[str, Any] = {
        "id": "http", "op": "http", "method": str(method or "GET").upper(),
        "url": url, "timeout_ms": int(timeout_ms),
    }
    if headers:
        step["headers"] = dict(headers)
    if body is not None:
        step["body"] = body
    if write:
        step["write"] = True
    return {"name": "controller.http", "steps": [step]}


def exec_task(argv: list[str], *, timeout_ms: int = 8000) -> dict[str, Any]:
    if not argv or any(not isinstance(item, str) for item in argv):
        raise ProbeTaskError("exec argv must be a non-empty string list")
    if len(argv) == 1 and (" " in argv[0] or ";" in argv[0] or "|" in argv[0]):
        raise UnsupportedTask("probe exec takes argv, not a shell string")
    return {"name": "controller.exec",
            "steps": [{"id": "exec", "op": "exec", "argv": argv, "timeout_ms": int(timeout_ms)}]}


def upload_task(path: str, data: bytes, *, mode: int = 0o600,
                chunk_size: int = 48 * 1024) -> list[dict[str, Any]]:
    chunks = []
    for offset in range(0, max(1, len(data)), chunk_size):
        chunk = data[offset:offset + chunk_size]
        chunks.append({
            "path": path, "offset": offset, "mode": mode,
            "data_b64": base64.b64encode(chunk).decode("ascii"),
            "sha256": hashlib.sha256(data).hexdigest(),
            "final": offset + len(chunk) >= len(data),
        })
    if not data:
        chunks.append({"path": path, "offset": 0, "mode": mode, "data_b64": "",
                       "sha256": hashlib.sha256(b"").hexdigest(), "final": True})
    return chunks


def download_task(path: str, *, offset: int = 0, max_bytes: int = 48 * 1024) -> dict[str, Any]:
    return {"path": path, "offset": int(offset), "max_bytes": int(max_bytes)}


def spawn_task(argv: list[str], *, detach: bool = False,
               probe_id: str | None = None, binary: bytes | None = None) -> dict[str, Any]:
    if binary is not None:
        return {"binary_b64": base64.b64encode(binary).decode("ascii"),
                "sha256": hashlib.sha256(binary).hexdigest(),
                "probe_id": probe_id or f"child-{uuid.uuid4().hex[:8]}"}
    return {"name": "controller.spawn",
            "steps": [{"id": "spawn", "op": "spawn", "argv": list(argv),
                       "detach": bool(detach)}]}


def translate_action(action: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    """Translate a legacy action name into a declarative task.

    ``python`` and ``shell`` are intentionally unsupported: there is no
    interpreter in the target Pod.
    """
    payload = dict(payload or {})
    action = str(action or "").lower()
    if action == "http":
        return http_task(payload.get("method", "GET"), str(payload.get("url") or ""),
                         headers=payload.get("headers"), body=payload.get("body"),
                         timeout_ms=int(payload.get("timeout_ms") or 8000),
                         write=bool(payload.get("write")))
    if action in ("exec", "command"):
        return exec_task(list(payload.get("argv") or []),
                         timeout_ms=int(payload.get("timeout_ms") or 8000))
    if action in ("python", "py", "shell", "sh", "bash"):
        raise UnsupportedTask(
            f"action {action!r} requires an interpreter; the target only accepts native templates"
        )
    if action == "upload":
        return {"chunks": upload_task(str(payload.get("path") or ""),
                                      payload.get("data") or b"",
                                      mode=int(payload.get("mode") or 0o600))}
    if action == "download":
        return download_task(str(payload.get("path") or ""),
                             offset=int(payload.get("offset") or 0),
                             max_bytes=int(payload.get("max_bytes") or 48 * 1024))
    if action == "spawn":
        return spawn_task(list(payload.get("argv") or []),
                          detach=bool(payload.get("detach")),
                          probe_id=payload.get("probe_id"),
                          binary=payload.get("binary"))
    if action == "template":
        return {"template": payload.get("template") or {},
                "params": payload.get("params") or {}}
    raise UnsupportedTask(f"unknown task action {action!r}")


class ProbeTaskDispatcher:
    """Execute controller tasks against one or more registered probes."""

    def __init__(self, store, registry: ProbeRegistry | None = None):
        self.store = store
        self.registry = registry or ProbeRegistry(store)
        self.controller = ProbeController(store, self.registry)

    def register(self, probe_id: str, transport, **kwargs) -> dict[str, Any]:
        return self.controller.add(probe_id, transport, **kwargs)

    def dispatch(self, probe_id: str, task: ProbeTask) -> dict[str, Any]:
        self.registry.record_task(task.task_id, probe_id=probe_id,
                                  session_id=task.session_id, kind=task.kind,
                                  status="running", params=task.payload)
        try:
            if task.kind == "template":
                result = self.controller.run_template(
                    probe_id, task.payload.get("template") or {},
                    task.payload.get("params") or {},
                )
            elif task.kind == "http":
                result = self.controller.run_template(probe_id, task.payload,
                                                       task.payload.get("params") or {})
            elif task.kind == "exec":
                result = self.controller.run_template(
                    probe_id, task.payload, task.payload.get("params") or {}
                )
            elif task.kind == "upload":
                result = {"chunks": []}
                for chunk in task.payload.get("chunks") or []:
                    result["chunks"].append(self.controller._request(
                        probe_id, "upload", chunk, kind="upload"
                    ))
            elif task.kind == "download":
                result = {"data_b64": base64.b64encode(
                    self.controller.download(probe_id, task.payload.get("path") or "",
                                             max_bytes=int(task.payload.get("max_bytes") or 1024 * 1024))
                ).decode("ascii")}
            elif task.kind == "spawn":
                binary = task.payload.get("binary")
                result = self.controller.spawn(
                    probe_id, binary or b"", probe_id=task.payload.get("probe_id"),
                    remote_path=task.payload.get("path"),
                )
            else:
                raise UnsupportedTask(f"unknown task kind {task.kind!r}")
        except Exception as exc:
            self.registry.record_task(task.task_id, probe_id=probe_id,
                                      session_id=task.session_id, kind=task.kind,
                                      status="failed", params=task.payload,
                                      result={"error": str(exc)})
            raise
        self.registry.record_task(task.task_id, probe_id=probe_id,
                                  session_id=task.session_id, kind=task.kind,
                                  status="success", params=task.payload, result=result)
        return result


def run_module_via_probe(
    controller: ProbeController,
    session: PentestSession,
    module_key: str,
    meta,
    params: dict[str, Any],
) -> dict[str, Any]:
    """Run a canonical template through a probe and fold the result.

    This is the template path; RoE/backup gates remain in ``core.runner`` when
    called from a full session.  Direct callers (tests/lab) get the same probe
    execution without a host fallback.
    """
    from ..tpl.execute import execute_template
    from ..tpl.probe import RustProbe

    if not session.probe_ids:
        raise ProbeTaskError("no probe registered for this session")
    probe_id = str(params.get("probe_id") or session.probe_ids[-1])
    transport = RustProbe(controller.client(probe_id))
    actor = SimpleNamespace(name=session.actor, role=session.role,
                            can=lambda action: action == "execute")
    return execute_template(controller.store, actor, meta, params, probe=transport,
                            run=None)  # type: ignore[arg-type]
