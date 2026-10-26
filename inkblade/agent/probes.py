# -*- coding: utf-8 -*-
"""Probe session boundary: every target-side action goes through ``probe_task``.

The session is the only execution surface the workers know.  It never imports a
module, never falls back to the host, and refuses to start when no probe is
configured.  Two backends are supported:

* ``rust-local`` — ``inkblade-probe run --stdio`` via the framed client and the
  canonical→native lowering in :mod:`inkblade.tpl.probe`.
* ``reference`` — the explicit conformance runtime for the mock range
  (``INKBLADE_ALLOW_REFERENCE_PROBE=1``); it is labelled ``runtime=reference``
  everywhere and is never selected implicitly in production.

Tests and embedding code may pass a transport object directly; that is still a
``probe_task`` call and is recorded as evidence from a probe.
"""
from __future__ import annotations

import json
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Protocol

from ..tpl.probe import (LocalFramedClient, ProbeFailed, ProbeTransport, ProbeUnavailable,
                         ReferenceRuntime, RustProbe, validate_result)
from ..tpl.backends import LocalBackend, K8sShim


class ProbeSessionError(ProbeUnavailable):
    """Session/probe configuration error (no host fallback)."""


class ProbeTaskTransport(Protocol):
    runtime: str

    def run(self, template: dict, params: dict, context: dict) -> dict: ...


class SessionTransport:
    """Adapts ``ProbeSession.probe_task`` to the template transport protocol."""

    def __init__(self, session: "ProbeSession"):
        self.session = session
        self.runtime = session.runtime

    def run(self, template: dict, params: dict, context: dict) -> dict:
        task_id = f"{template.get('key') or 'probe'}-{uuid.uuid4().hex[:10]}"
        result = self.session.probe_task(template, params, task_id)
        if not isinstance(result, dict):
            raise ProbeFailed("probe_task 必须返回对象")
        return validate_result(result, template)


class ProbeSession:
    """A user session + a probe backend; exposes only ``probe_task`` for execution."""

    def __init__(self, *, base_session, backend, runtime: str, probe_id: str = ""):
        self.base_session = base_session
        self.backend = backend
        self.runtime = str(runtime)
        self.probe_id = str(probe_id)
        self.name = getattr(base_session, "name", "agent")
        self.role = getattr(base_session, "role", "tester")
        self._local = threading.local()
        self._lock = threading.Lock()
        self.calls: list[dict] = []

    # ------------------------------------------------------------ user session
    def can(self, action: str) -> bool:
        fn = getattr(self.base_session, "can", None)
        return bool(fn(action)) if callable(fn) else action in ("execute", "read")

    def visible_workspaces(self, root: Path | None = None) -> list[str]:
        fn = getattr(self.base_session, "visible_workspaces", None)
        return fn(root=root) if callable(fn) else []

    # ------------------------------------------------------------ probe task
    def probe_task(self, template: dict, params: dict, task_id: str) -> dict:
        if self.backend is None:
            raise ProbeUnavailable(f"probe {self.probe_id!r} 没有可用传输（拒绝宿主回退）")
        if not isinstance(template, dict) or not template.get("key"):
            raise ProbeFailed("probe_task 需要 canonical template")
        if not isinstance(params, dict):
            raise ProbeFailed("probe_task params 必须是对象")
        started = time.time()
        digest = _template_digest(template, params)
        try:
            result = self.backend.run(template, dict(params), {
                "probe_id": self.probe_id, "runtime": self.runtime,
                "task_id": task_id,
            })
        except Exception as exc:
            with self._lock:
                self.calls.append({"task_id": task_id, "key": template.get("key"),
                                   "runtime": self.runtime, "ok": False,
                                   "error": f"{type(exc).__name__}: {exc}",
                                   "digest": digest, "duration_ms": _ms(started)})
            raise
        if not isinstance(result, dict):
            raise ProbeFailed("probe backend 返回非对象")
        with self._lock:
            self.calls.append({"task_id": task_id, "key": template.get("key"),
                               "runtime": self.runtime, "ok": True,
                               "status": result.get("status", ""), "digest": digest,
                               "duration_ms": _ms(started)})
        self._local.last = result
        return result

    def last_probe_result(self) -> dict | None:
        return getattr(self._local, "last", None)

    # ------------------------------------------------------------ adapter
    def probe(self) -> ProbeTaskTransport:
        return SessionTransport(self)

    def call_count(self) -> int:
        with self._lock:
            return len(self.calls)

    def close(self) -> None:
        close = getattr(self.backend, "close", None)
        if callable(close):
            close()


def _ms(started: float) -> int:
    return int((time.time() - started) * 1000)


def _template_digest(template: dict, params: dict) -> str:
    import hashlib

    raw = json.dumps({"template": template, "params": params}, ensure_ascii=False,
                     sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


# --------------------------------------------------------------------------
# Probe configuration / construction
# --------------------------------------------------------------------------
def probes_path(store) -> Path:
    ws = Path(store.ws_dir) / "agent" / "probes.json"
    if ws.is_file():
        return ws
    return Path(store.root) / "agent-probes.json"


def load_probe_config(store, probe_id: str) -> dict | None:
    path = probes_path(store)
    if not path.is_file():
        return None
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise ProbeSessionError(f"{path} 非法 JSON: {exc}") from exc
    items = doc.get("probes") if isinstance(doc, dict) else doc
    if not isinstance(items, list):
        raise ProbeSessionError(f"{path} 需要 probes 数组")
    for item in items:
        if isinstance(item, dict) and str(item.get("id") or "") == str(probe_id):
            return dict(item)
    return None


def _reference_backend(*, workdir: str | Path | None = None, k8s: K8sShim | None = None,
                       env: dict | None = None):
    backend = LocalBackend(workdir=workdir, k8s=k8s, env=env)
    return ReferenceRuntime(backend)


def reference_allowed() -> bool:
    return os.environ.get("INKBLADE_ALLOW_REFERENCE_PROBE") == "1"


def build_probe_session(store, base_session, probe_id: str, *,
                        spec: dict | None = None, allow_reference: bool | None = None,
                        workdir: str | Path | None = None,
                        k8s: K8sShim | None = None) -> ProbeSession:
    """Resolve ``--probe <id>``; unknown or unconfigured ids are a hard refusal."""
    if not str(probe_id or "").strip():
        raise ProbeUnavailable("未指定 --probe；agent 拒绝在没有探针时执行")
    config = dict(spec) if spec is not None else load_probe_config(store, probe_id)
    if config is None and str(probe_id) == "reference":
        config = {"id": "reference", "kind": "reference"}
    if config is None:
        raise ProbeUnavailable(
            f"未知 probe {probe_id!r}（配置 {probes_path(store)}）；拒绝宿主回退")
    kind = str(config.get("kind") or "")
    runtime = str(config.get("runtime") or "")
    if kind == "transport":
        backend = config.get("backend")
        if backend is None:
            raise ProbeUnavailable(f"probe {probe_id} transport 缺 backend")
        return ProbeSession(base_session=base_session, backend=backend,
                            runtime=runtime or getattr(backend, "runtime", "probe"),
                            probe_id=probe_id)
    if kind == "reference":
        allowed = reference_allowed() if allow_reference is None else bool(allow_reference)
        if not allowed:
            raise ProbeUnavailable(
                "reference 运行时只允许 mock range：设置 INKBLADE_ALLOW_REFERENCE_PROBE=1 "
                "或显式 allow_reference=True（结果会标记 runtime=reference）")
        backend = _reference_backend(workdir=workdir or config.get("workdir"), k8s=k8s,
                                     env=config.get("env"))
        return ProbeSession(base_session=base_session, backend=backend,
                            runtime="reference", probe_id=probe_id)
    if kind in ("rust-local", "rust"):
        binary = str(config.get("binary") or os.environ.get("INKBLADE_PROBE_BIN") or "")
        token = str(config.get("token") or os.environ.get("INKBLADE_PROBE_TOKEN") or "")
        token_env = str(config.get("token_env") or "")
        if token_env:
            token = os.environ.get(token_env, "")
        if not binary or not Path(binary).is_file():
            raise ProbeUnavailable(f"probe {probe_id}: Rust 二进制不存在 {binary!r}")
        if not token:
            raise ProbeUnavailable(f"probe {probe_id}: 缺少 HMAC token")
        backend = RustProbe(LocalFramedClient(binary, token,
                                              timeout_ms=int(config.get("timeout_ms") or 120000)))
        return ProbeSession(base_session=base_session, backend=backend,
                            runtime="rust", probe_id=probe_id)
    if kind == "rust-object":
        client = config.get("client")
        if client is None:
            raise ProbeUnavailable(f"probe {probe_id}: rust-object 缺 client")
        return ProbeSession(base_session=base_session, backend=RustProbe(client),
                            runtime="rust", probe_id=probe_id)
    raise ProbeUnavailable(f"probe {probe_id}: 未知 kind={kind!r}")


def probe_status(store) -> dict:
    path = probes_path(store)
    items: list[dict] = []
    if path.is_file():
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
            raw = doc.get("probes") if isinstance(doc, dict) else doc
            for item in raw or []:
                if isinstance(item, dict):
                    items.append({"id": item.get("id"), "kind": item.get("kind"),
                                  "runtime": item.get("runtime"),
                                  "binary": bool(item.get("binary") or
                                                 os.environ.get("INKBLADE_PROBE_BIN"))})
        except ValueError:
            items.append({"error": "invalid probes.json"})
    return {"path": str(path), "exists": path.is_file(),
            "reference_allowed": reference_allowed(), "probes": items}
