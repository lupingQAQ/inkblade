# -*- coding: utf-8 -*-
"""Probe registry and controller.

Every probe is a row in SQLite (``probes.db``) and a transport endpoint.  A
child spawned by a parent is addressed through the parent's multiplexed
connection (the Rust server routes frames by ``probe``/``probe_id``), so the
operator never needs a second inbound port.
"""

from __future__ import annotations

import json
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from ..channel import ChannelError, ProbeConnection, ProbeError
from . import jsonio
from .evidence import EvidenceStore


class ProbeRegistryError(ValueError):
    pass


_SCHEMA = """
CREATE TABLE IF NOT EXISTS probes(
    probe_id TEXT PRIMARY KEY,
    parent_id TEXT,
    session_id TEXT,
    workspace TEXT,
    namespace TEXT,
    pod TEXT,
    node TEXT,
    caps TEXT,
    status TEXT,
    read_only INTEGER,
    last_seen REAL,
    created_at REAL,
    meta TEXT
);
CREATE TABLE IF NOT EXISTS probe_tasks(
    task_id TEXT PRIMARY KEY,
    probe_id TEXT,
    session_id TEXT,
    kind TEXT,
    status TEXT,
    params TEXT,
    result TEXT,
    created_at REAL,
    updated_at REAL
);
CREATE INDEX IF NOT EXISTS idx_probes_parent ON probes(parent_id);
CREATE INDEX IF NOT EXISTS idx_probe_tasks_probe ON probe_tasks(probe_id);
"""


def _db_path(store: EvidenceStore) -> Path:
    return Path(store.ws_dir) / "probes.db"


class ProbeRegistry:
    def __init__(self, store: EvidenceStore):
        self.store = store
        self.path = _db_path(store)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        import sqlite3

        conn = sqlite3.connect(self.path)
        try:
            conn.executescript(_SCHEMA)
            conn.commit()
        finally:
            conn.close()

    @contextmanager
    def _db(self):
        import sqlite3

        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def register(
        self,
        probe_id: str,
        *,
        parent_id: str | None = None,
        session_id: str = "",
        namespace: str = "",
        pod: str = "",
        node: str = "",
        caps: Iterable[str] = (),
        status: str = "online",
        read_only: bool = True,
        meta: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if not probe_id or len(probe_id) > 200:
            raise ProbeRegistryError("invalid probe id")
        now = time.time()
        with self._db() as conn:
            conn.execute(
                "INSERT INTO probes(probe_id,parent_id,session_id,workspace,namespace,pod,node,"
                "caps,status,read_only,last_seen,created_at,meta) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(probe_id) DO UPDATE SET parent_id=excluded.parent_id,"
                "session_id=excluded.session_id,namespace=excluded.namespace,pod=excluded.pod,"
                "node=excluded.node,caps=excluded.caps,status=excluded.status,"
                "read_only=excluded.read_only,last_seen=excluded.last_seen,meta=excluded.meta",
                (probe_id, parent_id, session_id, self.store.workspace, namespace, pod, node,
                 json.dumps(list(caps), ensure_ascii=False), status, int(read_only),
                 now, now, json.dumps(meta or {}, ensure_ascii=False)),
            )
        return self.get(probe_id) or {}

    def get(self, probe_id: str) -> dict[str, Any] | None:
        with self._db() as conn:
            row = conn.execute("SELECT * FROM probes WHERE probe_id=?", (probe_id,)).fetchone()
        return _row(row) if row else None

    def touch(self, probe_id: str, *, status: str | None = None) -> None:
        with self._db() as conn:
            if status:
                conn.execute("UPDATE probes SET last_seen=?,status=? WHERE probe_id=?",
                             (time.time(), status, probe_id))
            else:
                conn.execute("UPDATE probes SET last_seen=? WHERE probe_id=?", (time.time(), probe_id))

    def list(self, *, session_id: str | None = None, status: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM probes"
        clauses: list[str] = []
        args: list[Any] = []
        if session_id:
            clauses.append("session_id=?")
            args.append(session_id)
        if status:
            clauses.append("status=?")
            args.append(status)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY created_at"
        with self._db() as conn:
            rows = conn.execute(query, args).fetchall()
        return [_row(row) for row in rows]

    def children(self, probe_id: str) -> list[dict[str, Any]]:
        with self._db() as conn:
            rows = conn.execute("SELECT * FROM probes WHERE parent_id=? ORDER BY created_at",
                                (probe_id,)).fetchall()
        return [_row(row) for row in rows]

    def tree(self, root_id: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        root = self.get(root_id)
        if not root:
            return out

        def walk(node: dict[str, Any]) -> None:
            out.append(node)
            for child in self.children(str(node["probe_id"])):
                walk(child)

        walk(root)
        return out

    def cleanup_order(self, root_id: str) -> list[dict[str, Any]]:
        return list(reversed(self.tree(root_id)))

    def mark_offline(self, probe_id: str) -> None:
        self.touch(probe_id, status="offline")

    def delete(self, probe_id: str) -> None:
        with self._db() as conn:
            conn.execute("DELETE FROM probes WHERE probe_id=?", (probe_id,))

    def record_task(
        self,
        task_id: str,
        *,
        probe_id: str,
        session_id: str = "",
        kind: str = "",
        status: str = "running",
        params: dict[str, Any] | None = None,
        result: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = time.time()
        with self._db() as conn:
            conn.execute(
                "INSERT INTO probe_tasks(task_id,probe_id,session_id,kind,status,params,result,"
                "created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(task_id) DO UPDATE SET status=excluded.status,result=excluded.result,"
                "updated_at=excluded.updated_at",
                (task_id, probe_id, session_id, kind, status,
                 json.dumps(params or {}, ensure_ascii=False, default=str),
                 json.dumps(result or {}, ensure_ascii=False, default=str), now, now),
            )
        return self.task(task_id) or {}

    def task(self, task_id: str) -> dict[str, Any] | None:
        with self._db() as conn:
            row = conn.execute("SELECT * FROM probe_tasks WHERE task_id=?", (task_id,)).fetchone()
        if not row:
            return None
        item = dict(row)
        for key in ("params", "result"):
            try:
                item[key] = json.loads(item.get(key) or "{}")
            except ValueError:
                item[key] = {}
        return item

    def tasks(self, *, probe_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        query = "SELECT task_id FROM probe_tasks"
        args: list[Any] = []
        if probe_id:
            query += " WHERE probe_id=?"
            args.append(probe_id)
        query += " ORDER BY created_at DESC LIMIT ?"
        args.append(int(limit))
        with self._db() as conn:
            rows = conn.execute(query, args).fetchall()
        return [self.task(str(row[0])) or {} for row in rows]


def _row(row) -> dict[str, Any]:
    item = dict(row)
    try:
        item["caps"] = json.loads(item.get("caps") or "[]")
    except ValueError:
        item["caps"] = []
    try:
        item["meta"] = json.loads(item.get("meta") or "{}")
    except ValueError:
        item["meta"] = {}
    item["read_only"] = bool(item.get("read_only"))
    return item


@dataclass
class ProbeEndpoint:
    probe_id: str
    transport: ProbeConnection
    parent_id: str | None = None
    direct: bool = True


class ProbeController:
    """Registry + live transport endpoints.  No module talks to a host socket."""

    def __init__(self, store: EvidenceStore, registry: ProbeRegistry | None = None):
        self.store = store
        self.registry = registry or ProbeRegistry(store)
        self._endpoints: dict[str, ProbeEndpoint] = {}

    def add(
        self,
        probe_id: str,
        transport: ProbeConnection,
        *,
        parent_id: str | None = None,
        session_id: str = "",
        namespace: str = "",
        pod: str = "",
        node: str = "",
        direct: bool = True,
        meta: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        endpoint = ProbeEndpoint(probe_id=probe_id, transport=transport,
                                 parent_id=parent_id, direct=direct)
        self._endpoints[probe_id] = endpoint
        record = self.registry.register(
            probe_id, parent_id=parent_id, session_id=session_id,
            namespace=namespace, pod=pod, node=node,
            caps=transport.caps, status="online", read_only=transport.read_only, meta=meta,
        )
        self.registry.record_task(
            f"register-{probe_id}", probe_id=probe_id, session_id=session_id,
            kind="register", status="success",
            result={"caps": transport.caps, "version": transport.version},
        )
        return record

    def endpoint(self, probe_id: str) -> ProbeEndpoint:
        endpoint = self._endpoints.get(probe_id)
        if endpoint is None:
            raise ProbeRegistryError(f"probe {probe_id} is not connected")
        return endpoint

    def endpoint_for(self, probe_id: str) -> ProbeEndpoint:
        return self.endpoint(probe_id)

    def list_connected(self) -> list[str]:
        return sorted(self._endpoints)

    def remove(self, probe_id: str, *, offline: bool = True) -> None:
        self._endpoints.pop(probe_id, None)
        if offline:
            self.registry.mark_offline(probe_id)

    def _request(self, probe_id: str, op: str, args: dict[str, Any], *,
                 timeout: float | None = None, task_id: str | None = None,
                 kind: str = "") -> dict[str, Any]:
        endpoint = self.endpoint(probe_id)
        task_key = task_id or f"task-{uuid.uuid4().hex[:12]}"
        self.registry.record_task(task_key, probe_id=probe_id, kind=kind or op,
                                  status="running", params=args)
        try:
            if endpoint.direct:
                result = endpoint.transport.request(op, args, timeout=timeout, task_id=task_key)
            else:
                result = endpoint.transport.request(
                    op, args, timeout=timeout, probe_id=probe_id, task_id=task_key
                )
        except Exception as exc:
            self.registry.record_task(task_key, probe_id=probe_id, kind=kind or op,
                                      status="failed", params=args,
                                      result={"error": str(exc), "type": type(exc).__name__})
            raise
        self.registry.record_task(task_key, probe_id=probe_id, kind=kind or op,
                                  status="success", params=args, result=result)
        self.registry.touch(probe_id)
        return result

    def ping(self, probe_id: str) -> dict[str, Any]:
        return self._request(probe_id, "ping", {}, kind="ping")

    def collect(self, probe_id: str) -> dict[str, Any]:
        return self._request(probe_id, "collect", {}, kind="collect")

    def exec(self, probe_id: str, argv: list[str], **kwargs) -> dict[str, Any]:
        args = {"argv": list(argv)}
        for key in ("timeout_ms", "max_output"):
            if kwargs.get(key) is not None:
                args[key] = kwargs[key]
        return self._request(probe_id, "exec", args, kind="exec")

    def upload(self, probe_id: str, path: str, data: bytes, *, mode: int = 0o600) -> dict[str, Any]:
        endpoint = self.endpoint(probe_id)
        return endpoint.transport.upload(path, data, mode=mode)

    def download(self, probe_id: str, path: str, *, max_bytes: int = 16 * 1024 * 1024) -> bytes:
        endpoint = self.endpoint(probe_id)
        return endpoint.transport.download(path, max_bytes=max_bytes)

    def run_template(self, probe_id: str, template: dict[str, Any] | str,
                     params: dict[str, Any] | None = None, *,
                     timeout: float | None = None) -> dict[str, Any]:
        endpoint = self.endpoint(probe_id)
        task_id = f"task-{uuid.uuid4().hex[:12]}"
        self.registry.record_task(task_id, probe_id=probe_id, kind="template",
                                  status="running", params={"template": template, "params": params or {}})
        try:
            if endpoint.direct:
                result = endpoint.transport.run_task(
                    template, params or {}, task_id=task_id, timeout=timeout
                )
            else:
                result = endpoint.transport.run_task(
                    template, params or {}, task_id=task_id, timeout=timeout,
                    probe_id=probe_id,
                )
        except Exception as exc:
            self.registry.record_task(task_id, probe_id=probe_id, kind="template",
                                      status="failed", result={"error": str(exc)})
            raise
        self.registry.record_task(task_id, probe_id=probe_id, kind="template",
                                  status="success", result=result)
        return result

    def client(self, probe_id: str):
        """Return the minimal ``task`` client expected by ``tpl.probe.RustProbe``."""
        controller = self

        class _Client:
            def task(self, template, params=None, task_id=None):
                return controller.run_template(
                    probe_id, template, params or {}, timeout=None
                )

        return _Client()


    def spawn(
        self,
        parent_id: str,
        binary: bytes,
        *,
        probe_id: str | None = None,
        remote_path: str | None = None,
        via: str = "direct",
        namespace: str = "",
        pod: str = "",
        container: str = "",
        session_id: str = "",
        timeout: float | None = None,
    ) -> dict[str, Any]:
        child_id = probe_id or f"child-{uuid.uuid4().hex[:8]}"
        if via not in ("direct", "k8s-exec", "shared-volume"):
            raise ProbeRegistryError(f"unknown spawn transport {via}")
        endpoint = self.endpoint(parent_id)
        if via == "direct":
            remote = remote_path or f"/tmp/.inkblade-probe-child-{child_id}"
            # Chunked upload first (sha256 verified), then ask the parent to
            # materialise/start the child.  This avoids oversized protocol
            # frames and matches the RCE/bootstrap path.
            endpoint.transport.upload(remote, binary, mode=0o700)
            result = endpoint.transport.request("spawn", {
                "binary_path": remote,
                "sha256": __import__("hashlib").sha256(binary).hexdigest(),
                "probe_id": child_id,
                "path": remote,
            }, timeout=timeout)
        else:
            # The parent probe's k8s capability runs the uploaded child in the
            # target pod.  The controller still addresses the child through the
            # parent's multiplexed connection; no host kubectl is used.
            if via == "shared-volume" and not remote_path:
                raise ProbeRegistryError("shared-volume spawn needs an existing remote_path")
            if via == "k8s-exec":
                if not (namespace and pod):
                    raise ProbeRegistryError("k8s-exec spawn needs namespace and pod")
                # Upload the child through the parent, then ask the parent's
                # k8s exec capability to start it.
                if remote_path:
                    endpoint.transport.upload(remote_path, binary, mode=0o700)
                argv = [remote_path or "", "beacon"]
                result = self._request(parent_id, "k8s", {
                    "action": "exec", "namespace": namespace, "pod": pod,
                    "container": container or None, "argv": argv,
                }, kind="spawn.k8s-exec")
                result = {"probe_id": child_id, "parent_id": parent_id,
                          "registered": False, "via": via, "k8s": result}
            else:
                result = {"probe_id": child_id, "parent_id": parent_id,
                          "registered": False, "via": via,
                          "remote_path": remote_path}
        self.registry.register(
            child_id, parent_id=parent_id, session_id=session_id,
            namespace=namespace, pod=pod, status="online",
            read_only=endpoint.transport.read_only,
            meta={"via": via, "remote_path": remote_path or result.get("path")},
        )
        self._endpoints[child_id] = ProbeEndpoint(
            probe_id=child_id, transport=endpoint.transport,
            parent_id=parent_id, direct=False,
        )
        return result

    def cleanup(self, probe_id: str, *, recursive: bool = True,
                paths: Iterable[str] = ()) -> list[dict[str, Any]]:
        nodes = self.registry.cleanup_order(probe_id) if recursive else [
            self.registry.get(probe_id) or {"probe_id": probe_id}
        ]
        receipts: list[dict[str, Any]] = []
        for node in nodes:
            node_id = str(node.get("probe_id") or "")
            if not node_id:
                continue
            try:
                result = self._request(node_id, "cleanup", {"paths": list(paths)}, kind="cleanup")
                receipts.append({"probe_id": node_id, "ok": True, "result": result})
            except Exception as exc:  # parent may already be gone in a partial teardown
                receipts.append({"probe_id": node_id, "ok": False, "error": str(exc)})
            self._endpoints.pop(node_id, None)
            self.registry.mark_offline(node_id)
        return receipts

    def close(self) -> None:
        for endpoint in list(self._endpoints.values()):
            if endpoint.direct:
                try:
                    endpoint.transport.close()
                except Exception:
                    pass
        self._endpoints.clear()


def audit_registry(store: EvidenceStore, actor: str, action: str, target: str,
                   params: dict[str, Any] | None = None, result: str = "ok") -> dict[str, Any]:
    return jsonio.append_audit(store, actor, action, target=target, params=params, result=result)
