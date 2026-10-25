# -*- coding: utf-8 -*-
"""本地多租户控制面：ThreadingHTTP + 多进程 worker + SQLite 原子配额/审批。

模拟边界：
- 单机、单 SQLite、模拟模块工作（sleep + 小 artifact），不是商业 SaaS；
- 隔离用 workspace + EvidenceStore 真实落盘；配额/审批用 SQLite 事务保证原子；
- 没有跨 region/HA、Postgres、KMS、真实网络准入。
"""
from __future__ import annotations

import json
import multiprocessing as mp
import os
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS tenants(
  id TEXT PRIMARY KEY, token TEXT UNIQUE, role TEXT NOT NULL,
  workspace TEXT UNIQUE NOT NULL, max_concurrent INTEGER NOT NULL,
  max_runs INTEGER NOT NULL, max_evidence_bytes INTEGER NOT NULL,
  work_ms INTEGER NOT NULL DEFAULT 5);
CREATE TABLE IF NOT EXISTS runs(
  id TEXT PRIMARY KEY, tenant TEXT NOT NULL, module TEXT NOT NULL,
  evidence_bytes INTEGER NOT NULL, status TEXT NOT NULL,
  created_at REAL NOT NULL, started_at REAL, finished_at REAL,
  worker INTEGER, error TEXT);
CREATE TABLE IF NOT EXISTS approvals(
  id TEXT PRIMARY KEY, tenant TEXT NOT NULL, action TEXT NOT NULL,
  status TEXT NOT NULL, created_at REAL NOT NULL, decided_at REAL,
  decided_by TEXT);
CREATE INDEX IF NOT EXISTS runs_tenant_status ON runs(tenant, status);
CREATE INDEX IF NOT EXISTS approvals_tenant_status ON approvals(tenant, status);
"""


def _connect(db_path: Path | str) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path), timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


@dataclass
class Tenant:
    id: str
    token: str
    role: str
    workspace: str
    max_concurrent: int
    max_runs: int
    max_evidence_bytes: int
    work_ms: int


class Service:
    def __init__(self, root: Path | str, *, tenants: int = 8, workers: int = 4,
                 work_ms: int = 5, host: str = "127.0.0.1", port: int = 0,
                 seed: bool = True):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.db_path = self.root / "saas.db"
        self.evidence_root = self.root / "evidence"
        self.n_tenants = tenants
        self.n_workers = workers
        self.work_ms = work_ms
        self.host = host
        self.port = port
        self._queue: Any = None
        self._workers: list[mp.Process] = []
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._ctx = mp.get_context("spawn")
        self._lock = threading.Lock()
        if seed:
            self._init_db()
            self.seed_tenants(tenants, work_ms=work_ms)

    # ---------- DB ----------
    def _init_db(self) -> None:
        conn = _connect(self.db_path)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(SCHEMA)
            conn.commit()
        finally:
            conn.close()

    def seed_tenants(self, count: int, *, work_ms: int | None = None) -> None:
        conn = _connect(self.db_path)
        try:
            for i in range(count):
                tid = f"tenant-{i:02d}"
                conn.execute(
                    "INSERT OR IGNORE INTO tenants(id,token,role,workspace,max_concurrent,"
                    "max_runs,max_evidence_bytes,work_ms) VALUES(?,?,?,?,?,?,?,?)",
                    (tid, f"tok-{tid}", "lead", f"ws-{tid}", 4, 50, 1 << 20,
                     int(work_ms if work_ms is not None else self.work_ms)))
            conn.execute(
                "INSERT OR IGNORE INTO tenants(id,token,role,workspace,max_concurrent,"
                "max_runs,max_evidence_bytes,work_ms) VALUES(?,?,?,?,?,?,?,?)",
                ("tenant-tester", "tok-tenant-tester", "tester", "ws-tenant-tester",
                 4, 50, 1 << 20, int(work_ms if work_ms is not None else self.work_ms)))
            conn.commit()
        finally:
            conn.close()

    def configure_tenant(self, tenant_id: str, **values) -> None:
        allowed = {"max_concurrent", "max_runs", "max_evidence_bytes", "work_ms", "role"}
        conn = _connect(self.db_path)
        try:
            for key, value in values.items():
                if key not in allowed:
                    raise ValueError(f"不支持配置 {key}")
                conn.execute(f"UPDATE tenants SET {key}=? WHERE id=?", (value, tenant_id))
            conn.commit()
        finally:
            conn.close()

    def tenant_by_token(self, token: str) -> Tenant | None:
        conn = _connect(self.db_path)
        try:
            row = conn.execute("SELECT * FROM tenants WHERE token=?", (token,)).fetchone()
            return Tenant(**dict(row)) if row else None
        finally:
            conn.close()

    def tenant_by_id(self, tenant_id: str) -> Tenant | None:
        conn = _connect(self.db_path)
        try:
            row = conn.execute("SELECT * FROM tenants WHERE id=?", (tenant_id,)).fetchone()
            return Tenant(**dict(row)) if row else None
        finally:
            conn.close()

    # ---------- quota / submit ----------
    def submit(self, tenant: Tenant, module: str, evidence_bytes: int) -> tuple[int, dict]:
        if not module or len(module) > 120:
            return 400, {"error": "module required"}
        if evidence_bytes < 0 or evidence_bytes > 8 << 20:
            return 400, {"error": "evidence_bytes out of range"}
        conn = _connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM tenants WHERE id=?", (tenant.id,)).fetchone()
            if row is None:
                conn.rollback()
                return 401, {"error": "unknown tenant"}
            cfg = Tenant(**dict(row))
            if evidence_bytes > cfg.max_evidence_bytes:
                conn.rollback()
                return 429, {"error": "evidence quota", "quota": "max_evidence_bytes",
                             "limit": cfg.max_evidence_bytes}
            total = conn.execute("SELECT COUNT(*) FROM runs WHERE tenant=?",
                                 (tenant.id,)).fetchone()[0]
            if total >= cfg.max_runs:
                conn.rollback()
                return 429, {"error": "run quota", "quota": "max_runs", "limit": cfg.max_runs}
            active = conn.execute(
                "SELECT COUNT(*) FROM runs WHERE tenant=? AND status IN ('queued','running')",
                (tenant.id,)).fetchone()[0]
            if active >= cfg.max_concurrent:
                conn.rollback()
                return 429, {"error": "concurrency quota", "quota": "max_concurrent",
                             "limit": cfg.max_concurrent}
            used = conn.execute("SELECT COALESCE(SUM(evidence_bytes),0) FROM runs WHERE tenant=?",
                                (tenant.id,)).fetchone()[0]
            if used + evidence_bytes > cfg.max_evidence_bytes * 8:
                conn.rollback()
                return 429, {"error": "evidence budget", "quota": "max_evidence_bytes",
                             "limit": cfg.max_evidence_bytes * 8}
            rid = "run-" + uuid.uuid4().hex[:12]
            conn.execute("INSERT INTO runs(id,tenant,module,evidence_bytes,status,created_at)"
                         " VALUES(?,?,?,?,?,?)",
                         (rid, tenant.id, module, evidence_bytes, "queued", time.time()))
            conn.commit()
        finally:
            conn.close()
        self._queue.put({"run_id": rid, "tenant": tenant.id, "workspace": tenant.workspace,
                         "module": module, "evidence_bytes": evidence_bytes,
                         "work_ms": tenant.work_ms})
        return 202, {"run_id": rid, "status": "queued"}

    def get_run(self, tenant: Tenant, run_id: str) -> tuple[int, dict]:
        conn = _connect(self.db_path)
        try:
            row = conn.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
            if row is None:
                return 404, {"error": "run not found"}
            if row["tenant"] != tenant.id:
                return 403, {"error": "cross-tenant access denied"}
            return 200, dict(row)
        finally:
            conn.close()

    def list_runs(self, tenant: Tenant, limit: int = 100) -> list[dict]:
        conn = _connect(self.db_path)
        try:
            rows = conn.execute("SELECT * FROM runs WHERE tenant=? ORDER BY created_at DESC LIMIT ?",
                                (tenant.id, max(1, min(500, limit)))).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    def usage(self, tenant: Tenant) -> dict:
        conn = _connect(self.db_path)
        try:
            total = conn.execute("SELECT COUNT(*) FROM runs WHERE tenant=?", (tenant.id,)).fetchone()[0]
            active = conn.execute(
                "SELECT COUNT(*) FROM runs WHERE tenant=? AND status IN ('queued','running')",
                (tenant.id,)).fetchone()[0]
            done = conn.execute("SELECT COUNT(*) FROM runs WHERE tenant=? AND status='done'",
                                (tenant.id,)).fetchone()[0]
            used = conn.execute("SELECT COALESCE(SUM(evidence_bytes),0) FROM runs WHERE tenant=?",
                                (tenant.id,)).fetchone()[0]
            pending = conn.execute(
                "SELECT COUNT(*) FROM approvals WHERE tenant=? AND status='pending'",
                (tenant.id,)).fetchone()[0]
            return {"tenant": tenant.id, "runs_total": total, "active": active,
                    "done": done, "evidence_bytes": used,
                    "pending_approvals": pending,
                    "limits": {"max_concurrent": tenant.max_concurrent,
                               "max_runs": tenant.max_runs,
                               "max_evidence_bytes": tenant.max_evidence_bytes}}
        finally:
            conn.close()

    # ---------- approvals ----------
    def create_approval(self, tenant: Tenant, action: str) -> tuple[int, dict]:
        if not action or len(action) > 200:
            return 400, {"error": "action required"}
        aid = "app-" + uuid.uuid4().hex[:12]
        conn = _connect(self.db_path)
        try:
            conn.execute("INSERT INTO approvals(id,tenant,action,status,created_at)"
                         " VALUES(?,?,?, 'pending', ?)", (aid, tenant.id, action, time.time()))
            conn.commit()
            return 201, {"approval_id": aid, "status": "pending"}
        finally:
            conn.close()

    def approve(self, tenant: Tenant, approval_id: str) -> tuple[int, dict]:
        if tenant.role != "lead":
            return 403, {"error": f"{tenant.role} 无 approve 权限"}
        conn = _connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM approvals WHERE id=?", (approval_id,)).fetchone()
            if row is None or row["tenant"] != tenant.id:
                conn.rollback()
                return 404, {"error": "approval not found"}
            cur = conn.execute(
                "UPDATE approvals SET status='approved', decided_at=?, decided_by=?"
                " WHERE id=? AND tenant=? AND status='pending'",
                (time.time(), tenant.id, approval_id, tenant.id))
            if cur.rowcount == 0:
                conn.rollback()
                return 409, {"error": "already decided", "status": row["status"]}
            conn.commit()
            return 200, {"approval_id": approval_id, "status": "approved"}
        finally:
            conn.close()

    def reject(self, tenant: Tenant, approval_id: str, reason: str = "") -> tuple[int, dict]:
        if tenant.role != "lead":
            return 403, {"error": f"{tenant.role} 无 approve 权限"}
        conn = _connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM approvals WHERE id=?", (approval_id,)).fetchone()
            if row is None or row["tenant"] != tenant.id:
                conn.rollback()
                return 404, {"error": "approval not found"}
            cur = conn.execute(
                "UPDATE approvals SET status='rejected', decided_at=?, decided_by=?"
                " WHERE id=? AND tenant=? AND status='pending'",
                (time.time(), tenant.id, approval_id, tenant.id))
            if cur.rowcount == 0:
                conn.rollback()
                return 409, {"error": "already decided", "status": row["status"]}
            conn.commit()
            return 200, {"approval_id": approval_id, "status": "rejected",
                         "reason": reason[:200]}
        finally:
            conn.close()

    def get_approval(self, tenant: Tenant, approval_id: str) -> tuple[int, dict]:
        conn = _connect(self.db_path)
        try:
            row = conn.execute("SELECT * FROM approvals WHERE id=?", (approval_id,)).fetchone()
            if row is None:
                return 404, {"error": "approval not found"}
            if row["tenant"] != tenant.id:
                return 403, {"error": "cross-tenant access denied"}
            return 200, dict(row)
        finally:
            conn.close()

    # ---------- lifecycle ----------
    def start_workers(self) -> None:
        if self._workers:
            return
        self._queue = self._ctx.Queue()
        for i in range(self.n_workers):
            proc = self._ctx.Process(target=_worker_main,
                                     args=(str(self.root), str(self.db_path), self._queue, i),
                                     daemon=True)
            proc.start()
            self._workers.append(proc)

    def stop_workers(self) -> None:
        if not self._workers:
            return
        for _ in self._workers:
            self._queue.put(None)
        for proc in self._workers:
            proc.join(timeout=10)
            if proc.is_alive():
                proc.terminate()
                proc.join(timeout=5)
        self._workers.clear()
        try:
            self._queue.close()
        except Exception:
            pass

    def start_http(self) -> "Service":
        service = self

        class Handler(_Handler):
            svc = service

        class Server(ThreadingHTTPServer):
            request_queue_size = 256
            daemon_threads = True

        self._httpd = Server((self.host, self.port), Handler)
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def start(self) -> "Service":
        self.start_workers()
        self.start_http()
        return self

    def stop(self) -> None:
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        self.stop_workers()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def __enter__(self): return self.start()
    def __exit__(self, *exc): self.stop()


# ---------------------------------------------------------------- worker

def _worker_main(root: str, db_path: str, queue, index: int) -> None:
    from trident.core.evidence import EvidenceStore

    while True:
        job = queue.get()
        if job is None:
            break
        run_id = job["run_id"]
        conn = _connect(db_path)
        try:
            cur = conn.execute(
                "UPDATE runs SET status='running', started_at=?, worker=?"
                " WHERE id=? AND status='queued'", (time.time(), index, run_id))
            if cur.rowcount == 0:
                conn.commit()
                continue
            conn.commit()
            store = EvidenceStore(Path(root), workspace=job["workspace"])
            evidence_bytes = int(job["evidence_bytes"])
            run = store.create_run(f"saas-{run_id}")
            payload = (f"tenant={job['tenant']} module={job['module']} "
                       f"evidence_bytes={evidence_bytes}\n").encode()
            if evidence_bytes > len(payload):
                payload = payload + b"\x00" * (evidence_bytes - len(payload))
            elif evidence_bytes > 0:
                payload = payload[:evidence_bytes]
            artifact = Path(run.dir) / "artifact.bin"
            artifact.write_bytes(payload)
            time.sleep(max(0, int(job.get("work_ms", 0))) / 1000.0)
            run.add_step(step_key=f"{job['tenant']}-{job['module']}",
                         prompt_or_cmd=f"simulated module {job['module']}",
                         env={"tenant": job["tenant"], "worker": index},
                         result_summary="simulated run complete",
                         artifacts=[artifact])
            run.finalize_run()
            conn.execute("UPDATE runs SET status='done', finished_at=? WHERE id=?",
                         (time.time(), run_id))
            conn.commit()
        except Exception as exc:  # noqa: BLE001
            try:
                conn.execute("UPDATE runs SET status='failed', error=?, finished_at=? WHERE id=?",
                             (f"{type(exc).__name__}: {exc}"[:500], time.time(), run_id))
                conn.commit()
            except Exception:
                pass
        finally:
            conn.close()


# ---------------------------------------------------------------- HTTP

class _Handler(BaseHTTPRequestHandler):
    svc: Service = None  # type: ignore[assignment]

    def log_message(self, *args):
        pass

    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        try:
            value = json.loads(self.rfile.read(length).decode())
            return value if isinstance(value, dict) else {}
        except ValueError:
            return {}

    def _auth(self):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            self._json(401, {"error": "login required"})
            return None
        tenant = self.svc.tenant_by_token(auth[7:])
        if tenant is None:
            self._json(401, {"error": "invalid token"})
        return tenant

    def do_GET(self):
        if self.path == "/health":
            return self._json(200, {"ok": True})
        tenant = self._auth()
        if tenant is None:
            return
        if self.path == "/v1/runs":
            return self._json(200, {"runs": self.svc.list_runs(tenant)})
        if self.path == "/v1/usage":
            return self._json(200, self.svc.usage(tenant))
        if self.path.startswith("/v1/runs/"):
            rid = self.path[len("/v1/runs/"):].split("?")[0]
            status, doc = self.svc.get_run(tenant, rid)
            return self._json(status, doc)
        if self.path.startswith("/v1/approvals/"):
            aid = self.path[len("/v1/approvals/"):].split("?")[0]
            status, doc = self.svc.get_approval(tenant, aid)
            return self._json(status, doc)
        return self._json(404, {"error": "not found"})

    def do_POST(self):
        path = self.path.split("?")[0]
        body = self._body()
        if path == "/v1/login":
            tenant = self.svc.tenant_by_token(str(body.get("token") or ""))
            if tenant is None or tenant.id != str(body.get("tenant") or ""):
                return self._json(401, {"error": "invalid tenant/token"})
            return self._json(200, {"token": tenant.token, "tenant": tenant.id,
                                    "role": tenant.role, "workspace": tenant.workspace})
        tenant = self._auth()
        if tenant is None:
            return
        if path == "/v1/runs":
            # workspace 由 token 决定；显式传入不同 workspace 一律拒绝，防越权
            if body.get("workspace") not in (None, "", tenant.workspace):
                return self._json(403, {"error": "workspace mismatch"})
            try:
                evidence_bytes = int(body.get("evidence_bytes", 4096))
            except (TypeError, ValueError):
                return self._json(400, {"error": "evidence_bytes must be int"})
            status, doc = self.svc.submit(tenant, str(body.get("module") or ""), evidence_bytes)
            return self._json(status, doc)
        if path == "/v1/approvals":
            status, doc = self.svc.create_approval(tenant, str(body.get("action") or ""))
            return self._json(status, doc)
        if path.startswith("/v1/approvals/") and path.endswith("/approve"):
            aid = path[len("/v1/approvals/"):-len("/approve")]
            status, doc = self.svc.approve(tenant, aid)
            return self._json(status, doc)
        if path.startswith("/v1/approvals/") and path.endswith("/reject"):
            aid = path[len("/v1/approvals/"):-len("/reject")]
            status, doc = self.svc.reject(tenant, aid, str(body.get("reason") or ""))
            return self._json(status, doc)
        return self._json(404, {"error": "not found"})


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Trident SaaS control-plane lab")
    ap.add_argument("--root", default=str(Path(__file__).resolve().parent / "out"))
    ap.add_argument("--tenants", type=int, default=8)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--work-ms", type=int, default=5)
    ap.add_argument("--port", type=int, default=0)
    args = ap.parse_args(argv)
    svc = Service(args.root, tenants=args.tenants, workers=args.workers,
                  work_ms=args.work_ms, port=args.port).start()
    print(f"saas lab: {svc.url}  tenants={args.tenants} workers={args.workers}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        svc.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
