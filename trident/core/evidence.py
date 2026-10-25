"""证据三层存储：上下文摘要层（压缩）/ 数据库层（SQLite）/ 归档层（tar+SHA256）。"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import sqlite3
import tarfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

SCHEMA_TABLES = [
    "runs", "steps", "prompts", "env", "findings", "evidence",
    "actions", "backups", "rollbacks", "roe", "combos",
    "graph_nodes", "graph_edges", "traffic",
]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs(name TEXT PRIMARY KEY, created_at REAL, status TEXT);
CREATE TABLE IF NOT EXISTS steps(id INTEGER PRIMARY KEY, run TEXT, step_key TEXT,
    started_at REAL, finished_at REAL, result_summary TEXT, archive TEXT, status TEXT);
CREATE TABLE IF NOT EXISTS prompts(id INTEGER PRIMARY KEY, step_id INTEGER, kind TEXT, content TEXT, digest TEXT);
CREATE TABLE IF NOT EXISTS env(id INTEGER PRIMARY KEY, step_id INTEGER, key TEXT, value TEXT);
CREATE TABLE IF NOT EXISTS findings(id INTEGER PRIMARY KEY, run TEXT, step_key TEXT,
    severity TEXT, title TEXT, detail TEXT, evidence_path TEXT, is_zeroday INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS evidence(id INTEGER PRIMARY KEY, step_id INTEGER, path TEXT, sha256 TEXT, kind TEXT);
CREATE TABLE IF NOT EXISTS actions(id INTEGER PRIMARY KEY, ts REAL, actor TEXT, workspace TEXT,
    action TEXT, target TEXT, params TEXT, result TEXT, rollback_to TEXT, is_zeroday INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS backups(id INTEGER PRIMARY KEY, run TEXT, step_key TEXT,
    target TEXT, backup_path TEXT, sha256 TEXT, rollback_action TEXT, created_at REAL);
CREATE TABLE IF NOT EXISTS rollbacks(id INTEGER PRIMARY KEY, backup_id INTEGER, ts REAL, ok INTEGER);
CREATE TABLE IF NOT EXISTS roe(id INTEGER PRIMARY KEY, workspace TEXT, scope_sha256 TEXT,
    status TEXT, fields TEXT, created_at REAL);
CREATE TABLE IF NOT EXISTS combos(id INTEGER PRIMARY KEY, run TEXT, signature TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS graph_nodes(node_id TEXT PRIMARY KEY, kind TEXT, layer TEXT, attrs TEXT);
CREATE TABLE IF NOT EXISTS graph_edges(id INTEGER PRIMARY KEY, src TEXT, dst TEXT,
    verdict TEXT, method TEXT, chain TEXT);
CREATE TABLE IF NOT EXISTS traffic(id INTEGER PRIMARY KEY, run TEXT, module TEXT, seq INTEGER,
    method TEXT, url TEXT, req_headers TEXT, req_body TEXT,
    status INTEGER, resp_body TEXT, error TEXT, sha256 TEXT, ts REAL);
"""


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _digest(text: str) -> str:
    return _sha256_bytes(text.encode("utf-8"))[:16]


def _zstd_available() -> bool:
    if os.environ.get("TRIDENT_FORCE_NO_ZSTD") == "1":
        return False
    try:
        import zstandard  # noqa: F401

        return True
    except Exception:
        return False


class Run:
    def __init__(self, store: "EvidenceStore", name: str, run_dir: Path):
        self.store = store
        self.name = name
        self.dir = run_dir
        self._ctx_lines: list[str] = []

    # ---------- 数据库层 ----------
    def _db(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.dir / "evidence.db")
        conn.row_factory = sqlite3.Row
        return conn

    @contextmanager
    def _tx(self):
        conn = self._db()
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def query(self, sql: str, args: tuple = ()) -> list[tuple]:
        with self._tx() as conn:
            return list(conn.execute(sql, args))

    # ---------- 归档层 ----------
    def _compress(self, payload: bytes, suffix_hint: str) -> tuple[bytes, str]:
        if _zstd_available():
            import zstandard

            return zstandard.compress(payload), suffix_hint + ".zst"
        return gzip.compress(payload), suffix_hint + ".gz"

    def _archive_step(self, step_key: str, artifacts: list[Path]) -> str:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            for art in artifacts:
                if Path(art).is_file():
                    tf.add(str(art), arcname=Path(art).name)
        data, ext = self._compress(buf.getvalue(), ".tar")
        arch = self.dir / "steps" / f"{step_key}{ext}"
        arch.write_bytes(data)
        return str(arch.relative_to(self.dir)).replace("\\", "/")

    # ---------- 三层事务 ----------
    def add_step(
        self,
        step_key: str,
        prompt_or_cmd: str,
        env: dict[str, Any],
        result_summary: str,
        artifacts: list[Path] | None = None,
    ) -> dict[str, Any]:
        started = time.time()
        archive_rel = self._archive_step(step_key, artifacts or [])
        arch_bytes = (self.dir / archive_rel).read_bytes()
        arch_sha = _sha256_bytes(arch_bytes)
        with self._tx() as conn:
            cur = conn.execute(
                "INSERT INTO steps(run, step_key, started_at, finished_at, result_summary, archive, status)"
                " VALUES(?,?,?,?,?,?,?)",
                (self.name, step_key, started, time.time(), result_summary, archive_rel, "success"),
            )
            step_id = cur.lastrowid
            conn.execute(
                "INSERT INTO prompts(step_id, kind, content, digest) VALUES(?,?,?,?)",
                (step_id, "cmd", prompt_or_cmd, _digest(prompt_or_cmd)),
            )
            for k, v in env.items():
                conn.execute("INSERT INTO env(step_id, key, value) VALUES(?,?,?)", (step_id, k, str(v)))
            conn.execute(
                "INSERT INTO evidence(step_id, path, sha256, kind) VALUES(?,?,?,?)",
                (step_id, archive_rel, arch_sha, "archive"),
            )
            self._append_manifest(archive_rel, arch_sha)
        # 上下文摘要层
        line = json.dumps(
            {
                "step": step_key,
                "prompt_digest": _digest(prompt_or_cmd),
                "env_digest": _digest(json.dumps(env, sort_keys=True, default=str)),
                "result_digest": _digest(result_summary),
                "pointers": {"db": step_id, "archive": archive_rel},
            },
            ensure_ascii=False,
        )
        self._ctx_lines.append(line)
        self._flush_context()
        return {"run": self.name, "step": step_key, "archive": archive_rel, "rowid": step_id}

    def _append_manifest(self, rel: str, sha: str) -> None:
        mpath = self.dir / "manifest.sha256"
        with mpath.open("a", encoding="utf-8") as fh:
            fh.write(f"{sha}  {rel}\n")

    def _flush_context(self) -> None:
        payload = ("\n".join(self._ctx_lines) + "\n").encode("utf-8")
        (self.dir / "context.jsonl.gz").write_bytes(gzip.compress(payload))

    def finalize_run(self) -> None:
        steps = self.query("SELECT step_key, result_summary FROM steps ORDER BY id")
        summary = {
            "summary": True,
            "run": self.name,
            "step_count": len(steps),
            "digests": [f"{r[0]}:{_digest(str(r[1]))}" for r in steps],
        }
        self._ctx_lines.append(json.dumps(summary, ensure_ascii=False))
        self._flush_context()
        with self._tx() as conn:
            conn.execute("UPDATE runs SET status='finalized' WHERE name=?", (self.name,))

    # ---------- 发现 ----------
    def add_finding(
        self,
        step_key: str,
        sev: str,
        title: str,
        detail: str,
        evidence_path: str = "",
        is_zeroday: bool = False,
    ) -> None:
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO findings(run, step_key, severity, title, detail, evidence_path, is_zeroday)"
                " VALUES(?,?,?,?,?,?,?)",
                (self.name, step_key, sev, title, detail, evidence_path, int(is_zeroday)),
            )

    @property
    def findings(self) -> list[dict[str, Any]]:
        rows = self.query(
            "SELECT step_key, severity, title, detail, evidence_path, is_zeroday FROM findings WHERE run=? ORDER BY id",
            (self.name,),
        )
        keys = ["step_key", "severity", "title", "detail", "evidence_path", "is_zeroday"]
        return [dict(zip(keys, r)) for r in rows]

    # ---------- 审计/备份/组合/图 ----------
    def log_action(self, actor: str, action: str, target: str, params: dict,
                   result: str, rollback_to: str | None = None, is_zeroday: bool = False) -> None:
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO actions(ts, actor, workspace, action, target, params, result, rollback_to, is_zeroday)"
                " VALUES(?,?,?,?,?,?,?,?,?)",
                (time.time(), actor, self.store.workspace, action, target,
                 json.dumps(params, ensure_ascii=False, default=str), result, rollback_to, int(is_zeroday)),
            )

    def record_backup(self, step_key: str, target: str, backup_path: Path,
                      rollback_action: str) -> int:
        sha = _sha256_bytes(backup_path.read_bytes())
        with self._tx() as conn:
            cur = conn.execute(
                "INSERT INTO backups(run, step_key, target, backup_path, sha256, rollback_action, created_at)"
                " VALUES(?,?,?,?,?,?,?)",
                (self.name, step_key, target, str(backup_path), sha, rollback_action, time.time()),
            )
            return cur.lastrowid

    def record_rollback(self, backup_id: int, ok: bool) -> None:
        with self._tx() as conn:
            conn.execute("INSERT INTO rollbacks(backup_id, ts, ok) VALUES(?,?,?)", (backup_id, time.time(), int(ok)))

    def upsert_node(self, node_id: str, kind: str, layer: str, attrs: dict | None = None) -> None:
        with self._tx() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO graph_nodes(node_id, kind, layer, attrs) VALUES(?,?,?,?)",
                (node_id, kind, layer, json.dumps(attrs or {}, ensure_ascii=False)),
            )

    def add_edge(self, src: str, dst: str, verdict: str, method: str, chain: str = "") -> None:
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO graph_edges(src, dst, verdict, method, chain) VALUES(?,?,?,?,?)",
                (src, dst, verdict, method, chain),
            )

    # ---------- 流量录制（XBow 对标 ④：请求/响应全量入库） ----------
    def record_traffic(self, module: str, entries: list[dict]) -> int:
        """把模块 HTTP trace 条目全量写入 traffic 表（幂等：同 run+module 清除后重写）。"""
        rows = []
        for i, e in enumerate(entries or []):
            body = e.get("body")
            resp = e.get("response")
            rows.append((
                self.name, module, i, str(e.get("method", "")), str(e.get("url", "")),
                json.dumps(e.get("headers") or {}, ensure_ascii=False, default=str),
                json.dumps(body, ensure_ascii=False, default=str) if body is not None else None,
                int(e.get("status") or 0),
                json.dumps(resp, ensure_ascii=False, default=str) if resp is not None else None,
                str(e.get("error") or "") or None,
                _sha256_bytes(json.dumps(
                    {k: e.get(k) for k in ("method", "url", "body", "headers", "status", "response")},
                    ensure_ascii=False, default=str, sort_keys=True).encode("utf-8")),
                float(e.get("ts") or time.time()),
            ))
        with self._tx() as conn:
            conn.execute("DELETE FROM traffic WHERE run=? AND module=?", (self.name, module))
            conn.executemany(
                "INSERT INTO traffic(run, module, seq, method, url, req_headers, req_body,"
                " status, resp_body, error, sha256, ts) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                rows,
            )
        return len(rows)

    @property
    def traffic(self) -> list[dict[str, Any]]:
        rows = self.query(
            "SELECT module, seq, method, url, req_headers, req_body, status, resp_body,"
            " error, sha256, ts FROM traffic WHERE run=? ORDER BY module, seq",
            (self.name,),
        )
        keys = ["module", "seq", "method", "url", "req_headers", "req_body",
                "status", "resp_body", "error", "sha256", "ts"]
        return [dict(zip(keys, r)) for r in rows]


class EvidenceStore:
    def __init__(self, root: Path | str, workspace: str = "local-lab"):
        self.root = Path(root)
        self.workspace = workspace
        self.ws_dir = self.root / "evidence" / workspace
        self.ws_dir.mkdir(parents=True, exist_ok=True)

    def create_run(self, name: str) -> Run:
        run_dir = self.ws_dir / name
        (run_dir / "steps").mkdir(parents=True, exist_ok=True)
        (run_dir / "backups").mkdir(exist_ok=True)
        run = Run(self, name, run_dir)
        with run._tx() as conn:
            conn.executescript(_SCHEMA)
            conn.execute(
                "INSERT OR REPLACE INTO runs(name, created_at, status) VALUES(?,?,?)",
                (name, time.time(), "active"),
            )
        consent = self.consent()
        if consent is not None:
            with run._tx() as conn:
                conn.execute(
                    "INSERT INTO roe(workspace, scope_sha256, status, fields, created_at) VALUES(?,?,?,?,?)",
                    (self.workspace, consent["sha256"], "complete",
                     json.dumps(consent["fields"], ensure_ascii=False), consent["ts"]),
                )
        return run

    def pin_roe(self, fields: dict) -> None:
        """写入工作区级授权（consent.json）；后续每个 run 固化该记录。"""
        import hashlib as _h

        payload = json.dumps(fields, ensure_ascii=False, sort_keys=True)
        sha = _h.sha256(payload.encode("utf-8")).hexdigest()
        (self.ws_dir / "consent.json").write_text(
            json.dumps({"fields": fields, "sha256": sha, "ts": time.time(), "status": "complete"},
                       ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def consent(self) -> dict | None:
        p = self.ws_dir / "consent.json"
        if not p.exists():
            return None
        return json.loads(p.read_text(encoding="utf-8"))

    def open_run(self, name: str) -> Run:
        run_dir = self.ws_dir / name
        if not run_dir.exists():
            raise KeyError(f"run not found: {name}")
        return Run(self, name, run_dir)

    def verify_manifest(self, run: str) -> bool:
        run_dir = self.ws_dir / run
        mpath = run_dir / "manifest.sha256"
        if not mpath.exists():
            return False
        lines = [l for l in mpath.read_text(encoding="utf-8").splitlines() if l.strip()]
        steps_dir = run_dir / "steps"
        expected = len([p for p in steps_dir.iterdir() if p.is_file()]) if steps_dir.exists() else 0
        if not lines or len(lines) < expected:
            return False
        ok = True
        for line in lines:
            sha, rel = line.split("  ", 1)
            f = run_dir / rel
            if not f.exists() or _sha256_bytes(f.read_bytes()) != sha:
                ok = False
        return ok
