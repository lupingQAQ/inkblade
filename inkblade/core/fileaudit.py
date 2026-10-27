# -*- coding: utf-8 -*-
"""文件/操作审计台账：探针执行的命令与读取的文件。

设计约束：

* 只记录**目标容器内**的路径。宿主逃逸前缀（``/proc/*/root``、``/host``、
  containerd/docker socket、``/var/lib/kubelet`` 等）在控制器侧直接拒绝，
  探针侧（``probe/src/auditops.rs``）执行同一份拒绝规则；两侧都不做
  「读取失败也算通过」的降级。
* 审计行写入 evidence DB 的 ``file_ops`` 表，并通过 ``step_id``/``step_key``
  与 ``steps`` 表关联；时间线（``core/timeline.py``）再把 ``steps``/``actions``
  /``file_ops``/利用标记汇总成统一 ``timeline.json``。
* 环境变量只落摘要（排序后 SHA256），不落明文；argv 中的凭据形态在展示层
  由 ``core/redact.py`` 脱敏。

事件字段（与 ``FILE_OPS_TABLE`` 一一对应）::

    step_id / step_key / task_id
    probe_id / cluster / namespace
    pid / argv / cwd / env_digest
    opened_files[read|write] / path / mode / size_bytes / sha256
    exit_code / stdout_hash / duration_ms / technique
    ts / phase / op / result / detail

``op`` 取值：``exec``（命令级事件，``opened_files`` 为采样结果）、
``read`` / ``write`` / ``list``（显式文件操作，``path``/``sha256`` 有效）。
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

FILE_OPS_TABLE = """
CREATE TABLE IF NOT EXISTS file_ops(
    id INTEGER PRIMARY KEY,
    run TEXT,
    step_id INTEGER,
    step_key TEXT,
    task_id TEXT,
    ts REAL,
    phase TEXT,
    op TEXT,
    technique TEXT,
    probe_id TEXT,
    cluster TEXT,
    namespace TEXT,
    pid INTEGER DEFAULT 0,
    argv TEXT,
    cwd TEXT,
    env_digest TEXT,
    opened_files TEXT,
    path TEXT,
    mode TEXT,
    size_bytes INTEGER DEFAULT 0,
    sha256 TEXT,
    exit_code INTEGER,
    stdout_hash TEXT,
    duration_ms INTEGER,
    result TEXT,
    detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_file_ops_run ON file_ops(run, ts);
CREATE INDEX IF NOT EXISTS idx_file_ops_step ON file_ops(run, step_id);
"""

EVENT_FIELDS = (
    "step_id", "step_key", "task_id", "ts", "phase", "op", "technique",
    "probe_id", "cluster", "namespace", "pid", "argv", "cwd", "env_digest",
    "opened_files", "path", "mode", "size_bytes", "sha256", "exit_code",
    "stdout_hash", "duration_ms", "result", "detail",
)

FILE_OP_OPS = ("exec", "read", "write", "list")

# 宿主逃逸 / 宿主敏感路径：只读目标容器内的路径，命中即拒绝。
HOST_ESCAPE_PREFIXES = (
    "/host",
    "/hostfs",
    "/mnt/host",
    "/var/lib/kubelet",
    "/var/lib/docker",
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/run/containerd",
    "/var/run/containerd",
    "/sys/kernel/debug",
    "/dev/mem",
    "/dev/kmem",
    "/dev/kmsg",
    "/proc/sysrq-trigger",
    "/proc/kcore",
)
_PROC_ROOT_RE = re.compile(r"^/proc/(?:\d+|self|thread-self)/root(?:/|$)")

# SOC 侧对应的审计键（报告「操作与文件访问台账」节引用）。
SOC_AUDIT_KEYS: tuple[dict[str, str], ...] = (
    {
        "surface": "auditd",
        "key": "inkblade_exec",
        "rule": "-a always,exit -F arch=b64 -S execve -F key=inkblade_exec",
        "fields": "argv / exe / pid / cwd / exit",
    },
    {
        "surface": "auditd",
        "key": "inkblade_file_read",
        "rule": "-a always,exit -F arch=b64 -S openat -S open -F success=1 "
                "-F dir=/proc -k inkblade_file_read",
        "fields": "path / flags / pid",
    },
    {
        "surface": "falco",
        "key": "inkblade_probe_exec",
        "rule": "evt.type in (execve, execveat) and proc.pname = inkblade-probe",
        "fields": "proc.cmdline / proc.cwd / proc.pid / proc.exitcode",
    },
    {
        "surface": "falco",
        "key": "inkblade_probe_file_read",
        "rule": "evt.type in (open, openat) and fd.typechar = f and "
                "proc.pname = inkblade-probe",
        "fields": "fd.name / fd.num / proc.pid",
    },
    {
        "surface": "opentelemetry",
        "key": "inkblade.process.exec",
        "rule": "span name = inkblade.process.exec (OTLP logs/traces)",
        "fields": "process.command_line / process.working_directory / process.pid / "
                  "process.exit.code / file.path / file.size / file.hash",
    },
)


class UnsafePath(ValueError):
    """请求的路径会逃逸目标容器（宿主路径），拒绝执行。"""


def safe_path(path: str) -> tuple[bool, str]:
    """判断路径是否只落在目标容器内；返回 ``(ok, reason)``。"""
    raw = str(path or "").strip()
    if not raw:
        return False, "empty path"
    if "\x00" in raw:
        return False, "NUL byte in path"
    normalized = raw.replace("\\", "/")
    if normalized.startswith("//"):
        normalized = "/" + normalized.lstrip("/")
    if _PROC_ROOT_RE.match(normalized):
        return False, "host escape via /proc/<pid>/root"
    for prefix in HOST_ESCAPE_PREFIXES:
        if normalized == prefix or normalized.startswith(prefix + "/"):
            return False, f"host path is out of scope: {prefix}"
    parts = [p for p in normalized.split("/") if p not in ("", ".")]
    if ".." in parts:
        return False, "path traversal is not allowed"
    return True, ""


def require_safe_path(path: str) -> str:
    ok, reason = safe_path(path)
    if not ok:
        raise UnsafePath(f"{path!r}: {reason}")
    return str(path)


def hash_text(text: str) -> str:
    return hashlib.sha256(str(text).encode("utf-8", "replace")).hexdigest()


def env_digest(env: dict[str, Any] | None) -> str:
    """环境变量摘要：只保留排序后的键值 SHA256（不落明文）。"""
    if not env:
        return ""
    payload = json.dumps({str(k): str(v) for k, v in env.items()},
                         sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def redact_argv(argv: Sequence[str]) -> list[str]:
    """argv 展示脱敏（凭据形态只留尾 4 位）；存储仍保留原值供审计对账。"""
    from .redact import redact_line

    return [redact_line(str(item)) for item in argv]


def opened_entry(path: str, mode: str = "read", *, fd: int = 0,
                 size_bytes: int = 0, sha256: str = "") -> dict[str, Any]:
    return {
        "path": str(path), "mode": mode, "fd": int(fd),
        "size_bytes": int(size_bytes), "sha256": str(sha256),
    }


def normalize_opened(items: Iterable[Any] | None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in items or []:
        if isinstance(item, str):
            out.append(opened_entry(item, "read"))
        elif isinstance(item, dict):
            mode = str(item.get("mode") or item.get("access") or "read")
            if mode not in ("read", "write", "rw"):
                mode = "read"
            out.append(opened_entry(
                str(item.get("path") or ""), mode,
                fd=int(item.get("fd") or 0),
                size_bytes=int(item.get("size_bytes") or item.get("size") or 0),
                sha256=str(item.get("sha256") or ""),
            ))
    return [entry for entry in out if entry["path"]]


def resolve_step_id(run, step_key: str, step_id: int | None = None) -> int | None:
    if step_id:
        return int(step_id)
    if not step_key:
        return None
    try:
        rows = run.query(
            "SELECT id FROM steps WHERE run=? AND step_key=? ORDER BY id DESC LIMIT 1",
            (run.name, step_key),
        )
    except Exception:  # noqa: BLE001 - 老库/未建表不应阻断审计
        return None
    return int(rows[0][0]) if rows else None


def ensure_schema(run) -> None:
    """旧 run 的 evidence.db 补建 file_ops（幂等）。"""
    with run._tx() as conn:  # noqa: SLF001 - 同包内部存储原语
        conn.executescript(FILE_OPS_TABLE)


def record(
    run,
    *,
    op: str,
    step_key: str = "",
    step_id: int | None = None,
    task_id: str = "",
    probe_id: str = "",
    cluster: str = "",
    namespace: str = "",
    pid: int = 0,
    argv: Sequence[str] | None = None,
    cwd: str = "",
    env: dict[str, Any] | None = None,
    opened_files: Iterable[Any] | None = None,
    path: str = "",
    mode: str = "",
    size_bytes: int = 0,
    sha256: str = "",
    exit_code: int | None = None,
    stdout: str = "",
    stdout_hash: str = "",
    duration_ms: int | None = None,
    technique: str = "",
    phase: str = "post",
    result: str = "ok",
    detail: str = "",
    ts: float | None = None,
) -> int:
    """写入一条 file_ops 审计行，返回行号。"""
    op = str(op or "exec")
    if op not in FILE_OP_OPS:
        raise ValueError(f"unknown file audit op {op!r}")
    if path:
        require_safe_path(path)
    entries = normalize_opened(opened_files)
    for entry in entries:
        ok, reason = safe_path(entry["path"])
        if not ok:
            raise UnsafePath(f"refusing to audit out-of-scope read {entry['path']!r}: {reason}")
    if op == "exec" and not entries:
        # 命令没有打开文件是合法结果（echo/true），但 argv 必须存在。
        entries = []
    argv_list = [str(item) for item in (argv or [])]
    digest = stdout_hash or (hash_text(stdout) if stdout else "")
    ensure_schema(run)
    with run._tx() as conn:  # noqa: SLF001
        cur = conn.execute(
            "INSERT INTO file_ops(run, step_id, step_key, task_id, ts, phase, op, technique,"
            " probe_id, cluster, namespace, pid, argv, cwd, env_digest, opened_files, path,"
            " mode, size_bytes, sha256, exit_code, stdout_hash, duration_ms, result, detail)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                run.name, resolve_step_id(run, step_key, step_id), step_key, task_id,
                float(ts if ts is not None else time.time()), phase, op, technique,
                probe_id, cluster, namespace, int(pid or 0),
                json.dumps(argv_list, ensure_ascii=False),
                cwd, env_digest(env),
                json.dumps(entries, ensure_ascii=False, sort_keys=True),
                path, mode, int(size_bytes or 0), sha256,
                int(exit_code) if exit_code is not None else None,
                digest, int(duration_ms) if duration_ms is not None else None,
                result, detail,
            ),
        )
        return int(cur.lastrowid or 0)


def _row_to_event(row) -> dict[str, Any]:
    item = dict(row)
    for key in ("argv", "opened_files"):
        raw = item.get(key)
        try:
            item[key] = json.loads(raw) if raw else []
        except (TypeError, ValueError):
            item[key] = []
    return item


def file_ops(run, *, step_key: str | None = None, limit: int | None = None) -> list[dict[str, Any]]:
    """读取 file_ops（按时间正序）；表不存在时返回空列表（老 run）。"""
    sql = "SELECT * FROM file_ops WHERE run=?"
    args: list[Any] = [run.name]
    if step_key:
        sql += " AND step_key=?"
        args.append(step_key)
    sql += " ORDER BY ts, id"
    if limit:
        sql += " LIMIT ?"
        args.append(int(limit))
    try:
        rows = run.query(sql, tuple(args))
    except Exception:  # noqa: BLE001 - sqlite3.OperationalError for old DB
        return []
    keys = None
    out = []
    for row in rows:
        # sqlite3.Row supports keys(); tuple rows fall back to EVENT order.
        if hasattr(row, "keys"):
            out.append(_row_to_event(row))
        else:
            if keys is None:
                keys = ("id", "run") + EVENT_FIELDS
            out.append(dict(zip(keys, row)))
    return out


def probe_supports(probe, op: str) -> bool:
    caps = getattr(probe, "caps", None)
    if caps is None:
        return True  # controller-side wrapper: assume modern probe; error is explicit
    return str(op) in {str(c) for c in caps}


def audit_exec_via_probe(probe, argv: Sequence[str], *, cwd: str = "",
                         timeout_ms: int = 8000, technique: str = "") -> dict[str, Any]:
    """经探针 ``audit-exec`` 执行命令并取回审计载荷。

    探针不支持时（旧版本）降级为普通 ``exec``，返回 ``supported=False``，
    由调用方把「未采样」如实登记（不伪造 opened_files）。
    """
    if not probe_supports(probe, "audit-exec"):
        result = probe.exec(list(argv))
        return {"supported": False, "exec": result, "audit": {}}
    args: dict[str, Any] = {"argv": [str(item) for item in argv],
                            "timeout_ms": int(timeout_ms)}
    if cwd:
        args["cwd"] = cwd
    if technique:
        args["technique"] = technique
    payload = probe.request("audit-exec", args)
    return {"supported": True, "exec": payload.get("exec") or payload,
            "audit": payload.get("audit") or payload}


@dataclass
class FileOpRecorder:
    """把一个 step 的命令执行与显式文件访问登记到 file_ops。"""

    run: Any
    step_key: str = ""
    step_id: int | None = None
    probe_id: str = ""
    cluster: str = ""
    namespace: str = ""
    task_id: str = ""
    technique: str = ""
    rows: list[int] = field(default_factory=list)

    def _common(self) -> dict[str, Any]:
        return {
            "step_key": self.step_key, "step_id": self.step_id,
            "probe_id": self.probe_id, "cluster": self.cluster,
            "namespace": self.namespace, "task_id": self.task_id,
            "technique": self.technique,
        }

    def exec(self, result: dict[str, Any], argv: Sequence[str], *,
             cwd: str = "", env: dict[str, Any] | None = None,
             supported: bool = True, ts: float | None = None) -> int:
        """登记命令执行；``result`` 为探针 ``audit-exec`` 的 exec 段。"""
        audit = result.get("audit") if isinstance(result.get("audit"), dict) else {}
        if isinstance(result.get("exec"), dict):
            nested = dict(result["exec"])
            nested.setdefault("opened_files", audit.get("opened_files") or [])
            result = nested
        opened = result.get("opened_files") or audit.get("opened_files") or []
        pid = int(result.get("pid") or audit.get("pid") or 0)
        exit_code = result.get("exit_code", result.get("rc"))
        detail = ""
        outcome = "ok"
        if not supported:
            outcome = "unsampled"
            detail = "probe lacks audit-exec; opened_files not sampled"
        if result.get("timed_out"):
            outcome = "timeout"
        elif exit_code not in (None, 0) and outcome == "ok":
            outcome = f"exit:{exit_code}"
        row = record(
            self.run, op="exec", **self._common(),
            pid=pid, argv=list(argv),
            cwd=str(result.get("cwd") or cwd or ""), env=env,
            opened_files=opened,
            exit_code=int(exit_code) if exit_code is not None else None,
            stdout=str(result.get("stdout") or ""),
            duration_ms=int(result.get("duration_ms") or 0) or None,
            phase="post",
            result=outcome, detail=detail, ts=ts,
        )
        self.rows.append(row)
        return row

    def file_read(self, path: str, *, data: bytes | str | None = None,
                  sha256: str = "", size_bytes: int | None = None,
                  result: str = "ok", detail: str = "", ts: float | None = None) -> int:
        if isinstance(data, str):
            data = data.encode("utf-8")
        if data is not None:
            sha256 = sha256 or hashlib.sha256(data).hexdigest()
            size_bytes = len(data) if size_bytes is None else size_bytes
        row = record(self.run, op="read", **self._common(), path=path, mode="read",
                     sha256=sha256, size_bytes=int(size_bytes or 0),
                     result=result, detail=detail, ts=ts)
        self.rows.append(row)
        return row

    def file_list(self, path: str, entries: Iterable[Any] | None, *,
                  result: str = "ok", detail: str = "",
                  ts: float | None = None) -> int:
        names = []
        for entry in entries or []:
            if isinstance(entry, dict):
                names.append(str(entry.get("path") or entry.get("name") or ""))
            else:
                names.append(str(entry))
        payload = json.dumps([n for n in names if n], ensure_ascii=False)
        row = record(self.run, op="list", **self._common(), path=path, mode="read",
                     sha256=hash_text(payload), size_bytes=len(names),
                     result=result, detail=detail, ts=ts)
        self.rows.append(row)
        return row

    def file_write(self, path: str, *, data: bytes | str | None = None,
                   sha256: str = "", size_bytes: int | None = None,
                   result: str = "ok", detail: str = "", ts: float | None = None) -> int:
        if isinstance(data, str):
            data = data.encode("utf-8")
        if data is not None:
            sha256 = sha256 or hashlib.sha256(data).hexdigest()
            size_bytes = len(data) if size_bytes is None else size_bytes
        row = record(self.run, op="write", **self._common(), path=path, mode="write",
                     sha256=sha256, size_bytes=int(size_bytes or 0),
                     result=result, detail=detail, ts=ts)
        self.rows.append(row)
        return row


def probe_read_file(probe, path: str, *, max_bytes: int = 1024 * 1024) -> dict[str, Any]:
    require_safe_path(path)
    return probe.request("read-file", {"path": str(path), "max_bytes": int(max_bytes)})


def probe_list_files(probe, path: str, *, pattern: str = "") -> dict[str, Any]:
    require_safe_path(path)
    args: dict[str, Any] = {"path": str(path)}
    if pattern:
        args["pattern"] = pattern
    return probe.request("list-files", args)


def read_and_record(probe, run, path: str, *, recorder: FileOpRecorder | None = None,
                    max_bytes: int = 1024 * 1024) -> dict[str, Any]:
    """显式读文件（探针 read-file）并落一条 read 审计行。"""
    recorder = recorder or FileOpRecorder(run, probe_id=str(getattr(probe, "probe_id", "")))
    payload = probe_read_file(probe, path, max_bytes=max_bytes)
    recorder.file_read(path, sha256=str(payload.get("sha256") or ""),
                       size_bytes=int(payload.get("size") or 0),
                       result="ok" if payload.get("exists", True) else "missing")
    return payload


def list_and_record(probe, run, path: str, *, recorder: FileOpRecorder | None = None,
                    pattern: str = "") -> dict[str, Any]:
    recorder = recorder or FileOpRecorder(run, probe_id=str(getattr(probe, "probe_id", "")))
    payload = probe_list_files(probe, path, pattern=pattern)
    recorder.file_list(path, payload.get("entries") or [],
                       result="ok" if payload.get("exists", True) else "missing")
    return payload


def ledger(run) -> dict[str, Any]:
    """报告/UI 用的按 step 分组台账（含未关联 step 的事件）。"""
    rows = file_ops(run)
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(row.get("step_key") or "(未关联 step)", []).append(row)
    return {
        "count": len(rows),
        "steps": [
            {"step_key": key, "events": grouped[key]}
            for key in sorted(grouped)
        ],
    }
