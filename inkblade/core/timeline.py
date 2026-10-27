# -*- coding: utf-8 -*-
"""统一时间线：steps / actions / file_ops / 利用标记 → ``timeline.json``。

一次 run 的所有可观察动作收敛到同一事件流，供 WebUI 时间线视图、静态导出和
报告复用。事件字段（稳定契约，UI/报告/测试均按此读取）::

    seq             单调序号（同 ts 的稳定排序键）
    ts              Unix 秒（浮点）
    kind            step | action | file_op | exploit
    subject         主体（probe_id / actor / step_key）
    action          动作（step.run / execute / exec / read / list / finding）
    target          目标（步骤键 / 模块 / 命令（脱敏）/ 发现标题）
    files           文件清单 [{path, mode, size_bytes, sha256}]
    result          结果（success / exit:0 / severity …）
    evidence_sha256 证据哈希（归档 SHA256 / 文件 SHA256 / stdout 摘要）
    step_key/step_id/probe_id/namespace   关联键
    ref             可回链引用（DB 行号 / 归档相对路径）
    detail          结构化补充（argv、cwd、exit_code、duration_ms …）

排序规则：``(ts, kind 优先级, seq)``，同一毫秒内保持 DB 读取顺序，保证重放稳定。
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Callable

from .fileaudit import redact_argv, safe_path

SCHEMA = "inkblade-timeline-v1"
KIND_ORDER = {"step": 1, "action": 2, "file_op": 3, "exploit": 4}
EVENT_KEYS = (
    "seq", "ts", "kind", "subject", "action", "target", "files", "result",
    "evidence_sha256", "step_key", "step_id", "probe_id", "namespace", "ref", "detail",
)


def _field(row: Any, key: str, index: int | None = None) -> Any:
    try:
        return row[key]
    except (IndexError, KeyError, TypeError):
        if index is not None:
            try:
                return row[index]
            except (IndexError, TypeError):
                return None
        return None


def _text(value: Any) -> str:
    return "" if value is None else str(value)


def _json(value: Any, default: Any) -> Any:
    if value in (None, ""):
        return default
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


def _short_hash(text: str) -> str:
    return hashlib.sha256(str(text).encode("utf-8", "replace")).hexdigest()


def _archive_map(query: Callable[..., list[Any]], run_name: str) -> dict[str, str]:
    try:
        rows = query(
            "SELECT s.step_key, e.sha256 FROM steps s JOIN evidence e ON e.step_id=s.id"
            " WHERE s.run=? ORDER BY s.id", (run_name,))
    except Exception:  # noqa: BLE001 - 老库/空库
        return {}
    out: dict[str, str] = {}
    for row in rows:
        key = _text(_field(row, "step_key", 0))
        sha = _text(_field(row, "sha256", 1))
        if key and sha:
            out[key] = sha
    return out


def _step_events(query, run_name: str, archives: dict[str, str]) -> list[dict[str, Any]]:
    events = []
    try:
        rows = query(
            "SELECT id, step_key, started_at, finished_at, result_summary, archive, status"
            " FROM steps WHERE run=? ORDER BY id", (run_name,))
    except Exception:  # noqa: BLE001
        return events
    for row in rows:
        step_key = _text(_field(row, "step_key", 1))
        started = _field(row, "started_at", 2) or 0
        finished = _field(row, "finished_at", 3) or started
        archive = _text(_field(row, "archive", 5))
        events.append({
            "ts": float(started or 0),
            "kind": "step",
            "subject": step_key or "step",
            "action": "step.run",
            "target": step_key,
            "files": [],
            "result": _text(_field(row, "status", 6) or "unknown"),
            "evidence_sha256": archives.get(step_key, ""),
            "step_key": step_key,
            "step_id": int(_field(row, "id", 0) or 0) or None,
            "probe_id": "",
            "namespace": "",
            "ref": archive,
            "detail": {
                "started_at": started, "finished_at": finished,
                "duration_ms": int(max(0.0, float(finished or 0) - float(started or 0)) * 1000),
                "summary": _text(_field(row, "result_summary", 4)),
            },
        })
    return events


def _file_events(query, run_name: str) -> list[dict[str, Any]]:
    try:
        rows = query(
            "SELECT id, ts, op, technique, probe_id, namespace, pid, argv, cwd, opened_files,"
            " path, mode, size_bytes, sha256, exit_code, stdout_hash, duration_ms, result,"
            " detail, step_key, step_id FROM file_ops WHERE run=? ORDER BY ts, id", (run_name,))
    except Exception:  # noqa: BLE001 - 老 run 没有 file_ops 表
        return []
    events = []
    for row in rows:
        op = _text(_field(row, "op", 2) or "exec")
        argv = _json(_field(row, "argv", 7), [])
        if not isinstance(argv, list):
            argv = []
        opened = _json(_field(row, "opened_files", 9), [])
        if not isinstance(opened, list):
            opened = []
        files = []
        for entry in opened:
            if not isinstance(entry, dict):
                continue
            path = _text(entry.get("path"))
            if not path:
                continue
            ok, _reason = safe_path(path)
            files.append({
                "path": path,
                "mode": _text(entry.get("mode") or "read"),
                "size_bytes": int(entry.get("size_bytes") or 0),
                "sha256": _text(entry.get("sha256")),
                "in_scope": ok,
            })
        single_path = _text(_field(row, "path", 10))
        if single_path and not any(f["path"] == single_path for f in files):
            ok, _reason = safe_path(single_path)
            files.append({
                "path": single_path, "mode": _text(_field(row, "mode", 11) or op),
                "size_bytes": int(_field(row, "size_bytes", 12) or 0),
                "sha256": _text(_field(row, "sha256", 13)), "in_scope": ok,
            })
        exit_code = _field(row, "exit_code", 14)
        stdout_hash = _text(_field(row, "stdout_hash", 15))
        result = _text(_field(row, "result", 17) or "ok")
        display_argv = redact_argv([_text(item) for item in argv])
        command = " ".join(display_argv).strip()
        target = single_path or command or op
        events.append({
            "ts": float(_field(row, "ts", 1) or 0),
            "kind": "file_op",
            "subject": _text(_field(row, "probe_id", 4)) or "probe",
            "action": op,
            "target": target,
            "files": files,
            "result": result,
            "evidence_sha256": _text(_field(row, "sha256", 13)) or stdout_hash
            or (_short_hash(" ".join(_text(item) for item in argv)) if argv else ""),
            "step_key": _text(_field(row, "step_key", 19)),
            "step_id": int(_field(row, "step_id", 20) or 0) or None,
            "probe_id": _text(_field(row, "probe_id", 4)),
            "namespace": _text(_field(row, "namespace", 5)),
            "ref": f"file_ops#{int(_field(row, 'id', 0) or 0)}",
            "detail": {
                "argv": display_argv, "cwd": _text(_field(row, "cwd", 8)),
                "pid": int(_field(row, "pid", 6) or 0),
                "exit_code": int(exit_code) if exit_code is not None else None,
                "duration_ms": int(_field(row, "duration_ms", 16) or 0) or None,
                "stdout_hash": stdout_hash,
                "technique": _text(_field(row, "technique", 3)),
                "note": _text(_field(row, "detail", 18)),
            },
        })
    return events


def _action_events(query, run_name: str, archives: dict[str, str]) -> list[dict[str, Any]]:
    # 每个 run 的 evidence.db 独立，actions 表即该 run 的动作日志。
    try:
        rows = query(
            "SELECT id, ts, actor, action, target, params, result, is_zeroday"
            " FROM actions ORDER BY ts, id")
    except Exception:  # noqa: BLE001
        return []
    events = []
    for row in rows:
        action = _text(_field(row, "action", 3))
        params = _json(_field(row, "params", 5), {})
        target = _text(_field(row, "target", 4))
        files = []
        if isinstance(params, dict):
            for key in ("path", "file", "target_path"):
                value = params.get(key)
                if isinstance(value, str) and value.startswith("/"):
                    ok, _reason = safe_path(value)
                    files.append({"path": value, "mode": "write", "size_bytes": 0,
                                  "sha256": "", "in_scope": ok})
        is_zeroday = bool(_field(row, "is_zeroday", 7))
        kind = "exploit" if (action.startswith("exploit") or is_zeroday) else "action"
        if kind == "exploit" and not action.startswith("exploit"):
            action = f"exploit.{action}"
        events.append({
            "ts": float(_field(row, "ts", 1) or 0),
            "kind": kind,
            "subject": _text(_field(row, "actor", 2)) or "actor",
            "action": action,
            "target": target,
            "files": files,
            "result": _text(_field(row, "result", 6) or "ok"),
            "evidence_sha256": archives.get(target, "") or _short_hash(
                json.dumps(params, ensure_ascii=False, sort_keys=True, default=str)),
            "step_key": target if target in archives else "",
            "step_id": None,
            "probe_id": "",
            "namespace": _text(params.get("namespace") if isinstance(params, dict) else ""),
            "ref": f"actions#{int(_field(row, 'id', 0) or 0)}",
            "detail": {"params": params, "is_zeroday": is_zeroday},
        })
    return events


def _finding_events(query, run_name: str, archives: dict[str, str]) -> list[dict[str, Any]]:
    try:
        rows = query(
            "SELECT id, step_key, severity, title, detail, evidence_path, is_zeroday"
            " FROM findings WHERE run=? ORDER BY id", (run_name,))
    except Exception:  # noqa: BLE001
        return []
    events = []
    for row in rows:
        step_key = _text(_field(row, "step_key", 1))
        title = _text(_field(row, "title", 3))
        events.append({
            "ts": float(_field(row, "id", 0) or 0),  # findings 无 ts：以 id 稳定排序
            "kind": "exploit",
            "subject": step_key or "finding",
            "action": f"finding.{_text(_field(row, 'severity', 2)) or 'info'}",
            "target": title,
            "files": [],
            "result": _text(_field(row, "severity", 2) or "info"),
            "evidence_sha256": archives.get(step_key, ""),
            "step_key": step_key,
            "step_id": None,
            "probe_id": "",
            "namespace": "",
            "ref": _text(_field(row, "evidence_path", 5)) or f"findings#{int(_field(row, 'id', 0) or 0)}",
            "detail": {"zeroday": bool(_field(row, "is_zeroday", 6)),
                       "detail": _text(_field(row, "detail", 4))},
        })
    return events


def _collect(query: Callable[..., list[Any]], run_name: str) -> list[dict[str, Any]]:
    archives = _archive_map(query, run_name)
    events: list[dict[str, Any]] = []
    events += _step_events(query, run_name, archives)
    events += _action_events(query, run_name, archives)
    events += _file_events(query, run_name)
    # 发现没有时间戳：用同 step 的 step 起始时间，再用 kind 优先级排在文件事件之后。
    step_times = {e["step_key"]: e["ts"] for e in events if e["kind"] == "step"}
    findings = _finding_events(query, run_name, archives)
    for event in findings:
        base = step_times.get(event.get("step_key") or "", 0.0)
        event["ts"] = float(base or 0.0)
        if not base:
            event["ts"] = max((e["ts"] for e in events), default=0.0) + 1e-6
    events += findings

    events.sort(key=lambda e: (round(float(e.get("ts") or 0), 6),
                               KIND_ORDER.get(str(e.get("kind")), 99)))
    for index, event in enumerate(events):
        event["seq"] = index
    return events


def build_timeline(run) -> dict[str, Any]:
    """从打开的 ``Run`` 构建时间线文档（纯内存，不落盘）。"""
    events = _collect(run.query, run.name)
    counts: dict[str, int] = {}
    for event in events:
        counts[event["kind"]] = counts.get(event["kind"], 0) + 1
    return {
        "schema": SCHEMA,
        "run": run.name,
        "generated_at": time.time(),
        "counts": counts,
        "events": events,
    }


def build_timeline_from_db(db_path: Path | str, run_name: str | None = None) -> dict[str, Any]:
    """无 ``Run`` 对象时（WebUI/静态导出）直接从 evidence.db 构建。"""
    db_path = Path(db_path)
    name = run_name or db_path.parent.name
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        def query(sql: str, args: tuple = ()) -> list[Any]:
            return list(conn.execute(sql, args))

        events = _collect(query, name)
    finally:
        conn.close()
    counts: dict[str, int] = {}
    for event in events:
        counts[event["kind"]] = counts.get(event["kind"], 0) + 1
    return {
        "schema": SCHEMA, "run": name, "generated_at": time.time(),
        "counts": counts, "events": events,
    }


def write_timeline(run, path: Path | str | None = None) -> Path:
    """构建并原子写入 ``timeline.json``（默认 run 目录）。"""
    doc = build_timeline(run)
    target = Path(path) if path else Path(run.dir) / "timeline.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(target.name + ".tmp")
    tmp.write_text(json.dumps(doc, ensure_ascii=False, indent=1, default=str),
                   encoding="utf-8")
    tmp.replace(target)
    return target


def load_timeline(run_dir: Path | str, *, build_if_missing: bool = False) -> dict[str, Any] | None:
    """读取已落盘的 ``timeline.json``；可选按 DB 现建（老 run 兼容）。"""
    run_dir = Path(run_dir)
    path = run_dir / "timeline.json"
    if path.is_file():
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            doc = None
        if isinstance(doc, dict) and doc.get("schema") == SCHEMA:
            return doc
    if not build_if_missing:
        return None
    db = run_dir / "evidence.db"
    if not db.is_file():
        return None
    return build_timeline_from_db(db, run_dir.name)


def timeline_events(run_dir: Path | str) -> list[dict[str, Any]]:
    doc = load_timeline(run_dir, build_if_missing=True) or {}
    events = doc.get("events") or []
    return [e for e in events if isinstance(e, dict)]
