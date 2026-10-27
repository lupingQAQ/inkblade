# -*- coding: utf-8 -*-
"""durable execution 事件日志（append-only + checkpoint + resume/replay，崩溃恢复）。

设计约束：
- **只追加**：每条事件一行 JSONL，含 ``prev``（上一条 hash）与 ``hash``（链式 SHA256），
  任何改行/删行/半写行都会被 ``verify()`` 定位到具体行号（不静默放过）；
- **步骤级**：事件种类 ``step.started`` / ``step.finished``（payload.ok 区分成功失败），
  ``checkpoint`` 标记可恢复边界；``resume()`` 给出 completed / failed / incomplete 三态，
  incomplete = 已 started 未 finished（进程崩溃点），供 supervisor 重派；
- **durable**：默认逐条 flush + fsync（``fsync=False`` 用于测试/吞吐场景）；
- **replay**：从事件流重建步骤状态机与统计，不执行任何模块。

事件字段：``seq/ts/kind/step/payload/prev/hash``。
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from collections import Counter
from contextlib import contextmanager
from pathlib import Path
from typing import Any

_APPEND_LOCKS: dict[str, threading.Lock] = {}
_APPEND_LOCKS_GUARD = threading.Lock()


def _append_lock(path: Path) -> threading.Lock:
    key = str(path.resolve())
    with _APPEND_LOCKS_GUARD:
        return _APPEND_LOCKS.setdefault(key, threading.Lock())


@contextmanager
def _cross_process_lock(path: Path):
    """Best-effort exclusive lock for concurrent journal appenders.

    A process-local lock is enough for threads; the sidecar lock file also
    serialises multiple controller processes on the same workspace.  The lock
    is deliberately kept outside the journal file so truncation/rotation of
    the journal never loses the mutex.
    """
    lock_path = path.with_name(path.name + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = lock_path.open("a+b")
    try:
        if os.name == "nt":
            import msvcrt
            if lock_path.stat().st_size == 0:
                handle.write(b"\0")
                handle.flush()
            while True:
                try:
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
                    break
                except OSError:
                    time.sleep(0.01)
        else:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            if os.name == "nt":
                import msvcrt
                handle.seek(0)
                try:
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        handle.close()

JOURNAL_RELPATH = "_journal/journal.jsonl"
FINISHED_OK = "step.finished"


class JournalError(ValueError):
    """事件字段非法 / 日志损坏。"""


def _canonical(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _hash_event(prev: str, body: dict) -> str:
    return hashlib.sha256((prev + _canonical(body)).encode("utf-8")).hexdigest()


class Journal:
    """工作区级 append-only 事件日志（一个 run/工作区一个文件即可）。"""

    def __init__(self, path: Path | str, *, fsync: bool = True):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fsync = fsync

    # ---------------------------------------------------------------- 生命周期
    @classmethod
    def for_store(cls, store, *, fsync: bool = True) -> "Journal":
        return cls(Path(store.ws_dir) / JOURNAL_RELPATH, fsync=fsync)

    def exists(self) -> bool:
        return self.path.is_file() and self.path.stat().st_size > 0

    # ---------------------------------------------------------------- 追加
    def append(self, kind: str, *, step: str = "", payload: dict | None = None) -> dict:
        if not isinstance(kind, str) or not kind.strip():
            raise JournalError("kind 须为非空字符串")
        if payload is not None and not isinstance(payload, dict):
            raise JournalError("payload 须为 dict 或 None")
        if not isinstance(step, str):
            raise JournalError("step 须为字符串")
        with _append_lock(self.path), _cross_process_lock(self.path):
            events = self.events(strict=False)
            seq = (events[-1]["seq"] + 1) if events else 1
            prev = _hash_event_prev(events)
            body = {"seq": seq, "ts": time.time(), "kind": kind, "step": step,
                    "payload": payload or {}}
            event = {**body, "prev": prev, "hash": _hash_event(prev, body)}
            line = json.dumps(event, ensure_ascii=False, separators=(",", ":"), default=str)
            with self.path.open("a", encoding="utf-8", newline="\n") as fh:
                fh.write(line + "\n")
                fh.flush()
                if self._fsync:
                    os.fsync(fh.fileno())
            return event

    # ---------------------------------------------------------------- 读取
    def events(self, *, strict: bool = True) -> list[dict]:
        """读取全部事件；strict=False 时跳过无法解析的行（verify 自行定位）。"""
        if not self.path.exists():
            return []
        out: list[dict] = []
        for lineno, line in enumerate(self.path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except ValueError as exc:
                if strict:
                    raise JournalError(f"第 {lineno} 行不是合法 JSON: {exc}") from exc
                continue
            if strict and not isinstance(event, dict):
                raise JournalError(f"第 {lineno} 行不是事件对象")
            out.append(event)
        return out

    # ---------------------------------------------------------------- 校验
    def verify(self) -> dict:
        """逐行重算哈希链：返回 {ok, events, broken_at, reason}。"""
        if not self.path.exists():
            return {"ok": True, "events": 0, "broken_at": None, "reason": ""}
        prev = ""
        count = 0
        for lineno, line in enumerate(self.path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except ValueError:
                return {"ok": False, "events": count, "broken_at": lineno,
                        "reason": "invalid-json（半写/截断行）"}
            if not isinstance(event, dict):
                return {"ok": False, "events": count, "broken_at": lineno,
                        "reason": "not-an-event"}
            if event.get("seq") != count + 1:
                return {"ok": False, "events": count, "broken_at": lineno,
                        "reason": f"seq 不连续（期望 {count + 1}）"}
            if event.get("prev") != prev:
                return {"ok": False, "events": count, "broken_at": lineno,
                        "reason": "prev 与上一条 hash 不一致（删行/插行）"}
            body = {k: event.get(k) for k in ("seq", "ts", "kind", "step", "payload")}
            expected = _hash_event(prev, body)
            if event.get("hash") != expected:
                return {"ok": False, "events": count, "broken_at": lineno,
                        "reason": "hash 不匹配（内容被改）"}
            prev = event["hash"]
            count += 1
        return {"ok": True, "events": count, "broken_at": None, "reason": ""}

    def _verified_events(self) -> list[dict]:
        verdict = self.verify()
        if not verdict["ok"]:
            raise JournalError(
                f"日志损坏（第 {verdict['broken_at']} 行：{verdict['reason']}），拒绝 resume/replay"
            )
        return self.events()

    # ---------------------------------------------------------------- checkpoint
    def checkpoint(self, label: str, data: dict | None = None) -> dict:
        if not isinstance(label, str) or not label.strip():
            raise JournalError("checkpoint label 须为非空字符串")
        return self.append("checkpoint", payload={"label": label, "data": dict(data or {})})

    # ---------------------------------------------------------------- 恢复
    def resume(self) -> dict:
        """崩溃恢复视图：completed / failed / incomplete 步骤 + 最新 checkpoint。"""
        started: list[str] = []
        finished: dict[str, bool] = {}
        checkpoints: list[dict] = []
        order: list[str] = []
        for event in self._verified_events():
            step = event.get("step") or ""
            if event["kind"] == "step.started" and step:
                started.append(step)
                if step not in order:
                    order.append(step)
            elif event["kind"] == FINISHED_OK and step:
                finished[step] = bool((event.get("payload") or {}).get("ok"))
                if step not in order:
                    order.append(step)
            elif event["kind"] == "checkpoint":
                payload = event.get("payload") or {}
                checkpoints.append({"label": payload.get("label", ""),
                                    "seq": event["seq"], "data": payload.get("data") or {}})
        completed = [s for s in order if finished.get(s) is True]
        failed = [s for s in order if finished.get(s) is False]
        incomplete = [s for s in order if s in started and s not in finished]
        return {
            "seq": (self.events()[-1]["seq"] if self.events() else 0),
            "completed": completed,
            "failed": failed,
            "incomplete": incomplete,
            "checkpoints": checkpoints,
        }

    def replay(self) -> dict:
        """从事件流重建状态（零执行）：步骤状态 + 事件种类计数 + 最后序号。"""
        events = self._verified_events()
        steps: dict[str, str] = {}
        for event in events:
            step = event.get("step") or ""
            if not step:
                continue
            if event["kind"] == "step.started":
                steps[step] = "started"
            elif event["kind"] == FINISHED_OK:
                steps[step] = "success" if (event.get("payload") or {}).get("ok") else "failed"
        return {
            "steps": steps,
            "kinds": dict(Counter(e["kind"] for e in events)),
            "last_seq": events[-1]["seq"] if events else 0,
            "events": len(events),
        }


def _hash_event_prev(events: list[dict]) -> str:
    if not events:
        return ""
    last = events[-1]
    if "hash" not in last:
        raise JournalError("末条事件缺 hash（日志损坏）")
    return str(last["hash"])
