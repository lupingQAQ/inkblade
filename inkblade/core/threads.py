# -*- coding: utf-8 -*-
"""run 内问答线程 / 侧问（clean-room 等价实现）：tester 提问 → lead 回复。

硬边界（与 explorer 审批同一权限矩阵）：
- 提问：tester / lead / admin（``execute`` 能力位）；auditor 只读；
- 回复/关闭：lead / admin（``approve`` 能力位）；提问者本人可取消自己的待答问题；
- **绝不触发执行**：本模块不导入 runner/chains，只读写问答文件 + 追加审计；
- 全程审计：每条消息写 run.evidence.db 的 actions 表（动作 thread-question /
  thread-reply，参数含消息摘要与长度，不复制正文），线程文件内保留消息正文与逐条
  audit 记录，供复核；同时追加工作区 ``audit.jsonl``。

存储：工作区 ``threads/<run>.json``（一个 run 一个文件，线程按创建顺序）。
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any

from . import jsonio

MAX_BODY = 4000
MAX_SUBJECT = 200
_LOCK = threading.RLock()


class ThreadError(ValueError):
    """线程/消息参数非法。"""


class ThreadDenied(PermissionError):
    """角色不足。"""


class Threads:
    def __init__(self, store, *, clock=time.time):
        self.store = store
        self.root = Path(store.ws_dir) / "threads"
        self.root.mkdir(parents=True, exist_ok=True)
        self._clock = clock

    # ------------------------------------------------------------ 文件
    def _path(self, run: str) -> Path:
        # run 必须真实存在（含 evidence.db），不接受任意路径
        try:
            self.store.open_run(run)
        except KeyError as exc:
            raise ThreadError(f"run 不存在：{run}") from exc
        safe = str(run)
        if any(ch in safe for ch in "\\/:*?\"<>|"):
            raise ThreadError(f"非法 run 名 {run!r}")
        return self.root / f"{safe}.json"

    def _load(self, run: str) -> dict:
        doc = jsonio.read_json(self._path(run), None)
        if not isinstance(doc, dict) or not isinstance(doc.get("threads"), list):
            doc = {"version": 1, "run": run, "threads": []}
        return doc

    def _save(self, run: str, doc: dict) -> None:
        jsonio.write_json(self._path(run), doc)

    def _find(self, doc: dict, thread_id: str) -> dict:
        for t in doc["threads"]:
            if t.get("id") == thread_id:
                return t
        raise ThreadError(f"未知线程 {thread_id}")

    # ------------------------------------------------------------ 提问
    def ask(self, session, run: str, subject: str, body: str,
            *, thread_id: str = "") -> dict:
        if not session.can("execute"):
            raise ThreadDenied(f"{session.name}({session.role}) 无提问权限（tester/lead/admin）")
        subject = str(subject or "").strip()
        body = str(body or "").strip()
        if not subject or len(subject) > MAX_SUBJECT:
            raise ThreadError(f"subject 必填且不超过 {MAX_SUBJECT} 字")
        if not body or len(body) > MAX_BODY:
            raise ThreadError(f"body 必填且不超过 {MAX_BODY} 字")
        now = self._clock()
        with _LOCK:
            doc = self._load(run)
            tid = thread_id or f"thr-{len(doc['threads']) + 1:04d}"
            if any(t.get("id") == tid for t in doc["threads"]):
                raise ThreadError(f"线程 id 重复 {tid}")
            mid = f"{tid}-m1"
            msg = {"id": mid, "seq": 1, "kind": "question", "author": session.name,
                   "role": session.role, "body": body, "ts": now,
                   "digest": jsonio.digest(f"{tid}|{mid}|{body}")}
            thread = {
                "id": tid, "run": run, "subject": subject, "status": "awaiting_lead",
                "created_by": session.name, "created_at": now,
                "execution": {"triggered": False},
                "messages": [msg], "audit": [],
            }
            _append_audit(thread, session, "thread.question", mid, subject, now)
            doc["threads"].append(thread)
            self._save(run, doc)
        self._external_audit(session, run, "thread-question", tid, msg, "recorded")
        return thread

    # ------------------------------------------------------------ 回复/关闭/取消
    def reply(self, session, run: str, thread_id: str, body: str) -> dict:
        if not session.can("approve"):
            raise ThreadDenied(f"{session.name}({session.role}) 无回复权限（lead/admin）")
        body = str(body or "").strip()
        if not body or len(body) > MAX_BODY:
            raise ThreadError(f"body 必填且不超过 {MAX_BODY} 字")
        now = self._clock()
        with _LOCK:
            doc = self._load(run)
            thread = self._find(doc, thread_id)
            if thread.get("status") in ("closed", "canceled"):
                raise ThreadError(f"线程 {thread_id} 状态 {thread.get('status')}，不可回复")
            seq = len(thread["messages"]) + 1
            mid = f"{thread_id}-m{seq}"
            msg = {"id": mid, "seq": seq, "kind": "reply", "author": session.name,
                   "role": session.role, "body": body, "ts": now,
                   "digest": jsonio.digest(f"{thread_id}|{mid}|{body}")}
            thread["messages"].append(msg)
            thread["status"] = "answered"
            thread["answered_by"] = session.name
            thread["answered_at"] = now
            _append_audit(thread, session, "thread.reply", mid, body, now)
            self._save(run, doc)
        self._external_audit(session, run, "thread-reply", thread_id, msg, "recorded")
        return thread

    def close(self, session, run: str, thread_id: str, *, resolution: str = "") -> dict:
        if not session.can("approve"):
            raise ThreadDenied(f"{session.name}({session.role}) 无关闭权限（lead/admin）")
        with _LOCK:
            doc = self._load(run)
            thread = self._find(doc, thread_id)
            thread["status"] = "closed"
            thread["resolution"] = str(resolution)[:MAX_BODY]
            thread["closed_by"] = session.name
            thread["closed_at"] = self._clock()
            _append_audit(thread, session, "thread.close", thread_id, resolution, self._clock())
            self._save(run, doc)
        jsonio.append_audit(self.store, session.name, "thread.close", thread_id,
                            {"run": run, "resolution": resolution}, "ok")
        return thread

    def cancel(self, session, run: str, thread_id: str, *, reason: str = "") -> dict:
        with _LOCK:
            doc = self._load(run)
            thread = self._find(doc, thread_id)
            if session.name != thread.get("created_by") and not session.can("approve"):
                raise ThreadDenied(f"{session.name} 非提问者且无 approve 权限，不可取消")
            if thread.get("status") in ("closed", "canceled"):
                raise ThreadError(f"线程 {thread_id} 已终态 {thread.get('status')}")
            thread["status"] = "canceled"
            thread["cancel_reason"] = str(reason)[:MAX_BODY]
            thread["canceled_by"] = session.name
            thread["canceled_at"] = self._clock()
            _append_audit(thread, session, "thread.cancel", thread_id, reason, self._clock())
            self._save(run, doc)
        jsonio.append_audit(self.store, session.name, "thread.cancel", thread_id,
                            {"run": run, "reason": reason}, "ok")
        return thread

    # ------------------------------------------------------------ 查询
    def get(self, run: str, thread_id: str) -> dict:
        return self._find(self._load(run), thread_id)

    def list_threads(self, run: str | None = None) -> list[dict]:
        if run is not None:
            return list(self._load(run)["threads"])
        out: list[dict] = []
        for p in sorted(self.root.glob("*.json")):
            doc = jsonio.read_json(p, {})
            if isinstance(doc, dict):
                out.extend(doc.get("threads") or [])
        return out

    def events(self, run: str, thread_id: str) -> dict:
        thread = self.get(run, thread_id)
        return {"thread_id": thread_id, "run": run, "status": thread.get("status"),
                "events": [{"seq": m.get("seq"), "kind": m.get("kind"),
                            "author": m.get("author"), "role": m.get("role"),
                            "ts": m.get("ts"), "digest": m.get("digest"),
                            "body": m.get("body")} for m in thread.get("messages", [])]}

    def summary(self, run: str | None = None) -> dict:
        threads = self.list_threads(run)
        return {"threads": len(threads),
                "awaiting_lead": sum(1 for t in threads if t.get("status") == "awaiting_lead"),
                "answered": sum(1 for t in threads if t.get("status") == "answered"),
                "closed": sum(1 for t in threads if t.get("status") == "closed"),
                "canceled": sum(1 for t in threads if t.get("status") == "canceled")}

    # ------------------------------------------------------------ 审计
    def _external_audit(self, session, run: str, action: str, thread_id: str,
                        msg: dict, result: str) -> None:
        try:
            r = self.store.open_run(run)
            r.log_action(session.name, action, thread_id,
                         {"message_id": msg["id"], "digest": msg["digest"],
                          "body_len": len(msg["body"])}, result)
        except Exception:
            pass  # run 索引异常不应阻断问答；工作区审计仍写入
        jsonio.append_audit(self.store, session.name, action, thread_id,
                            {"run": run, "message_id": msg["id"],
                             "digest": msg["digest"], "body_len": len(msg["body"])}, result)


def _append_audit(thread: dict, session, action: str, target: str, text: str, ts: float) -> None:
    thread.setdefault("audit", []).append({
        "ts": ts, "actor": session.name, "role": session.role,
        "action": action, "target": target, "digest": jsonio.digest(str(text)),
        "execution": False,
    })
