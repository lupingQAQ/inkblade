# -*- coding: utf-8 -*-
"""分层 supervisor-worker：任务队列 + 有界并发（1–8）+ 失败重派 + 审批门。

硬边界（与 explorer/runner 同源）：
- worker **只执行已批准动作**：动作需自带 ``approval.status == "approved"``，或所属
  proposal 整体已批准；否则 ``ApprovalRequired`` 且任务不入队（无残留）；
- 执行器默认 ``core.runner.run_module``——授权闸门 + 备份闸门 + 三层落证照旧；
  单任务失败不会绕过闸门（异常原样上报）；
- 失败重派上限 ``max_attempts``（默认 2），重派事件写入 journal（可崩溃恢复）；
- 并发上限 1–8（构造期校验），持久化队列 ``supervisor/queue.json``，
  控制面重启后 pending/running 任务可继续（running 复位为 pending）。
"""

from __future__ import annotations

import json
import queue as queue_mod
import threading
import time
from pathlib import Path
from typing import Any, Callable

WORKERS_MIN, WORKERS_MAX = 1, 8
QUEUE_RELPATH = "supervisor/queue.json"


class SupervisorError(ValueError):
    """并发/任务字段非法。"""


class ApprovalRequired(PermissionError):
    """动作未经 lead 批准，拒绝入队/执行。"""


def estimate_tokens(text: str) -> int:
    """确定性 token 估算（无 tokenizer 依赖）：CJK 按字、其余按 4 字符/词。"""
    cjk = sum(1 for ch in text if "\u4e00" <= ch <= "\u9fff")
    rest = len(text) - cjk
    return max(1, cjk + rest // 4)


def _approved(action: dict, proposal: dict | None) -> bool:
    approval = action.get("approval") or {}
    if str(approval.get("status", "")).lower() == "approved" and approval.get("approved_by"):
        return True
    if proposal is not None:
        if str(proposal.get("status", "")).lower() == "approved":
            pap = proposal.get("approval") or {}
            if str(pap.get("status", "")).lower() == "approved" and pap.get("approved_by"):
                return True
    return False


class Supervisor:
    def __init__(self, store, session, *, modules_dir: Path | str | None = None,
                 workers: int = 2, max_attempts: int = 2,
                 executor: Callable[[dict], dict] | None = None,
                 journal=None):
        if not isinstance(workers, int) or not (WORKERS_MIN <= workers <= WORKERS_MAX):
            raise SupervisorError(f"workers 须在 {WORKERS_MIN}–{WORKERS_MAX}，得到 {workers!r}")
        if not isinstance(max_attempts, int) or max_attempts < 1:
            raise SupervisorError(f"max_attempts 须 ≥1，得到 {max_attempts!r}")
        self.store = store
        self.session = session
        self.workers = workers
        self.max_attempts = max_attempts
        self.modules_dir = Path(modules_dir) if modules_dir else Path(store.root) / "modules"
        self._executor = executor or self._default_executor
        if journal is None:
            from .journal import Journal

            journal = Journal.for_store(store)
        self.journal = journal
        self.path = Path(store.ws_dir) / QUEUE_RELPATH
        self._lock = threading.Lock()
        self._tasks: list[dict] = self._load()

    # ---------------------------------------------------------------- 持久化
    def _load(self) -> list[dict]:
        if not self.path.exists():
            return []
        try:
            items = json.loads(self.path.read_text(encoding="utf-8"))
        except ValueError:
            return []
        for task in items:
            if task.get("status") == "running":  # 控制面崩溃：复位待重派
                task["status"] = "pending"
        return list(items)

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._tasks, ensure_ascii=False, indent=1), encoding="utf-8")
        tmp.replace(self.path)

    # ---------------------------------------------------------------- 入队
    def submit(self, actions: list[dict], *, proposal: dict | None = None) -> list[dict]:
        if not self.session.can("execute"):
            raise PermissionError(f"{self.session.name}({self.session.role}) 无 execute 权限")
        if not actions:
            raise SupervisorError("actions 为空")
        for action in actions:
            if not isinstance(action, dict) or not action.get("module"):
                raise SupervisorError("action 须含 module")
            if not _approved(action, proposal):
                raise ApprovalRequired(
                    f"动作 {action.get('module')} 未批准（需 lead approve 后入队）"
                )
        created: list[dict] = []
        with self._lock:
            for action in actions:
                seq = len(self._tasks) + 1
                task = {
                    "id": f"task-{time.strftime('%Y%m%d-%H%M%S')}-{seq:03d}",
                    "module": action["module"],
                    "params": dict(action.get("params") or {}),
                    "proposal": (proposal or {}).get("id", action.get("proposal", "")),
                    "task": action.get("task", ""),
                    "status": "pending",
                    "attempts": 0,
                    "max_attempts": self.max_attempts,
                    "approval": action.get("approval") or (proposal or {}).get("approval") or {},
                    "created_at": time.time(),
                    "started_at": None,
                    "finished_at": None,
                    "error": "",
                    "result": None,
                    "tokens": estimate_tokens(json.dumps(
                        {"module": action["module"], "params": action.get("params") or {}},
                        ensure_ascii=False)),
                }
                self._tasks.append(task)
                created.append(dict(task))
            self._save()
        return created

    def tasks(self) -> list[dict]:
        with self._lock:
            return [dict(t) for t in self._tasks]

    # ---------------------------------------------------------------- 执行
    def _default_executor(self, task: dict) -> dict:
        from .runner import run_module

        res = run_module(self.store, self.session, task["module"], task["params"], self.modules_dir)
        return {"ok": True, "run": res.get("run"), "step": res.get("step"),
                "summary": res.get("result_summary", "")}

    def _update(self, task_id: str, **fields) -> None:
        with self._lock:
            for task in self._tasks:
                if task["id"] == task_id:
                    task.update(fields)
                    break
            self._save()

    def run(self) -> dict:
        started = time.time()
        pending_ids = [t["id"] for t in self.tasks() if t["status"] == "pending"]
        work: queue_mod.Queue[str] = queue_mod.Queue()
        for tid in pending_ids:
            work.put(tid)
        lock = threading.Lock()
        retries = {"n": 0}

        def worker() -> None:
            while True:
                try:
                    task_id = work.get_nowait()
                except queue_mod.Empty:
                    return
                task = next((t for t in self.tasks() if t["id"] == task_id), None)
                if task is None:
                    continue
                attempt = int(task["attempts"]) + 1
                self._update(task_id, status="running", attempts=attempt,
                             started_at=task.get("started_at") or time.time(), error="")
                self.journal.append("task.started", step=task["module"],
                                    payload={"task": task_id, "attempt": attempt})
                try:
                    result = self._executor({**task, "attempts": attempt})
                except Exception as exc:  # 单任务失败：重派或终态失败
                    err = f"{type(exc).__name__}: {exc}"
                    if attempt < self.max_attempts:
                        with lock:
                            retries["n"] += 1
                        self._update(task_id, status="pending", error=err)
                        self.journal.append("task.retry", step=task["module"],
                                            payload={"task": task_id, "attempt": attempt, "error": err})
                        work.put(task_id)
                    else:
                        self._update(task_id, status="failed", error=err,
                                     finished_at=time.time())
                        self.journal.append("task.failed", step=task["module"],
                                            payload={"task": task_id, "attempt": attempt, "error": err})
                    continue
                self._update(task_id, status="success", result=result or {}, error="",
                             finished_at=time.time())
                self.journal.append("task.succeeded", step=task["module"],
                                    payload={"task": task_id, "attempt": attempt,
                                             "result": result or {}})

        threads = [threading.Thread(target=worker, daemon=True) for _ in range(self.workers)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()

        final = self.tasks()
        success = sum(1 for t in final if t["status"] == "success")
        failed = sum(1 for t in final if t["status"] == "failed")
        return {
            "mode": "supervisor-worker",
            "workers": self.workers,
            "tasks": final,
            "summary": {
                "total": len(final),
                "success": success,
                "failed": failed,
                "pending": sum(1 for t in final if t["status"] == "pending"),
                "retries": sum(max(0, int(t["attempts"]) - 1) for t in final),
                "approvals": sum(1 for t in final if (t.get("approval") or {}).get("status") == "approved"),
                "tokens": sum(int(t.get("tokens", 0)) * max(1, int(t.get("attempts", 0))) for t in final),
                "duration_ms": int((time.time() - started) * 1000),
            },
        }
