# -*- coding: utf-8 -*-
"""core/swarm.py — 角色化 worker（recon/exploit/verify/report）+ 本机多进程队列。

边界（与 supervisor/explorer 同源）：
- **只执行已批准任务**：``approval.status == approved`` 且有 ``approved_by``（或所属
  proposal 已批准）；否则 ``ApprovalRequired``，且入队前整体校验、零残留。
- 角色上限 ``ROLE_CAPS`` 每角色默认 2、最小 2、最大 8；总 worker 1–16。4 个角色都有
  任务时，4 worker = 每角色 1 个（≤上限）；worker 数少于角色数时退化为通用 worker 池。
- 本机多进程：``multiprocessing``（Windows spawn）每角色一条 ``Queue``，worker 进程
  取任务、执行、回结果；失败重派由父进程按 ``max_attempts`` 重入同角色队列。
- 执行器可插拔：``simulate``（评测/测试，确定性 sleep）与 ``runner``（生产：子进程内
  构造 EvidenceStore + ``core.runner.run_module``，授权/备份/落证闸门照旧）。
- 审批计数按任务（预授权批量批准），不冒充人工点击；时延/并发由结果时间戳计算。
"""

from __future__ import annotations

import multiprocessing as mp
import os
import queue as queue_mod
import time
from pathlib import Path
from typing import Any, Callable

ROLES = ("recon", "exploit", "verify", "report")
ROLE_CAPS = {"recon": 2, "exploit": 2, "verify": 2, "report": 2}
ROLE_MIN_CAP = 2
ROLE_MAX_CAP = 8
WORKERS_MAX = 16
DEFAULT_TIMEOUT = 180


class SwarmError(ValueError):
    """角色/worker/任务字段非法。"""


class ApprovalRequired(PermissionError):
    """任务未经 lead 批准，拒绝入队/执行。"""


def _approved(task: dict, proposal: dict | None = None) -> bool:
    approval = task.get("approval") or {}
    if str(approval.get("status", "")).lower() == "approved" and approval.get("approved_by"):
        return True
    if proposal:
        pap = proposal.get("approval") or {}
        return (str(proposal.get("status", "")).lower() == "approved"
                and str(pap.get("status", "")).lower() == "approved"
                and bool(pap.get("approved_by")))
    return False


# ---------------------------------------------------------------- 子进程执行器

def _run_task(task: dict, spec: dict) -> dict:
    kind = str(spec.get("kind") or "simulate")
    if kind == "simulate":
        sim = task.get("simulate") or {}
        delay_ms = int(sim.get("delay_ms", spec.get("delay_ms", 50)) or 0)
        if delay_ms:
            time.sleep(delay_ms / 1000.0)
        attempt = int(task.get("attempt") or 1)
        if task.get("fail"):
            raise RuntimeError("simulated failure（permanent）")
        if attempt <= int(task.get("fail_times") or 0):
            raise RuntimeError("simulated failure（transient）")
        return {"findings": max(0, delay_ms // 10), "delay_ms": delay_ms}
    if kind == "runner":
        from .evidence import EvidenceStore
        from .runner import run_module
        from .users import Session

        home = Path(spec["home"])
        workspace = str(spec.get("workspace") or "local-lab")
        store = EvidenceStore(home, workspace=workspace)
        session = Session(None, str(spec.get("actor") or "swarm"),
                          str(spec.get("session_role") or "tester"), [workspace], "swarm")
        res = run_module(store, session, str(task["module"]), dict(task.get("params") or {}),
                         spec.get("modules_dir"))
        return {"run": res.get("run", ""), "step": res.get("step", ""),
                "summary": res.get("result_summary", "")}
    raise SwarmError(f"未知执行器 kind={kind}")


def _worker_main(queue, result_q, spec: dict) -> None:  # pragma: no cover - 子进程
    role = str(spec.get("worker_role") or "any")
    approval_ms = int(spec.get("approval_ms") or 0)
    while True:
        task = queue.get()
        if task is None:
            return
        started = time.time()
        approval_started = started
        if approval_ms:
            time.sleep(approval_ms / 1000.0)
        approval_done = time.time()
        try:
            output = _run_task(task, spec)
            ok, error = True, ""
        except Exception as exc:  # 单任务失败：回父进程决定重派/终态
            output, ok, error = {}, False, f"{type(exc).__name__}: {exc}"
        finished = time.time()
        result_q.put({
            "task_id": str(task.get("id") or ""),
            "role": str(task.get("role") or role),
            "module": str(task.get("module") or ""),
            "ok": bool(ok),
            "error": error,
            "output": output,
            "attempt": int(task.get("attempt") or 1),
            "attempts": int(task.get("attempt") or 1),
            "pid": os.getpid(),
            "started_at": started,
            "approval_ms": int((approval_done - approval_started) * 1000),
            "finished_at": finished,
            "duration_ms": int((finished - started) * 1000),
        })


def _peak(rows: list[dict]) -> int:
    events = []
    for row in rows:
        events.append((float(row["started_at"]), 1))
        events.append((float(row["finished_at"]), -1))
    events.sort(key=lambda e: (e[0], e[1]))  # 同一时刻先结束后开始，避免把交接算成重叠
    now = peak = 0
    for _, delta in events:
        now += delta
        peak = max(peak, now)
    return peak


# ---------------------------------------------------------------- 队列

class Swarm:
    def __init__(self, *, workers: int = 4, roles=ROLES, role_caps: dict | None = None,
                 executor: dict | None = None, max_attempts: int = 2,
                 ctx=None):
        if not isinstance(workers, int) or isinstance(workers, bool) \
                or not (1 <= workers <= WORKERS_MAX):
            raise SwarmError(f"workers 须在 1–{WORKERS_MAX}，得到 {workers!r}")
        caps = dict(role_caps or ROLE_CAPS)
        roles = tuple(roles)
        if not roles or any(r not in caps for r in roles):
            raise SwarmError(f"未知角色：{set(roles) - set(caps)}")
        if set(caps) - set(ROLE_CAPS):
            raise SwarmError(f"未知角色上限：{set(caps) - set(ROLE_CAPS)}")
        for role in roles:
            cap = caps[role]
            if not isinstance(cap, int) or isinstance(cap, bool) \
                    or not (ROLE_MIN_CAP <= cap <= ROLE_MAX_CAP):
                raise SwarmError(f"角色 {role} 上限须在 {ROLE_MIN_CAP}–{ROLE_MAX_CAP}，"
                                 f"得到 {cap!r}")
        if not isinstance(max_attempts, int) or max_attempts < 1:
            raise SwarmError("max_attempts 须 ≥1")
        self.workers = workers
        self.roles = roles
        self.role_caps = caps
        self.max_attempts = int(max_attempts)
        self.executor = dict(executor or {"kind": "simulate"})
        self._ctx = ctx or mp.get_context("spawn")
        self._queues: dict[str, Any] = {}
        self._result_q = None
        self._procs: list = []
        self.distribution: dict[str, int] = {}
        self._tasks: dict[str, dict] = {}
        self._submitted_ids: set[str] = set()
        self._final: dict[str, dict] = {}
        self._log: list[dict] = []
        self._started = False
        self.last_result: dict | None = None

    # ---------- 生命周期 ----------
    def _plan(self, roles_present: list[str]) -> dict[str, int]:
        """角色 → worker 数：每角色先 1 个，剩余按轮转补到上限。"""
        present = [r for r in self.roles if r in roles_present]
        plan = {r: 0 for r in present}
        if self.workers >= len(present):
            for r in present:
                plan[r] = 1
            remaining = self.workers - len(present)
            idx = 0
            while remaining > 0 and any(plan[r] < self.role_caps[r] for r in present):
                r = present[idx % len(present)]
                if plan[r] < self.role_caps[r]:
                    plan[r] += 1
                    remaining -= 1
                idx += 1
        else:
            plan = {"any": self.workers}
        return plan

    def _start(self, tasks: list[dict]) -> None:
        if self._started:
            return
        roles_present = sorted({str(t["role"]) for t in tasks})
        self.distribution = self._plan(roles_present)
        self._result_q = self._ctx.Queue()
        if "any" in self.distribution:
            self._queues = {"any": self._ctx.Queue()}
        else:
            self._queues = {role: self._ctx.Queue() for role in self.distribution}
        for role, count in self.distribution.items():
            for _ in range(count):
                spec = {**self.executor, "worker_role": role}
                proc = self._ctx.Process(target=_worker_main,
                                         args=(self._queues[role], self._result_q, spec),
                                         daemon=True)
                proc.start()
                self._procs.append(proc)
        self._started = True

    def close(self) -> None:
        if not self._started:
            return
        for role, queue in self._queues.items():
            count = self.distribution.get(role, len(self._procs))
            for _ in range(count):
                try:
                    queue.put(None)
                except Exception:
                    pass
        for proc in self._procs:
            proc.join(timeout=10)
            if proc.is_alive():
                proc.terminate()
        for queue in self._queues.values():
            try:
                queue.close()
                queue.join_thread()
            except Exception:
                pass
        if self._result_q is not None:
            try:
                self._result_q.close()
                self._result_q.join_thread()
            except Exception:
                pass
        self._procs = []
        self._started = False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # ---------- 入队 ----------
    def _route(self, role: str):
        if "any" in self._queues:
            return self._queues["any"]
        if role not in self._queues:
            raise SwarmError(f"本次 swarm 未启动角色 {role} 的队列")
        return self._queues[role]

    def submit(self, tasks: list[dict], *, proposal: dict | None = None) -> int:
        if not tasks:
            raise SwarmError("tasks 为空")
        seen = set()
        for item in tasks:
            if not isinstance(item, dict) or not item.get("id"):
                raise SwarmError("任务须为 dict 且含 id")
            tid = str(item["id"])
            if tid in seen or tid in self._submitted_ids:
                raise SwarmError(f"任务 id 重复：{tid}")
            if str(item.get("role")) not in self.roles:
                raise SwarmError(f"任务 {tid} 角色非法：{item.get('role')!r}")
            if not str(item.get("module") or ""):
                raise SwarmError(f"任务 {tid} 缺 module")
            if not _approved(item, proposal):
                raise ApprovalRequired(f"任务 {tid}（{item['module']}）未批准（需 lead approve）")
            seen.add(tid)
        self._start(tasks)
        for item in tasks:
            tid = str(item["id"])
            task = {**item, "attempt": 1}
            self._tasks[tid] = task
            self._submitted_ids.add(tid)
            self._route(str(task["role"])).put(task)
        return len(tasks)

    def pending(self) -> int:
        return sum(1 for tid in self._submitted_ids if tid not in self._final)

    # ---------- 执行 ----------
    def _collect(self, expected: int, *, timeout: float) -> None:
        deadline = time.time() + float(timeout)
        while len(self._final) < expected and time.time() < deadline:
            try:
                result = self._result_q.get(timeout=0.2)
            except queue_mod.Empty:
                if self._procs and not any(p.is_alive() for p in self._procs):
                    break
                continue
            self._log.append(result)
            tid = result["task_id"]
            task = self._tasks.get(tid)
            if task is None:
                continue
            if not result["ok"] and int(result["attempt"]) < self.max_attempts:
                retry = {**task, "attempt": int(result["attempt"]) + 1}
                self._tasks[tid] = retry
                result["retry"] = True
                self._route(str(task["role"])).put(retry)
                continue
            self._final[tid] = result
        missing = [tid for tid in self._submitted_ids if tid not in self._final]
        for tid in missing:
            self._final[tid] = {
                "task_id": tid, "role": str(self._tasks[tid]["role"]),
                "module": str(self._tasks[tid]["module"]), "ok": False,
                "error": "timeout: worker 未返回结果", "output": {},
                "attempt": int(self._tasks[tid].get("attempt") or 1),
                "pid": 0, "started_at": time.time(), "finished_at": time.time(),
                "duration_ms": 0, "approval_ms": 0,
            }

    def run(self, tasks: list[dict], *, proposal: dict | None = None,
            timeout: float = DEFAULT_TIMEOUT) -> dict:
        started = time.time()
        self._final = {}
        self._log = []
        self._tasks = {}
        self._submitted_ids = set()
        self.submit(tasks, proposal=proposal)
        self._collect(len(tasks), timeout=timeout)
        wall_ms = int((time.time() - started) * 1000)
        results = [self._final[tid] for tid in self._tasks if tid in self._final]
        results.sort(key=lambda r: r["task_id"])
        by_role: dict[str, dict] = {}
        for role in self.roles:
            rows = [r for r in results if r["role"] == role]
            if not rows:
                continue
            by_role[role] = {
                "total": len(rows),
                "success": sum(1 for r in rows if r["ok"]),
                "failed": sum(1 for r in rows if not r["ok"]),
                "retries": sum(1 for r in self._log
                               if r["role"] == role and r.get("retry")),
                "pids": sorted({r["pid"] for r in rows if r["pid"]}),
            }
        retries = sum(1 for r in self._log if r.get("retry"))
        summary = {
            "mode": "swarm",
            "workers": self.workers,
            "workers_used": len(self._procs),
            "distribution": dict(self.distribution),
            "total": len(results),
            "success": sum(1 for r in results if r["ok"]),
            "failed": sum(1 for r in results if not r["ok"]),
            "pending": self.pending(),
            "retries": retries,
            "approvals": sum(1 for t in self._tasks.values()
                             if str((t.get("approval") or {}).get("status")) == "approved"),
            "wall_ms": wall_ms,
            "peak_concurrency": _peak(self._log or results),
            "approval_ms_total": sum(int(r.get("approval_ms") or 0) for r in results),
            "pids": sorted({r["pid"] for r in results if r["pid"]}),
            "by_role": by_role,
            "results": results,
        }
        self.last_result = summary
        return summary
