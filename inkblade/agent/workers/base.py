# -*- coding: utf-8 -*-
"""Worker base types and the role→worker pool."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ...tpl.probe import ProbeUnavailable
from ..graph import PlanGraph


class WorkerError(RuntimeError):
    """Worker cannot execute the intent."""


class NoWorker(WorkerError):
    """No worker is registered for the intent role."""


@dataclass
class WorkerResult:
    ok: bool
    intent: str
    role: str
    module: str
    output: dict = field(default_factory=dict)
    observation: Any = None
    error: str = ""
    tokens: int = 0
    probe_calls: int = 0
    duration_ms: int = 0

    def as_dict(self) -> dict:
        return {
            "ok": self.ok, "intent": self.intent, "role": self.role,
            "module": self.module, "output": dict(self.output), "error": self.error,
            "tokens": self.tokens, "probe_calls": self.probe_calls,
            "duration_ms": self.duration_ms,
        }


class Worker:
    role = "worker"

    def __init__(self, *, store, session, modules_dir: str | Path,
                 runtime=None, graph: PlanGraph | None = None, objective=None):
        self.store = store
        self.session = session
        self.modules_dir = Path(modules_dir)
        self.runtime = runtime
        self.graph = graph
        self.objective = objective

    @property
    def name(self) -> str:
        return f"{self.role}-worker"

    def execute(self, intent: dict) -> WorkerResult:
        raise NotImplementedError

    def _probe(self):
        session = self.session
        probe = getattr(session, "probe", None)
        if callable(probe):
            candidate = probe()
            if candidate is not None:
                return candidate
        if callable(getattr(session, "probe_task", None)):
            raise ProbeUnavailable("session 只有 probe_task，缺少 transport 适配器")
        raise ProbeUnavailable("没有探针会话：拒绝执行（agent 不做宿主回退）")


class WorkerPool:
    def __init__(self, workers: dict[str, Worker] | None = None):
        self.workers = dict(workers or {})

    def for_role(self, role: str) -> Worker:
        worker = self.workers.get(str(role))
        if worker is None:
            raise NoWorker(f"没有 {role!r} 角色 worker（已注册 {sorted(self.workers)}）")
        return worker

    def roles(self) -> list[str]:
        return sorted(self.workers)

    def execute(self, intent: dict) -> WorkerResult:
        worker = self.for_role(str(intent.get("role") or ""))
        started = time.time()
        result = worker.execute(intent)
        if result.duration_ms == 0:
            result.duration_ms = int((time.time() - started) * 1000)
        return result


def build_worker_pool(*, store, session, modules_dir, runtime=None, graph=None,
                      objective=None, roles: list[str] | None = None) -> WorkerPool:
    from .exploit import ExploitWorker
    from .recon import ReconWorker
    from .report import ReportWorker
    from .verify import VerifyWorker

    registry = {
        "recon": ReconWorker, "exploit": ExploitWorker,
        "verify": VerifyWorker, "report": ReportWorker,
    }
    wanted = list(roles or registry)
    workers = {}
    for role in wanted:
        cls = registry.get(role)
        if cls is None:
            raise NoWorker(f"未知 worker 角色: {role!r}")
        workers[role] = cls(store=store, session=session, modules_dir=modules_dir,
                            runtime=runtime, graph=graph, objective=objective)
    return WorkerPool(workers)
