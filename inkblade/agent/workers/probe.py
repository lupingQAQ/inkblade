# -*- coding: utf-8 -*-
"""Probe-backed worker: one intent → one deterministic template run."""
from __future__ import annotations

import time
from pathlib import Path

from ...core.runner import run_module
from ...tpl.probe import ProbeUnavailable
from ..observer import failure_observation, normalize_run
from ..runtime import estimate_tokens
from .base import Worker, WorkerError, WorkerResult


class ProbeWorker(Worker):
    role = "recon"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._last_run = ""

    def _probe(self):
        session = self.session
        probe = getattr(session, "probe", None)
        if callable(probe):
            candidate = probe()
            if candidate is not None and callable(getattr(candidate, "run", None)):
                return candidate
        raise ProbeUnavailable("没有 probe_task transport：拒绝执行")

    def execute(self, intent: dict) -> WorkerResult:
        started = time.time()
        iid = str(intent.get("id") or "")
        module = str(intent.get("module") or "")
        role = str(intent.get("role") or self.role)
        if role != self.role:
            return WorkerResult(False, iid, role, module,
                                error=f"{self.name} 不处理 role={role}")
        if not module:
            return WorkerResult(False, iid, role, module, error="intent 缺 module")
        before = self.session.call_count() if callable(
            getattr(self.session, "call_count", None)) else 0
        try:
            probe = self._probe()
            result = run_module(self.store, self.session, module,
                                dict(intent.get("params") or {}),
                                self.modules_dir, probe=probe)
        except Exception as exc:  # noqa: BLE001 - failure is an observation
            observation = failure_observation(intent, exc)
            return WorkerResult(False, iid, role, module, observation=observation,
                                error=observation.summary,
                                probe_calls=max(0, self._calls() - before),
                                duration_ms=int((time.time() - started) * 1000))
        if result.get("skipped"):
            return WorkerResult(False, iid, role, module,
                                output={"skipped": True, "reason": result.get("summary", "")},
                                error=f"surface gate skipped: {result.get('summary', '')}",
                                probe_calls=max(0, self._calls() - before),
                                duration_ms=int((time.time() - started) * 1000))
        run_name = str(result.get("run") or "")
        self._last_run = run_name
        try:
            run = self.store.open_run(run_name)
            observation = normalize_run(
                run, intent, step_rowid=result.get("rowid"),
                step_archive=str(result.get("archive") or ""))
        except Exception as exc:  # noqa: BLE001 - no evidence means no success
            observation = failure_observation(intent, exc)
            return WorkerResult(False, iid, role, module, observation=observation,
                                error=observation.summary,
                                probe_calls=max(0, self._calls() - before),
                                duration_ms=int((time.time() - started) * 1000))
        tokens = estimate_tokens({"module": module, "params": intent.get("params") or {},
                                  "summary": observation.summary})
        return WorkerResult(True, iid, role, module,
                            output={"run": run_name, "step": result.get("step", module),
                                    "archive": result.get("archive", ""),
                                    "summary": result.get("summary", ""),
                                    "findings": len(observation.facts),
                                    "evidence": len(observation.evidence)},
                            observation=observation, tokens=tokens,
                            probe_calls=max(0, self._calls() - before),
                            duration_ms=int((time.time() - started) * 1000))

    def _calls(self) -> int:
        fn = getattr(self.session, "call_count", None)
        return int(fn()) if callable(fn) else 0
