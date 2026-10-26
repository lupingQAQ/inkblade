# -*- coding: utf-8 -*-
"""Verify worker: independent, read-only confirmation of claimed effects."""
from __future__ import annotations

from .base import WorkerResult
from .probe import ProbeWorker


class VerifyWorker(ProbeWorker):
    role = "verify"

    def execute(self, intent: dict) -> WorkerResult:
        if intent.get("writes"):
            return WorkerResult(False, str(intent.get("id") or ""), self.role,
                                str(intent.get("module") or ""),
                                error="verify worker 只执行只读复核")
        return super().execute(intent)
