# -*- coding: utf-8 -*-
"""Recon worker: read-only enumeration only."""
from __future__ import annotations

from .base import WorkerResult
from .probe import ProbeWorker


class ReconWorker(ProbeWorker):
    role = "recon"

    def execute(self, intent: dict) -> WorkerResult:
        if intent.get("writes"):
            return WorkerResult(False, str(intent.get("id") or ""), self.role,
                                str(intent.get("module") or ""),
                                error="recon worker 只执行只读意图")
        return super().execute(intent)
