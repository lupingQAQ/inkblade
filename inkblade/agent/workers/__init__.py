# -*- coding: utf-8 -*-
"""Role workers (recon / exploit / verify / report).

Workers are the only components that may touch a probe session.  The supervisor
never calls ``run_module`` or ``probe_task``; it leases an intent and hands it to
a role worker.  Workers return observations; the supervisor/observer persist
graph facts and evidence.
"""
from __future__ import annotations

from .base import NoWorker, Worker, WorkerPool, WorkerResult, build_worker_pool
from .probe import ProbeWorker
from .recon import ReconWorker
from .exploit import ExploitWorker
from .verify import VerifyWorker
from .report import ReportWorker

__all__ = [
    "NoWorker", "Worker", "WorkerPool", "WorkerResult", "build_worker_pool",
    "ProbeWorker", "ReconWorker", "ExploitWorker", "VerifyWorker", "ReportWorker",
]
