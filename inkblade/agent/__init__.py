# -*- coding: utf-8 -*-
"""InkBlade autonomous agent runtime (2026 architecture).

The package is an *external* runtime around the deterministic probe kernel:

* :mod:`inkblade.agent.runtime` — append-only, hash-chained event log with
  checkpoints, resume, replay and time travel.
* :mod:`inkblade.agent.graph` — Fact / Intent / Hint blackboard with causal
  edges and evidence gating.
* :mod:`inkblade.agent.scheduler` — frontier selection, leases, retries and
  four-dimensional budgets.
* :mod:`inkblade.agent.workers` — role workers (recon/exploit/verify/report)
  that execute probe tasks through a session.
* :mod:`inkblade.agent.protocols` — MCP Tasks, SEP-2640 skills and A2A.
* :mod:`inkblade.agent.memory` — working / episodic / semantic memory plus
  reflexion.
* :mod:`inkblade.agent.skills` — versioned skill library with approval and
  success statistics.
* :mod:`inkblade.agent.eval` — CyberGym/AgentDojo-style evaluation harness.

No module code is imported or executed here.  Every target-side action is a
declarative template sent through ``session.probe_task`` to the Rust probe.
"""
from __future__ import annotations

__all__ = [
    "runtime", "graph", "scheduler", "workers", "protocols", "memory",
    "skills", "eval", "objectives", "planner", "supervisor",
]
