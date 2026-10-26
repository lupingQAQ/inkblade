# -*- coding: utf-8 -*-
"""Frontier scheduler: leases, priority/cost ordering, retries and hard budgets.

The scheduler is the only component that picks the next intent.  It never
executes a probe: it leases an intent to a worker and records the transition in
the event log.  ``supervisor`` mode is FIFO for the control baseline;
``graph-swarm`` mode uses the graph frontier (priority, cost, memory prior).
"""
from __future__ import annotations

import copy
import time
from dataclasses import dataclass, field
from typing import Any

from .graph import GraphError, PlanGraph
from .runtime import AgentRuntime, Budget, BudgetExceeded, StopRequested

SCHEDULER_MODES = ("graph-swarm", "supervisor", "deterministic")


class SchedulerError(ValueError):
    """Invalid scheduler operation."""


@dataclass
class SchedulerStatus:
    mode: str
    claimed: int = 0
    completed: int = 0
    failed: int = 0
    blocked: int = 0
    reclaimed: int = 0
    refused: int = 0
    budget_trips: int = 0
    dead_letter: list[dict] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "mode": self.mode, "claimed": self.claimed, "completed": self.completed,
            "failed": self.failed, "blocked": self.blocked, "reclaimed": self.reclaimed,
            "refused": self.refused, "budget_trips": self.budget_trips,
            "dead_letter": copy.deepcopy(self.dead_letter),
        }


class TaskScheduler:
    def __init__(self, graph: PlanGraph, budget: Budget, runtime: AgentRuntime | None = None,
                 *, memory=None, policy=None, mode: str = "graph-swarm",
                 max_attempts: int = 2, lease_seconds: float = 60.0,
                 retry_backoff: float = 0.0, clock=time.time):
        if mode not in SCHEDULER_MODES:
            raise SchedulerError(f"未知调度模式 {mode!r}（{SCHEDULER_MODES}）")
        self.graph = graph
        self.budget = budget
        self.runtime = runtime
        self.memory = memory
        self.policy = policy
        self.mode = mode
        self.max_attempts = max(1, int(max_attempts))
        self.lease_seconds = max(1.0, float(lease_seconds))
        self.retry_backoff = max(0.0, float(retry_backoff))
        self._clock = clock
        self.status = SchedulerStatus(mode=mode)
        self._tripped = False

    # ------------------------------------------------------------ events
    def _emit(self, kind: str, payload: dict, *, actor: str = "scheduler") -> None:
        if self.runtime is not None:
            self.runtime.emit(kind, payload, actor=actor)

    def _stop_check(self) -> None:
        if self.runtime is not None and self.runtime.is_stopped():
            raise StopRequested("operator stop / workspace abort")

    # ------------------------------------------------------------ selection
    def _ordered(self, now: float) -> list[dict]:
        frontier = self.graph.frontier(now=now, memory=self.memory)
        if self.mode in ("supervisor", "deterministic"):
            frontier.sort(key=lambda n: (int(n.get("created_seq", 0)), n["id"]))
        return frontier

    def claim_next(self, worker_id: str) -> dict | None:
        """Lease one ready intent or return None when the frontier is empty."""
        self._stop_check()
        try:
            self.budget.check(reserve_steps=1)
        except BudgetExceeded as exc:
            self._trip_budget(exc)
            raise
        now = float(self._clock())
        for intent in self.graph.reclaim_expired(now=now,
                                                 backoff_seconds=self.retry_backoff):
            self.status.reclaimed += 1
            self._emit("intent.reclaimed", {
                "intent": intent["id"], "attempts": intent.get("attempts", 0),
                "retryable": intent.get("status") == "open",
                "next_attempt_at": intent.get("next_attempt_at", 0),
                "summary": f"lease expired: {intent['id']}",
            })
        frontier = self._ordered(now)
        if not frontier:
            return None
        for intent in frontier:
            if self.policy is not None:
                decision = self.policy.check_intent(intent, self.graph)
                if not decision.allow:
                    self.status.refused += 1
                    self.graph.block(intent["id"], decision.reason)
                    self._emit("policy.refused", {
                        "intent": intent["id"], "kind": decision.kind,
                        "reason": decision.reason,
                        "summary": f"policy refused {intent['id']}: {decision.reason}",
                    })
                    self._emit("intent.blocked", {
                        "intent": intent["id"], "reason": decision.reason,
                        "summary": f"blocked {intent['id']}",
                    })
                    if decision.kind in ("ApprovalRequired",):
                        self._emit("approval.required", {
                            "intent": intent["id"], "reason": decision.reason,
                            "summary": "manual approval required for write intent",
                        })
                    continue
            try:
                claimed = self.graph.claim(intent["id"], worker_id,
                                           lease_seconds=self.lease_seconds, now=now)
            except GraphError as exc:
                self._emit("scheduler.error", {"intent": intent["id"],
                                               "reason": str(exc)})
                continue
            if intent.get("priority_reason"):
                claimed["priority_reason"] = intent["priority_reason"]
            self.budget.consume("steps", 1)
            self._emit("budget.spent", {
                "kind": "steps", "amount": 1,
                "total": self.budget.spent.get("steps", 0),
                "limit": self.budget.limits.get("steps", 0),
                "summary": f"steps {self.budget.spent.get('steps', 0)}/"
                           f"{self.budget.limits.get('steps', 0) or '∞'}",
            })
            self.status.claimed += 1
            self._emit("intent.claimed", {
                "intent": claimed["id"], "owner": worker_id,
                "lease_until": claimed.get("lease_until", 0),
                "priority": claimed.get("priority", 0),
                "cost_tokens": claimed.get("cost_tokens", 0),
                "frontier": [i["id"] for i in frontier],
                "summary": f"claimed {claimed['id']} ({claimed.get('role')}/"
                           f"{claimed.get('module')}) by {worker_id}",
            })
            self._emit("decision.made", {
                "kind": "select_intent", "chosen": claimed["id"],
                "options": [i["id"] for i in frontier],
                "rationale": claimed.get("priority_reason") or
                             f"frontier priority={claimed.get('priority')} "
                             f"cost={claimed.get('cost_tokens')}",
                "summary": f"selected {claimed['id']}",
            })
            return claimed
        return None

    def heartbeat(self, intent_id: str) -> dict:
        now = float(self._clock())
        intent = self.graph.heartbeat(intent_id, lease_seconds=self.lease_seconds, now=now)
        self._emit("intent.heartbeat", {
            "intent": intent_id, "lease_until": intent.get("lease_until", 0),
            "summary": f"heartbeat {intent_id}",
        })
        return intent

    # ------------------------------------------------------------ outcomes
    def complete(self, intent_id: str, *, evidence: list[str] | None = None,
                 result: dict | None = None) -> dict:
        intent = self.graph.complete(intent_id, evidence=evidence, result=result or {})
        try:
            self.budget.consume("actions", 1)
        except BudgetExceeded as exc:
            self._trip_budget(exc)
            raise
        self._emit("budget.spent", {
            "kind": "actions", "amount": 1,
            "total": self.budget.spent.get("actions", 0),
            "limit": self.budget.limits.get("actions", 0),
            "summary": f"actions {self.budget.spent.get('actions', 0)}/"
                       f"{self.budget.limits.get('actions', 0) or '∞'}",
        })
        self.status.completed += 1
        payload = {
            "intent": intent_id, "evidence": list(evidence or []),
            "result": _json_safe(result or {}),
            "summary": f"completed {intent_id}",
        }
        self._emit("intent.completed", payload)
        return intent

    def fail(self, intent_id: str, reason: str, *, retryable: bool = True) -> dict:
        intent = self.graph.fail(intent_id, reason, retryable=retryable,
                                 now=float(self._clock()),
                                 backoff_seconds=self.retry_backoff)
        self.status.failed += 1
        payload = {
            "intent": intent_id, "reason": str(reason), "retryable": bool(retryable),
            "attempts": intent.get("attempts", 0),
            "next_attempt_at": intent.get("next_attempt_at", 0),
            "status": intent.get("status"),
            "summary": f"failed {intent_id}: {reason}",
        }
        self._emit("intent.failed", payload)
        if intent.get("status") == "failed":
            self.status.dead_letter.append({"intent": intent_id, "reason": str(reason)})
            self._emit("intent.dead_letter", {
                "intent": intent_id, "reason": str(reason),
                "summary": f"dead letter {intent_id}",
            })
        return intent

    def block(self, intent_id: str, reason: str) -> dict:
        intent = self.graph.block(intent_id, reason)
        self.status.blocked += 1
        self._emit("intent.blocked", {"intent": intent_id, "reason": str(reason),
                                      "summary": f"blocked {intent_id}"})
        return intent

    # ------------------------------------------------------------ budget
    def _trip_budget(self, exc: BudgetExceeded) -> None:
        self._tripped = True
        self.status.budget_trips += 1
        self._emit("budget.exceeded", {
            "kind": exc.kind, "spent": exc.spent, "limit": exc.limit,
            "summary": f"budget {exc.kind} exceeded ({exc.spent}/{exc.limit})",
        })

    @property
    def tripped(self) -> bool:
        return self._tripped

    def budget_view(self) -> dict:
        return self.budget.to_dict()

    def state(self) -> dict:
        return {"status": self.status.as_dict(), "budget": self.budget_view(),
                "graph": self.graph.summary(memory=self.memory)}


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)
