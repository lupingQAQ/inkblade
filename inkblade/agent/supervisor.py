# -*- coding: utf-8 -*-
"""Supervisor: plans graph deltas, leases intents, dispatches role workers.

The supervisor never executes a probe.  It asks the planner for graph changes,
the scheduler picks the frontier, and a role worker executes the probe task.
Every transition is an event in :mod:`inkblade.agent.runtime`, so the run can be
resumed, replayed or inspected without re-execution.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from ..tpl.probe import ProbeUnavailable
from .graph import PlanGraph
from .memory import AgentMemory
from .objectives import Objective, get_objective, objective_keys
from .observer import apply_observation, evidence_digest
from .planner import (DeterministicPlanner, LLMPlanner, LLMRequired, Planner,
                      PlannerError, build_planner)
from .policy import AgentAuthorization, Guard, PolicyError, preflight
from .probes import ProbeSession, build_probe_session
from .runtime import AgentRuntime, Budget, BudgetExceeded, StopRequested
from .scheduler import TaskScheduler
from .skills import SkillLibrary
from .workers import WorkerPool, build_worker_pool


class SupervisorError(RuntimeError):
    """Invalid supervisor operation."""


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


class AgentSupervisor:
    def __init__(self, *, runtime: AgentRuntime, graph: PlanGraph, scheduler: TaskScheduler,
                 planner: Planner, workers: WorkerPool, objective: Objective,
                 memory: AgentMemory, skills: SkillLibrary, guard: Guard,
                 probe: ProbeSession, max_workers: int = 1, max_rounds: int = 64,
                 dry_run: bool = False, approval: str = "auto",
                 propose_skills: bool = False):
        self.runtime = runtime
        self.graph = graph
        self.scheduler = scheduler
        self.planner = planner
        self.workers = workers
        self.objective = objective
        self.memory = memory
        self.skills = skills
        self.guard = guard
        self.probe = probe
        self.max_workers = max(1, min(8, int(max_workers)))
        self.max_rounds = max(1, int(max_rounds))
        self.dry_run = bool(dry_run)
        self.approval = str(approval)
        self.propose_skills = bool(propose_skills)
        self._lock = threading.RLock()
        self._planner_stop = ""
        self._stop_reason = ""
        self._budget_stop = ""
        self._rounds = 0
        self.last_result: dict | None = None

    # ------------------------------------------------------------ constructors
    @classmethod
    def create(cls, store, session, *, objective: str = "cluster-takeover",
               probe_id: str = "", llm: Any = "", budgets: dict | None = None,
               mode: str = "graph-swarm", modules_dir: str | Path | None = None,
               allow_destructive: bool = False, approval: str = "auto",
               start_token: str = "", confirm: bool = False, dry_run: bool = False,
               workers: int = 1, max_rounds: int = 64,
               probe_spec: dict | None = None, allow_reference: bool | None = None,
               workdir: str | Path | None = None, k8s=None,
               module_map: dict[str, str] | None = None,
               param_map: dict[str, dict] | None = None,
               planner: Planner | None = None, manual_approved: bool = False,
               run_id: str | None = None, fsync: bool = True,
               propose_skills: bool = False) -> "AgentSupervisor":
        if mode not in ("graph-swarm", "supervisor", "deterministic"):
            raise SupervisorError(f"未知 mode: {mode!r}")
        obj = get_objective(objective)
        modules_dir = Path(modules_dir) if modules_dir else Path(store.root) / "modules"
        # No probe → refuse before creating a run (no host fallback).
        probe = build_probe_session(store, session, probe_id, spec=probe_spec,
                                    allow_reference=allow_reference, workdir=workdir,
                                    k8s=k8s)
        if mode != "deterministic" and (planner is None and not str(llm or "").strip()):
            raise LLMRequired("agent 模式需要 --llm；确定性模式请显式 --mode deterministic")
        auth = preflight(store, session, objective=objective, mode=mode,
                         allow_destructive=allow_destructive, budgets=budgets,
                         start_token=start_token, confirm=confirm, approval=approval)
        effective_budgets = dict(budgets or {})
        runtime = AgentRuntime.create(
            store, objective=objective, mode=mode, probe_id=probe_id, llm=str(llm),
            budgets=effective_budgets, authorization=auth.to_dict(),
            run_id=run_id, fsync=fsync, objective_meta=obj.as_dict())
        meta = {
            "modules_dir": str(modules_dir), "allow_destructive": bool(allow_destructive),
            "approval": approval, "workers": int(workers), "max_rounds": int(max_rounds),
            "dry_run": bool(dry_run), "module_map": dict(module_map or {}),
            "param_map": dict(param_map or {}), "propose_skills": bool(propose_skills),
            "manual_approved": bool(manual_approved),
        }
        runtime.meta.update(meta)
        (Path(runtime.dir) / "run.json").write_text(
            json.dumps(runtime.meta, ensure_ascii=False, indent=2), encoding="utf-8")
        graph = PlanGraph(objective=objective)
        budget = Budget(tokens=effective_budgets.get("tokens", 0),
                        steps=effective_budgets.get("steps", 0),
                        actions=effective_budgets.get("actions", 0),
                        duration_ms=effective_budgets.get("duration_ms", 0))
        scheduler = TaskScheduler(graph, budget, runtime, mode=mode,
                                  memory=AgentMemory(store), policy=None,
                                  lease_seconds=60.0, retry_backoff=0.0)
        guard = Guard(store, session, auth, approval=approval,
                      manual_approved=manual_approved, modules_dir=modules_dir,
                      objective=obj)
        scheduler.policy = guard
        if scheduler.defense_gate is None:
            from ..core.defense_policy import DefenseGate

            scheduler.defense_gate = DefenseGate()
        memory = AgentMemory(store)
        scheduler.memory = memory
        memory.working.add(f"objective={objective}; mode={mode}; "
                           f"RoE={auth.roe_level}; allow_destructive={allow_destructive}",
                           kind="goal", ref=runtime.run_id)
        graph.add_hint(obj.goal, source="objective", priority=9,
                       created_by="system")
        for hint in graph.hints():
            runtime.emit("graph.hint.added", {"hint": hint,
                                               "summary": f"hint: {hint['text'][:80]}"})
        built_planner = planner or build_planner(
            llm if llm not in (None, "") else "deterministic", store, objective=obj,
            module_map=module_map, param_map=param_map)
        if mode == "deterministic" and not isinstance(built_planner, DeterministicPlanner):
            built_planner = DeterministicPlanner(obj, module_map=module_map,
                                                 param_map=param_map)
        pool = build_worker_pool(store=store, session=probe, modules_dir=modules_dir,
                                 runtime=runtime, graph=graph, objective=obj)
        supervisor = cls(runtime=runtime, graph=graph, scheduler=scheduler,
                         planner=built_planner, workers=pool, objective=obj,
                         memory=memory, skills=SkillLibrary(store), guard=guard,
                         probe=probe, max_workers=workers, max_rounds=max_rounds,
                         dry_run=dry_run, approval=approval,
                         propose_skills=propose_skills)
        return supervisor

    @classmethod
    def load(cls, store, run_id: str | None = None, *, session, llm: Any = None,
             probe_id: str | None = None, modules_dir: str | Path | None = None,
             mode: str | None = None, planner: Planner | None = None,
             allow_reference: bool | None = None, probe_spec: dict | None = None,
             workdir: str | Path | None = None, k8s=None,
             manual_approved: bool = False, max_rounds: int | None = None,
             workers: int | None = None) -> "AgentSupervisor":
        runtime = AgentRuntime.load(store, run_id)
        meta = runtime.meta
        from .policy import AuthorizationRequired, verify_authorization
        from ..core import roe as _roe

        auth_doc = meta.get("authorization") or {}
        if not verify_authorization(store, auth_doc):
            raise AuthorizationRequired("run 授权签名缺失/被篡改，拒绝 resume")
        if _roe.roe_status(store) != "complete":
            raise AuthorizationRequired("RoE 未签署/验签失败，拒绝 resume")
        ok_window, window_reason = _roe.window_status(
            (store.consent() or {}).get("fields") or {})
        if not ok_window:
            raise AuthorizationRequired(f"授权时间窗外：{window_reason}")
        if bool(auth_doc.get("allow_destructive")) and \
                str(auth_doc.get("roe_level")) != "全影响演示":
            raise AuthorizationRequired("resume 的写权限与 RoE 级别不一致")
        obj = get_objective(str(meta.get("objective") or "cluster-takeover"))
        pid = str(probe_id if probe_id is not None else meta.get("probe") or "")
        probe = build_probe_session(store, session, pid, spec=probe_spec,
                                    allow_reference=allow_reference, workdir=workdir,
                                    k8s=k8s)
        graph, budget = _replay_state(runtime, obj)
        run_mode = str(mode or meta.get("mode") or "graph-swarm")
        scheduler = TaskScheduler(graph, budget, runtime, mode=run_mode,
                                  memory=AgentMemory(store), policy=None,
                                  lease_seconds=60.0, retry_backoff=0.0)
        auth = AgentAuthorization.from_dict(meta.get("authorization") or {})
        guard = Guard(store, session, auth, approval=str(meta.get("approval") or "auto"),
                      manual_approved=bool(manual_approved or meta.get("manual_approved")),
                      modules_dir=modules_dir or meta.get("modules_dir") or
                      Path(store.root) / "modules", objective=obj)
        scheduler.policy = guard
        if scheduler.defense_gate is None:
            from ..core.defense_policy import DefenseGate

            scheduler.defense_gate = DefenseGate()
        memory = AgentMemory(store)
        scheduler.memory = memory
        if planner is None:
            llm_value = llm if llm is not None else meta.get("llm")
            if run_mode == "deterministic":
                planner = DeterministicPlanner(
                    obj, module_map=meta.get("module_map") or {},
                    param_map=meta.get("param_map") or {})
            else:
                planner = build_planner(llm_value, store, objective=obj,
                                        module_map=meta.get("module_map") or {},
                                        param_map=meta.get("param_map") or {})
        pool = build_worker_pool(store=store, session=probe,
                                 modules_dir=modules_dir or meta.get("modules_dir") or
                                 Path(store.root) / "modules",
                                 runtime=runtime, graph=graph, objective=obj)
        return cls(runtime=runtime, graph=graph, scheduler=scheduler,
                   planner=planner, workers=pool, objective=obj, memory=memory,
                   skills=SkillLibrary(store), guard=guard, probe=probe,
                   max_workers=int(workers if workers is not None else
                                   (meta.get("workers") or 1)),
                   max_rounds=int(max_rounds if max_rounds is not None else 64),
                   dry_run=bool(meta.get("dry_run")),
                   approval=str(meta.get("approval") or "auto"),
                   propose_skills=bool(meta.get("propose_skills")))

    # ------------------------------------------------------------ state
    def state(self) -> dict:
        evaluation = self.objective.evaluate(self.graph)
        frontier = self.graph.frontier(now=time.time(), memory=self.memory)
        graph_summary = self.graph.summary(memory=self.memory)
        return {
            "objective": self.objective.as_dict(),
            "objective_eval": evaluation,
            "mode": self.scheduler.mode,
            "graph": graph_summary,
            "graph_obj": self.graph,
            "frontier": [
                {"id": i["id"], "role": i["role"], "module": i["module"],
                 "priority": i["priority"], "cost_tokens": i["cost_tokens"],
                 "writes": bool(i["writes"]), "cleanup": bool(i["cleanup"]),
                 "expected_evidence": i.get("expected_evidence") or [],
                 "rationale": i.get("rationale", "")}
                for i in frontier
            ],
            "facts": [f for f in self.graph.facts()],
            "hints": self.graph.hints(),
            "budget": {**self.scheduler.budget.to_dict(),
                       "remaining": {k: self.scheduler.budget.remaining(k)
                                     for k in ("tokens", "steps", "actions", "duration_ms")}},
            "memory": self.memory.context(self.objective.goal, k=3),
            "skills": self.skills.search(self.objective.key, k=3),
            "attempts": sum(int(i.get("attempts", 0)) for i in self.graph.intents()),
            "last_failure": next((i.get("last_error") for i in self.graph.intents()
                                  if i.get("last_error")), ""),
        }

    # ------------------------------------------------------------ planning
    def _plan(self) -> bool:
        """Ask the planner for graph deltas; return True if anything new was added."""
        before = {i["id"] for i in self.graph.intents()}
        try:
            decision = self.planner.propose(self.state())
        except Exception as exc:  # planner failure is recorded; no probe is run
            self.runtime.emit("llm.degraded", {
                "reason": f"{type(exc).__name__}: {exc}",
                "summary": f"planner failed: {exc}",
            })
            if isinstance(self.planner, LLMPlanner) and self.planner.fallback is not None:
                self.planner = self.planner.fallback
                decision = self.planner.propose(self.state())
            else:
                raise
        tokens = int(decision.get("tokens") or 0)
        if tokens:
            try:
                self.scheduler.budget.consume("tokens", tokens)
                self.runtime.emit("budget.spent", {
                    "kind": "tokens", "amount": tokens,
                    "total": self.scheduler.budget.spent.get("tokens", 0),
                    "limit": self.scheduler.budget.limits.get("tokens", 0),
                    "summary": f"tokens {self.scheduler.budget.spent.get('tokens', 0)}/"
                               f"{self.scheduler.budget.limits.get('tokens', 0) or '∞'}",
                })
            except BudgetExceeded as exc:
                self._budget_stop = str(exc)
                self.scheduler._trip_budget(exc)
                return False
        if decision.get("degraded"):
            self.runtime.emit("llm.degraded", {
                "reason": decision.get("degrade_reason", ""),
                "source": decision.get("source", ""),
                "summary": "planner degraded to deterministic fallback",
            })
        payload = {
            "decision": decision.get("decision"), "rationale": decision.get("rationale"),
            "source": decision.get("source"), "tokens": tokens,
            "degraded": bool(decision.get("degraded")),
            "intents": [{k: _json_safe(v) for k, v in i.items() if k != "params"}
                        for i in decision.get("intents") or []],
            "facts": _json_safe(decision.get("facts") or []),
            "summary": f"plan: {decision.get('decision')} — "
                       f"{str(decision.get('rationale') or '')[:180]}",
        }
        self.runtime.emit("plan.proposed", payload)
        self.runtime.emit("decision.made", {
            "kind": "plan", "chosen": decision.get("decision"),
            "rationale": decision.get("rationale"),
            "options": [i.get("module") for i in decision.get("intents") or []],
            "evidence": [], "summary": "planner decision recorded",
        })
        if decision.get("decision") == "stop":
            self._planner_stop = str(decision.get("rationale") or "planner stop")
            return False
        changed = False
        for fact in decision.get("facts") or []:
            if fact.get("status", "hypothesis") != "hypothesis":
                continue
            try:
                node = self.graph.add_fact(
                    fact.get("claim", ""), status="hypothesis", kind=fact.get("fact_kind", "hypothesis"),
                    severity=fact.get("severity", "info"), attrs=fact.get("attrs") or {})
                self.runtime.emit("graph.fact.added", {"fact": node,
                                                        "summary": f"hypothesis: {node['claim']}"})
                changed = True
            except Exception as exc:  # noqa: BLE001
                self.runtime.emit("plan.rejected", {"reason": str(exc),
                                                    "summary": "invalid hypothesis"})
        hint = decision.get("hint")
        if isinstance(hint, dict) and hint.get("text"):
            try:
                node = self.graph.add_hint(str(hint["text"]), source="llm",
                                           priority=int(hint.get("priority", 5)),
                                           created_by="planner")
                self.runtime.emit("graph.hint.added", {"hint": node,
                                                        "summary": f"hint: {node['text'][:80]}"})
                changed = True
            except Exception:  # noqa: BLE001
                pass
        existing = {(i.get("role"), i.get("module")) for i in self.graph.intents()}
        for item in decision.get("intents") or []:
            role = str(item.get("role") or "")
            module = str(item.get("module") or "")
            if role == "report" and module in ("report", "agent-report"):
                module = "agent-report"
            if (role, module) in existing:
                continue
            requires = [r for r in (item.get("requires") or []) if r in
                        {n["id"] for n in self.graph.to_dict()["nodes"]}]
            try:
                node = self.graph.add_intent(
                    role, module, item.get("params") or {},
                    priority=int(item.get("priority", 5)),
                    cost_tokens=int(item.get("cost_tokens", 100)),
                    requires=requires, produces=item.get("produces") or [],
                    success=item.get("success", ""), writes=bool(item.get("writes")),
                    cleanup=bool(item.get("cleanup")),
                    max_attempts=int(item.get("max_attempts", 2)),
                    rationale=str(item.get("rationale") or decision.get("rationale") or ""),
                    expected_evidence=item.get("expected_evidence") or [],
                    probe=bool(item.get("probe", role != "report")),
                    tags=item.get("tags") or [])
            except Exception as exc:  # noqa: BLE001
                self.runtime.emit("plan.rejected", {"module": module,
                                                    "reason": str(exc),
                                                    "summary": f"rejected intent {module}"})
                continue
            self.runtime.emit("graph.intent.added", {"intent": node,
                                                     "summary": f"intent {node['id']} "
                                                                f"{role}/{module}"})
            existing.add((role, module))
            changed = True
        after = {i["id"] for i in self.graph.intents()}
        return changed or bool(after - before)

    # ------------------------------------------------------------ execution
    def _retryable(self, error: str) -> bool:
        low = str(error or "").lower()
        permanent = ("backup", "scope", "manual", "read-only", "unknown", "未注册",
                     "probe-unavailable", "no probe", "没有 probe", "approval")
        return not any(word in low for word in permanent)

    def _apply_result(self, intent: dict, result) -> None:
        iid = str(intent.get("id") or "")
        if result.ok and result.observation is not None:
            observation = result.observation
            applied = apply_observation(self.graph, observation)
            for eid in applied["evidence"]:
                node = self.graph.node(eid)
                self.runtime.emit("graph.evidence.added", {
                    "evidence": node, "summary": f"evidence {node['id']} "
                                                 f"sha256={node['sha256'][:12]}"})
            for fid in applied["facts"]:
                node = self.graph.node(fid)
                self.runtime.emit("graph.fact.added", {
                    "fact": node, "summary": f"{node['status']} fact: {node['claim'][:90]}"})
            self.runtime.emit("observation", {
                "intent": iid, "observation": observation.to_dict(),
                "digest": evidence_digest(observation),
                "summary": observation.summary,
            })
            try:
                self.scheduler.complete(iid, evidence=applied["evidence"],
                                        result=result.output)
            except Exception as exc:  # noqa: BLE001
                self.scheduler.fail(iid, f"complete failed: {exc}", retryable=False)
                self.runtime.emit("observation.failed", {
                    "intent": iid, "reason": str(exc), "summary": "evidence gate rejected"})
            self.memory.working.add(observation.summary, kind="observation", ref=iid)
        elif result.ok:
            try:
                self.scheduler.complete(iid, evidence=[], result=result.output)
                if result.output.get("report"):
                    self.runtime.emit("report.written", {
                        "intent": iid, "path": result.output.get("report"),
                        "sha256": result.output.get("sha256", ""),
                        "summary": "report artifact written",
                    })
            except Exception as exc:  # noqa: BLE001
                self.scheduler.fail(iid, f"complete failed: {exc}", retryable=False)
            self.memory.working.add(f"report: {result.output.get('report', '')}",
                                    kind="report", ref=iid)
        else:
            observation = result.observation
            failure = (observation.failures if observation is not None else
                       [{"kind": "worker-error", "reason": result.error}])
            self.runtime.emit("observation.failed", {
                "intent": iid, "failure": _json_safe(failure),
                "summary": result.error or "worker failed",
            })
            retryable = self._retryable(result.error)
            self.scheduler.fail(iid, result.error or "worker failed", retryable=retryable)
            self.memory.working.add(f"failure {intent.get('module')}: {result.error}",
                                    kind="failure", ref=iid)

    def _execute_batch(self) -> int:
        claimed: list[dict] = []
        for _ in range(self.max_workers):
            try:
                intent = self.scheduler.claim_next("worker")
            except BudgetExceeded as exc:
                self._budget_stop = str(exc)
                break
            except StopRequested:
                self._stop_reason = "operator stop"
                break
            if intent is None:
                break
            claimed.append(intent)
        if not claimed:
            return 0
        # Worker execution happens outside the graph lock; only the main thread
        # folds observations and scheduler transitions.
        results = []
        with ThreadPoolExecutor(max_workers=len(claimed)) as pool:
            futures = {}
            for intent in claimed:
                try:
                    worker = self.workers.for_role(str(intent.get("role") or ""))
                    futures[pool.submit(worker.execute, intent)] = intent
                except Exception as exc:  # noqa: BLE001
                    from .workers.base import WorkerResult

                    results.append((intent, WorkerResult(False, intent["id"],
                                                         intent.get("role", ""),
                                                         intent.get("module", ""),
                                                         error=str(exc))))
            for future in as_completed(futures):
                intent = futures[future]
                try:
                    result = future.result()
                except Exception as exc:  # noqa: BLE001
                    from .workers.base import WorkerResult

                    result = WorkerResult(False, intent["id"], intent.get("role", ""),
                                          intent.get("module", ""), error=str(exc))
                results.append((intent, result))
        for intent, result in results:
            self._apply_result(intent, result)
        self._rounds += 1
        self.runtime.checkpoint("after-batch", {
            "graph": self.graph.to_dict(), "budget": self.scheduler.budget.to_dict(),
            "status": self.scheduler.status.as_dict(),
        })
        return len(claimed)

    # ------------------------------------------------------------ finalize
    def _status(self, *, forced: str = "") -> str:
        if forced:
            return forced
        if self.runtime.is_stopped() or self._stop_reason:
            return "stopped"
        if self._budget_stop:
            return "budget-exceeded"
        if self.objective.success(self.graph):
            return "success"
        if self.scheduler.status.refused and not self.scheduler.status.completed:
            return "policy-refused"
        return "failed"

    def _finalize(self, *, status: str = "", reason: str = "") -> dict:
        status = self._status(forced=status)
        evaluation = self.objective.evaluate(self.graph)
        reflection = self.memory.reflect(self.runtime, self.graph, self.objective)
        draft_skill = None
        if status == "success" and self.propose_skills:
            try:
                draft = self.skills.propose_from_graph(self.graph, objective=self.objective.key)
                draft_skill = self.skills.submit(self.guard.session, draft)
            except Exception as exc:  # noqa: BLE001
                draft_skill = {"error": str(exc)}
        metrics = {
            "success": status == "success",
            "status": status,
            "steps": max(self.scheduler.status.claimed,
                         sum(1 for e in self.runtime.events()
                             if e["kind"] == "intent.claimed")),
            "tokens": int(self.scheduler.budget.spent.get("tokens", 0)),
            "actions": int(self.scheduler.budget.spent.get("actions", 0)),
            "probe_calls": self.probe.call_count(),
            "interventions": sum(1 for e in self.runtime.trace()
                                 if e["kind"] == "approval.required"),
            "evidence_coverage": evaluation.get("summary", {}).get(
                "evidence_coverage", self.graph.evidence_coverage()),
            "duration_ms": self.scheduler.budget.elapsed_ms(),
            "intents": len(self.graph.intents()),
            "intents_done": len(self.graph.intents(status="done")),
            "intents_failed": len(self.graph.intents(status="failed")),
            "facts_confirmed": len(self.graph.confirmed_facts()),
            "events": len(self.runtime.events()),
        }
        summary = {
            "schema": "inkblade-agent-summary/1",
            "run_id": self.runtime.run_id, "objective": self.objective.key,
            "mode": self.scheduler.mode, "status": status,
            "success": status == "success", "reason": reason,
            "metrics": metrics, "objective_eval": evaluation,
            "graph": self.graph.summary(memory=self.memory),
            "budget": self.scheduler.budget.to_dict(),
            "scheduler": self.scheduler.status.as_dict(),
            "reflection": reflection, "draft_skill": draft_skill,
            "trace": str(self.runtime.log.path),
            "report": str(Path(self.runtime.dir) / "report.md")
            if (Path(self.runtime.dir) / "report.md").is_file() else "",
        }
        summary_path = Path(self.runtime.dir) / "summary.json"
        summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2,
                                           default=str), encoding="utf-8")
        summary["summary_path"] = str(summary_path)
        if status == "stopped" and not any(
                e.get("kind") == "run.stopped" for e in self.runtime.log.events(strict=False)):
            self.runtime.request_stop(reason or "stopped", actor="supervisor")
        if status == "paused":
            self.runtime.emit("run.paused", {
                "status": status, "reason": reason, "metrics": metrics,
                "summary": f"run paused: {reason}",
            }, actor="supervisor")
        else:
            self.runtime.emit("run.completed", {
                "status": status, "success": status == "success",
                "reason": reason, "metrics": metrics,
                "summary": f"run {status}: {metrics['steps']} step(s), "
                           f"{metrics['tokens']} token(s), evidence "
                           f"{metrics['evidence_coverage']:.2f}",
            }, actor="supervisor")
        self.runtime.checkpoint("final", {
            "graph": self.graph.to_dict(), "budget": self.scheduler.budget.to_dict(),
            "status": self.scheduler.status.as_dict(), "summary": summary,
        })
        self.last_result = summary
        return summary

    # ------------------------------------------------------------ run
    def run(self, *, resume: bool = False) -> dict:
        if self.dry_run:
            try:
                self._plan()
            except Exception as exc:  # noqa: BLE001
                return self._finalize(status="failed",
                                      reason=f"planner failed: {exc}")
            return self._finalize(status="dry-run",
                                  reason="dry-run: plan only, no probe executed")
        if resume:
            self.runtime.emit("run.resumed", {
                "from_seq": self.runtime.log.replay()["last_seq"],
                "summary": "run resumed from durable journal",
            }, actor="supervisor")
            # A claimed-but-unfinished intent is an interrupted step, not a
            # live lease.  Requeue it before planning the frontier.
            self.graph.reclaim_expired(now=time.time() + 10 ** 9)
        try:
            while self._rounds < self.max_rounds:
                if self.runtime.is_stopped():
                    self._stop_reason = "operator stop"
                    break
                try:
                    self.scheduler.budget.check()
                except BudgetExceeded as exc:
                    self._budget_stop = str(exc)
                    self.scheduler._trip_budget(exc)
                    break
                if self.objective.success(self.graph):
                    break
                frontier = self.graph.frontier(now=time.time(), memory=self.memory)
                if not frontier:
                    try:
                        changed = self._plan()
                    except Exception as exc:  # noqa: BLE001
                        self._planner_stop = f"planner failed: {exc}"
                        break
                    frontier = self.graph.frontier(now=time.time(), memory=self.memory)
                    if not frontier:
                        if self._planner_stop or not changed:
                            break
                        continue
                executed = self._execute_batch()
                if executed == 0:
                    # policy blocked the whole frontier or budget tripped
                    if self._budget_stop or self.scheduler.status.refused:
                        break
                    if not self.graph.frontier(now=time.time(), memory=self.memory):
                        try:
                            changed = self._plan()
                        except Exception as exc:  # noqa: BLE001
                            self._planner_stop = f"planner failed: {exc}"
                            break
                        if not changed:
                            break
            if self.objective.success(self.graph):
                return self._finalize(status="success")
            if self._stop_reason:
                return self._finalize(status="stopped", reason=self._stop_reason)
            if self._budget_stop:
                return self._finalize(status="budget-exceeded", reason=self._budget_stop)
            if self._rounds >= self.max_rounds:
                return self._finalize(status="paused",
                                      reason="max rounds reached; resumable")
            if self.scheduler.status.refused:
                return self._finalize(status="policy-refused",
                                      reason="policy refused the frontier")
            return self._finalize(status="failed",
                                  reason=self._planner_stop or "objective not satisfied")
        except StopRequested as exc:
            self._stop_reason = str(exc)
            return self._finalize(status="stopped", reason=str(exc))

    # ------------------------------------------------------------ views
    @classmethod
    def status(cls, store, run_id: str | None = None) -> dict:
        runtime = AgentRuntime.load(store, run_id)
        meta = runtime.meta
        obj = get_objective(str(meta.get("objective") or "cluster-takeover"))
        graph, budget = _replay_state(runtime, obj)
        evaluation = obj.evaluate(graph)
        summary = {}
        path = Path(runtime.dir) / "summary.json"
        if path.is_file():
            try:
                summary = json.loads(path.read_text(encoding="utf-8"))
            except ValueError:
                summary = {}
        return {
            "schema": "inkblade-agent-status/1",
            "run_id": runtime.run_id, "objective": obj.key,
            "mode": meta.get("mode", ""), "probe": meta.get("probe", ""),
            "llm": meta.get("llm", ""), "journal": runtime.log.verify(),
            "stopped": runtime.is_stopped(), "events": runtime.log.replay()["events"],
            "graph": graph.summary(), "objective_eval": evaluation,
            "budget": budget.to_dict(), "summary": summary,
            "trace": runtime.trace(limit=20),
        }

    @classmethod
    def replay(cls, store, run_id: str | None = None, *, to_seq: int | None = None) -> dict:
        runtime = AgentRuntime.load(store, run_id)
        meta = runtime.meta
        obj = get_objective(str(meta.get("objective") or "cluster-takeover"))
        graph, budget = _replay_state(runtime, obj, to_seq=to_seq)
        return {
            "schema": "inkblade-agent-replay/1",
            "run_id": runtime.run_id, "to_seq": to_seq,
            "journal": runtime.log.verify(),
            "events": runtime.log.replay(to_seq=to_seq),
            "graph": graph.summary(), "graph_state": graph.to_dict(),
            "objective_eval": obj.evaluate(graph), "budget": budget.to_dict(),
            "trace": runtime.trace(limit=None),
        }

    @classmethod
    def stop(cls, store, run_id: str | None = None, *, reason: str = "") -> dict:
        runtime = AgentRuntime.load(store, run_id)
        runtime.request_stop(reason or "operator stop", actor="cli")
        return runtime.status()


def _replay_state(runtime: AgentRuntime, objective: Objective,
                  to_seq: int | None = None) -> tuple[PlanGraph, Budget]:
    checkpoint = runtime.log.latest_checkpoint()
    graph = PlanGraph(objective=objective.key)
    start_seq = 0
    if checkpoint and (to_seq is None or int(checkpoint["seq"]) <= int(to_seq)):
        data = checkpoint.get("data") or {}
        if data.get("graph"):
            graph = PlanGraph.from_dict(data["graph"])
        start_seq = int(checkpoint["seq"])
    events = runtime.log.verified_events()
    for event in events:
        if int(event["seq"]) <= start_seq:
            continue
        if to_seq is not None and int(event["seq"]) > int(to_seq):
            break
        graph.apply_event(event)
    limits = dict(runtime.meta.get("budgets") or {})
    if checkpoint and (to_seq is None or int(checkpoint["seq"]) <= int(to_seq)):
        bdata = (checkpoint.get("data") or {}).get("budget")
        if bdata:
            budget = Budget.from_dict(bdata)
        else:
            budget = Budget.from_events(events, limits=limits)
    else:
        budget = Budget.from_events(events, limits=limits)
    return graph, budget


def run_agent(store, session, **kwargs) -> dict:
    supervisor = AgentSupervisor.create(store, session, **kwargs)
    return supervisor.run()


def resume_agent(store, session, run_id: str | None = None, **kwargs) -> dict:
    supervisor = AgentSupervisor.load(store, run_id, session=session, **kwargs)
    return supervisor.run(resume=True)
