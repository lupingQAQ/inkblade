# -*- coding: utf-8 -*-
"""core/autonomy.py — L3 自主执行护栏：lead 预授权 + 白名单 + 预算硬顶 + 异常即停 + 全审计。

定位（对比 ARTEX 的 intercept 人工审批，见 docs/AUTONOMY.md）：
- **L0/L1** 人工逐步审批（现状 explorer）；**L2** 批量审批（一次批准整条提议）；
  **L3** lead 一次性预授权 token + 白名单 + 预算，之后由循环自动 propose→approve→execute，
  但每个动作仍逐条走 ``core.runner`` 的授权闸门/备份闸门/三层落证。
- L3 不是「模型自由行动」：预授权是**授权前置**（RoE 必须为「全影响演示」+ lead token），
  白名单/预算/异常停止是**运行时硬边界**，不是提示词约束。

落盘：
- ``autonomy/grant.json``：预授权文档（token 只存 sha256 + 工作区 HMAC，明文仅在 grant 时返回一次）；
- ``autonomy/trace.jsonl``：逐步决策 trace（候选/模式/动作/digest），供确定性回放；
- ``audit.jsonl``：grant/preflight/step/stop/denied/fallback 全量审计（参数脱敏）。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from pathlib import Path
from typing import Any, Callable, Iterable

from . import cost, jsonio, roe
from .env import getenv

GRANT_RELPATH = "autonomy/grant.json"
TRACE_RELPATH = "autonomy/trace.jsonl"
AUDIT_ACTOR = "autonomy"

MAX_ACTIONS_LIMIT = 50
MAX_STEPS_LIMIT = 20
ANOMALY_FAILURES = 2

AUTONOMY_LEVELS = {
    "L0": {"name": "manual", "auto_approve": False, "batch": 1,
           "summary": "逐动作人工审批；提议不执行"},
    "L1": {"name": "assisted", "auto_approve": False, "batch": 1,
           "summary": "规则/LLM 辅助排序，仍逐动作人工审批"},
    "L2": {"name": "batch-approval", "auto_approve": False, "batch": 5,
           "summary": "一次批准一批（≤5）动作，执行仍逐步过闸门"},
    "L3": {"name": "preauthorized-autonomy", "auto_approve": True, "batch": 5,
           "summary": "lead 预授权 token + 白名单 + 预算硬顶 + 异常即停；全审计可回放"},
}


class AutonomyError(ValueError):
    """L3 配置/状态非法。"""


class AutonomyRefused(AutonomyError):
    """预检拒绝（授权/级别/token/端点/白名单/预算）。"""


class GuardTrip(AutonomyError):
    """运行中护栏触发（异常即停）。"""

    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


def _now() -> float:
    return time.time()


def _canonical(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _plan_input(actions: Iterable[dict]) -> list[dict]:
    """可回放的决策面：只保留影响执行的字段（预算/审计字段不参与 digest）。"""
    out = []
    for idx, action in enumerate(actions, 1):
        out.append({"seq": int(action.get("seq") or idx),
                    "module": str(action.get("module") or ""),
                    "writes": bool(action.get("writes")),
                    "params": dict(action.get("params") or {})})
    return out


def plan_digest(actions: Iterable[dict]) -> str:
    return hashlib.sha256(_canonical(_plan_input(actions)).encode("utf-8")).hexdigest()


def llm_available(store) -> bool:
    """L3 的 LLM 端点判定：core/llmpool 已启用且有端点，或显式 env 端点。"""
    if getenv("LLM_BASE_URL"):
        return True
    try:
        from .llmpool import pool_available
        return bool(pool_available(store))
    except Exception:
        return False


# ---------------------------------------------------------------- 预授权

class AutonomyGrant:
    """lead 预授权：白名单/写权限/动作数/步数/预算/有效期 + 一次性 token。"""

    def __init__(self, store, doc: dict):
        self.store = store
        self.doc = dict(doc)
        self.path = jsonio.ws_path(store, GRANT_RELPATH)

    # ---------- 字段 ----------
    @property
    def id(self) -> str:
        return str(self.doc.get("id") or "")

    @property
    def status(self) -> str:
        return str(self.doc.get("status") or "active")

    @property
    def allowlist(self) -> list[str]:
        return [str(x) for x in self.doc.get("allowlist") or []]

    @property
    def allow_writes(self) -> bool:
        return bool(self.doc.get("allow_writes"))

    @property
    def max_actions(self) -> int:
        return int(self.doc.get("max_actions") or 0)

    @property
    def max_steps(self) -> int:
        return int(self.doc.get("max_steps") or 0)

    @property
    def budget(self) -> dict:
        return dict(self.doc.get("budget") or {})

    @property
    def granted_by(self) -> str:
        return str(self.doc.get("granted_by") or "")

    @property
    def expires_at(self) -> float:
        return float(self.doc.get("expires_at") or 0)

    @property
    def token_hint(self) -> str:
        return str(self.doc.get("token_sha256") or "")[:12]

    def verify_token(self, token: str) -> bool:
        want = str(self.doc.get("token_sha256") or "")
        got = hashlib.sha256(str(token or "").encode("utf-8")).hexdigest()
        return bool(want) and hmac.compare_digest(want, got)

    def public_doc(self) -> dict:
        """对外视图：不含 token sha 与 HMAC（只留可引用的前 12 位提示）。"""
        return {k: v for k, v in self.doc.items()
                if k not in ("token_sha256", "hmac")} | {"token_hint": self.token_hint}

    # ---------- 生命周期 ----------
    @staticmethod
    def _validate(*, allowlist, max_actions, max_steps, budget) -> None:
        if not allowlist:
            raise AutonomyRefused("白名单不能为空（L3 只执行显式列出的模块）")
        if not (1 <= int(max_actions) <= MAX_ACTIONS_LIMIT):
            raise AutonomyRefused(f"max_actions 须在 1-{MAX_ACTIONS_LIMIT}")
        if not (1 <= int(max_steps) <= MAX_STEPS_LIMIT):
            raise AutonomyRefused(f"max_steps 须在 1-{MAX_STEPS_LIMIT}")
        for key in ("tokens", "latency_ms", "approvals", "interventions"):
            if int((budget or {}).get(key, 0)) <= 0:
                raise AutonomyRefused(f"预算 {key} 必须为正（硬顶不接受 0/负数）")

    @classmethod
    def create(cls, store, session, *, allowlist: Iterable[str],
               max_actions: int = 5, max_steps: int = 3,
               budget: dict | None = None, allow_writes: bool = False,
               ttl_seconds: int = 1800, note: str = "") -> tuple["AutonomyGrant", str]:
        """lead 签发预授权；返回 (grant, token)。token 明文只在此刻可见。"""
        if not session.can("approve"):
            raise PermissionError(f"{session.name}({session.role}) 无 approve 权限（须 lead/admin）")
        modules = [str(m).strip() for m in allowlist if str(m).strip()]
        budget = dict(budget or {"tokens": 20000, "latency_ms": 120000,
                                 "approvals": 6, "interventions": 2})
        cls._validate(allowlist=modules, max_actions=max_actions, max_steps=max_steps,
                      budget=budget)
        if int(ttl_seconds) < 1:
            raise AutonomyRefused("ttl_seconds 须 ≥1")
        token = secrets.token_hex(16)
        now = _now()
        doc = {
            "schema": "inkblade-autonomy-grant/1",
            "id": f"grant-{time.strftime('%Y%m%d-%H%M%S', time.gmtime(now))}-{secrets.token_hex(3)}",
            "status": "active",
            "allowlist": modules,
            "allow_writes": bool(allow_writes),
            "max_actions": int(max_actions),
            "max_steps": int(max_steps),
            "budget": budget,
            "granted_by": session.name,
            "granted_at": now,
            "expires_at": now + int(ttl_seconds),
            "note": str(note),
            "token_sha256": hashlib.sha256(token.encode("utf-8")).hexdigest(),
        }
        doc["hmac"] = roe.signature(doc, roe.workspace_key(store))
        grant = cls(store, doc)
        jsonio.write_json(grant.path, doc)
        jsonio.append_audit(store, session.name, "autonomy.grant", grant.id,
                            {"allowlist": modules, "max_actions": max_actions,
                             "max_steps": max_steps, "budget": budget,
                             "allow_writes": bool(allow_writes),
                             "expires_at": doc["expires_at"], "note": note}, "ok")
        return grant, token

    @classmethod
    def load(cls, store, *, clock: Callable[[], float] | None = None) -> "AutonomyGrant":
        path = jsonio.ws_path(store, GRANT_RELPATH)
        doc = jsonio.read_json(path, None)
        if not isinstance(doc, dict):
            raise AutonomyRefused("缺少 lead 预授权 grant（先 inkblade autonomy grant）")
        body = {k: v for k, v in doc.items() if k != "hmac"}
        expect = roe.signature(body, roe.workspace_key(store))
        if not hmac.compare_digest(str(doc.get("hmac") or ""), expect):
            raise AutonomyRefused("预授权 grant 验签失败（被篡改）")
        if str(doc.get("status") or "") != "active":
            raise AutonomyRefused("预授权 grant 已撤销/非 active")
        return cls(store, doc)

    @classmethod
    def revoke(cls, store, session, *, reason: str = "") -> dict:
        if not session.can("approve"):
            raise PermissionError(f"{session.name}({session.role}) 无 approve 权限")
        grant = cls.load(store)
        grant.doc["status"] = "revoked"
        grant.doc["revoked_by"] = session.name
        grant.doc["revoked_at"] = _now()
        grant.doc["revoke_reason"] = str(reason)
        grant.doc["hmac"] = roe.signature(
            {k: v for k, v in grant.doc.items() if k != "hmac"}, roe.workspace_key(store))
        jsonio.write_json(grant.path, grant.doc)
        jsonio.append_audit(store, session.name, "autonomy.revoke", grant.id,
                            {"reason": reason}, "ok")
        return grant.public_doc()


# ---------------------------------------------------------------- 运行时护栏

class AutonomyGuard:
    """预检 + 逐动作硬边界 + 预算记账 + 审计/trace。"""

    def __init__(self, store, grant: AutonomyGrant, *, budget: cost.Budget | None = None,
                 llm_required: bool = False, anomaly_limit: int = ANOMALY_FAILURES,
                 clock: Callable[[], float] | None = None):
        self.store = store
        self.grant = grant
        self.llm_required = bool(llm_required)
        self.anomaly_limit = max(1, int(anomaly_limit))
        self._clock = clock or _now
        limits = grant.budget
        self.budget = budget or cost.Budget(
            tokens=int(limits.get("tokens", 20000)),
            latency_ms=int(limits.get("latency_ms", 120000)),
            approvals=int(limits.get("approvals", 6)),
            interventions=int(limits.get("interventions", 2)))
        self.started_at = self._clock()
        self.steps = 0
        self.actions = 0
        self.consecutive_failures = 0
        self.stopped: dict | None = None
        self.trace_path = jsonio.ws_path(store, TRACE_RELPATH)
        self._reserved = {"tokens": 0, "latency_ms": 0, "approvals": 0,
                          "interventions": 0}
        self._audit("autonomy.guard.init", grant.id,
                    {"llm_required": self.llm_required, "budget": limits}, "ok")

    # ---------- 预检 ----------
    @classmethod
    def preflight(cls, store, *, token: str, llm_required: bool = False,
                  clock: Callable[[], float] | None = None,
                  budget_overrides: dict | None = None) -> "AutonomyGuard":
        now = (clock or _now)()
        if roe.roe_status(store) != "complete":
            raise AutonomyRefused("工作区授权未签署/验签失败：L3 拒绝执行")
        level = str((store.consent() or {}).get("fields", {}).get("level") or "")
        if level != roe.LEVELS[-1]:
            raise AutonomyRefused(
                f"L3 需 RoE 级别「{roe.LEVELS[-1]}」，当前「{level or '未声明'}」")
        grant = AutonomyGrant.load(store, clock=clock)
        if not str(token or "").strip():
            raise AutonomyRefused("缺少 lead 预授权 token（--preauth-token）")
        if not grant.verify_token(token):
            raise AutonomyRefused("预授权 token 不匹配")
        if now > grant.expires_at:
            raise AutonomyRefused(f"预授权已过期（expires_at={grant.expires_at:.0f}）")
        if llm_required and not llm_available(store):
            raise AutonomyRefused(
                "L3 --llm 需要真实 OpenAI 兼容端点（core/llmpool 已启用且有端点，"
                "或 INKBLADE_LLM_BASE_URL）；无端点拒绝执行，不静默回退")
        budget = cost.Budget(
            tokens=int(grant.budget.get("tokens", 20000)),
            latency_ms=int(grant.budget.get("latency_ms", 120000)),
            approvals=int(grant.budget.get("approvals", 6)),
            interventions=int(grant.budget.get("interventions", 2)))
        overrides = dict(budget_overrides or {})
        if overrides:
            # 只允许收紧，不允许放大预授权硬顶
            budget = cost.Budget(
                tokens=min(budget.tokens, int(overrides.get("tokens", budget.tokens))),
                latency_ms=min(budget.latency_ms,
                               int(overrides.get("latency_ms", budget.latency_ms))),
                approvals=min(budget.approvals,
                              int(overrides.get("approvals", budget.approvals))),
                interventions=min(budget.interventions,
                                  int(overrides.get("interventions", budget.interventions))))
        guard = cls(store, grant, budget=budget, llm_required=llm_required, clock=clock)
        guard._audit("autonomy.preflight", grant.id,
                     {"level": level, "llm_required": llm_required,
                      "budget": budget.status()["limits"]}, "ok")
        return guard

    # ---------- 审计 ----------
    def _audit(self, action: str, target: str, params: dict | None = None,
               result: str = "ok") -> dict:
        return jsonio.append_audit(self.store, AUDIT_ACTOR, action, target,
                                    {**(params or {}), "grant": self.grant.id}, result)

    def _trace(self, row: dict) -> None:
        with Path(self.trace_path).open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True, default=str) + "\n")

    # ---------- 硬边界 ----------
    def check_action(self, action: dict) -> dict:
        """逐动作校验；返回估算成本。任何违反 → GuardTrip（调用方立即停）。"""
        module = str(action.get("module") or "")
        if module not in self.grant.allowlist:
            raise GuardTrip("allowlist", f"模块 {module} 不在预授权白名单")
        if bool(action.get("writes")) and not self.grant.allow_writes:
            raise GuardTrip("write-not-granted", f"模块 {module} 为写动作但 grant 未允许写")
        violation = roe.scope_violation(self.store, dict(action.get("params") or {}))
        if violation:
            raise GuardTrip("scope", violation)
        tokens = int(action.get("tokens") or cost.estimate_tokens(
            f"{module} {action.get('params', '')} {action.get('reason', '')}"))
        latency = int(action.get("latency_ms") or max(1, tokens * 3))
        st = self.budget.status()
        for key, need in (("tokens", tokens), ("latency_ms", latency),
                          ("approvals", 1), ("interventions", 0)):
            if key == "interventions" and not need:
                continue
            used = int(self.budget.used[key]) + int(self._reserved[key])
            if used + need > int(getattr(self.budget, key)):
                raise GuardTrip(
                    "budget",
                    f"{key} 硬顶 {getattr(self.budget, key)}，已用 {used}，下一步需 {need}"
                    f"（{st['state']}）")
        self._reserved["tokens"] += tokens
        self._reserved["latency_ms"] += latency
        self._reserved["approvals"] += 1
        return {"tokens": tokens, "latency_ms": latency, "approvals": 1}

    def record_step(self, actions: list[dict], *, duration_ms: int = 0,
                    failures: int = 0) -> dict:
        """结算一步：reserved → used；更新连续失败计数。"""
        self.steps += 1
        self.actions += len(actions)
        est_tokens = int(self._reserved["tokens"])
        est_latency = int(self._reserved["latency_ms"])
        est_approvals = int(self._reserved["approvals"])
        self.budget.record(tokens=est_tokens,
                           latency_ms=max(est_latency, int(duration_ms or 0)),
                           approvals=est_approvals)
        self._reserved = {"tokens": 0, "latency_ms": 0, "approvals": 0,
                          "interventions": 0}
        if failures >= self.anomaly_limit:
            self.consecutive_failures = failures
        elif failures:
            self.consecutive_failures += failures
        else:
            self.consecutive_failures = 0
        return self.budget.status()

    def should_stop(self) -> GuardTrip | None:
        if self.steps >= self.grant.max_steps:
            return GuardTrip("max-steps", f"已达预授权步数 {self.grant.max_steps}")
        if self.consecutive_failures >= self.anomaly_limit:
            return GuardTrip("anomaly",
                             f"连续失败 {self.consecutive_failures} ≥ {self.anomaly_limit}")
        if self.budget.status()["state"] == "over":
            return GuardTrip("budget", "预算已越硬顶")
        return None

    def stop(self, reason: str, detail: str = "") -> dict:
        if self.stopped is None:
            self.stopped = {"reason": str(reason), "detail": str(detail),
                            "at": self._clock(), "steps": self.steps,
                            "actions": self.actions}
            self._audit("autonomy.stop", self.grant.id, dict(self.stopped), "stopped")
        return self.stopped

    # ---------- 汇总 ----------
    def summary(self) -> dict:
        return {"mode": "L3", "grant": self.grant.id, "granted_by": self.grant.granted_by,
                "allowlist": list(self.grant.allowlist),
                "allow_writes": self.grant.allow_writes,
                "llm_required": self.llm_required,
                "steps": self.steps, "actions": self.actions,
                "budget": self.budget.status(),
                "consecutive_failures": self.consecutive_failures,
                "stopped": self.stopped, "trace": str(self.trace_path),
                "audit": str(Path(self.store.ws_dir) / "audit.jsonl")}


# ---------------------------------------------------------------- L3 循环

class AutonomyRunner:
    """propose → 护栏校验 → 预授权批准（由 planner 完成）→ execute 的受控循环。

    ``planner(step, guard)`` 返回 ``{"id", "actions", "mode", "llm_note"}``；
    生产适配器为 :class:`ExplorerPlanner`。``executor(proposal)`` 返回
    ``{"results": [...], "ok": bool, "duration_ms": int}``；生产适配器为
    :class:`SupervisorExecutor`。
    """

    def __init__(self, guard: AutonomyGuard, planner: Callable, executor: Callable, *,
                 session, llm_requested: bool = False, max_steps: int | None = None):
        self.guard = guard
        self.planner = planner
        self.executor = executor
        self.session = session
        self.llm_requested = bool(llm_requested)
        self.max_steps = min(int(max_steps or guard.grant.max_steps), guard.grant.max_steps)

    def run(self) -> dict:
        steps: list[dict] = []
        fallbacks = 0
        stop: dict | None = None
        for step in range(1, self.max_steps + 1):
            trip = self.guard.should_stop()
            if trip:
                stop = self.guard.stop(trip.reason, trip.detail)
                break
            proposal = self.planner(step, self.guard)
            actions = list(proposal.get("actions") or [])
            mode = str(proposal.get("mode") or "rules")
            note = str(proposal.get("llm_note") or "")
            if not actions:
                stop = self.guard.stop("no-candidates", f"第 {step} 步无候选")
                break
            if self.llm_requested and mode != "llm":
                fallbacks += 1
                self.guard._audit("autonomy.llm.fallback", str(proposal.get("id") or ""),
                                  {"step": step, "mode": mode, "note": note}, "degraded")
            if len(actions) > self.guard.grant.max_actions:
                stop = self.guard.stop(
                    "action-cap",
                    f"单步 {len(actions)} 个动作 > 预授权上限 {self.guard.grant.max_actions}")
                break
            try:
                for action in actions:
                    if bool(action.get("writes")) and not self.guard.grant.allow_writes:
                        raise GuardTrip("write-not-granted",
                                        f"模块 {action.get('module')} 为写动作")
                    self.guard.check_action(action)
            except GuardTrip as trip:
                self.guard._audit("autonomy.action.denied", str(proposal.get("id") or ""),
                                  {"step": step, "reason": trip.reason,
                                   "detail": trip.detail}, "denied")
                stop = self.guard.stop(trip.reason, trip.detail)
                break
            started = self.guard._clock()
            try:
                result = self.executor(proposal) or {}
            except Exception as exc:  # 执行器崩溃 = 异常即停（不吞）
                self.guard.record_step(actions, duration_ms=0, failures=len(actions))
                self.guard._audit("autonomy.executor.error", str(proposal.get("id") or ""),
                                  {"step": step, "error": f"{type(exc).__name__}: {exc}"},
                                  "failed")
                stop = self.guard.stop("executor-error",
                                       f"{type(exc).__name__}: {exc}")
                break
            elapsed_ms = int(result.get("duration_ms") or
                             (self.guard._clock() - started) * 1000)
            results = list(result.get("results") or [])
            failures = sum(1 for r in results if str(r.get("status")) != "success")
            self.guard.record_step(actions, duration_ms=elapsed_ms, failures=failures)
            plan = _plan_input(actions)
            row = {"kind": "step", "at": self.guard._clock(), "step": step,
                   "proposal": str(proposal.get("id") or ""), "mode": mode,
                   "llm_note": note, "plan": plan,
                   "plan_sha256": plan_digest(actions),
                   "results": results, "budget": self.guard.budget.status()}
            self.guard._trace(row)
            steps.append({"step": step, "proposal": row["proposal"], "mode": mode,
                          "actions": plan, "plan_sha256": row["plan_sha256"],
                          "failures": failures, "results": results})
            self.guard._audit("autonomy.step", row["proposal"],
                              {"step": step, "mode": mode, "actions": len(actions),
                               "failures": failures, "plan_sha256": row["plan_sha256"],
                               "budget": row["budget"]["state"]},
                              "ok" if not failures else "partial")
            if failures:
                trip = self.guard.should_stop()
                if trip:
                    stop = self.guard.stop(trip.reason, trip.detail)
                    break
        if stop is None:
            stop = self.guard.stop("complete", f"完成 {len(steps)} 步")
        summary = self.guard.summary()
        return {"mode": "L3", **summary, "steps": steps, "stop": stop,
                "llm_fallbacks": fallbacks}


# ---------------------------------------------------------------- 生产适配器

class ExplorerPlanner:
    """Explorer.propose + 预授权批准；只允许在 L3 guard 通过后调用。"""

    def __init__(self, explorer, session, *, llm: bool = False, max_actions: int = 5):
        self.explorer = explorer
        self.session = session
        self.llm = bool(llm)
        self.max_actions = int(max_actions)

    def __call__(self, step: int, guard: AutonomyGuard) -> dict:
        proposal = self.explorer.propose(self.session, use_llm=self.llm,
                                         max_actions=min(self.max_actions,
                                                         guard.grant.max_actions))
        approved = self.explorer.approve_preauthorized(proposal["id"], grant=guard.grant)
        return {"id": approved["id"], "actions": approved["actions"],
                "mode": approved.get("mode", "rules"),
                "llm_note": approved.get("llm_note", "")}


class SupervisorExecutor:
    """已批准提议 → supervisor 入队/执行（逐模块走 runner 闸门与落证）。"""

    def __init__(self, store, session, *, workers: int = 1, modules_dir=None):
        self.store = store
        self.session = session
        self.workers = int(workers)
        self.modules_dir = modules_dir

    def __call__(self, proposal: dict) -> dict:
        from .supervisor import Supervisor

        supervisor = Supervisor(self.store, self.session, workers=self.workers,
                                modules_dir=self.modules_dir)
        supervisor.submit(list(proposal["actions"]),
                          proposal={"id": proposal["id"], "status": "approved",
                                    "approval": {"status": "approved",
                                                 "approved_by": "preauth"}})
        return supervisor.run()


def run_supervisor_guarded(store, session, guard: AutonomyGuard, *,
                           workers: int = 1, executor: Callable | None = None,
                           modules_dir=None) -> dict:
    """L3 下的 supervisor 队列执行：先整队校验白名单/预算，再统一跑。"""
    from .supervisor import Supervisor

    supervisor = Supervisor(store, session, workers=workers,
                            modules_dir=modules_dir, executor=executor)
    pending = [t for t in supervisor.tasks() if t["status"] == "pending"]
    for task in pending:
        approval = task.get("approval") or {}
        if str(approval.get("status") or "") != "approved":
            guard._audit("autonomy.action.denied", f"supervisor:{task['id']}",
                         {"reason": "approval", "module": task["module"]}, "denied")
            raise AutonomyRefused(f"任务 {task['id']}（{task['module']}）未经 lead 批准")
    if not pending:
        guard._audit("autonomy.supervisor.run", guard.grant.id,
                     {"pending": 0, "note": "no pending tasks"}, "ok")
        return {"summary": {"total": 0, "success": 0, "failed": 0,
                            "pending": 0, "approvals": 0, "duration_ms": 0},
                "tasks": [], "autonomy": guard.summary()}
    from .registry import load_modules

    mod_path = Path(modules_dir) if modules_dir else Path(store.root) / "modules"
    modules = load_modules(mod_path) if mod_path.exists() else {}
    try:
        for task in pending:
            meta = modules.get(task["module"])
            guard.check_action({
                "module": task["module"],
                "params": task.get("params") or {},
                "writes": bool(getattr(meta, "writes", False)),
            })
    except GuardTrip as trip:
        guard._audit("autonomy.action.denied", "supervisor:queue",
                     {"reason": trip.reason, "detail": trip.detail}, "denied")
        raise AutonomyRefused(f"supervisor 队列校验失败：{trip.detail}") from trip
    result = supervisor.run()
    failures = int((result.get("summary") or {}).get("failed", 0))
    guard.record_step([{"module": t["module"], "params": t.get("params") or {}}
                       for t in pending],
                      duration_ms=int((result.get("summary") or {}).get("duration_ms", 0)),
                      failures=failures)
    guard._audit("autonomy.supervisor.run", guard.grant.id,
                 {"pending": len(pending), "workers": workers,
                  "success": (result.get("summary") or {}).get("success", 0),
                  "failed": failures}, "ok" if not failures else "partial")
    if failures >= guard.anomaly_limit:
        guard.stop("anomaly", f"supervisor 连续失败 {failures}")
    return {**result, "autonomy": guard.summary()}


# ---------------------------------------------------------------- 回放

def replay_trace(store, *, path: str | Path | None = None) -> dict:
    """确定性回放：只重放「决策面」，不执行任何模块，不改动证据。

    逐行校验 ``plan`` 与 ``plan_sha256``；任何篡改 → AutonomyRefused。
    """
    trace_path = Path(path) if path else jsonio.ws_path(store, TRACE_RELPATH)
    if not Path(trace_path).exists():
        raise AutonomyRefused(f"trace 不存在：{trace_path}")
    steps: list[dict] = []
    for line in Path(trace_path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError as exc:
            raise AutonomyRefused(f"trace 坏行：{exc}") from exc
        if row.get("kind") != "step":
            continue
        plan = list(row.get("plan") or [])
        expect = plan_digest(plan)
        if not hmac.compare_digest(str(row.get("plan_sha256") or ""), expect):
            raise AutonomyRefused(
                f"trace 第 {row.get('step')} 步 digest 不匹配（被篡改或版本不一致）")
        steps.append({"step": int(row.get("step") or 0),
                      "proposal": str(row.get("proposal") or ""),
                      "mode": str(row.get("mode") or ""),
                      "actions": plan, "plan_sha256": expect})
    if not steps:
        raise AutonomyRefused("trace 中没有可回放的步骤")
    return {"mode": "replay", "executed": False, "deterministic": True,
            "source": str(trace_path), "steps": steps,
            "total_actions": sum(len(s["actions"]) for s in steps)}
