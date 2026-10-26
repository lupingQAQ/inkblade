# -*- coding: utf-8 -*-
"""Structured planner for graph deltas (OpenAI-compatible, retry + fallback).

The planner never executes and never confirms a fact.  It returns one JSON
object per call:

``{"decision":"propose_intents", "rationale":"...", "expected_evidence":[...],
   "intents":[{...}], "facts":[{...}], "hint":{...}}``
or ``{"decision":"stop", "rationale":"..."}``.

``LLMPlanner`` uses the workspace model pool (``--llm pool``) or any injected
OpenAI-compatible client.  ``ScriptedPlanner`` is the deterministic mock used
by tests/evals.  ``DeterministicPlanner`` is the degraded fallback and the
baseline for the evaluation harness.
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any, Callable

from .graph import ROLES
from .objectives import Objective

DECISION_KINDS = ("propose_intents", "stop")
_FORBIDDEN_PARAM_KEYS = ("command", "shell", "script", "run_python", "python_code",
                         "shell_command")


class PlannerError(ValueError):
    """LLM output or planner configuration invalid."""


class LLMRequired(PlannerError):
    """Agent mode requires an LLM; deterministic mode is the explicit fallback."""


def _extract_json(text: str) -> dict:
    raw = str(text or "").strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```[a-zA-Z0-9_-]*\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)
    start = raw.find("{")
    if start < 0:
        raise PlannerError("LLM 输出不含 JSON 对象")
    try:
        value, _ = json.JSONDecoder().raw_decode(raw[start:])
    except ValueError as exc:
        raise PlannerError(f"LLM JSON 解析失败: {exc}") from exc
    if not isinstance(value, dict):
        raise PlannerError("LLM 输出必须是 JSON 对象")
    return value


def validate_decision(doc: dict) -> dict:
    if not isinstance(doc, dict):
        raise PlannerError("decision 必须是对象")
    decision = str(doc.get("decision") or "")
    if decision not in DECISION_KINDS:
        raise PlannerError(f"decision 必须是 {DECISION_KINDS}，得到 {decision!r}")
    rationale = str(doc.get("rationale") or doc.get("reason") or "").strip()
    if not rationale:
        raise PlannerError("decision 缺 rationale（决策轨迹必须有理由）")
    out = {**doc, "decision": decision, "rationale": rationale}
    if decision == "stop":
        return out
    intents = doc.get("intents")
    if not isinstance(intents, list) or not intents:
        raise PlannerError("propose_intents 需要非空 intents 数组")
    clean: list[dict] = []
    for idx, item in enumerate(intents):
        if not isinstance(item, dict):
            raise PlannerError(f"intents[{idx}] 必须是对象")
        role = str(item.get("role") or "")
        if role not in ROLES:
            raise PlannerError(f"intents[{idx}].role 非法: {role!r}")
        module = str(item.get("module") or "").strip()
        if not module:
            raise PlannerError(f"intents[{idx}] 缺 module")
        params = item.get("params") or {}
        if not isinstance(params, dict):
            raise PlannerError(f"intents[{idx}].params 必须是对象")
        bad = [k for k in params if str(k).lower() in _FORBIDDEN_PARAM_KEYS]
        if bad:
            raise PlannerError(f"intents[{idx}] 含禁止的执行参数: {bad}")
        priority = item.get("priority", 5)
        try:
            priority = int(priority)
        except (TypeError, ValueError) as exc:
            raise PlannerError(f"intents[{idx}].priority 必须是整数") from exc
        if not (0 <= priority <= 10):
            raise PlannerError(f"intents[{idx}].priority 必须在 0–10")
        expected = item.get("expected_evidence") or doc.get("expected_evidence") or []
        if isinstance(expected, str):
            expected = [expected]
        if not isinstance(expected, list):
            raise PlannerError(f"intents[{idx}].expected_evidence 必须是数组")
        clean.append({
            **item, "role": role, "module": module, "params": params,
            "priority": priority,
            "writes": bool(item.get("writes")),
            "cleanup": bool(item.get("cleanup")),
            "probe": bool(item.get("probe", role != "report")),
            "expected_evidence": [str(e) for e in expected],
            "requires": [str(r) for r in (item.get("requires") or [])],
            "cost_tokens": int(item.get("cost_tokens") or 100),
            "success": str(item.get("success") or ""),
        })
    out["intents"] = clean
    facts = doc.get("facts") or []
    if not isinstance(facts, list):
        raise PlannerError("facts 必须是数组")
    for idx, fact in enumerate(facts):
        if not isinstance(fact, dict):
            raise PlannerError(f"facts[{idx}] 必须是对象")
        status = str(fact.get("status") or "hypothesis")
        if status != "hypothesis":
            raise PlannerError("LLM 只能提出 hypothesis；confirmed 必须由探针证据晋升")
    out["facts"] = facts
    return out


class Planner:
    source = "planner"

    def propose(self, state: dict) -> dict:
        raise NotImplementedError

    def name(self) -> str:
        return self.source


SYSTEM_PROMPT = """You are the planning supervisor of an authorized penetration test.
You maintain a Fact/Intent/Hint graph. Never claim a fact is confirmed: only probe
evidence can do that. Never invent evidence, credentials or command execution.
Propose at most four intents per call. Each intent names a declarative probe
template module, a role (recon/exploit/verify/report), params, priority 0-10,
expected evidence, and rationale. Write intents are only allowed when the
objective permits them and policy will enforce RoE/backup. Return JSON only.

Schema:
{"decision":"propose_intents","rationale":"...","expected_evidence":["..."],
 "intents":[{"role":"recon","module":"...","params":{},"priority":9,
             "requires":["fact-1"],"writes":false,"cleanup":false,
             "expected_evidence":["..."],"success":"..."}],
 "facts":[{"claim":"...","status":"hypothesis","fact_kind":"..."}],
 "hint":{"text":"...","priority":5}}
or
{"decision":"stop","rationale":"objective satisfied or budget exhausted"}
"""


def state_for_llm(state: dict) -> dict:
    allowed = ("objective", "objective_eval", "graph", "frontier", "facts", "hints",
               "budget", "memory", "skills", "attempts", "last_failure", "mode")
    return {key: state.get(key) for key in allowed if key in state}


class LLMPlanner(Planner):
    """OpenAI-compatible planner with bounded retries and an optional fallback."""

    source = "llm"

    def __init__(self, store, *, pool=None, llm: str = "pool", max_retries: int = 2,
                 fallback: Planner | None = None, clock=time.time):
        self.store = store
        self.llm = str(llm or "pool")
        self.max_retries = max(0, int(max_retries))
        self.fallback = fallback
        self._clock = clock
        if pool is None:
            from ..core.llmpool import LLMPool

            pool = LLMPool(store)
        self.pool = pool
        self.calls: list[dict] = []

    def _complete(self, messages: list[dict]) -> dict:
        if not hasattr(self.pool, "complete"):
            raise LLMRequired("LLM planner 需要 OpenAI 兼容的 complete() 客户端")
        result = self.pool.complete(messages, purpose="agent.plan", max_tokens=1800)
        if not isinstance(result, dict):
            raise PlannerError("LLM 客户端返回非对象")
        text = str(result.get("text") or result.get("content") or "")
        if not text.strip():
            raise PlannerError("LLM 返回空内容")
        tokens = int((result.get("usage") or {}).get("tokens") or
                     result.get("tokens") or max(1, len(text) // 4))
        return {"text": text, "tokens": tokens, "endpoint": result.get("endpoint", ""),
                "latency_ms": result.get("latency_ms", 0)}

    def propose(self, state: dict) -> dict:
        payload = json.dumps(state_for_llm(state), ensure_ascii=False, sort_keys=True,
                             default=str)
        messages = [{"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": payload}]
        last_error = ""
        for attempt in range(1, self.max_retries + 2):
            started = self._clock()
            try:
                result = self._complete(messages)
                decision = validate_decision(_extract_json(result["text"]))
                decision["source"] = "llm"
                decision["tokens"] = int(result["tokens"])
                decision["attempts"] = attempt
                decision["endpoint"] = result.get("endpoint", "")
                decision["latency_ms"] = int((self._clock() - started) * 1000)
                self.calls.append({"ok": True, "attempt": attempt,
                                   "tokens": decision["tokens"]})
                return decision
            except Exception as exc:  # retry invalid output/transport
                last_error = f"{type(exc).__name__}: {exc}"
                self.calls.append({"ok": False, "attempt": attempt,
                                   "error": last_error})
                if attempt <= self.max_retries:
                    time.sleep(min(2.0, 0.2 * attempt))
        if self.fallback is not None:
            decision = self.fallback.propose(state)
            decision["degraded"] = True
            decision["degrade_reason"] = last_error
            decision["source"] = decision.get("source") or "deterministic"
            decision.setdefault("tokens", 0)
            return decision
        raise PlannerError(f"LLM 规划失败（{self.max_retries + 1} 次）：{last_error}")


class ScriptedPlanner(Planner):
    """Deterministic mock LLM: a list/path/callable of structured responses."""

    source = "scripted"

    def __init__(self, script: Any, *, default_tokens: int = 32, loop: bool = False,
                 start_index: int = 0):
        self.loop = bool(loop)
        self.default_tokens = int(default_tokens)
        self._index = max(0, int(start_index))
        self.calls: list[dict] = []
        self._callable: Callable[[dict], dict] | None = None
        if callable(script):
            self._callable = script
            self.responses: list[dict] = []
        else:
            self.responses = self._load(script)

    @staticmethod
    def _load(script: Any) -> list[dict]:
        if isinstance(script, dict):
            if "responses" in script:
                script = script["responses"]
            else:
                script = [script]
        if isinstance(script, (str, Path)):
            path = Path(script)
            if str(script).startswith("mock:"):
                path = Path(str(script).split(":", 1)[1])
            doc = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(doc, dict) and "responses" in doc:
                doc = doc["responses"]
            if not isinstance(doc, list):
                raise PlannerError(f"{path} 需要 responses 数组")
            script = doc
        if not isinstance(script, list):
            raise PlannerError("scripted planner 需要列表/响应对象/路径")
        return [dict(item) for item in script]

    def propose(self, state: dict) -> dict:
        if self._callable is not None:
            doc = self._callable(state)
        elif self._index < len(self.responses):
            doc = self.responses[self._index]
            self._index += 1
        elif self.loop and self.responses:
            doc = self.responses[-1]
        else:
            doc = {"decision": "stop", "rationale": "scripted planner exhausted"}
        decision = validate_decision(dict(doc))
        decision["source"] = "scripted"
        decision["tokens"] = int(decision.get("tokens", self.default_tokens))
        decision["attempts"] = 1
        self.calls.append({"ok": True, "index": self._index,
                           "tokens": decision["tokens"]})
        return decision


class DeterministicPlanner(Planner):
    """Degraded baseline: fixed objective stages, no LLM, no graph expansion."""

    source = "deterministic"

    def __init__(self, objective: Objective, *, module_map: dict[str, str] | None = None,
                 param_map: dict[str, dict] | None = None):
        self.objective = objective
        self.module_map = dict(module_map or {})
        self.param_map = dict(param_map or {})
        self.calls: list[dict] = []

    def propose(self, state: dict) -> dict:
        graph = state.get("graph_obj")
        if graph is None:
            raise PlannerError("deterministic planner 需要 state.graph_obj")
        stage = self.objective.next_stage(graph, module_map=self.module_map,
                                          param_map=self.param_map)
        if stage is None:
            decision = {"decision": "stop", "source": "deterministic", "tokens": 0,
                        "attempts": 1,
                        "rationale": "deterministic stages exhausted or blocked"}
        else:
            decision = {
                "decision": "propose_intents", "source": "deterministic",
                "tokens": 0, "attempts": 1,
                "rationale": stage.get("rationale") or f"stage {stage.get('stage')}",
                "expected_evidence": stage.get("expected_evidence") or [],
                "intents": [{**stage, "stage": stage.get("stage")}],
            }
        self.calls.append({"ok": True, "stage": stage.get("stage") if stage else None})
        return validate_decision(decision)


def build_planner(llm: Any, store, *, objective: Objective,
                  module_map: dict[str, str] | None = None,
                  param_map: dict[str, dict] | None = None,
                  fallback: bool = True) -> Planner:
    """Build the planner from CLI/config value; LLM is mandatory for agent modes."""
    if isinstance(llm, Planner):
        return llm
    if llm is None or str(llm).strip() == "":
        raise LLMRequired(
            "agent 模式需要 --llm（OpenAI 兼容池或 mock:<script>）；"
            "确定性模式请显式 --mode deterministic")
    value = str(llm).strip()
    if value in ("deterministic", "none"):
        return DeterministicPlanner(objective, module_map=module_map, param_map=param_map)
    if value.startswith("mock:") or value.startswith("script:") or \
            (value.endswith(".json") and Path(value).is_file()):
        script = value.split(":", 1)[1] if ":" in value else value
        return ScriptedPlanner(script)
    deterministic = DeterministicPlanner(objective, module_map=module_map,
                                         param_map=param_map)
    return LLMPlanner(store, llm=value, fallback=deterministic if fallback else None)
