# -*- coding: utf-8 -*-
"""成本预算（token / 时延 / 审批 / 人工干预）与超支降级。

第三节差距：参赛队伍要么按「一题 7692 元」烧钱拿 AK，要么因为并发 429 把
比赛节奏拖垮；我们的 explorer 没有预算概念，只会把候选塞满 5 个动作。
本模块把成本变成一等公民：先估算，再在超支时**确定性地降级**（先丢可选
步骤，再砍写动作），而不是让模型「自觉省一点」。

纯函数；不读时钟、不发请求。
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

DEFAULT_BUDGET = {"tokens": 20000, "latency_ms": 120000,
                  "approvals": 6, "interventions": 2}

WARN_RATIO = 0.8


def estimate_tokens(text: Any) -> int:
    """粗估 token（4 字符 ≈ 1 token；中文按字符下限保护）。"""
    s = str(text or "")
    return max(1, math.ceil(len(s) / 4))


def _action_cost(action: dict) -> tuple[int, int]:
    text = f"{action.get('module', '')} {action.get('params', '')} {action.get('reason', '')}"
    tokens = int(action.get("tokens") or estimate_tokens(text))
    latency = int(action.get("latency_ms") or max(1, tokens * 3))
    return tokens, latency


def plan_cost(actions: list[dict]) -> dict:
    per = []
    for i, action in enumerate(actions):
        tokens, latency = _action_cost(action)
        per.append({"index": i, "module": action.get("module"),
                    "writes": bool(action.get("writes")), "tokens": tokens,
                    "latency_ms": latency})
    return {"tokens": sum(p["tokens"] for p in per),
            "latency_ms": sum(p["latency_ms"] for p in per),
            "actions": len(per), "per_action": per}


@dataclass
class Budget:
    tokens: int = DEFAULT_BUDGET["tokens"]
    latency_ms: int = DEFAULT_BUDGET["latency_ms"]
    approvals: int = DEFAULT_BUDGET["approvals"]
    interventions: int = DEFAULT_BUDGET["interventions"]
    used: dict = field(default_factory=lambda: {"tokens": 0, "latency_ms": 0,
                                                "approvals": 0, "interventions": 0})

    def __post_init__(self):
        for key, val in (("tokens", self.tokens), ("latency_ms", self.latency_ms),
                         ("approvals", self.approvals), ("interventions", self.interventions)):
            if int(val) < 0:
                raise ValueError(f"预算 {key} 不能为负")
        self.tokens, self.latency_ms = int(self.tokens), int(self.latency_ms)
        self.approvals, self.interventions = int(self.approvals), int(self.interventions)

    def record(self, *, tokens: int = 0, latency_ms: int = 0, approvals: int = 0,
               interventions: int = 0) -> dict:
        for key, val in (("tokens", tokens), ("latency_ms", latency_ms),
                         ("approvals", approvals), ("interventions", interventions)):
            self.used[key] += max(0, int(val))
        return self.status()

    def _ratio(self, key: str) -> float:
        limit = getattr(self, key)
        return 1.0 if limit == 0 and self.used[key] > 0 else \
            (self.used[key] / limit if limit else 0.0)

    def status(self) -> dict:
        ratios = {k: round(self._ratio(k), 3) for k in ("tokens", "latency_ms",
                                                        "approvals", "interventions")}
        state = "over" if any(r >= 1.0 for r in ratios.values()) else \
            ("warn" if any(r >= WARN_RATIO for r in ratios.values()) else "ok")
        remaining = {k: max(0, getattr(self, k) - self.used[k])
                     for k in ("tokens", "latency_ms", "approvals", "interventions")}
        return {"state": state, "ratios": ratios, "remaining": remaining,
                "used": dict(self.used),
                "limits": {"tokens": self.tokens, "latency_ms": self.latency_ms,
                           "approvals": self.approvals,
                           "interventions": self.interventions}}


def _fits(actions: list[dict], *, tokens: int, latency_ms: int) -> bool:
    plan = plan_cost(actions)
    return plan["tokens"] <= tokens and plan["latency_ms"] <= latency_ms


def degrade(actions: list[dict], *, budget: Budget, level: int = 1) -> dict:
    """超支降级：先丢 optional，再砍写动作，至少保留一个只读动作。"""
    st = budget.status()
    budget_tokens = int(st["remaining"]["tokens"]) if st["state"] != "ok" else budget.tokens
    budget_latency = int(st["remaining"]["latency_ms"]) if st["state"] != "ok" else budget.latency_ms
    original = plan_cost(actions)
    if _fits(actions, tokens=budget_tokens, latency_ms=budget_latency):
        return {"actions": list(actions), "dropped": [], "degraded": False,
                "over_budget": False, "reason": "预算内，无需降级",
                "saved": {"tokens": 0, "latency_ms": 0}, "plan": original}

    kept = list(actions)
    dropped: list[dict] = []

    def _drop(predicate) -> None:
        for action in list(kept):
            if len(kept) <= 1:
                return
            if not predicate(action):
                continue
            if _fits(kept, tokens=budget_tokens, latency_ms=budget_latency):
                return
            kept.remove(action)
            dropped.append(action)

    _drop(lambda a: bool(a.get("optional")))
    if level >= 2:
        _drop(lambda a: bool(a.get("writes")))
    while len(kept) > 1 and not _fits(kept, tokens=budget_tokens,
                                     latency_ms=budget_latency):
        dropped.append(kept.pop())

    final = plan_cost(kept)
    return {
        "actions": kept,
        "dropped": dropped,
        "degraded": bool(dropped),
        "over_budget": not _fits(kept, tokens=budget_tokens,
                                 latency_ms=budget_latency),
        "reason": ("预算超支：已丢弃 %d 个动作（可选/写/尾部低优先级）" % len(dropped))
                  if dropped else "预算超支：已无可丢弃动作，保留最小动作集并上报",
        "saved": {"tokens": original["tokens"] - final["tokens"],
                  "latency_ms": original["latency_ms"] - final["latency_ms"]},
        "plan": final,
    }


def apply_budget(actions: list[dict], *, budget: Budget) -> dict:
    """提议路径入口：返回可直接写入 proposal 的降级结果。"""
    out = degrade(actions, budget=budget)
    out["reason"] = ("预算检查：" + out["reason"]) if out["degraded"] else out["reason"]
    return out


class CostTracker:
    """逐步记账 + 汇总，用于评测与 Web 只读视图。"""

    def __init__(self, budget: Budget | None = None):
        self.budget = budget or Budget()
        self.rows: list[dict] = []

    def record(self, step: Any, *, tokens: int = 0, latency_ms: int = 0,
               approvals: int = 0, interventions: int = 0, cached: bool = False) -> dict:
        row = {"step": str(step), "tokens": int(tokens), "latency_ms": int(latency_ms),
               "approvals": int(approvals), "interventions": int(interventions),
               "cached": bool(cached)}
        self.rows.append(row)
        self.budget.record(tokens=tokens, latency_ms=latency_ms,
                           approvals=approvals, interventions=interventions)
        return row

    def summary(self) -> dict:
        return {
            "steps": len(self.rows),
            "tokens": sum(r["tokens"] for r in self.rows),
            "latency_ms": sum(r["latency_ms"] for r in self.rows),
            "approvals": sum(r["approvals"] for r in self.rows),
            "interventions": sum(r["interventions"] for r in self.rows),
            "cached_steps": sum(1 for r in self.rows if r["cached"]),
            "state": self.budget.status()["state"],
            "budget": self.budget.status(),
            "rows": self.rows,
        }
