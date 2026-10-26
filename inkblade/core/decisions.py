# -*- coding: utf-8 -*-
"""决策/意图留档（CM-03）：规划器推荐理由与战术选择全量入 run 证据库。

- 新表 ``decisions``（run/kind/goal/options/chosen/rationale/actor/evidence_path）；
- ``record`` 要求非空 rationale；chosen 必须在 options 内（字符串或含 id/chain/module 的对象）；
- ``record_plan`` 把 agent_planner 的候选链（排名/判定/中英理由）逐条留档，
  与 plan-only 边界一致：只写决策记录，不执行、不建 run；
- 每条决策同时写 actions 表（action=decision）与工作区 audit.jsonl，便于对时线复核。
"""

from __future__ import annotations

import json
import time
from typing import Any

from . import jsonio

KINDS = ("planner", "tactic", "approval", "other")
_TABLE = (
    "CREATE TABLE IF NOT EXISTS decisions(id INTEGER PRIMARY KEY, run TEXT, kind TEXT, goal TEXT,"
    " options TEXT, chosen TEXT, rationale TEXT, actor TEXT, evidence_path TEXT, created_at REAL)"
)


class DecisionError(ValueError):
    """决策参数非法。"""


def _ensure(run) -> None:
    with run._tx() as conn:
        conn.execute(_TABLE)


def _option_keys(options: list) -> set[str]:
    out = set()
    for o in options:
        if isinstance(o, dict):
            for key in ("id", "chain", "module", "name"):
                if o.get(key):
                    out.add(str(o[key]))
            out.add(json.dumps(o, ensure_ascii=False, sort_keys=True))
        else:
            out.add(str(o))
    return out


def record(store, run_name: str, *, kind: str, goal: str, options: list,
           chosen: str, rationale: str, actor: str, evidence_path: str = "") -> dict:
    if kind not in KINDS:
        raise DecisionError(f"未知决策类型 {kind!r}")
    if not str(goal).strip() or not str(rationale).strip():
        raise DecisionError("goal 与 rationale 不能为空")
    try:
        run = store.open_run(run_name)
    except KeyError as exc:
        raise DecisionError(f"run 不存在：{run_name}") from exc
    if options and str(chosen) not in _option_keys(options):
        raise DecisionError(f"chosen={chosen!r} 不在 options 内")
    if evidence_path and not (run.dir / evidence_path).is_file():
        raise DecisionError(f"证据路径不存在：{evidence_path}")
    _ensure(run)
    now = time.time()
    with run._tx() as conn:
        cur = conn.execute(
            "INSERT INTO decisions(run, kind, goal, options, chosen, rationale, actor,"
            " evidence_path, created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (run_name, kind, str(goal), json.dumps(options, ensure_ascii=False),
             str(chosen), str(rationale), str(actor), evidence_path, now))
        did = cur.lastrowid
    run.log_action(actor, "decision", str(goal),
                   {"decision_id": did, "kind": kind, "chosen": chosen}, "recorded")
    jsonio.append_audit(store, actor, "decision.record", str(goal),
                        {"run": run_name, "kind": kind, "chosen": chosen,
                         "decision_id": did}, "ok")
    return {"id": did, "run": run_name, "kind": kind, "goal": goal,
            "chosen": chosen, "rationale": rationale, "options": options,
            "actor": actor, "created_at": now}


def record_plan(store, plan: dict, *, actor: str, run: str = "") -> dict:
    """把 planner 输出逐候选留档；plan 必须带 run 或显式传 run。"""
    run_name = run or plan.get("run") or ""
    if not run_name:
        raise DecisionError("计划无 run（先执行过模块或显式指定 run）")
    candidates = plan.get("candidates") or []
    if not candidates:
        raise DecisionError("计划无候选")
    options = [c.get("chain") for c in candidates]
    chosen = candidates[0].get("chain")
    rows = []
    for c in candidates:
        rationale = "；".join((c.get("reasons") or {}).get("zh") or []) or "无理由"
        rows.append(record(store, run_name, kind="planner",
                           goal=f"chain:{c.get('chain')}", options=options, chosen=chosen,
                           rationale=f"rank={c.get('rank')} verdict={c.get('verdict')} {rationale}",
                           actor=actor))
    return {"run": run_name, "decisions": rows, "count": len(rows)}


def list_decisions(store, run_name: str) -> list[dict]:
    try:
        run = store.open_run(run_name)
    except KeyError as exc:
        raise DecisionError(f"run 不存在：{run_name}") from exc
    _ensure(run)
    rows = run.query(
        "SELECT id, kind, goal, options, chosen, rationale, actor, evidence_path, created_at"
        " FROM decisions WHERE run=? ORDER BY id", (run_name,))
    keys = ["id", "kind", "goal", "options", "chosen", "rationale", "actor",
            "evidence_path", "created_at"]
    out = []
    for r in rows:
        d = dict(zip(keys, r))
        try:
            d["options"] = json.loads(d.get("options") or "[]")
        except ValueError:
            d["options"] = []
        out.append(d)
    return out


def render_md(store, run_name: str) -> str:
    rows = list_decisions(store, run_name)
    lines = [f"# 决策留档：{run_name}", "",
             "| # | 类型 | 目标 | 选择 | 理由 | 执行者 |", "|---|---|---|---|---|---|"]
    for d in rows:
        lines.append(f"| {d['id']} | {d['kind']} | {d['goal']} | {d['chosen']} | "
                     f"{d['rationale']} | {d['actor']} |")
    return "\n".join(lines) + "\n"
