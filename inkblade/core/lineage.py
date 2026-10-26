# -*- coding: utf-8 -*-
"""探索血缘图（CM-16）：goal → intent → fact(step) → finding 的边与反查。

- 新表 ``lineage``（run/src/dst/relation/attrs）；节点用稳定字符串 ID：
  ``goal:...`` / ``intent:<proposal>:<module>`` / ``step:<module>`` / ``finding:<fingerprint>``；
- ``ingest_run`` 从 run 的 steps/findings 生成 fact→finding 边与 run→step 包含边；
- ``ingest_proposal`` 把已批准提议的意图边接入（可选 run 参数连接执行步骤）；
- ``ancestors`` / ``descendants`` 支撑反查与影响分析；``coverage`` 统计每个 goal 覆盖的
  distinct finding 数与覆盖率；
- 只写血缘表与审计，不执行模块；节点 attrs 允许标题/严重度等摘要，禁止原始凭据。
"""

from __future__ import annotations

import json
import time
from typing import Any

from . import jsonio

_TABLE = (
    "CREATE TABLE IF NOT EXISTS lineage(id INTEGER PRIMARY KEY, run TEXT, src TEXT, dst TEXT,"
    " relation TEXT, attrs TEXT, created_at REAL)"
)


class LineageError(ValueError):
    """血缘边非法。"""


def _ensure(run) -> None:
    with run._tx() as conn:
        conn.execute(_TABLE)


def _open(store, run_name: str):
    try:
        return store.open_run(run_name)
    except KeyError as exc:
        raise LineageError(f"run 不存在：{run_name}") from exc


def add_edge(store, run_name: str, src: str, dst: str, relation: str,
             attrs: dict | None = None) -> dict:
    if not str(src).strip() or not str(dst).strip():
        raise LineageError("src/dst 不能为空")
    if src == dst:
        raise LineageError("禁止自环")
    run = _open(store, run_name)
    _ensure(run)
    exists = run.query(
        "SELECT id FROM lineage WHERE run=? AND src=? AND dst=? AND relation=?",
        (run_name, src, dst, relation))
    if exists:
        return {"id": exists[0][0], "src": src, "dst": dst, "relation": relation,
                "duplicate": True}
    now = time.time()
    with run._tx() as conn:
        cur = conn.execute(
            "INSERT INTO lineage(run, src, dst, relation, attrs, created_at)"
            " VALUES(?,?,?,?,?,?)",
            (run_name, src, dst, relation,
             json.dumps(jsonio.redact(attrs or {}), ensure_ascii=False), now))
        eid = cur.lastrowid
    return {"id": eid, "run": run_name, "src": src, "dst": dst,
            "relation": relation, "created_at": now}


def add_edges(store, run_name: str, edges: list[tuple]) -> dict:
    count = 0
    for edge in edges:
        if len(edge) == 3:
            src, dst, rel = edge
            attrs = {}
        elif len(edge) == 4:
            src, dst, rel, attrs = edge
        else:
            raise LineageError("edge 必须是 (src,dst,relation[,attrs])")
        add_edge(store, run_name, src, dst, rel, attrs)
        count += 1
    jsonio.append_audit(store, "lineage", "lineage.add", run_name,
                        {"edges": count}, "ok")
    return {"run": run_name, "edges": count}


def ingest_run(store, run_name: str) -> dict:
    run = _open(store, run_name)
    _ensure(run)
    steps = run.query("SELECT id, step_key, archive FROM steps ORDER BY id")
    findings = run.findings
    edges = []
    seen_steps = set()
    for _sid, step_key, _archive in steps:
        if step_key in seen_steps:
            continue
        seen_steps.add(step_key)
        edges.append((f"run:{run_name}", f"step:{step_key}", "contains", {}))
    for f in findings:
        fp = jsonio.fingerprint(f"{f.get('step_key')}|{f.get('title')}")
        node = f"finding:{fp}"
        edges.append((f"step:{f.get('step_key')}", node, "produces",
                      {"title": f.get("title", ""), "severity": f.get("severity", "info")}))
    for e in edges:
        add_edge(store, run_name, e[0], e[1], e[2], e[3])
    jsonio.append_audit(store, "lineage", "lineage.ingest_run", run_name,
                        {"steps": len(seen_steps), "findings": len(findings)}, "ok")
    return {"run": run_name, "steps": len(seen_steps), "findings": len(findings),
            "edges": len(edges)}


def ingest_proposal(store, proposal: dict, *, run: str = "") -> dict:
    pid = proposal.get("id") or "proposal"
    goal = f"goal:proposal:{pid}"
    edges = []
    counts = 0
    if run:
        _open(store, run)
    for action in proposal.get("actions") or []:
        intent = f"intent:{pid}:{action.get('module')}:{action.get('seq')}"
        edges.append((goal, intent, "proposes", {"module": action.get("module"),
                                                 "writes": bool(action.get("writes"))}))
        counts += 1
        if run:
            edges.append((intent, f"step:{action.get('module')}", "executed-as", {}))
    if not edges:
        raise LineageError("提议无 actions")
    for e in edges:
        # 提议在未执行时 run 可省略；未执行血缘落工作区 JSONL，避免虚构 run
        if run:
            add_edge(store, run, e[0], e[1], e[2], e[3])
        else:
            jsonio.append_audit(store, "lineage", "lineage.intent", e[0],
                                {"dst": e[1], "relation": e[2]}, "ok")
    return {"proposal": pid, "run": run, "intents": counts, "edges": len(edges),
            "run_bound": bool(run)}


def graph(store, run_name: str) -> dict:
    run = _open(store, run_name)
    _ensure(run)
    rows = run.query("SELECT src, dst, relation, attrs, created_at FROM lineage WHERE run=? ORDER BY id",
                     (run_name,))
    nodes, edges = {}, []
    for src, dst, rel, attrs, ts in rows:
        for nid in (src, dst):
            nodes.setdefault(nid, {"id": nid, "kind": nid.split(":", 1)[0]})
        try:
            a = json.loads(attrs or "{}")
        except ValueError:
            a = {}
        edges.append({"src": src, "dst": dst, "relation": rel, "attrs": a, "created_at": ts})
    return {"run": run_name, "nodes": sorted(nodes.values(), key=lambda n: n["id"]),
            "edges": edges, "counts": {"nodes": len(nodes), "edges": len(edges)}}


def descendants(store, run_name: str, node: str, *, max_depth: int = 12) -> list[dict]:
    g = graph(store, run_name)
    return _walk(g, node, reverse=False, max_depth=max_depth)


def ancestors(store, run_name: str, node: str, *, max_depth: int = 12) -> list[dict]:
    g = graph(store, run_name)
    return _walk(g, node, reverse=True, max_depth=max_depth)


def _walk(g: dict, start: str, *, reverse: bool, max_depth: int) -> list[dict]:
    adj: dict[str, list[dict]] = {}
    for e in g["edges"]:
        a, b = (e["dst"], e["src"]) if reverse else (e["src"], e["dst"])
        adj.setdefault(a, []).append({**e, "node": b})
    out, seen, queue = [], {start}, [(start, 0)]
    while queue:
        cur, depth = queue.pop(0)
        if depth >= max_depth:
            continue
        for e in adj.get(cur, []):
            if e["node"] in seen:
                continue
            seen.add(e["node"])
            out.append({"node": e["node"], "via": e["src"] if not reverse else e["dst"],
                        "relation": e["relation"], "depth": depth + 1})
            queue.append((e["node"], depth + 1))
    return out


def coverage(store, run_name: str, goals: list[str] | None = None) -> dict:
    g = graph(store, run_name)
    goal_nodes = goals or [n["id"] for n in g["nodes"] if n["id"].startswith("goal:")]
    details = []
    covered = set()
    for goal in goal_nodes:
        desc = descendants(store, run_name, goal)
        finds = {d["node"] for d in desc if d["node"].startswith("finding:")}
        covered |= finds
        details.append({"goal": goal, "findings": sorted(finds), "count": len(finds)})
    total = sum(1 for n in g["nodes"] if n["id"].startswith("finding:"))
    return {"run": run_name, "goals": len(goal_nodes),
            "covered_findings": len(covered), "total_findings": total,
            "ratio": round(len(covered) / total, 3) if total else 0.0,
            "details": details}


def to_dot(store, run_name: str) -> str:
    g = graph(store, run_name)
    lines = [f'digraph "{run_name}" {{', "  rankdir=LR;"]
    for n in g["nodes"]:
        lines.append(f'  "{n["id"]}" [label="{n["id"]}"];')
    for e in g["edges"]:
        lines.append(f'  "{e["src"]}" -> "{e["dst"]}" [label="{e["relation"]}"];')
    lines.append("}")
    return "\n".join(lines) + "\n"
