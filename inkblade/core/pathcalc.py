# -*- coding: utf-8 -*-
"""攻击路径计算（CM-23）：最短路径 / 全部简单路径 / 割点 / 关键节点排序 + 图查询。

输入为图快照或 ``{nodes,edges}``：
- 边支持 ``src/dst``（evidence）与 ``source/target``（UI）两种字段；
- 只读算法，无外部依赖；路径深度/数量有界（默认 8 层 / 200 条）；
- ``critical_nodes`` 以“移除该节点后消失的 s-t 路径数”排序，直接支撑修复优先级；
- ``articulation_points`` 在无向投影上求割点（结构瓶颈），与有向路径互补。
"""

from __future__ import annotations

from collections import deque
from typing import Any

MAX_PATHS = 200
MAX_DEPTH = 8


class PathError(ValueError):
    """图/参数非法。"""


def adjacency(graph: dict) -> tuple[dict[str, set[str]], dict[str, set[str]], list[str]]:
    if not isinstance(graph, dict):
        raise PathError("graph 必须是对象")
    nodes = [n.get("id") for n in (graph.get("nodes") or []) if isinstance(n, dict) and n.get("id")]
    for e in graph.get("edges") or []:
        for key in ("src", "source"):
            if e.get(key) and e[key] not in nodes:
                nodes.append(e[key])
        for key in ("dst", "target"):
            if e.get(key) and e[key] not in nodes:
                nodes.append(e[key])
    out: dict[str, set[str]] = {n: set() for n in nodes}
    inc: dict[str, set[str]] = {n: set() for n in nodes}
    for e in graph.get("edges") or []:
        src = e.get("src") or e.get("source")
        dst = e.get("dst") or e.get("target")
        if not src or not dst or src == dst:
            continue
        out.setdefault(src, set()).add(dst)
        inc.setdefault(dst, set()).add(src)
    return out, inc, sorted(out)


def shortest_path(graph: dict, src: str, dst: str) -> list[str]:
    out, _inc, _nodes = adjacency(graph)
    if src not in out or dst not in out:
        return []
    prev: dict[str, str] = {src: ""}
    q = deque([src])
    while q:
        cur = q.popleft()
        if cur == dst:
            break
        for nxt in sorted(out.get(cur, ())):
            if nxt not in prev:
                prev[nxt] = cur
                q.append(nxt)
    if dst not in prev:
        return []
    path = [dst]
    while path[-1] != src:
        path.append(prev[path[-1]])
    return list(reversed(path))


def all_simple_paths(graph: dict, src: str, dst: str, *, max_paths: int = MAX_PATHS,
                     max_depth: int = MAX_DEPTH, exclude: set[str] | None = None) -> list[list[str]]:
    out, _inc, _nodes = adjacency(graph)
    exclude = set(exclude or set())
    if src in exclude or dst in exclude or src not in out or dst not in out:
        return []
    paths: list[list[str]] = []

    def dfs(cur: str, path: list[str], seen: set[str]) -> None:
        if len(paths) >= max_paths or len(path) > max_depth:
            return
        if cur == dst:
            paths.append(list(path))
            return
        for nxt in sorted(out.get(cur, ())):
            if nxt in seen or nxt in exclude:
                continue
            seen.add(nxt)
            path.append(nxt)
            dfs(nxt, path, seen)
            path.pop()
            seen.remove(nxt)

    dfs(src, [src], {src})
    return paths


def articulation_points(graph: dict) -> list[str]:
    """无向投影上的 Tarjan 割点（递归实现，节点数通常 < 10k）。"""
    out, inc, nodes = adjacency(graph)
    und = {n: set(out.get(n, set())) | set(inc.get(n, set())) for n in nodes}
    disc: dict[str, int] = {}
    low: dict[str, int] = {}
    parent: dict[str, str | None] = {}
    points: set[str] = set()
    time_ref = [0]

    def dfs(u: str, root: bool) -> None:
        disc[u] = low[u] = time_ref[0]
        time_ref[0] += 1
        children = 0
        for v in sorted(und.get(u, ())):
            if v not in disc:
                parent[v] = u
                children += 1
                dfs(v, False)
                low[u] = min(low[u], low[v])
                if not root and low[v] >= disc[u]:
                    points.add(u)
            elif parent.get(u) != v:
                low[u] = min(low[u], disc[v])
        if root and children > 1:
            points.add(u)

    for n in nodes:
        if n not in disc:
            parent[n] = None
            dfs(n, True)
    return sorted(points)


def critical_nodes(graph: dict, sources: list[str] | None = None,
                   targets: list[str] | None = None, *, top: int = 10) -> list[dict]:
    out, inc, nodes = adjacency(graph)
    sources = sources or [n for n in nodes if not inc.get(n)]
    targets = targets or [n for n in nodes if not out.get(n)]
    base_paths = []
    for s in sources:
        for t in targets:
            if s != t:
                base_paths.extend(all_simple_paths(graph, s, t))
    base = len(base_paths)
    scored = []
    for node in nodes:
        if node in sources or node in targets:
            continue
        remain = 0
        for s in sources:
            for t in targets:
                if s != t:
                    remain += len(all_simple_paths(graph, s, t, exclude={node}))
        scored.append({"node": node, "eliminated_paths": base - remain,
                       "remaining_paths": remain, "base_paths": base})
    scored.sort(key=lambda x: (-x["eliminated_paths"], x["node"]))
    return scored[:max(1, int(top))]


def query(graph: dict, node: str, *, direction: str = "out", depth: int = 1) -> dict:
    out, inc, _nodes = adjacency(graph)
    if direction not in ("out", "in", "both"):
        raise PathError("direction 须为 out/in/both")
    adj: dict[str, set[str]] = {}
    if direction in ("out", "both"):
        for k, v in out.items():
            adj.setdefault(k, set()).update(v)
    if direction in ("in", "both"):
        for k, v in inc.items():
            adj.setdefault(k, set()).update(v)
    seen = {node}
    frontier = [node]
    levels = []
    for d in range(1, max(1, int(depth)) + 1):
        nxt = []
        for cur in frontier:
            for v in sorted(adj.get(cur, ())):
                if v not in seen:
                    seen.add(v)
                    nxt.append(v)
        levels.append({"depth": d, "nodes": nxt})
        frontier = nxt
        if not frontier:
            break
    return {"node": node, "direction": direction, "levels": levels,
            "count": len(seen) - 1}


def stats(graph: dict) -> dict:
    out, inc, nodes = adjacency(graph)
    return {"nodes": len(nodes), "edges": sum(len(v) for v in out.values()),
            "sources": sum(1 for n in nodes if not inc.get(n)),
            "sinks": sum(1 for n in nodes if not out.get(n)),
            "isolated": sum(1 for n in nodes if not out.get(n) and not inc.get(n))}
