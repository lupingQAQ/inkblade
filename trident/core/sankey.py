# -*- coding: utf-8 -*-
"""Sankey 攻击路径图 + 系统性修复优先级（CM-19）。

- 输入图快照（nodes/edges）；默认 source=入度 0 节点，sink=出度 0 节点，也可显式指定；
- 枚举有界简单路径 → 计算节点/边在路径中的出现次数，生成 Sankey 三层数据
  （stage=路径中的最小层号，value=经过该节点的路径数）；
- ``fix_priority``：对每个中间节点计算“移除后减少的路径数”，量化“修一处消多少路径”；
  与 ``pathcalc.critical_nodes`` 同口径，但输出直接面向报告；
- 无路径/空图返回结构化空结果，不抛异常（报告可继续渲染）。
"""

from __future__ import annotations

from . import pathcalc


def analyze(snapshot: dict, *, sources: list[str] | None = None,
            targets: list[str] | None = None, max_paths: int = 200,
            max_depth: int = 8, top_fixes: int = 10) -> dict:
    graph = snapshot if isinstance(snapshot, dict) else {}
    out, inc, nodes = pathcalc.adjacency(graph)
    sources = sources or [n for n in nodes if not inc.get(n)]
    targets = targets or [n for n in nodes if not out.get(n)]
    paths: list[list[str]] = []
    for s in sources:
        for t in targets:
            if s == t:
                continue
            remain = max_paths - len(paths)
            if remain <= 0:
                break
            paths.extend(pathcalc.all_simple_paths(graph, s, t, max_paths=remain,
                                                   max_depth=max_depth))
    paths = paths[:max_paths]
    node_value: dict[str, int] = {}
    node_stage: dict[str, int] = {}
    links: dict[tuple[str, str], int] = {}
    for path in paths:
        for i, n in enumerate(path):
            node_value[n] = node_value.get(n, 0) + 1
            node_stage[n] = min(node_stage.get(n, i), i)
            if i + 1 < len(path):
                links[(n, path[i + 1])] = links.get((n, path[i + 1]), 0) + 1
    sankey_nodes = [{"id": n, "stage": node_stage[n], "value": node_value[n]}
                    for n in sorted(node_value, key=lambda x: (node_stage[x], x))]
    sankey_links = [{"source": s, "target": t, "value": v}
                    for (s, t), v in sorted(links.items(), key=lambda x: (-x[1], x[0]))]
    fixes = []
    if paths:
        base = len(paths)
        for node in sorted(node_value):
            if node in sources or node in targets:
                continue
            remain = 0
            for s in sources:
                for t in targets:
                    if s == t:
                        continue
                    remain += len(pathcalc.all_simple_paths(graph, s, t, exclude={node},
                                                            max_paths=max_paths))
            fixes.append({"node": node, "base_paths": base, "remaining_paths": remain,
                          "eliminated_paths": max(0, base - remain),
                          "eliminated_ratio": round(max(0, base - remain) / base, 3)})
        fixes.sort(key=lambda x: (-x["eliminated_paths"], x["node"]))
    return {
        "paths": paths, "path_count": len(paths),
        "sources": sources, "targets": targets,
        "nodes": sankey_nodes, "links": sankey_links,
        "fix_priority": fixes[:max(1, int(top_fixes))],
        "stats": {"nodes": len(nodes), "edges": sum(len(v) for v in out.values()),
                  "path_nodes": len(node_value), "path_links": len(sankey_links)},
        "note": "" if paths else "无可枚举的攻击路径（入口/目标不连通或环导致无简单路径）",
    }


def render_md(result: dict) -> str:
    lines = [f"# 攻击路径 Sankey（{result.get('path_count', 0)} 条路径）", ""]
    if result.get("note"):
        lines.append(f"> {result['note']}")
    lines += ["## 修复优先级", "", "| 节点 | 消除路径 | 占比 | 剩余 |", "|---|---|---|---|"]
    for f in result.get("fix_priority", []):
        lines.append(f"| {f['node']} | {f['eliminated_paths']} | {f['eliminated_ratio']} "
                     f"| {f['remaining_paths']} |")
    lines += ["", "## 路径", ""]
    for p in result.get("paths", [])[:20]:
        lines.append("- " + " → ".join(p))
    return "\n".join(lines) + "\n"
