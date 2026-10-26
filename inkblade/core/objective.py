"""Objective 编排：把「cluster-takeover」等目标拆成阶段，并在阶段③（提权）前自动选路。

核心约束（与任务一致）：
- 阶段③执行前调用 ``privesc.paths``，按权重/跳数选择最短可行提权路径；
- 记录选择理由、备选路径、每条边的检测键；
- 路径执行失败时自动回退下一条路径，并把尝试/失败原因写入结果与报告；
- 报告输出「提权面 + 提权路径图 + 选择依据」，不隐藏回退与失败。

默认 ``execute_objective`` 为 plan-only（不真正调用模块）；注入 executor 时按步骤执行，
仍由 runner 的 ROE/范围/备份闸门做最终约束。
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, Callable

from .privesc import (
    GRANT_VECTOR,
    PrivescGraph,
    PrivescPath,
    PrivescError,
    distinct_vectors,
    explain,
    load_matrix,
    render_path_mermaid,
)


class NoPathError(PrivescError):
    """从当前主体到目标没有可行提权路径。"""


OBJECTIVES: dict[str, dict] = {
    "cluster-takeover": {
        "key": "cluster-takeover",
        "title": {"zh": "ML 集群接管", "en": "ML cluster takeover"},
        "target": "cluster-admin",
        "phases": [
            {
                "id": "recon", "index": 1,
                "title": {"zh": "侦察与主体枚举", "en": "Recon and principal enumeration"},
                "modules": ["rbac-mapping", "privileged-workloads", "kubelet-api-surface"],
            },
            {
                "id": "foothold", "index": 2,
                "title": {"zh": "初始立足点", "en": "Initial foothold"},
                "modules": ["overprivileged-sa-escalation"],
            },
            {
                "id": "privesc", "index": 3,
                "title": {"zh": "提权到 cluster-admin", "en": "Escalate to cluster-admin"},
                "dynamic": "privesc",
            },
            {
                "id": "impact", "index": 4,
                "title": {"zh": "影响验证与报告", "en": "Impact verification and reporting"},
                "modules": [],
            },
        ],
    },
}


def _ids(doc: Any) -> list[str]:
    if doc is None:
        return []
    if hasattr(doc, "vector_ids"):
        return list(dict.fromkeys(doc.vector_ids))
    return list(dict.fromkeys(doc.get("vector_ids", [])))


def _pick_principal(graph: PrivescGraph, from_principal: str | None) -> str:
    if from_principal:
        return from_principal
    for p in graph.principals:
        if p.cluster_admin:
            continue
        if p.capabilities:
            return p.id
    if graph.principals:
        return graph.principals[0].id
    raise NoPathError("没有可用的起始主体：快照未推断出任何 principal")


def _path_steps(path: PrivescPath) -> list[dict]:
    steps: list[dict] = []
    seen: set[str] = set()
    for edge in path.edges:
        if edge.vector == GRANT_VECTOR or edge.vector in seen:
            continue
        seen.add(edge.vector)
        steps.append({
            "id": f"privesc-{len(steps) + 1}",
            "vector": edge.vector,
            "module": edge.module,
            "primitive": edge.primitive,
            "requires": list(edge.requires),
            "detection": edge.detection,
            "weight": edge.weight,
            "from": edge.src,
            "to": edge.dst,
        })
    return steps


def _rationale(chosen: PrivescPath, alternates: list[PrivescPath]) -> str:
    vectors = " → ".join(distinct_vectors(chosen))
    return (
        f"按总权重优先选择路径 `{vectors}`：权重 {chosen.weight:g} (weight)、{chosen.hops} 步；"
        f"备选 {len(alternates)} 条。排序规则：总权重 → 跳数 → 向量 id 字典序（稳定）；"
        "每条边的模块均已在注册表登记；执行失败时按备选顺序回退。"
    )


def plan_objective(objective: str = "cluster-takeover", *,
                   snapshot: dict | str | Path | None = None,
                   from_principal: str | None = None,
                   limit: int = 4, mode: str = "weight",
                   matrix: dict | None = None) -> dict:
    """生成 objective 计划：阶段③前选路，记录理由/备选。"""
    if objective not in OBJECTIVES:
        raise ValueError(f"未知 objective: {objective}")
    obj = copy.deepcopy(OBJECTIVES[objective])
    m = matrix or load_matrix()
    if isinstance(snapshot, (str, Path)):
        from .privesc import load_snapshot

        snapshot = load_snapshot(snapshot)
    graph = PrivescGraph(m, snapshot=snapshot or {})
    principal = _pick_principal(graph, from_principal)
    try:
        candidates = graph.paths(principal, to=obj["target"], limit=limit, mode=mode)
    except Exception as exc:
        raise NoPathError(f"无法为 {principal} 选择提权路径：{exc}") from exc
    if not candidates:
        inferred = next((p for p in graph.principals if p.id == principal), None)
        caps = ", ".join(inferred.capabilities) if inferred else "（无）"
        raise NoPathError(
            f"主体 {principal} 没有到 {obj['target']} 的可行提权路径；"
            f"已推断权限: {caps}。建议先补做 RBAC/工作负载/节点侦察，或更换起始主体。")
    chosen, alternates = candidates[0], candidates[1:]
    phases = obj["phases"]
    for phase in phases:
        if phase.get("dynamic") == "privesc":
            phase["status"] = "ready"
            phase["selection"] = {
                "from": principal,
                "to": obj["target"],
                "mode": mode,
                "limit": limit,
                "chosen": chosen.to_dict(),
                "alternates": [p.to_dict() for p in alternates],
                "rationale": _rationale(chosen, alternates),
                "explanation": explain(chosen),
            }
            phase["plans"] = [
                {"path": p.to_dict(), "steps": _path_steps(p)}
                for p in candidates
            ]
        else:
            phase["status"] = "planned"
            phase["steps"] = [{"module": key, "params": {}} for key in phase.get("modules", [])]
    return {
        "objective": objective,
        "title": obj["title"],
        "target": obj["target"],
        "principal": principal,
        "phases": phases,
        "summary": (
            f"{obj['title']['zh']}：{len(phases)} 阶段；阶段③选择提权路径 "
            f"`{' → '.join(_ids(chosen))}`（权重 {chosen.weight:g}/{chosen.hops} 步）；"
            f"备选 {len(alternates)} 条"
        ),
        "graph": graph.to_dict(),
        "matrix_summary": {
            "vectors": len(m.get("vectors", [])),
            "edges": len(graph.edges),
            "nodes": len(graph.nodes),
        },
    }


def _attempt_path(phase: dict, entry: dict, executor: Callable[[dict, dict], Any],
                  attempt_no: int) -> dict:
    steps = entry.get("steps") or []
    row: dict[str, Any] = {
        "attempt": attempt_no,
        "path": entry.get("path"),
        "steps_total": len(steps),
        "status": "success",
        "executed": [],
    }
    for step in steps:
        try:
            outcome = executor(step, phase) if executor else {"status": "planned"}
            if isinstance(outcome, dict) and str(outcome.get("status", "")).lower() in ("failed", "error"):
                raise RuntimeError(str(outcome.get("error") or "executor returned failed"))
            row["executed"].append({"vector": step["vector"], "module": step["module"],
                                    "status": "success",
                                    "evidence": (outcome or {}).get("evidence") if isinstance(outcome, dict) else None})
        except Exception as exc:
            row["status"] = "failed"
            row["failed_step"] = step
            row["error"] = f"{type(exc).__name__}: {exc}"
            return row
    return row


def execute_objective(plan: dict, *,
                      executor: Callable[[dict, dict], Any] | None = None) -> dict:
    """执行 objective：阶段③按选路顺序尝试，失败回退下一条；其余阶段记录 planned。"""
    if not isinstance(plan, dict) or "phases" not in plan:
        raise ValueError("execute_objective 需要 plan_objective 的返回值")
    phases = plan["phases"]
    privesc_phase = next((p for p in phases if p.get("index") == 3), None)
    if privesc_phase is None:
        raise ValueError("objective 缺少阶段③（提权）")
    attempts: list[dict] = []
    selected: dict | None = None
    original = ((privesc_phase.get("selection") or {}).get("chosen") or {})
    for i, entry in enumerate(privesc_phase.get("plans") or [], 1):
        row = _attempt_path(privesc_phase, entry, executor, i)
        attempts.append(row)
        if row["status"] == "success":
            selected = entry.get("path")
            break
    ok = selected is not None
    fallback_used = bool(ok and selected and selected.get("vector_ids") != original.get("vector_ids"))
    result = {
        "ok": ok,
        "objective": plan.get("objective"),
        "title": plan.get("title"),
        "principal": plan.get("principal"),
        "target": plan.get("target"),
        "plan": plan,
        "attempts": attempts,
        "selected_path": selected,
        "fallback_used": fallback_used,
        "phases": [
            {"index": p.get("index"), "id": p.get("id"), "status": p.get("status"),
             "title": p.get("title")}
            for p in phases
        ],
        "executor": "custom" if executor else "plan-only",
    }
    result["report"] = render_objective_report(result)
    return result


def render_objective_report(result: dict) -> str:
    """输出「提权面 + 提权路径图 + 选择依据 + 执行/回退」。"""
    plan = result.get("plan") if isinstance(result, dict) and "plan" in result else result
    if plan is None:
        raise ValueError("render_objective_report 需要 plan 或 execute_objective 结果")
    phases = plan.get("phases") or []
    phase3 = next((p for p in phases if p.get("index") == 3), None)
    selection = (phase3 or {}).get("selection") or {}
    chosen = selection.get("chosen") or {}
    alternates = selection.get("alternates") or []
    principal = plan.get("principal", "")
    lines = [
        "# InkBlade Objective 报告",
        "",
        f"- Objective：`{plan.get('objective', '?')}` — {plan.get('title', {}).get('zh', '')}",
        f"- 起始主体：`{principal}`；目标：`{plan.get('target', '?')}`",
        f"- 阶段：{len(phases)}（侦察 → 立足 → 提权 → 影响）",
        f"- 结论：{'成功' if result.get('ok') else ('计划就绪（未执行）' if 'attempts' not in result else '失败')}",
        "",
        "## 提权面",
        "",
        f"- 选中路径：`{' → '.join(_ids(chosen)) or '（已是管理员/无路径）'}`",
        f"- 权重 {chosen.get('weight', 0)}，{chosen.get('hops', 0)} 步；备选 {len(alternates)} 条",
        f"- 当前主体权限与路径步骤见下方路径图与选择依据。",
        "",
        "### 提权路径图",
        "",
    ]
    # 用 Path 对象重建 Mermaid（plan 里是 dict）
    path_obj = _path_from_dict(chosen)
    if path_obj is not None:
        lines += render_path_mermaid(path_obj).splitlines()
        lines += ["", explain(path_obj), ""]
    else:
        lines += ["（无提权路径）", ""]
    lines += ["### 选择依据", ""]
    lines.append(selection.get("rationale") or "无选择理由（路径为空）")
    lines += ["", "### 备选路径", ""]
    if alternates:
        for i, alt in enumerate(alternates, 1):
            lines.append(f"{i}. 权重 {alt.get('weight')} / {alt.get('hops')} 步："
                         f"`{' → '.join(_ids(alt))}`")
    else:
        lines.append("（无备选；当前主体可能已是 cluster-admin）")
    lines += ["", "### 检测键", ""]
    for edge in chosen.get("edges", []):
        if edge.get("vector") == GRANT_VECTOR:
            continue
        lines.append(f"- `{edge.get('vector')}` → {edge.get('detection', '')}")
    lines += ["", "### 执行与回退", ""]
    if "attempts" not in result:
        lines.append("- 当前为 plan-only：未执行模块；执行前需通过 ROE/范围/备份闸门。")
    else:
        for row in result.get("attempts", []):
            vec = " → ".join(_ids(row.get("path") or {}))
            if row.get("status") == "success":
                lines.append(f"- 尝试 {row.get('attempt')}: `{vec}` → 成功")
            else:
                failed = (row.get("failed_step") or {}).get("vector", "?")
                lines.append(f"- 尝试 {row.get('attempt')}: `{vec}` → 失败于 `{failed}`；"
                             f"回退下一条（原因：{row.get('error', '')}）")
        lines.append(f"- 最终选择：`{' → '.join(_ids(result.get('selected_path') or {})) or '无'}`；"
                     f"是否使用回退：{'是' if result.get('fallback_used') else '否'}")
    lines += ["", "### 执行边界", "",
              "本报告是授权关系/原语推演 + 计划；真实执行需 `--allow-write`、ROE 级别、"
              "范围与备份闸门同时通过，且失败步骤会留下审计与回退记录。", ""]
    return "\n".join(lines)


def _path_from_dict(doc: dict) -> PrivescPath | None:
    if not doc or not doc.get("nodes"):
        return None
    from .privesc import Edge, Node

    nodes = tuple(Node(n["id"], n["kind"], n["label"]) for n in doc["nodes"])
    edges = []
    for e in doc.get("edges", []):
        edges.append(Edge(
            src=e["src"], dst=e["dst"], vector=e["vector"], vector_title=e.get("title", ""),
            primitive=e.get("primitive", ""), requires=tuple(e.get("requires", [])),
            evidence=e.get("evidence", ""), detection=e.get("detection", ""),
            weight=float(e.get("weight", 1.0)), module=e.get("module", ""),
            kind=e.get("kind", "attack"),
        ))
    return PrivescPath(nodes, tuple(edges))


# ---------------------------------------------------------------------------
# Cluster-takeover objective chain (separate planner above; shared public
# module name).  Implemented in ``objective_chain`` to keep the privesc
# planner and the real-cluster proof engine independent.
# ---------------------------------------------------------------------------
from .objective_chain import (  # noqa: E402,F401
    CHAIN_ID,
    FakeKubectlBackend,
    GateRefused,
    KubectlBackend,
    ObjectiveCancelled,
    ObjectiveError,
    StageFailed,
    check_gates,
    load_objective,
    normalize_marker,
    render_report,
    run_objective,
    write_report,
)

__all__ = [
    "OBJECTIVES", "NoPathError", "plan_objective", "execute_objective",
    "render_objective_report",
    "CHAIN_ID", "FakeKubectlBackend", "GateRefused", "KubectlBackend",
    "ObjectiveCancelled", "ObjectiveError", "StageFailed", "check_gates",
    "load_objective", "normalize_marker", "render_report", "run_objective",
    "write_report",
]
