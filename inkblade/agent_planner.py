# -*- coding: utf-8 -*-
"""Agent 规划器（只读）：读证据库 + 链前置 → 推荐链排序与理由。

硬边界（测试锁定）：
- 只读：不创建 run、不写 actions / backups / rollbacks，不调用 chains.execute / runner；
- 推荐结果永远 ``approval.status = "pending"``，审批角色固定 lead；
- 执行触发固定为 human（``execution.performed = false``）。
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from .core.chains import dry_run, evaluate_preconditions, load_chains
from .core.evidence import EvidenceStore

SCHEMA = "inkblade-agent-plan-v1"


def _runs(store: EvidenceStore) -> list[str]:
    """真实 run 目录 = 含 evidence.db 的目录（排除 explorer/ 等工作区级目录）。"""
    if not store.ws_dir.exists():
        return []
    return sorted(p.name for p in store.ws_dir.iterdir()
                  if p.is_dir() and not p.name.startswith("_")
                  and (p / "evidence.db").is_file())


def latest_run(store: EvidenceStore) -> str | None:
    runs = _runs(store)
    if not runs:
        return None
    return max(runs, key=lambda name: (store.ws_dir / name).stat().st_mtime)


def _chain_dir(chains_dir: Path | str | None) -> Path:
    return Path(chains_dir) if chains_dir else Path(__file__).resolve().parent / "chains"


def _score(verdict: str, satisfied: int, missing: int, writes: int, requires: int) -> int:
    base = {"成立": 300, "部分成立": 150, "不成立": 0}.get(verdict, 0)
    return base + satisfied * 10 - missing * 2 - writes * 3 + min(requires, 5)


def _reasons(chain: dict, plan: dict, verdict: str, missing: list[str],
             satisfied: int, total: int, writes: int) -> dict[str, list[str]]:
    zh = [f"前置判定：{verdict}（满足 {satisfied}/{total} 条）"]
    en = [f"Preconditions: {verdict} ({satisfied}/{total} satisfied)"]
    if missing:
        zh.append(f"缺失 {len(missing)} 条前置：{'; '.join(missing[:3])}"
                  + (" …" if len(missing) > 3 else ""))
        en.append(f"{len(missing)} missing precondition(s): {'; '.join(missing[:3])}"
                  + (" …" if len(missing) > 3 else ""))
    if writes:
        zh.append(f"含 {writes} 个写类步骤：执行前须取得备份回执（备份闸门，缺失即拒绝，退出码 91）")
        en.append(f"{writes} write step(s): backup receipts are mandatory before execution "
                  f"(backup gate refuses without them, exit code 91)")
    else:
        zh.append("全部步骤只读，无写面")
        en.append("All steps are read-only; no write surface")
    zh.append(f"证据锚：{len(plan.get('evidence', []))} 类证据需落库；"
              f"MITRE {', '.join(plan.get('mitre', [])) or '—'}")
    en.append(f"Evidence anchors: {len(plan.get('evidence', []))} categories; "
              f"MITRE {', '.join(plan.get('mitre', [])) or '-'}")
    if chain.get("requires"):
        zh.append(f"依赖侦察模块：{', '.join(chain['requires'])}")
        en.append(f"Required recon modules: {', '.join(chain['requires'])}")
    return {"zh": zh, "en": en}


def _policy_actions(steps: list[dict]) -> list[dict]:
    return [{"module": s.get("module"), "writes": bool(s.get("writes")),
             "dry_run": {"backup_targets": list(s.get("backup_targets") or [])}}
            for s in steps]


def _policy_summary(steps: list[dict]) -> dict:
    from .core import agent_policy
    decided = agent_policy.decide(_policy_actions(steps))
    return {k: decided[k] for k in ("level", "label", "approval_mode",
                                    "approval_count", "requires_human", "reason")}


def _cost_summary(steps: list[dict]) -> dict:
    from .core import cost
    plan = cost.plan_cost(_policy_actions(steps))
    return {**plan, "pricing": "确定性估算（4 字符/token）；非真实账单"}


def _summarize_steps(plan: dict) -> list[dict]:
    out = []
    for step in plan.get("steps", []):
        out.append({
            "id": step.get("id"),
            "module": step.get("module"),
            "writes": bool(step.get("writes")),
            "backup_targets": step.get("backup_targets", []),
            "write_surface": step.get("write_surface", []),
            "gate": step.get("gate", ""),
            "status": step.get("status", "ready"),
            "applicability": {
                "state": (step.get("applicability") or {}).get("state"),
                "gated": (step.get("applicability") or {}).get("gated", False),
                "cves": (step.get("applicability") or {}).get("cves", []),
            },
        })
    return out


def plan_workspace(
    store: EvidenceStore,
    *,
    run: str | None = None,
    chains_dir: Path | str | None = None,
    modules_dir: Path | str | None = None,
    policy: bool | None = None,
    inventory: dict | None = None,
    catalog_path: str | Path | None = None,
    assessment: dict | None = None,
) -> dict:
    """生成推荐计划；只读，不落任何 actions/run。

    ``policy=False``（或 env ``INKBLADE_AGENT_POLICY=off``）精确复现 HEAD 的
    计划字段；ON 为每个候选附加自主度/审批次数与成本估算（仍不执行）。
    ``inventory`` 提供时，候选链在规划前先做 CVE 适用性评估（blocked/unknown
    步骤不会进入可执行面），计划里带 applicability 依据。
    """
    from .core.explorer import policy_enabled

    policy_on = policy_enabled(policy)
    if assessment is None and inventory is not None:
        from .core.applicability import assess_cves

        assessment = assess_cves(inventory, catalog_path=catalog_path)
    runs = _runs(store)
    run_name = run or latest_run(store)
    if modules_dir is None:
        candidate = store.root / "modules"
        modules_dir = candidate if candidate.exists() else None
    findings: list[dict] = []
    if run_name is not None:
        findings = store.open_run(run_name).findings  # KeyError 向上抛出（未知 run）
    chains = load_chains(_chain_dir(chains_dir))

    candidates: list[dict] = []
    for chain in chains.values():
        verdict, missing = evaluate_preconditions(chain, findings)
        total = len(chain.get("preconditions", []))
        satisfied = total - len(missing)
        plan = dry_run(chain, findings, modules_dir, applicability=assessment)
        writes = sum(1 for step in plan.get("steps", []) if step.get("writes"))
        steps = _summarize_steps(plan)
        blocked_steps = [s for s in plan.get("steps", []) if s.get("status") == "blocked"]
        candidate = {
            "chain": chain["id"],
            "title": chain.get("title", {}),
            "category": chain.get("category", ""),
            "verdict": verdict,
            "missing": missing,
            "satisfied": satisfied,
            "preconditions": total,
            "score": _score(verdict, satisfied, len(missing), writes, len(chain.get("requires", []))),
            "writes": writes,
            "requires": list(chain.get("requires", [])),
            "mitre": list(chain.get("mitre", [])),
            "reasons": _reasons(chain, plan, verdict, missing, satisfied, total, writes),
            "steps": steps,
            "applicability": {
                "evaluated": assessment is not None,
                "summary": (assessment or {}).get("summary") or {},
                "catalog": (assessment or {}).get("catalog") or {},
                "inventory": (assessment or {}).get("inventory") or {},
                "blocked_steps": [s.get("module") for s in blocked_steps],
                "basis": plan.get("applicability_basis") or [],
            },
            "execution": {
                "trigger": "human",
                "performed": False,
                "approval_required": True,
                "note_zh": "规划器不执行；lead 审批后由人触发 chains.execute。",
                "note_en": "The planner never executes; after lead approval a human triggers chains.execute.",
            },
        }
        if policy_on:
            candidate["policy"] = _policy_summary(steps)
            candidate["cost"] = _cost_summary(steps)
        candidates.append(candidate)
    candidates.sort(key=lambda c: (-c["score"], c["chain"]))
    for i, cand in enumerate(candidates, 1):
        cand["rank"] = i

    return {
        "schema": SCHEMA,
        "workspace": store.workspace,
        "run": run_name,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "read_only": True,
        "writes": {"actions": 0, "runs": 0, "backups": 0},
        "evidence": {
            "runs": len(runs),
            "findings": len(findings),
            "run_names": runs,
        },
        "approval": {
            "required": True,
            "approver_role": "lead",
            "status": "pending",
            "approved_by": None,
            "approved_at": None,
            "reason_zh": "全部候选链默认待审批：lead 审核范围/级别/写面后再由人触发执行。",
            "reason_en": "Every candidate is pending: lead reviews scope/level/write surface before human-triggered execution.",
        },
        "execution": {
            "trigger": "human",
            "performed": False,
            "note_zh": "本命令只输出计划（plan-only）。",
            "note_en": "This command only emits a plan (plan-only).",
        },
        **( {"agent_policy": {"engine": "inkblade.agent_policy", "enabled": True,
                              "hard_boundary": "plan-only；审批后由人触发"}}
           if policy_on else {} ),
        "candidates": candidates,
    }


def render_plan_md(plan: dict) -> str:
    """人类可读计划（Markdown，中英对照）。"""
    lines = [
        "# InkBlade 仅规划 Agent Plan（只读 / plan-only）",
        "",
        f"- 工作区 Workspace: **{plan.get('workspace')}**",
        f"- 证据 Run: **{plan.get('run') or '（无）'}**",
        f"- 发现 Findings: {plan.get('evidence', {}).get('findings', 0)}",
        f"- 审批 Approval: **{plan.get('approval', {}).get('status')}** · "
        f"审批角色 {plan.get('approval', {}).get('approver_role')}",
        f"- 执行 Execution: {plan.get('execution', {}).get('trigger')} 触发 · "
        f"performed={plan.get('execution', {}).get('performed')}",
        "",
        "| # | 链 Chain | 类别 Category | 判定 Verdict | 分数 Score | 写步骤 Writes | 理由（中） | Reason (EN) |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for c in plan.get("candidates", []):
        title = c.get("title", {})
        lines.append(
            f"| {c['rank']} | {c['chain']} | {c.get('category', '')} | {c['verdict']} "
            f"| {c['score']} | {c['writes']} | {'; '.join(c['reasons']['zh'])} "
            f"| {'; '.join(c['reasons']['en'])} |"
        )
    lines += [
        "",
        "> 只读：规划器不写入 actions/run，不执行任何模块；候选链须经 lead 审批后由人触发。",
        "> Read-only: the planner writes no actions/runs and executes nothing; lead approval is required before human-triggered execution.",
    ]
    return "\n".join(lines)
