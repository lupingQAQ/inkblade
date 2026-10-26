# -*- coding: utf-8 -*-
"""自主度分级（L0-L3）/ 任务分解 / 重试回退策略——第三节产品化改进。

对标腾讯 Agent 渗透大赛参赛项目的共同经验（管理/执行/观察分层、黑板、
预算与终止条件外置），但**不照搬其自主执行边界**：Trident 的提议仍然只写
队列、不落地执行；本模块只回答「这批动作需要多少次人工确认、如何分阶段、
失败后是否值得重试」三个问题。

硬约束：
- 只在提议路径使用，纯函数、无 IO、无模块执行；
- 混合动作取最弱链路：一个不可逆写动作即可把整批降到 L1；
- 重试只对瞬时错误生效；闸门/越权/预算类错误立即停止或降级。
"""

from __future__ import annotations

from typing import Any

LEVELS = ("L0", "L1", "L2", "L3")

AUTONOMY = {
    "L0": {
        "key": "L0",
        "label": "观察",
        "summary": "只读观察与证据整理；不产生任何执行动作。",
        "approval": "none",
        "max_actions": 0,
        "auto_readonly": False,
    },
    "L1": {
        "key": "L1",
        "label": "建议",
        "summary": "逐动作人工确认；不可逆写动作必须单独预览与批准。",
        "approval": "per-action",
        "max_actions": 3,
        "auto_readonly": False,
    },
    "L2": {
        "key": "L2",
        "label": "监督执行",
        "summary": "按阶段批量批准；写动作需要备份闸门与回滚路径。",
        "approval": "batch",
        "max_actions": 8,
        "auto_readonly": False,
    },
    "L3": {
        "key": "L3",
        "label": "自治（只读）",
        "summary": "只读动作在一次计划批准后自动审计执行；写动作仍单独确认。",
        "approval": "batch",
        "max_actions": 12,
        "auto_readonly": True,
    },
}

STRATEGIES = ("phase", "dependency", "single")

_TRANSIENT = ("timeout", "timed out", "429", "rate limit", "502", "503", "504",
              "connection reset", "connection refused", "temporarily unavailable",
              "econnreset")
_PERMANENT = ("exit 91", "backup gate", "备份闸门", "consent", "未经授权", "403",
              "401", "forbidden", "denied", "scope", "越权", "out of scope")


class PolicyError(ValueError):
    """自主度/分解策略非法。"""


def _action_level(action: dict) -> dict:
    writes = bool(action.get("writes"))
    dry = action.get("dry_run") or {}
    backups = dry.get("backup_targets") or []
    if not writes:
        return {"level": "L3", "auto": True, "requires_human": False,
                "approval": "auto", "reason": "只读动作，可在计划批准后自动审计执行"}
    if backups:
        return {"level": "L2", "auto": False, "requires_human": False,
                "approval": "batch", "reason": "写动作具备备份目标，可阶段批量批准"}
    return {"level": "L1", "auto": False, "requires_human": True,
            "approval": "per-action", "reason": "不可逆写动作缺少备份目标，必须单独确认"}


def classify_action(action: dict) -> dict:
    """单个动作的能力档位（L3 只读 / L2 可回滚写 / L1 不可逆写）。"""
    if not isinstance(action, dict) or not action.get("module"):
        raise PolicyError(f"动作缺少 module: {action!r}")
    return _action_level(action)


def decide(actions: list[dict], *, requested: str | None = None) -> dict:
    """整批动作的有效自主度 = 最弱链路；给出审批次数与理由。"""
    if requested is not None and requested not in LEVELS:
        raise PolicyError(f"未知自主度 {requested!r}（可选 {LEVELS}）")
    if not actions:
        level = requested or "L0"
        return {"level": level, "approval_mode": AUTONOMY[level]["approval"],
                "approval_count": 0, "requires_human": False,
                "reason": "无动作", "actions": []}

    graded = [classify_action(a) for a in actions]
    weakest = min(graded, key=lambda g: LEVELS.index(g["level"]))["level"]
    level = weakest
    if requested is not None and LEVELS.index(requested) < LEVELS.index(level):
        level = requested
    mode = AUTONOMY[level]["approval"]
    if level == "L0":
        count = len(actions)
    elif mode == "batch":
        count = 1
    else:
        # L1：计划本身 1 次 + 每个不可逆写动作单独 1 次（只读动作随计划批）
        count = 1 + sum(1 for g in graded if g["requires_human"])
    requires_human = level == "L1" or any(g["requires_human"] for g in graded)
    return {
        "level": level,
        "label": AUTONOMY[level]["label"],
        "approval_mode": mode,
        "approval_count": count,
        "requires_human": requires_human,
        "reason": "; ".join(sorted({g["reason"] for g in graded})),
        "actions": [{"index": i, **g} for i, g in enumerate(graded)],
    }


def decompose(actions: list[dict], *, strategy: str = "phase") -> dict:
    """任务分解：phase（只读/写两段）/ dependency（每个写动作独占阶段）/ single。"""
    if strategy not in STRATEGIES:
        raise PolicyError(f"未知分解策略 {strategy!r}（可选 {STRATEGIES}）")
    if not actions:
        return {"strategy": strategy, "phases": [], "stages": 0}

    graded = [classify_action(a) for a in actions]
    reads = [i for i, g in enumerate(graded) if not actions[i].get("writes")]
    writes = [i for i, g in enumerate(graded) if actions[i].get("writes")]

    phases: list[dict] = []
    if strategy == "single":
        phases.append({"id": "phase-1", "name": "整批执行", "actions": list(range(len(actions))),
                       "auto": all(g["auto"] for g in graded),
                       "gate": any(actions[i].get("writes") for i in range(len(actions)))})
    elif strategy == "dependency":
        if reads:
            phases.append({"id": "phase-1", "name": "只读侦察", "actions": reads,
                           "auto": True, "gate": False})
        for n, idx in enumerate(writes, 1):
            phases.append({"id": f"phase-{len(phases) + 1}", "name": f"写步骤 {n}",
                           "actions": [idx], "auto": False, "gate": True})
    else:  # phase
        if reads:
            phases.append({"id": "phase-1", "name": "只读侦察", "actions": reads,
                           "auto": True, "gate": False})
        if writes:
            phases.append({"id": f"phase-{len(phases) + 1}", "name": "受控写验证",
                           "actions": writes, "auto": False, "gate": True})

    return {"strategy": strategy, "phases": phases, "stages": len(phases),
            "auto_actions": sum(len(p["actions"]) for p in phases if p["auto"]),
            "gated_actions": sum(len(p["actions"]) for p in phases if p["gate"])}


def retry_plan(error: Any, *, action: dict | None = None,
               attempted: set[str] | None = None) -> dict:
    """错误分类 → 重试/回退计划（有界，禁止无限重试）。"""
    text = str(error).lower()
    attempted = attempted or set()
    alternatives = [m for m in (action or {}).get("fallback") or [] if m not in attempted]

    if "budget" in text or "预算" in text or "quota" in text:
        return {"class": "budget", "attempts": 1, "backoff_ms": 0,
                "fallback": "degrade", "escalate": False,
                "reason": "预算超支：降级动作集而不是重试"}
    if any(k in text for k in _PERMANENT):
        return {"class": "permanent", "attempts": 1, "backoff_ms": 0,
                "fallback": "escalate", "escalate": True,
                "reason": "闸门/授权类错误：重试只会浪费预算，立即上报"}
    if isinstance(error, (TimeoutError, ConnectionError)) or any(k in text for k in _TRANSIENT):
        return {"class": "transient", "attempts": 2, "backoff_ms": 250,
                "fallback": alternatives[0] if alternatives else "same-action",
                "escalate": False,
                "reason": "瞬时错误：有界重试一次，仍失败则回退/上报"}
    if isinstance(error, ValueError) or any(k in text for k in ("schema", "invalid", "json")):
        return {"class": "invalid", "attempts": 1, "backoff_ms": 0,
                "fallback": "replan", "escalate": False,
                "reason": "输出不可解析：重新规划而不是重复同一调用"}
    return {"class": "permanent", "attempts": 1, "backoff_ms": 0,
            "fallback": alternatives[0] if alternatives else "escalate",
            "escalate": True, "reason": "未知错误按不可重试处理（保守）"}
