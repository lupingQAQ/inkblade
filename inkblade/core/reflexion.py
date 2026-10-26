# -*- coding: utf-8 -*-
"""运行后自反思（reflexion）：失败/降级步骤 → 改进建议 → 审批入技能库，**零执行**。

输入只读 evidence DB（actions/steps/findings）；输出建议不触发任何模块、不建 run、
不写 actions。``propose_skill`` 也只是向技能库提交 pending 记录，入库仍需 lead 批准。
"""

from __future__ import annotations

import json
import time

FAILED_PREFIX = "failed"


def _classify(result: str) -> str:
    text = (result or "").lower()
    if "backupgaterefused" in text or "refused-no-backup" in text or "备份" in text:
        return "backup-gate"
    if text.startswith(FAILED_PREFIX):
        return "execution-failed"
    return "degraded"


def reflect(run, *, max_suggestions: int = 5) -> dict:
    """分析一次 run：失败/降级步骤 → 结构化建议（不执行任何动作）。"""
    actions = run.query(
        "SELECT action, target, result, params FROM actions ORDER BY id")
    steps = run.query("SELECT step_key, result_summary FROM steps ORDER BY id")
    findings = run.findings

    failures: list[dict] = []
    for action, target, result, params in actions:
        text = str(result or "")
        if not (text.startswith(FAILED_PREFIX) or "refused" in text.lower()
                or "BackupGate" in text):
            continue
        failures.append({
            "step": target or action,
            "kind": _classify(text),
            "result": text[:300],
            "params": _safe_params(params),
        })

    degraded: list[dict] = []
    with_findings = {f.get("step_key") for f in findings}
    for step_key, summary in steps:
        if step_key in with_findings:
            continue
        degraded.append({"step": step_key, "reason": "步骤无发现（可能前置不足/目标不可达）",
                         "summary": (summary or "")[:200]})

    suggestions: list[dict] = []
    for failure in failures:
        if failure["kind"] == "backup-gate":
            suggestions.append({
                "action": f"为 {failure['step']} 补齐 backup_targets 并先跑 dry-run 复核写面",
                "rationale": "写类动作缺备份回执会被 runner 以退出码 91 拒绝；先备份再执行符合三闸门",
                "refs": [failure["step"]],
            })
        else:
            suggestions.append({
                "action": f"用 probe-only 参数复现 {failure['step']} 并抓取审计中的失败摘要",
                "rationale": "失败多为参数/目标面问题；只读探测可区分能力缺失与环境不可达",
                "refs": [failure["step"]],
            })
    if degraded and len(suggestions) < max_suggestions:
        suggestions.append({
            "action": "先跑只读前置（discovery/exposure-mapping）再把命中资产绑定到后续动作",
            "rationale": "零发现步骤通常缺资产上下文或 ROE 级别不足，前置结果可作为参数来源",
            "refs": sorted({d["step"] for d in degraded}),
        })
    if not failures and not degraded:
        suggestions.append({
            "action": "将该 run 的步骤序列固化为 playbook，纳入回归基线与周期调度",
            "rationale": "全步骤成功且零降级，适合作为可复用技能与漂移基线",
            "refs": [s[0] for s in steps],
        })
    suggestions = suggestions[:max_suggestions]

    playbook = []
    for step_key, summary in steps:
        playbook.append({
            "module": step_key,
            "params": {},
            "writes": False,
            "min_level": "",
            "evidence": {"summary": summary or "",
                         "findings": sum(1 for f in findings if f.get("step_key") == step_key)},
        })

    return {
        "run": run.name,
        "created_at": time.time(),
        "executed": False,
        "healthy": not failures and not degraded,
        "failures": failures,
        "degraded": degraded,
        "suggestions": suggestions,
        "playbook": playbook,
        "metrics": {
            "steps": len(steps),
            "findings": len(findings),
            "failures": len(failures),
            "degraded": len(degraded),
            "suggestions": len(suggestions),
        },
    }


def _safe_params(raw) -> dict:
    try:
        value = json.loads(raw) if isinstance(raw, str) else (raw or {})
    except ValueError:
        return {}
    if not isinstance(value, dict):
        return {}
    return {k: v for k, v in value.items() if k not in ("backup_targets", "token", "password")}


def propose_skill(reflection: dict, library, session, *, name: str = "") -> dict:
    """把反思结论转为 pending 技能（入库仍需 lead approve）。"""
    if reflection.get("executed") is not False:
        raise ValueError("reflection 必须来自零执行分析（executed=False）")
    playbook = list(reflection.get("playbook") or [])
    if not playbook:
        raise ValueError("reflection 无可用步骤，无法生成技能")
    skill_name = name or f"reflect-{reflection.get('run', 'run')}"
    skill = {
        "name": skill_name,
        "playbook": playbook,
        "source": "reflexion",
        "source_run": reflection.get("run", ""),
        "notes": [s["action"] for s in reflection.get("suggestions", [])],
    }
    return library.submit(session, skill)


def render_md(reflection: dict) -> str:
    lines = [
        f"# Reflexion — {reflection.get('run', '')}",
        "",
        f"- 健康: {'是' if reflection.get('healthy') else '否'}",
        f"- 步骤 {reflection['metrics']['steps']} / 发现 {reflection['metrics']['findings']} / "
        f"失败 {reflection['metrics']['failures']} / 降级 {reflection['metrics']['degraded']}",
        "- 零执行保证: reflection.executed=False",
        "",
        "## 失败与降级",
    ]
    for failure in reflection.get("failures", []):
        lines.append(f"- [{failure['kind']}] {failure['step']}: {failure['result']}")
    for item in reflection.get("degraded", []):
        lines.append(f"- [降级] {item['step']}: {item['reason']}")
    if not reflection.get("failures") and not reflection.get("degraded"):
        lines.append("- 无")
    lines += ["", "## 改进建议"]
    for i, suggestion in enumerate(reflection.get("suggestions", []), 1):
        lines.append(f"{i}. {suggestion['action']} — {suggestion['rationale']}"
                     f"（refs: {', '.join(suggestion['refs']) or '-'}）")
    return "\n".join(lines) + "\n"
