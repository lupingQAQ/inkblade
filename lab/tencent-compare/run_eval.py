# -*- coding: utf-8 -*-
"""腾讯 Agent 渗透大赛对比 · 策略级微评测（OFF = HEAD 行为 / ON = 第三节改进）。

为什么是「策略级」：参赛项目的能力差距集中在编排层（任务分解、审批点、
错误恢复、成本预算、证据可追溯），而不是某个漏洞利用脚本。本评测用确定性
动作成本 + 故障注入，直接驱动 ``agent_policy`` / ``observation`` / ``cost``
与 HEAD 基线，产出可复现的对照数字；不调用外部 LLM，也不打真实目标。

指标：成功率 / 时延 / token / 审批次数 / 人工干预次数 / 证据覆盖率。
用法：``python lab/tencent-compare/run_eval.py --write``
输出：``reports/samples/tencent-compare/tencent-compare.json`` +
      ``docs/SECTION3-METRICS.md``
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
TASKS_PATH = Path(__file__).resolve().parent / "tasks.json"
JSON_OUT = ROOT / "reports" / "samples" / "tencent-compare" / "tencent-compare.json"
DOC_OUT = ROOT / "docs" / "SECTION3-METRICS.md"

HEAD_COMMIT = "c921595"
OUTPUT_RATIO = 0.2          # 工具原始输出 ≈ 输入上下文的 20%
CONTEXT_SAVING = 0.35       # 结构化观察替代原始输出后保留的比例
RETRY_BACKOFF_MS = 250
TIMEOUT_PENALTY_MS = 3000
EVIDENCE_TARGET = 0.9

THRESHOLDS = [
    {"metric": "success_rate", "op": ">=", "kind": "delta", "margin": 0.25,
     "label": "成功率至少 +25 个百分点"},
    {"metric": "approval_items", "op": "<=", "kind": "rel", "margin": 0.85,
     "label": "审批审阅项（需人工过目的动作数）不超过基线 85%"},
    {"metric": "latency_ms", "op": "<=", "kind": "rel", "margin": 0.80,
     "label": "总时延不超过基线 80%"},
    {"metric": "tokens", "op": "<=", "kind": "rel", "margin": 0.85,
     "label": "总 token 不超过基线 85%"},
    {"metric": "human_interventions", "op": "<=", "kind": "abs", "margin": 0.0,
     "label": "人工干预降到 0"},
]
GUARDRAILS = [
    {"metric": "approvals", "op": "<=", "kind": "delta", "margin": 1.0,
     "label": "审批决策点不得比基线多 1 次以上（不可逆写需单独确认）"},
    {"metric": "evidence_ratio", "op": ">=", "kind": "abs", "margin": EVIDENCE_TARGET,
     "label": f"证据覆盖率 >= {EVIDENCE_TARGET}"},
]


class EvalError(ValueError):
    """任务集/评测配置非法。"""


def load_tasks(path: Path | str | None = None) -> list[dict]:
    p = Path(path) if path else TASKS_PATH
    data = json.loads(p.read_text(encoding="utf-8"))
    if data.get("schema") != "inkblade-tencent-compare-tasks-v1":
        raise EvalError(f"任务集 schema 非法: {data.get('schema')!r}")
    tasks = list(data.get("tasks") or [])
    if len(tasks) < 6:
        raise EvalError(f"任务数须 >= 6，当前 {len(tasks)}")
    seen: set[str] = set()
    for task in tasks:
        for field in ("id", "zone", "goal", "actions", "expect"):
            if field not in task:
                raise EvalError(f"任务缺字段 {field}: {task.get('id')}")
        if task["id"] in seen:
            raise EvalError(f"重复 id: {task['id']}")
        seen.add(task["id"])
        if not task["actions"]:
            raise EvalError(f"{task['id']}: actions 为空")
        for action in task["actions"]:
            if not action.get("module"):
                raise EvalError(f"{task['id']}: 动作缺 module")
            if "finding" not in action:
                raise EvalError(f"{task['id']}/{action.get('module')}: 缺 finding 判定")
    return tasks


def _action(raw: dict) -> dict:
    return {
        "module": raw["module"],
        "writes": bool(raw.get("writes")),
        "tokens": int(raw.get("tokens") or 300),
        "latency_ms": int(raw.get("latency_ms") or 600),
        "optional": bool(raw.get("optional")),
        "fallback": list(raw.get("fallback") or []),
        "params": dict(raw.get("params") or {}),
        "finding": raw.get("finding") or raw["module"],
        "dry_run": dict(raw.get("dry_run") or {}),
    }


def _evidence(action: dict) -> list[dict]:
    return [{"kind": "finding", "ref": action["finding"],
             "detail": f"{action['module']} 结构化结论"}]


# ---------------------------------------------------------------- OFF: HEAD
def run_head(tasks: list[dict]) -> dict:
    """复现 HEAD(c921595) explorer 执行语义：逐动作审批、单次尝试、无预算/观察。"""
    started = time.time()
    records = []
    for task in tasks:
        actions = [_action(a) for a in task["actions"]]
        fault = task.get("fault") or {}
        fault_used = False
        findings: set[str] = set()
        failures: list[str] = []
        tokens = latency = 0
        interventions = 0
        for action in actions:
            tokens += int(action["tokens"] * (1 + OUTPUT_RATIO))
            latency += action["latency_ms"]
            if fault and action["module"] == fault.get("module") and not fault_used:
                fault_used = True
                latency += TIMEOUT_PENALTY_MS
                tokens += int(action["tokens"] * 0.1)
                failures.append(f"{fault.get('kind')}:{fault.get('detail', '')}")
                interventions += 1
                continue
            findings.add(action["finding"])
        if task.get("budget"):
            plan_tokens = sum(a["tokens"] for a in actions)
            if plan_tokens > int(task["budget"].get("tokens", plan_tokens)):
                interventions += 1  # 手工裁剪超支动作
        ok, reason = _judge(task, findings, evidence_ratio=0.0)
        if failures and ok:
            ok, reason = False, failures[0]
        records.append({
            "id": task["id"], "zone": task["zone"], "success": ok, "reason": reason,
            "findings": len(findings), "tokens": tokens, "latency_ms": latency,
            "approvals": 1, "approval_items": len(actions),
            "human_interventions": interventions,
            "evidence_ratio": 0.0, "actions": len(actions),
            "faults": failures,
        })
    return _finish("off", records, started)


# ---------------------------------------------------------------- ON: 第三节改进
def run_policy(tasks: list[dict]) -> dict:
    from inkblade.core import agent_policy, cost, observation

    started = time.time()
    records = []
    with tempfile.TemporaryDirectory() as td:
        from inkblade.core.evidence import EvidenceStore

        store = EvidenceStore(Path(td), workspace="tencent-compare")
        for task in tasks:
            planned = [_action(a) for a in task["actions"]]
            seen_keys: set[str] = set()
            deduped: list[dict] = []
            for action in planned:
                key = observation.action_key(action)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                deduped.append(action)

            budget = cost.Budget(**task.get("budget", {}))
            graded = cost.apply_budget(deduped, budget=budget)
            actions = graded["actions"]
            decided = agent_policy.decide(actions)
            decomposition = agent_policy.decompose(actions, strategy="phase")
            tracker = cost.CostTracker(budget)
            rows: list[dict] = []
            findings: set[str] = set()
            interventions = 0
            escalations: list[dict] = []
            fault = task.get("fault") or {}
            fault_used = False

            def execute(action: dict, *, note: str = "") -> None:
                tracker.record(action["module"],
                               tokens=action["tokens"] +
                                      int(action["tokens"] * OUTPUT_RATIO * CONTEXT_SAVING),
                               latency_ms=action["latency_ms"], approvals=0,
                               interventions=0, cached=bool(note))
                findings.add(action["finding"])
                rows.append(observation.build(
                    len(rows) + 1, action, status="ok",
                    result_summary=f"{action['module']} 产出 {action['finding']}",
                    evidence=_evidence(action),
                    tokens=action["tokens"]))
                observation.append(store, rows[-1])

            for action in actions:
                if observation.is_dead_end(rows, action["module"]):
                    continue
                if fault and action["module"] == fault.get("module") and not fault_used:
                    fault_used = True
                    if fault.get("kind") == "dead_end":
                        for _ in range(2):
                            tracker.record(action["module"], tokens=action["tokens"],
                                           latency_ms=action["latency_ms"])
                            rows.append(observation.build(
                                len(rows) + 1, action, status="failed",
                                result_summary=str(fault.get("detail", "dead end")),
                                tokens=action["tokens"]))
                        fallback = fault.get("fallback")
                        picks = (observation.next_candidates([fallback], rows, limit=1)
                                 if fallback else [])
                        if picks:
                            execute(_action(fallback), note="fallback")
                        else:
                            interventions += 1
                        continue
                    retry = agent_policy.retry_plan(
                        TimeoutError(str(fault.get("detail", ""))), action=action)
                    tracker.record(action["module"], tokens=action["tokens"],
                                   latency_ms=action["latency_ms"])
                    rows.append(observation.build(
                        len(rows) + 1, action, status="failed",
                        result_summary=str(fault.get("detail", "")),
                        tokens=action["tokens"]))
                    if retry["class"] == "transient":
                        tracker.record(action["module"], tokens=action["tokens"],
                                       latency_ms=action["latency_ms"] + retry["backoff_ms"])
                        findings.add(action["finding"])
                        rows.append(observation.build(
                            len(rows) + 1, action, status="ok",
                            result_summary=f"retry#{retry['attempts']} recovered: "
                                           f"{action['module']}",
                            evidence=_evidence(action), tokens=action["tokens"]))
                        observation.append(store, rows[-1])
                    else:
                        interventions += 1
                        escalations.append({"module": action["module"],
                                            "class": retry["class"]})
                    continue
                execute(action)

            cov = observation.coverage(rows)
            covered = {e.get("ref") for row in rows for e in row.get("evidence") or []}
            traceable = len([f for f in findings if f in covered])
            evidence_ratio = round(traceable / len(findings), 3) if findings else 0.0
            ok, reason = _judge(task, findings, evidence_ratio=evidence_ratio)
            summary = tracker.summary()
            records.append({
                "id": task["id"], "zone": task["zone"], "success": ok, "reason": reason,
                "findings": len(findings), "tokens": summary["tokens"],
                "latency_ms": summary["latency_ms"],
                "approvals": decided["approval_count"], "approval_items": len(actions),
                "human_interventions": interventions,
                "evidence_ratio": evidence_ratio, "actions": len(actions),
                "observation_coverage": cov["ratio"],
                "planned_actions": len(planned), "deduped": len(planned) - len(deduped),
                "dropped": [a["module"] for a in graded["dropped"]],
                "level": decided["level"], "approval_mode": decided["approval_mode"],
                "requires_human": decided["requires_human"],
                "phases": decomposition["stages"], "degraded": graded["degraded"],
                "escalations": escalations,
            })
    return _finish("on", records, started)


def _judge(task: dict, findings: set[str], *, evidence_ratio: float) -> tuple[bool, str]:
    expect = task["expect"]
    need = int(expect.get("min_findings", 0))
    if len(findings) < need:
        return False, f"findings={len(findings)}<{need}"
    min_cov = float(expect.get("min_evidence_ratio", 0))
    if evidence_ratio + 1e-9 < min_cov:
        return False, f"evidence_ratio={evidence_ratio:.2f}<{min_cov:.2f}"
    return True, ""


def _finish(mode: str, records: list[dict], started: float) -> dict:
    total = len(records)
    success = sum(1 for r in records if r["success"])
    return {
        "mode": mode,
        "tasks": records,
        "summary": {
            "mode": mode,
            "tasks": total,
            "success": success,
            "success_rate": round(success / total, 3) if total else 0.0,
            "tokens": sum(int(r["tokens"]) for r in records),
            "latency_ms": sum(int(r["latency_ms"]) for r in records),
            "avg_latency_ms": int(sum(int(r["latency_ms"]) for r in records) / total)
                             if total else 0,
            "approvals": sum(int(r["approvals"]) for r in records),
            "approval_items": sum(int(r["approval_items"]) for r in records),
            "human_interventions": sum(int(r["human_interventions"]) for r in records),
            "evidence_ratio": round(sum(float(r["evidence_ratio"]) for r in records) / total, 3)
                             if total else 0.0,
            "duration_ms": int((time.time() - started) * 1000),
        },
    }


def compare(off: dict, on: dict) -> dict:
    def _limit(spec: dict, base: float) -> float:
        if spec["kind"] == "delta":
            return base + spec["margin"]
        if spec["kind"] == "rel":
            return base * spec["margin"]
        return spec["margin"]

    def _rows(specs: list[dict]) -> list[dict]:
        rows = []
        for spec in specs:
            metric = spec["metric"]
            base = float(off["summary"][metric])
            value = float(on["summary"][metric])
            limit = _limit(spec, base)
            passed = value + 1e-9 >= limit if spec["op"] == ">=" else \
                value <= limit + 1e-9
            rows.append({"metric": metric, "off": base, "on": value,
                         "limit": round(limit, 3), "op": spec["op"],
                         "label": spec["label"], "pass": passed})
        return rows

    thresholds = _rows(THRESHOLDS)
    guardrails = _rows(GUARDRAILS)
    significant = sum(1 for r in thresholds if r["pass"])
    return {"thresholds": thresholds, "guardrails": guardrails,
            "metrics": thresholds + guardrails,
            "significant": significant,
            "pass": significant >= 2 and all(r["pass"] for r in guardrails),
            "rule": "至少 2 项主指标达标 + 护栏（审批决策点/证据覆盖）全过"}


def wiring_check() -> dict:
    """确认 Explorer 提议路径真的接上了策略层（只读，不执行）。"""
    from inkblade.core.discovery import AssetInventory
    from inkblade.core.evidence import EvidenceStore
    from inkblade.core.explorer import Explorer
    from inkblade.core.roe import init_roe
    from inkblade.core.users import Session

    try:
        with tempfile.TemporaryDirectory() as td:
            store = EvidenceStore(Path(td), workspace="local-lab")
            init_roe(store, {"level": "利用验证", "namespaces": ["ml"],
                            "cidrs": ["10.0.0.0/8"]})
            AssetInventory(store).ingest({"services": [
                {"name": "sglang-admin", "namespace": "ml", "addr": "10.96.0.11",
                 "port": 30000, "labels": {"app": "sglang"}}]}, source="seed")
            proposal = Explorer(store, modules_dir=ROOT / "inkblade" / "modules").propose(
                Session(None, "lead", "lead", ["local-lab"], "eval"))
            return {"ok": "policy" in proposal and "observations" in proposal,
                    "keys": sorted(k for k in proposal if k in
                                   ("policy", "decomposition", "observations", "cost")),
                    "level": proposal.get("policy", {}).get("level"),
                    "approval_count": proposal.get("policy", {}).get("approval_count"),
                    "actions": len(proposal.get("actions") or []),
                    "observations": len(proposal.get("observations") or []),
                    "executed": proposal.get("execution", {}).get("performed")}
    except Exception as exc:  # 接线失败不掩盖主指标
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def evaluate(tasks: list[dict] | None = None, *, write: bool = False) -> dict:
    tasks = tasks if tasks is not None else load_tasks()
    off = run_head(tasks)
    on = run_policy(tasks)
    comparison = compare(off, on)
    report = {
        "schema": "inkblade-tencent-compare-v1",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "head_commit": HEAD_COMMIT,
        "switch": "INKBLADE_AGENT_POLICY=on|off（OFF 复现 HEAD 语义）",
        "scope": "策略级确定性微评测：动作成本为标定估算，不调用外部 LLM/真实目标",
        "tasks": len(tasks),
        "modes": {"off": off, "on": on},
        "comparison": comparison,
        "wiring": wiring_check(),
    }
    if write:
        JSON_OUT.parent.mkdir(parents=True, exist_ok=True)
        JSON_OUT.write_text(json.dumps(report, ensure_ascii=False, indent=2),
                            encoding="utf-8")
        DOC_OUT.write_text(render_markdown(report), encoding="utf-8")
    return report


def render_markdown(report: dict) -> str:
    off, on = report["modes"]["off"]["summary"], report["modes"]["on"]["summary"]
    cmp = report["comparison"]
    lines = [
        "# 第三节实测：腾讯 Agent 渗透大赛对标改进（OFF vs ON）",
        "",
        f"- 生成时间：{report['generated_at']}",
        f"- 基线：git `{report['head_commit']}`（`{report['switch']}`）",
        f"- 范围：{report['scope']}",
        f"- 任务数：{report['tasks']}",
        "",
        "## 主指标（计入显著性）",
        "",
        "| 指标 | OFF（HEAD） | ON（改进） | 阈值 | 结果 |",
        "|---|---:|---:|---|---|",
    ]
    for row in cmp["thresholds"]:
        lines.append(f"| {row['metric']} | {row['off']} | {row['on']} | "
                     f"{row['op']} {row['limit']} | {'PASS' if row['pass'] else 'FAIL'} |")
    lines += [
        "",
        "## 护栏（不计入显著性，但必须全过）",
        "",
        "| 指标 | OFF（HEAD） | ON（改进） | 阈值 | 结果 |",
        "|---|---:|---:|---|---|",
    ]
    for row in cmp["guardrails"]:
        lines.append(f"| {row['metric']} | {row['off']} | {row['on']} | "
                     f"{row['op']} {row['limit']} | {'PASS' if row['pass'] else 'FAIL'} |")
    lines += [
        "",
        f"**结论：{'PASS' if cmp['pass'] else 'FAIL'}** — "
        f"{cmp['significant']} 项主指标达标（{cmp['rule']}）。",
        "",
        "> 审批口径：OFF/ON 都以「一次计划批准」为 1 个决策点；ON 在不可逆写动作上"
        "额外要求逐动作确认（T8：2 个决策点），这是**有意的安全护栏**，因此审批决策点"
        "只允许 +1，不把「审批次数下降」当作卖点。真正下降的是**审阅项**"
        "（人类需要过目的动作预览数），对应 explorer 先去重/降级再请人批。",
        "",
        "## 逐任务",
        "",
        "| 任务 | 赛区 | OFF 成功 | ON 成功 | OFF token | ON token | "
        "OFF 审阅项 | ON 审阅项 | OFF 决策 | ON 决策 | ON 等级 | ON 证据覆盖 |",
        "|---|---|:--:|:--:|---:|---:|---:|---:|---:|---:|:--:|---:|",
    ]
    off_tasks = {t["id"]: t for t in report["modes"]["off"]["tasks"]}
    for task in report["modes"]["on"]["tasks"]:
        base = off_tasks[task["id"]]
        lines.append(
            f"| {task['id']} | {task['zone']} | {'PASS' if base['success'] else 'FAIL'} | "
            f"{'PASS' if task['success'] else 'FAIL'} | {base['tokens']} | {task['tokens']} | "
            f"{base.get('approval_items', '-')} | {task.get('approval_items', '-')} | "
            f"{base.get('approvals', '-')} | {task.get('approvals', '-')} | "
            f"{task.get('level', '-')} | {task['evidence_ratio']:.2f} |")
    wiring = report.get("wiring") or {}
    lines += [
        "",
        "## 接线检查",
        "",
        f"- Explorer.propose 返回策略字段：`{wiring.get('ok')}`；"
        f"键={wiring.get('keys')}；等级={wiring.get('level')}；"
        f"审批={wiring.get('approval_count')}；动作={wiring.get('actions')}；"
        f"观察={wiring.get('observations')}；执行={wiring.get('executed')}",
        "",
        "## 口径与限制（如实记录）",
        "",
        "1. 这是**策略级**微评测：动作 token/时延为按模块输出规模标定的确定性成本，",
        "   不是线上模型账单；成功判定基于 findings 数量与证据覆盖率。",
        "2. 故障注入覆盖瞬时错误、死胡同、永久闸门、预算超支四类，每类只出现一次，",
        "   用于验证策略而非估计总体成功率。",
        "3. OFF 复现 HEAD 的 explorer 语义：一次计划批准、单次尝试、无预算/无结构化观察；",
        "   ON 走 `agent_policy` / `observation` / `cost` 并保持「提议不执行」硬边界。",
        "4. 真实 LLM 的方差、网络时延与工具差异未纳入；下一轮应在冻结模型版本上重跑。",
        "",
        "## 复现",
        "",
        "```bash",
        "python lab/tencent-compare/run_eval.py --write",
        "python -m unittest tests.test_tencent_compare -v",
        "```",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Tencent agent contest compare micro-eval")
    parser.add_argument("--write", action="store_true", help="写入 JSON + SECTION3-METRICS.md")
    parser.add_argument("--tasks", default=str(TASKS_PATH))
    args = parser.parse_args(argv)
    report = evaluate(load_tasks(args.tasks), write=args.write)
    summary = report["comparison"]
    print(json.dumps({"success_rate": [report["modes"]["off"]["summary"]["success_rate"],
                                       report["modes"]["on"]["summary"]["success_rate"]],
                      "approvals": [report["modes"]["off"]["summary"]["approvals"],
                                    report["modes"]["on"]["summary"]["approvals"]],
                      "approval_items": [report["modes"]["off"]["summary"]["approval_items"],
                                         report["modes"]["on"]["summary"]["approval_items"]],
                      "latency_ms": [report["modes"]["off"]["summary"]["latency_ms"],
                                     report["modes"]["on"]["summary"]["latency_ms"]],
                      "tokens": [report["modes"]["off"]["summary"]["tokens"],
                                 report["modes"]["on"]["summary"]["tokens"]],
                      "interventions": [report["modes"]["off"]["summary"]["human_interventions"],
                                        report["modes"]["on"]["summary"]["human_interventions"]],
                      "pass": summary["pass"], "significant": summary["significant"]},
                     ensure_ascii=False, indent=2))
    return 0 if summary["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
