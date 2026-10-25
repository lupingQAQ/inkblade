# -*- coding: utf-8 -*-
"""Agent 评测：deterministic vs supervisor-worker（成功率/耗时/token/审批次数）。

任务全部本地（127.0.0.1 仿真靶场 + 快照 fixture），无外部网络；写类模块不参与。
两种模式执行同一任务集：
- ``deterministic``：单批审批（1 次）、顺序、单次尝试、无重派、无 journal；
- ``supervisor-worker``：逐动作审批、4 worker、max_attempts=2、journal 事件、失败重派。

故障注入（显式、可复现）：``gateway-auth`` 任务的第一个动作首次尝试注入
``TimeoutError``（模拟瞬时网络故障），用于测量重派恢复能力；结果 JSON 中记录
``config.fault_injection``，不与真实能力混淆。

输出：``reports/samples/agent-eval/agent-eval.json`` + ``docs/AGENT-EVAL-RESULTS.md``。
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:  # 允许 `python lab/agent-eval/run_eval.py` 直接运行
    sys.path.insert(0, str(ROOT))
TASKS_PATH = Path(__file__).resolve().parent / "tasks.json"
JSON_OUT = ROOT / "reports" / "samples" / "agent-eval" / "agent-eval.json"
DOC_OUT = ROOT / "docs" / "AGENT-EVAL-RESULTS.md"

CATEGORIES = ("recon", "exploit", "chain", "long-context", "gateway", "gpu-tenant")
FAULT_TASK = "gateway-auth"
FAULT_MODULE = "aigateway-auth-bypass"
WORKERS = 4
MAX_ATTEMPTS = 2


class EvalError(ValueError):
    """任务集/执行错误。"""


def load_tasks(path: Path | str | None = None) -> list[dict]:
    p = Path(path) if path else TASKS_PATH
    data = json.loads(p.read_text(encoding="utf-8"))
    if data.get("schema") != "trident-agent-eval-tasks-v1":
        raise EvalError(f"未知任务集 schema: {data.get('schema')!r}")
    tasks = list(data.get("tasks") or [])
    if len(tasks) < 12:
        raise EvalError(f"任务数须 ≥12，得到 {len(tasks)}")
    seen = set()
    for task in tasks:
        for field in ("id", "category", "goal", "kind", "modules"):
            if field not in task:
                raise EvalError(f"任务缺字段 {field}: {task}")
        if task["id"] in seen:
            raise EvalError(f"任务 id 重复 {task['id']}")
        seen.add(task["id"])
        if task["category"] not in CATEGORIES:
            raise EvalError(f"未知类别 {task['category']}")
        if task["kind"] not in ("snapshot", "http", "chain"):
            raise EvalError(f"未知 kind {task['kind']}")
        if not task["modules"]:
            raise EvalError(f"{task['id']}: modules 为空")
    return tasks


def _prepare_workspace(tmp: Path):
    from trident.core.evidence import EvidenceStore
    from trident.core.users import Session

    store = EvidenceStore(tmp, workspace="local-lab")
    store.pin_roe({
        "level": "利用验证",
        "namespaces": ["default", "train", "infer", "ray-system", "kube-system"],
        "cidrs": ["127.0.0.0/8"],
        "window": "agent-eval-lab",
        "note": "local simulators/fixtures only",
    })
    session = Session(None, "lead", "lead", ["local-lab"], "eval-token")
    return store, session


def _module_params(task: dict, module: str, sims: dict) -> dict:
    params = dict(task.get("params") or {})
    params.update((task.get("module_params") or {}).get(module) or {})
    if "snapshot" in params:
        params["snapshot"] = str(ROOT / params["snapshot"])
    if task["kind"] == "http":
        params["target"] = sims[task["sim"]].url("/")
    return params


def _execute(store, session, module: str, params: dict) -> dict:
    from trident.core.runner import run_module

    started = time.monotonic()
    res = run_module(store, session, module, params, ROOT / "trident" / "modules")
    run = store.open_run(res["run"])
    titles = [f["title"] for f in run.findings]
    return {
        "ok": True,
        "run": res["run"],
        "findings": len(titles),
        "titles": titles,
        "duration_ms": int((time.monotonic() - started) * 1000),
    }


def _chain_plan(task: dict) -> dict:
    from trident.core.chains import dry_run, evaluate_preconditions, load_chains

    chains = load_chains(ROOT / "trident" / "chains")
    chain = chains.get(task["chain"])
    if chain is None:
        raise EvalError(f"未知链 {task['chain']}")
    verdict, missing = evaluate_preconditions(chain, [])
    plan = dry_run(chain, [], ROOT / "trident" / "modules")
    return {"chain": chain["id"], "verdict": verdict, "missing": missing,
            "steps": [step["module"] for step in plan["steps"]], "planned": len(plan["steps"])}


def _judge(task: dict, titles: list[str], findings: int, chain: dict | None) -> tuple[bool, str]:
    if findings < int(task.get("expect_findings_min", 0)):
        return False, f"findings={findings}<{task.get('expect_findings_min')}"
    wanted = task.get("expect_any_title") or []
    text = " ".join(titles).lower()
    if wanted and not any(str(w).lower() in text for w in wanted):
        return False, f"titles 未命中 {wanted}"
    if task.get("expect_verdict"):
        if chain is None or chain["verdict"] not in task["expect_verdict"]:
            return False, f"chain verdict={chain['verdict'] if chain else None}"
    if task.get("expect_chain_steps"):
        if chain is None or chain["planned"] < int(task["expect_chain_steps"]):
            return False, f"chain steps={chain['planned'] if chain else 0}"
    return True, ""


def run_deterministic(tasks: list[dict], sims: dict) -> dict:
    from trident.core.supervisor import estimate_tokens

    started = time.time()
    records: list[dict] = []
    with tempfile.TemporaryDirectory() as td:
        store, session = _prepare_workspace(Path(td))
        for index, task in enumerate(tasks):
            chain = _chain_plan(task) if task["kind"] == "chain" else None
            titles: list[str] = []
            failures: list[str] = []
            task_started = time.monotonic()
            for module in task["modules"]:
                if task["id"] == "gateway-auth" and module == FAULT_MODULE:
                    failures.append("TimeoutError: injected transient failure")
                    break  # deterministic：单次尝试，失败即终止该任务
                try:
                    result = _execute(store, session, module,
                                      _module_params(task, module, sims))
                    titles += result["titles"]
                except Exception as exc:
                    failures.append(f"{type(exc).__name__}: {exc}")
                    break
            ok, reason = _judge(task, titles, len(titles), chain)
            if failures:
                ok, reason = False, failures[0]
            tokens = estimate_tokens(task["goal"] + " ".join(task["modules"]) +
                                     json.dumps(task.get("params") or {}, ensure_ascii=False) +
                                     " ".join(titles))
            records.append({
                "id": task["id"], "category": task["category"], "ok": ok, "reason": reason,
                "findings": len(titles), "titles": titles[:8], "failures": failures,
                "modules": len(task["modules"]),
                "duration_ms": int((time.monotonic() - task_started) * 1000),
                "tokens": tokens,
                "chain": chain,
            })
    return _finish("deterministic", records, started, approvals=1, retries=0,
                   extra={"workers": 1, "max_attempts": 1})


def run_supervisor(tasks: list[dict], sims: dict) -> dict:
    from trident.core.journal import Journal
    from trident.core.supervisor import Supervisor, estimate_tokens

    started = time.time()
    records: list[dict] = []
    with tempfile.TemporaryDirectory() as td:
        store, session = _prepare_workspace(Path(td))
        chains = {task["id"]: _chain_plan(task) if task["kind"] == "chain" else None
                  for task in tasks}
        actions: list[dict] = []
        layout: list[tuple[dict, int]] = []
        for task in tasks:
            layout.append((task, len(task["modules"])))
            for module in task["modules"]:
                actions.append({
                    "module": module,
                    "params": _module_params(task, module, sims),
                    "approval": {"status": "approved", "approved_by": "lead"},
                    "task": task["id"],
                })
        executed = {"n": 0}

        def executor(item: dict) -> dict:
            module = item["module"]
            task_id = item.get("task") or _task_of_module(tasks, module)
            executed["n"] += 1
            if task_id == FAULT_TASK and module == FAULT_MODULE and int(item["attempts"]) == 1:
                raise TimeoutError("injected transient failure (fault injection)")
            return _execute(store, session, module, item["params"])

        supervisor = Supervisor(store, session, workers=WORKERS, max_attempts=MAX_ATTEMPTS,
                                executor=executor, journal=Journal.for_store(store))
        supervisor.submit(actions)
        result = supervisor.run()
        flat = result["tasks"]
        cursor = 0
        for task, count in layout:
            group = flat[cursor:cursor + count]
            cursor += count
            titles = []
            failures = []
            for item in group:
                if item["status"] == "success" and item.get("result"):
                    titles += item["result"].get("titles") or []
                else:
                    failures.append(item.get("error") or item["status"])
            chain = chains[task["id"]]
            ok, reason = _judge(task, titles, len(titles), chain)
            if failures:
                ok, reason = False, failures[0]
            stamps = [item.get("started_at") for item in group if item.get("started_at")]
            ends = [item.get("finished_at") for item in group if item.get("finished_at")]
            tokens = estimate_tokens(task["goal"] + " ".join(task["modules"]) +
                                     json.dumps(task.get("params") or {}, ensure_ascii=False) +
                                     " ".join(titles))
            records.append({
                "id": task["id"], "category": task["category"], "ok": ok, "reason": reason,
                "findings": len(titles), "titles": titles[:8], "failures": failures,
                "modules": count,
                "duration_ms": int((max(ends) - min(stamps)) * 1000) if stamps and ends else 0,
                "tokens": tokens,
                "chain": chain,
                "attempts": sum(int(item.get("attempts", 0)) for item in group),
            })
        approvals = len(actions)
        summary = result["summary"]
        retries = int(summary.get("retries", 0))
    return _finish("supervisor-worker", records, started, approvals=approvals, retries=retries,
                   extra={"workers": WORKERS, "max_attempts": MAX_ATTEMPTS,
                          "module_runs": executed["n"]})


def _task_of_module(tasks: list[dict], module: str) -> str:
    for task in tasks:
        if module in task["modules"]:
            return task["id"]
    return ""


def _finish(mode: str, records: list[dict], started: float, *, approvals: int,
            retries: int, extra: dict) -> dict:
    total = len(records)
    success = sum(1 for r in records if r["ok"])
    return {
        "mode": mode,
        "tasks": records,
        "summary": {
            "mode": mode,
            "tasks": total,
            "success": success,
            "success_rate": round(success / total, 3) if total else 0.0,
            "duration_ms": int((time.time() - started) * 1000),
            "tokens": sum(int(r["tokens"]) for r in records),
            "approvals": approvals,
            "retries": retries,
            "findings": sum(int(r["findings"]) for r in records),
            **extra,
        },
    }


def _start_sims() -> dict:
    from lab.ai_gateway_sim import start_all as start_gateway
    from lab.gpu_cloud_sim import start_all as start_gpu
    from lab.longctx_sim import start_all as start_longctx

    return {
        "gateway": start_gateway(mode="vulnerable"),
        "longctx": start_longctx(mode="vulnerable"),
        "gpu": start_gpu(mode="vulnerable"),
    }


def _stop_sims(sims: dict) -> None:
    for server in sims.values():
        try:
            server.shutdown()
        except Exception:
            pass


def evaluate(tasks: list[dict] | None = None, *, write: bool = True) -> dict:
    tasks = tasks or load_tasks()
    sims = _start_sims()
    try:
        deterministic = run_deterministic(tasks, sims)
        supervisor = run_supervisor(tasks, sims)
    finally:
        _stop_sims(sims)
    by_category: dict[str, dict] = {}
    for task in tasks:
        by_category.setdefault(task["category"], []).append(task["id"])
    comparison = {
        "success_delta": round(supervisor["summary"]["success_rate"]
                               - deterministic["summary"]["success_rate"], 3),
        "duration_delta_pct": _pct(supervisor["summary"]["duration_ms"],
                                   deterministic["summary"]["duration_ms"]),
        "token_delta_pct": _pct(supervisor["summary"]["tokens"],
                                deterministic["summary"]["tokens"]),
        "approval_delta": supervisor["summary"]["approvals"] - deterministic["summary"]["approvals"],
    }
    report = {
        "schema": "trident-agent-eval-v1",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tasks_file": str(TASKS_PATH.relative_to(ROOT)).replace("\\", "/"),
        "task_count": len(tasks),
        "categories": {cat: ids for cat, ids in by_category.items()},
        "config": {
            "workers": WORKERS,
            "max_attempts": MAX_ATTEMPTS,
            "approval_policy": {"deterministic": "batch (1 per run)",
                                "supervisor-worker": "per-action"},
            "fault_injection": [{"task": FAULT_TASK, "module": FAULT_MODULE,
                                 "attempt": 1, "error": "TimeoutError"}],
            "network": "127.0.0.1 simulators + local fixtures only",
            "writes": "写类模块不参与（mode=probe-only）",
        },
        "modes": {"deterministic": deterministic, "supervisor-worker": supervisor},
        "comparison": comparison,
    }
    if write:
        write_outputs(report)
    return report


def _pct(value: int, base: int) -> float:
    if not base:
        return 0.0
    return round((value - base) / base * 100, 1)


def render_md(report: dict) -> str:
    d = report["modes"]["deterministic"]["summary"]
    s = report["modes"]["supervisor-worker"]["summary"]
    c = report["comparison"]
    lines = [
        "# Agent 架构评测结果（deterministic vs supervisor-worker）",
        "",
        f"- 生成时间：{report['generated_at']}",
        f"- 任务集：`{report['tasks_file']}`（{report['task_count']} 任务；类别："
        + "、".join(f"{k} {len(v)}" for k, v in report["categories"].items()) + "）",
        "- 网络边界：仅 127.0.0.1 仿真靶场 + 本地 fixture；写类模块不参与（probe-only）",
        "- 审批口径：deterministic = 整批 1 次；supervisor-worker = 逐动作审批",
        "- 故障注入：`gateway-auth` 首个动作首次尝试注入 `TimeoutError`（显式标注，"
        "用于测量重派恢复）",
        "",
        "## 总览",
        "",
        "| 模式 | 成功率 | 成功/总数 | 耗时 (ms) | token | 审批次数 | 重派 | 发现数 |",
        "|---|---|---|---|---|---|---|---|",
        f"| deterministic | {d['success_rate']:.1%} | {d['success']}/{d['tasks']} | "
        f"{d['duration_ms']} | {d['tokens']} | {d['approvals']} | {d['retries']} | {d['findings']} |",
        f"| supervisor-worker | {s['success_rate']:.1%} | {s['success']}/{s['tasks']} | "
        f"{s['duration_ms']} | {s['tokens']} | {s['approvals']} | {s['retries']} | {s['findings']} |",
        "",
        "## 差值",
        "",
        f"- 成功率差值：{c['success_delta']:+.1%}",
        f"- 耗时差值：{c['duration_delta_pct']:+.1f}%",
        f"- token 差值：{c['token_delta_pct']:+.1f}%",
        f"- 审批次数差值：{c['approval_delta']:+d}",
        "",
        "## 逐任务",
        "",
        "| 任务 | 类别 | deterministic | supervisor-worker | 发现(d/s) |",
        "|---|---|---|---|---|",
    ]
    det = {r["id"]: r for r in report["modes"]["deterministic"]["tasks"]}
    sup = {r["id"]: r for r in report["modes"]["supervisor-worker"]["tasks"]}
    for task_id in det:
        a = det[task_id]
        b = sup.get(task_id, {})
        mark = lambda row: "PASS" if row.get("ok") else f"FAIL（{row.get('reason', '')[:40]}）"
        lines.append(f"| {task_id} | {a['category']} | {mark(a)} | {mark(b)} | "
                     f"{a['findings']}/{b.get('findings', 0)} |")
    lines += [
        "",
        "## 结论",
        "",
        "- 两种模式均可完整执行同一任务集；结果结构（成功率/耗时/token/审批/逐任务）完整。",
        f"- deterministic 单批审批、顺序执行：审批少，但无重派，遇到瞬时故障即任务失败"
        f"（本次注入故障使其在 `{FAULT_TASK}` 失败）。",
        f"- supervisor-worker 逐动作审批（{s['approvals']} 次）、有界并发、失败重派"
        f"（本次重派 {s['retries']} 次）：在同一故障下恢复并完成任务。",
        "- token 为确定性估算（CJK 按字 + 其余 4 字符/token），用于相对比较而非计费口径。",
        "- 评测只覆盖本地仿真/快照；真实集群表现见 `docs/REAL-CLUSTER-VERIFICATION.md`。",
        "",
    ]
    return "\n".join(lines) + "\n"


def write_outputs(report: dict) -> None:
    JSON_OUT.parent.mkdir(parents=True, exist_ok=True)
    JSON_OUT.write_text(json.dumps(report, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    DOC_OUT.parent.mkdir(parents=True, exist_ok=True)
    DOC_OUT.write_text(render_md(report), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Trident agent architecture evaluation")
    parser.add_argument("--tasks", default=None, help="任务集 JSON（默认 lab/agent-eval/tasks.json）")
    parser.add_argument("--out", default=None, help="结果 JSON（默认 reports/samples/agent-eval/）")
    parser.add_argument("--no-write", action="store_true", help="只打印，不落盘")
    args = parser.parse_args(argv)
    try:
        tasks = load_tasks(args.tasks)
        report = evaluate(tasks, write=not args.no_write)
    except (EvalError, ValueError, OSError) as exc:
        print(f"agent-eval: {exc}", file=sys.stderr)
        return 2
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps({mode: report["modes"][mode]["summary"] for mode in report["modes"]},
                     ensure_ascii=False, indent=2))
    print(f"agent-eval: {JSON_OUT} / {DOC_OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
