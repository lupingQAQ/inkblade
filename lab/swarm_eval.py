# -*- coding: utf-8 -*-
"""Swarm 评测：15 任务 × 1 worker vs 4 worker（成功率/时延/审批/并发）。

口径（写 docs/SWARM-EVAL.md）：
- 任务集固定 15 个：recon×5、exploit×4、verify×4、report×2；每任务带 lead 预批准；
- 执行器 ``simulate``：按角色 sleep（60/90/70/40ms），审批门 40ms/任务；
  1 个永久失败（exploit-3）+ 1 个瞬时失败重试（verify-2，fail_times=1），max_attempts=2；
- 先跑 warm batch 启动进程，再测 3 个 batch 取中位数（排除 Windows spawn 启动成本）；
- 审批墙钟 = 各任务审批区间（started_at → +approval_ms）的并集，不是简单相加；
- 数字是本机模拟执行器的吞吐对照，**不是**真实模块/客户集群 SLA。
"""

from __future__ import annotations

import json
import statistics
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from inkblade.core.swarm import Swarm  # noqa: E402

OUT_DIR = REPO / "reports" / "samples" / "swarm-eval"
DOC = REPO / "docs" / "SWARM-EVAL.md"
ROLE_DELAY = {"recon": 60, "exploit": 90, "verify": 70, "report": 40}


def _task(tid: str, role: str, **extra) -> dict:
    item = {"id": tid, "role": role, "module": f"{role}-eval",
            "params": {"target": "fixture"}, "simulate": {"delay_ms": ROLE_DELAY[role]},
            "approval": {"status": "approved", "approved_by": "lead",
                         "approved_at": time.time()}}
    item.update(extra)
    return item


def build_tasks() -> list[dict]:
    out = []
    for i in range(5):
        out.append(_task(f"recon-{i:02d}", "recon"))
    for i in range(4):
        extra = {}
        if i == 3:
            extra["fail"] = True  # 永久失败：验证失败不被并发吞掉
        out.append(_task(f"exploit-{i:02d}", "exploit", **extra))
    for i in range(4):
        extra = {"fail_times": 1} if i == 2 else {}
        out.append(_task(f"verify-{i:02d}", "verify", **extra))
    for i in range(2):
        out.append(_task(f"report-{i:02d}", "report"))
    return out


def _union_ms(rows: list[dict]) -> int:
    spans = []
    for row in rows:
        ms = int(row.get("approval_ms") or 0)
        if ms <= 0:
            continue
        start = float(row.get("started_at") or 0)
        spans.append((start, start + ms / 1000.0))
    if not spans:
        return 0
    spans.sort()
    total = 0.0
    cur_s, cur_e = spans[0]
    for start, end in spans[1:]:
        if start <= cur_e:
            cur_e = max(cur_e, end)
        else:
            total += cur_e - cur_s
            cur_s, cur_e = start, end
    total += cur_e - cur_s
    return int(total * 1000)


def run_config(workers: int, *, reps: int = 3) -> dict:
    batch = build_tasks()
    warm = []
    for role in ROLE_DELAY:
        item = _task(f"warm-{role}", role)
        item["simulate"] = {"delay_ms": 25}
        warm.append(item)
    swarm = Swarm(workers=workers, executor={"kind": "simulate", "approval_ms": 40},
                  max_attempts=2)
    runs: list[dict] = []
    try:
        swarm.run(warm)  # 启动进程；不计入测量
        for _ in range(max(1, int(reps))):
            runs.append(swarm.run(batch))
    finally:
        swarm.close()
    walls = [r["wall_ms"] for r in runs]
    approvals = [r["approvals"] for r in runs]
    success = [r["success"] for r in runs]
    total = [r["total"] for r in runs]
    return {
        "workers": workers,
        "distribution": runs[0]["distribution"],
        "reps": len(runs),
        "total_tasks": total[0],
        "success": success[0],
        "failed": runs[0]["failed"],
        "success_rate": round(success[0] / total[0], 4) if total[0] else 0.0,
        "retries": runs[0]["retries"],
        "approvals": approvals[0],
        "approval_ms_total": runs[0]["approval_ms_total"],
        "approval_wall_ms": _union_ms(runs[0]["results"]),
        "wall_ms_median": int(statistics.median(walls)),
        "wall_ms_min": min(walls),
        "wall_ms_max": max(walls),
        "wall_ms_samples": walls,
        "peak_concurrency": runs[0]["peak_concurrency"],
        "pids": len(runs[0]["pids"]),
        "by_role": runs[0]["by_role"],
        "reproducible_task_ids": [t["id"] for t in batch],
    }


def run_eval(*, reps: int = 3, write: bool = True) -> dict:
    one = run_config(1, reps=reps)
    four = run_config(4, reps=reps)
    speedup = round(one["wall_ms_median"] / four["wall_ms_median"], 2) \
        if four["wall_ms_median"] else 0.0
    approval_speedup = round(one["approval_wall_ms"] / four["approval_wall_ms"], 2) \
        if four["approval_wall_ms"] else 0.0
    results = {
        "schema": "inkblade-swarm-eval/1",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source": "simulated-local-multiprocess",
        "task_set": {
            "total": 15,
            "roles": {"recon": 5, "exploit": 4, "verify": 4, "report": 2},
            "role_delay_ms": ROLE_DELAY,
            "approval_gate_ms": 40,
            "injected_failures": {"permanent": ["exploit-03"], "transient": ["verify-02"]},
            "max_attempts": 2,
        },
        "configs": {"1w": one, "4w": four},
        "comparison": {
            "speedup_wall": speedup,
            "approval_wall_speedup": approval_speedup,
            "success_rate_1w": one["success_rate"],
            "success_rate_4w": four["success_rate"],
            "approvals_1w": one["approvals"],
            "approvals_4w": four["approvals"],
            "retries_1w": one["retries"],
            "retries_4w": four["retries"],
        },
        "notes": [
            "simulate 执行器按角色 sleep，不是真实模块；数字只证明本机多进程队列的吞吐/审批并发",
            "先跑 warm batch 启动进程，测量 3 个 batch 取中位数（排除 Windows spawn 启动成本）",
            "1 个永久失败 + 1 个瞬时失败重试：成功率两边一致（14/15），并发不改变正确性",
            "审批墙钟是各任务审批区间的并集；审批次数不变（15 次预授权），并发只压缩墙钟",
        ],
        "reproduce": "python lab/swarm_eval.py",
    }
    if write:
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        (OUT_DIR / "results.json").write_text(
            json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (OUT_DIR / "results.md").write_text(render_md(results), encoding="utf-8")
        DOC.write_text(render_doc(results), encoding="utf-8")
    return results


def _pct(value: float) -> str:
    return f"{value:.2%}"


def _config_row(key: str, cfg: dict) -> str:
    dist = "、".join(f"{r}×{n}" for r, n in cfg["distribution"].items())
    return (f"| {key} | {cfg['workers']} | {dist} | {cfg['success']}/{cfg['total_tasks']} "
            f"({_pct(cfg['success_rate'])}) | {cfg['wall_ms_median']} ms | "
            f"{cfg['approvals']} | {cfg['approval_wall_ms']} ms | "
            f"{cfg['peak_concurrency']} | {cfg['retries']} | {cfg['pids']} |")


def render_md(results: dict) -> str:
    t = results["task_set"]
    c = results["configs"]
    cmp_ = results["comparison"]
    lines = [
        "# Swarm 评测结果（本机多进程，simulate 执行器）",
        "",
        f"> 生成：`{results['generated_at']}` · 来源：`{results['source']}`",
        "> 这是**模拟执行器**的吞吐/审批对照，不是真实模块或客户集群 SLA。",
        "",
        f"- 任务 {t['total']} 个：recon×{t['roles']['recon']}、exploit×{t['roles']['exploit']}、"
        f"verify×{t['roles']['verify']}、report×{t['roles']['report']}",
        f"- 角色时延：{t['role_delay_ms']}；审批门 {t['approval_gate_ms']}ms/任务；"
        f"max_attempts={t['max_attempts']}",
        f"- 注入失败：永久 {t['injected_failures']['permanent']}、瞬时 "
        f"{t['injected_failures']['transient']}",
        "",
        "| 配置 | worker | 角色分布 | 成功率 | 时延中位数 | 审批次数 | 审批墙钟 | 峰值并发 | 重试 | 进程 |",
        "|---|---:|---|---:|---:|---:|---:|---:|---:|---:|",
        _config_row("1 worker", c["1w"]),
        _config_row("4 worker", c["4w"]),
        "",
        f"- 时延加速：**{cmp_['speedup_wall']}×**（{c['1w']['wall_ms_median']} → "
        f"{c['4w']['wall_ms_median']} ms）",
        f"- 审批墙钟加速：**{cmp_['approval_wall_speedup']}×**"
        f"（{c['1w']['approval_wall_ms']} → {c['4w']['approval_wall_ms']} ms，审批次数同为 "
        f"{cmp_['approvals_1w']}）",
        f"- 成功率：1w {_pct(cmp_['success_rate_1w'])} / 4w {_pct(cmp_['success_rate_4w'])}"
        "（两边一致，失败与重试不被并发吞掉）",
        "",
        "## 说明",
        "",
    ]
    lines += [f"- {n}" for n in results["notes"]]
    lines += ["", f"复现：`{results['reproduce']}`", ""]
    return "\n".join(lines)


def render_doc(results: dict) -> str:
    t = results["task_set"]
    c = results["configs"]
    cmp_ = results["comparison"]
    lines = [
        "# Swarm 角色化 worker 评测（1 vs 4）",
        "",
        "> 目标：验证「角色化 worker + 本机多进程队列」在 15 个任务上不降低成功率，"
        "并量化时延与审批墙钟收益。**simulate 执行器，非真实模块/客户 SLA。**",
        f"> 机器可读：`reports/samples/swarm-eval/results.json`（本文数字由 "
        f"`python lab/swarm_eval.py` 生成）。",
        "",
        "## 1. 任务集",
        "",
        "| 项 | 值 |",
        "|---|---|",
        f"| 任务数 | {t['total']}（recon×{t['roles']['recon']} / exploit×"
        f"{t['roles']['exploit']} / verify×{t['roles']['verify']} / report×"
        f"{t['roles']['report']}） |",
        f"| 模拟时延 | recon {t['role_delay_ms']['recon']}ms、exploit "
        f"{t['role_delay_ms']['exploit']}ms、verify {t['role_delay_ms']['verify']}ms、report "
        f"{t['role_delay_ms']['report']}ms |",
        f"| 审批门 | {t['approval_gate_ms']}ms/任务（预授权批量批准；模拟 lead 校验） |",
        f"| 注入失败 | 永久 `{t['injected_failures']['permanent'][0]}`；瞬时 "
        f"`{t['injected_failures']['transient'][0]}`（fail_times=1） |",
        f"| 重派上限 | {t['max_attempts']} |",
        "| 测量 | warm batch 启动进程后，3 个 batch 取中位数 |",
        "",
        "## 2. 结果",
        "",
        "| 配置 | worker | 角色分布 | 成功率 | 时延中位数 | 审批次数 | 审批墙钟 | 峰值并发 | 重试 | 进程 |",
        "|---|---:|---|---:|---:|---:|---:|---:|---:|---:|",
        _config_row("1 worker", c["1w"]),
        _config_row("4 worker", c["4w"]),
        "",
        f"- **时延加速 {cmp_['speedup_wall']}×**：{c['1w']['wall_ms_median']} → "
        f"{c['4w']['wall_ms_median']} ms。",
        f"- **审批墙钟加速 {cmp_['approval_wall_speedup']}×**：{c['1w']['approval_wall_ms']} → "
        f"{c['4w']['approval_wall_ms']} ms；审批**次数不变**（{cmp_['approvals_1w']} 次预授权），"
        "并发只压缩等待墙钟。",
        f"- **成功率一致**：{_pct(cmp_['success_rate_1w'])} vs "
        f"{_pct(cmp_['success_rate_4w'])}（14/15；永久失败如实保留，瞬时失败重试成功）。",
        f"- 重试：{cmp_['retries_1w']} vs {cmp_['retries_4w']}；峰值并发 "
        f"{c['1w']['peak_concurrency']} vs {c['4w']['peak_concurrency']}；"
        f"进程数 {c['1w']['pids']} vs {c['4w']['pids']}（真实多进程）。",
        "",
        "## 3. 逐角色",
        "",
        "| 角色 | 1w 成功/总数 | 1w 重试 | 4w 成功/总数 | 4w 重试 |",
        "|---|---:|---:|---:|---:|",
    ]
    for role in ("recon", "exploit", "verify", "report"):
        one = c["1w"]["by_role"].get(role, {})
        four = c["4w"]["by_role"].get(role, {})
        lines.append(f"| {role} | {one.get('success', 0)}/{one.get('total', 0)} | "
                     f"{one.get('retries', 0)} | {four.get('success', 0)}/"
                     f"{four.get('total', 0)} | {four.get('retries', 0)} |")
    lines += [
        "",
        "## 4. 护栏（与 L3/supervisor 同源）",
        "",
        "- 每任务必须 `approval.status=approved` 且有 `approved_by`，否则 `ApprovalRequired`，"
        "入队前整体校验、零残留；",
        "- 角色上限每角色默认 2、最小 2、最大 8；总 worker 1–16；4 worker = 每角色 1 个；",
        "- 失败由父进程按 `max_attempts` 重派到**同角色**队列，超过上限才终态失败；",
        "- 生产执行器 `runner` 在子进程内构造 EvidenceStore + `core.runner.run_module`，"
        "授权/备份/三层落证闸门照旧（本评测未启用真实模块）。",
        "",
        "## 5. 诚实边界",
        "",
    ]
    lines += [f"- {n}" for n in results["notes"]]
    lines += [
        "- 真实模块的时延/资源占用取决于目标集群与模块实现；本页不能外推为生产 SLA。",
        "- Windows spawn 启动成本（每进程数百 ms）已用 warm batch 排除；冷启动场景需另测。",
        "- 审批墙钟是 40ms 模拟门；真实 lead 审批时延远高且不可并发压缩，预授权才是 L3 的"
        "关键收益。",
        "",
        "## 6. 复现",
        "",
        "```bash",
        results["reproduce"],
        "python -m unittest tests.test_swarm -v",
        "python -m inkblade swarm roles",
        "python -m inkblade swarm run --tasks tasks.json --workers 4 --executor simulate",
        "```",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    results = run_eval(write=True)
    cmp_ = results["comparison"]
    print(f"swarm-eval: {OUT_DIR / 'results.json'}")
    print(f"1w {results['configs']['1w']['wall_ms_median']}ms / "
          f"4w {results['configs']['4w']['wall_ms_median']}ms | "
          f"speedup {cmp_['speedup_wall']}x | success "
          f"{results['configs']['1w']['success']}/{results['configs']['1w']['total_tasks']} vs "
          f"{results['configs']['4w']['success']}/{results['configs']['4w']['total_tasks']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
