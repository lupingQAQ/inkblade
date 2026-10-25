"""same-target-collect.py — merge ARTEX + Trident same-target bench evidence.

Inputs (all produced by the same-target pipeline):
  --mock-log      lab/qemu-k3s/out/mock-llm.jsonl        (scripted-mock request log)
  --raw           lab/qemu-k3s/out/artex-same-target-raw.txt (guest KEY=value dump)
  --target-stats  lab/qemu-k3s/out/mock-target-stats-artex.json (target /__stats__ snapshot)
  --trident       lab/qemu-k3s/out/trident-chain.json    (same-target-trident.py output)
  --out           reports/samples/artex-bench/same-target.json (md written next to it)

Output: machine-readable same-target.json + human same-target.md with the
per-step / total latency, request-count, token and resource comparison table.
Token counts are estimated from the ARTEX request bodies (chars/4), the mock
is not a real tokenizer — stated as such in the report.
"""
from __future__ import annotations

import argparse
import json
import re
import time
from pathlib import Path


def _parse_raw(path: Path) -> dict:
    data: dict = {"stats_samples": [], "task_stats_samples": [], "task_polls": []}
    if not path.exists():
        return data
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.startswith("TASK_STATS_"):
            data["task_stats_samples"].append(value)
        elif key.startswith("STATS_"):
            data["stats_samples"].append(value)
        elif key == "TASK_POLL":
            data["task_polls"].append(value)
        else:
            data[key] = value
    return data


def _mem_mib(samples: list[str]) -> float | None:
    """Max combined MemUsage (MiB) over the docker stats samples in the window."""
    best: float | None = None
    for sample in samples:
        total = 0.0
        for part in sample.split(";;"):
            fields = part.split("|")
            if len(fields) < 2:
                continue
            m = re.match(r"([0-9.]+)([MG]iB)", fields[1].strip())
            if not m:
                continue
            val = float(m.group(1))
            total += val * 1024.0 if m.group(2) == "GiB" else val
        if total and (best is None or total > best):
            best = total
    return best


def _ms(raw_value: str | None) -> int | None:
    if raw_value is None:
        return None
    try:
        return int(raw_value)
    except ValueError:
        return None


def _collect_artex(mock_log: Path, raw: dict, stats_path: Path) -> dict:
    calls = []
    if mock_log.exists():
        with mock_log.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        calls.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

    tasks_json = {}
    if raw.get("TASKS_JSON"):
        try:
            tasks_json = json.loads(raw["TASKS_JSON"])
        except json.JSONDecodeError:
            tasks_json = {}

    task_entry = {}
    task_id = raw.get("TASK_ID", "")
    for t in tasks_json.get("tasks", []):
        if str(t.get("id")) == str(task_id):
            task_entry = t
            break
    findings = task_entry.get("findings", {}) or {}
    findings_total = sum(v for v in findings.values() if isinstance(v, int))

    stats = json.loads(stats_path.read_text(encoding="utf-8-sig")) if stats_path.exists() else {"hits": []}
    hits = [h for h in stats.get("hits", []) if h.get("path") != "/__stats__"]
    hit_by_path: dict[str, list[dict]] = {}
    for h in hits:
        hit_by_path.setdefault(h["path"], []).append(h)

    # -- step latencies ------------------------------------------------------
    steps: list[dict] = []
    goals_calls = [c for c in calls if c.get("agent") == "goals"]
    if goals_calls:
        steps.append({"step": "goal-decompose (set_goals)",
                      "ms": goals_calls[-1].get("finished_epoch_ms", 0)
                      - goals_calls[0].get("ts_epoch_ms", 0)})
    # probes: LLM call that issued a Bash probe -> matching target hit arrival
    used_hits: set[int] = set()
    probe_order = ["/__routes__", "/pause", "/pull_weights"]
    probe_i = 0
    for c in calls:
        reply = c.get("reply") or {}
        if reply.get("kind") != "tool" or reply.get("name") != "Bash":
            continue
        cmd = json.dumps(reply.get("args", {}))
        for path in probe_order:
            if path in cmd:
                # only take probes in issued order (idempotent across retries)
                arrival = None
                for h in hit_by_path.get(path, []):
                    if id(h) not in used_hits and h["t_epoch_ms"] >= c.get("finished_epoch_ms", 0):
                        arrival = h
                        break
                if arrival is not None:
                    used_hits.add(id(arrival))
                    steps.append({
                        "step": f"probe-{probe_i + 1} {arrival['method']} {path}",
                        "ms": arrival["t_epoch_ms"] - c.get("finished_epoch_ms", 0),
                        "llm_ms": c.get("duration_ms"),
                    })
                probe_i += 1
                break
    # non-probe tool steps: set_goals / report_finding / prove_goal
    for c in calls:
        reply = c.get("reply") or {}
        if reply.get("kind") != "tool":
            continue
        name = reply.get("name")
        if name in ("set_goals", "report_finding", "prove_goal", "add_intent", "graph_overview"):
            steps.append({"step": f"{name}", "ms": c.get("duration_ms"), "llm_ms": c.get("duration_ms")})

    by_agent: dict[str, int] = {}
    tin = tout = 0
    for c in calls:
        by_agent[c.get("agent", "?")] = by_agent.get(c.get("agent", "?"), 0) + 1
        tin += int(c.get("tokens_in_est") or 0)
        tout += int(c.get("tokens_out_est") or 0)

    return {
        "task_id": task_id,
        "task_http": raw.get("TASK_HTTP"),
        "task_final_status": raw.get("TASK_FINAL_STATUS"),
        "task_accept_ms": _ms(raw.get("TASK_ACCEPT_MS")),
        "task_total_ms": _ms(raw.get("TASK_TOTAL_MS")),
        "submit_epoch_ms": _ms(raw.get("TASK_SUBMIT_EPOCH_MS")),
        "done_epoch_ms": _ms(raw.get("TASK_DONE_EPOCH_MS")),
        "cold_start_health_ms": _ms(raw.get("COLD_START_HEALTH_MS")),
        "pg_ready_ms": _ms(raw.get("PG_READY_MS")),
        "llm_calls": len(calls),
        "llm_calls_by_agent": by_agent,
        "tokens_in_est": tin,
        "tokens_out_est": tout,
        "steps": steps,
        "findings_total": findings_total,
        "findings_by_severity": findings,
        "goals_total": task_entry.get("goals_total"),
        "goals_met": task_entry.get("goals_met"),
        "target_hits": hits,
        "target_hit_count": len(hits),
        "rss_mib_during_task": _mem_mib(raw.get("task_stats_samples") or raw.get("stats_samples", [])),
        "llm_call_log": [
            {"n": c.get("n"), "agent": c.get("agent"), "turn": c.get("turn"),
             "duration_ms": c.get("duration_ms"),
             "reply_kind": (c.get("reply") or {}).get("kind"),
             "reply_tool": (c.get("reply") or {}).get("name"),
             "prompt_chars": c.get("prompt_chars"), "tools_chars": c.get("tools_chars")}
            for c in calls],
    }


def _fmt(v, suffix: str = "") -> str:
    if v is None:
        return "—"
    if isinstance(v, (int, float)):
        return f"{v:,}{suffix}"
    return str(v)


def _render_md(doc: dict) -> str:
    a, t = doc["artex"], doc["trident"]
    lines: list[str] = []
    lines.append("# ARTEX vs Trident — 同靶场同面扫描对比（same-target）\n")
    lines.append(f"> 采集时间 {doc['meta']['collected_at']}；靶场 {doc['meta']['target']}"
                 f"（lab/mock_targets.py，vulnerable）。ARTEX v0.3.23（QEMU TCG k3s VM 内，"
                 f"官方镜像、零改动），LLM 为脚本化计划器 mock（按其真实协议返回确定的 "
                 f"tool_calls 序列）；Trident 同链 {t.get('chain')} 直接在本机执行。\n")

    lines.append("## 1. 验收要点\n")
    hits = a.get("target_hits") or []
    paths = sorted({h["path"] for h in hits})
    lines.append(f"- ARTEX 任务终态：**{a.get('task_final_status')}**"
                 f"（任务 #{a.get('task_id')}，提交→终态 {_fmt(a.get('task_total_ms'))} ms）")
    lines.append(f"- ARTEX worker 对靶场的真实 HTTP 请求：**{a.get('target_hit_count')} 次**"
                 f"（路径：{', '.join(paths) if paths else '—'}）")
    lines.append(f"- ARTEX 侧 finding：**{a.get('findings_total')} 条**"
                 f"（按级别 {json.dumps(a.get('findings_by_severity') or {}, ensure_ascii=False)}）")
    lines.append(f"- Trident 链执行：{'成功' if t.get('ok') else '失败'}"
                 f"（{', '.join(f'{s['step']}={s['status']}' for s in (t.get('step_timings') or []))}）\n")

    lines.append("## 2. 每步时延\n")
    lines.append("### ARTEX（LLM 轮 + 工具执行）\n")
    lines.append("| 步骤 | 时延 ms |")
    lines.append("|---|---|")
    for st in a.get("steps", []):
        lines.append(f"| {st['step']} | {_fmt(st.get('ms'))} |")
    lines.append(f"| **合计（任务提交→终态）** | **{_fmt(a.get('task_total_ms'))}** |\n")
    lines.append("### Trident（链步骤，证据库 started_at/finished_at）\n")
    lines.append("| 步骤 | 时延 ms |")
    lines.append("|---|---|")
    for st in (t.get("step_timings") or []):
        lines.append(f"| {st['step']} | {_fmt(st.get('ms'))} |")
    lines.append(f"| dry-run 计划 | {_fmt(t.get('dry_run_ms'))} |")
    lines.append(f"| **execute 合计** | **{_fmt(t.get('execute_ms'))}** |\n")

    lines.append("## 3. 总对比表\n")
    lines.append("| 指标 | ARTEX | Trident | 说明 |")
    lines.append("|---|---|---|---|")
    for row in doc["comparison"]:
        lines.append(f"| {row['metric']} | {row['artex']} | {row['trident']} | {row.get('note', '')} |")
    lines.append("")

    lines.append("## 4. 口径与限制\n")
    for note in doc["meta"]["notes"]:
        lines.append(f"- {note}")
    lines.append(f"- 原始证据：{json.dumps(doc['provenance'], ensure_ascii=False, indent=1)}")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mock-log", required=True)
    ap.add_argument("--raw", required=True)
    ap.add_argument("--target-stats", required=True)
    ap.add_argument("--trident", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--target", default="http://10.0.2.2:18080")
    ap.add_argument("--note", action="append", default=[])
    args = ap.parse_args()

    raw = _parse_raw(Path(args.raw))
    artex = _collect_artex(Path(args.mock_log), raw, Path(args.target_stats))
    trident = json.loads(Path(args.trident).read_text(encoding="utf-8"))

    trident_hits = trident.get("target_hit_count")
    comparison = [
        {"metric": "total_ms",
         "artex": artex.get("task_total_ms"),
         "trident": trident.get("execute_ms"),
         "note": "ARTEX=任务提交→终态（含 3s 轮询粒度）；Trident=链 execute 墙钟"},
        {"metric": "requests",
         "artex": artex.get("target_hit_count"),
         "trident": trident_hits,
         "note": "靶场 /__stats__ 计数（同靶场同面）"},
        {"metric": "tokens",
         "artex": f"in~{artex.get('tokens_in_est')}/out~{artex.get('tokens_out_est')}",
         "trident": "0",
         "note": "mock 按请求体 chars/4 估算；Trident 全链确定性、零 LLM token"},
        {"metric": "llm_calls",
         "artex": artex.get("llm_calls"),
         "trident": 0,
         "note": f"按 agent {json.dumps(artex.get('llm_calls_by_agent') or {}, ensure_ascii=False)}"},
        {"metric": "findings",
         "artex": artex.get("findings_total"),
         "trident": len([s for s in (trident.get("step_timings") or []) if s.get("status") == "success"]),
         "note": "ARTEX=report_finding 落库；Trident=链步骤成功数（各有证据语义）"},
        {"metric": "rss_mib",
         "artex": round(artex.get("rss_mib_during_task") or 0, 1) or None,
         "trident": round((trident.get("max_rss_kb") or 0) / 1024, 1) or None,
         "note": "ARTEX=任务窗口 docker stats 峰值（artex+pg 两容器）；Trident=执行进程工作集峰值"},
        {"metric": "cold_start_ms",
         "artex": artex.get("cold_start_health_ms"),
         "trident": None,
         "note": "ARTEX 栈冷启动（PG+容器+迁移）；Trident 进程内启动亚秒"},
    ]

    doc = {
        "meta": {
            "collected_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "target": args.target,
            "artex": "ruoji6/artex:v0.3.23 (QEMU TCG k3s VM, unmodified)",
            "llm": "scripted-planner mock (lab/qemu-k3s/artex-mock-llm.py v2)",
            "notes": args.note or [
                "ARTEX 时延含 QEMU TCG 放大（纯软件仿真），绝对值不代表裸机；同宿主同窗口对比才有意义。",
                "ARTEX 的 LLM 为脚本化计划器 mock：协议真实（真实 tool_calls/工具执行/落库），决策是确定脚本，不代表模型质量。",
                "token 估算 = ARTEX 请求体字符数/4（mock 非真实分词器）。",
                "Trident 为 Windows 本机进程，直接访问 127.0.0.1:18080（与 ARTEX 经 10.0.2.2:18080 同一靶场实例）。",
            ],
        },
        "artex": artex,
        "trident": trident,
        "comparison": comparison,
        "provenance": {
            "mock_llm_log": str(Path(args.mock_log)),
            "artex_raw": str(Path(args.raw)),
            "target_stats": str(Path(args.target_stats)),
            "trident_out": str(Path(args.trident)),
            "artex_tasks_json": (raw.get("TASKS_JSON") or "")[:4000],
            "collected_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        },
    }

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, ensure_ascii=False, indent=1), encoding="utf-8")
    out.with_suffix(".md").write_text(_render_md(doc), encoding="utf-8")
    print(f"[same-target-collect] wrote {out} and {out.with_suffix('.md')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
