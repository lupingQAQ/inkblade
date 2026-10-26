"""混沌编排器：顺序 / 并行 / 定时；中止条件 + 自动回滚 + 恢复断言 + SLO 度量。

单个实验生命周期（对齐 Chaos Toolkit Method）：

1. ``steady``    稳态假设必须全部成立，否则拒绝注入（steady_state_failed，不动靶场）；
2. ``inject``    执行注入动作；
3. ``measure``   SLO 影响度量（期间任一 measure probe 命中即记 degraded）；
4. ``abort``     中止条件评估（任一命中 → aborted_by_condition）+ 外部中止信号
   （``trident chaos abort`` 写入的标记文件 / 进程内 Event）；
5. ``rollback``  无论成败一律自动回滚；
6. ``recovery``  稳态复测（默认复用 steady probes）：恢复 → recovered=true，
   未恢复 → outcome=rollback_failed（人工介入）。

outcome 取值：``completed``（注入生效且恢复）/ ``aborted_by_condition`` /
``aborted_external`` / ``steady_state_failed`` / ``no_impact_detected`` /
``rollback_failed``。
"""

from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .catalog import ChaosExperiment, experiment_by_id
from .runtime import DnsShim, TargetRegistry, apply_action, eval_probe


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class ChaosOrchestrator:
    """编排一组实验；可跨线程共享（并行模式）。"""

    def __init__(self, home: str | Path = ".", *, targets: dict[str, str] | None = None,
                 auto_start: bool = True, stop_targets: bool = True):
        self.home = Path(home)
        self.registry = TargetRegistry(targets, auto_start=auto_start)
        self._stop_targets = stop_targets
        self._abort_event = threading.Event()
        self._external_abort_reason = ""
        self._lock = threading.Lock()
        self._active = False

    # ------------------------------------------------------------- 中止
    def abort(self, reason: str = "manual") -> None:
        self._abort_event.set()
        with self._lock:
            self._external_abort_reason = reason

    def _aborted(self) -> bool:
        if self._abort_event.is_set():
            return True
        return abort_requested(self.home)

    # ------------------------------------------------------------- 单实验
    def _run_one(self, exp: ChaosExperiment) -> dict:
        result: dict[str, Any] = {
            "id": exp.id, "title": exp.title, "category": exp.category,
            "target": exp.target, "ml_specific": exp.ml_specific, "slo": exp.slo,
            "started_at": _now_iso(), "phases": {}, "slo_impact": {},
        }
        started = time.perf_counter()
        dns = DnsShim()

        def phase(name: str, probes) -> list[dict]:
            rows = [eval_probe(p, targets=self.registry, default_target=exp.target,
                               via_proxy=exp.via_proxy, dns=dns) for p in probes]
            result["phases"][name] = rows
            return rows

        def action(name: str, act) -> dict:
            record = apply_action(act, targets=self.registry, experiment=exp, dns=dns)
            result["phases"][name] = record
            return record

        outcome = "completed"
        try:
            # 1) 稳态假设（不成立 → 拒绝注入）
            steady = phase("steady_state", exp.steady)
            if not all(r["ok"] for r in steady):
                outcome = "steady_state_failed"
                result["slo_impact"] = {"degraded": False, "recovered": False,
                                        "reason": "稳态假设未成立，已拒绝注入（fail-safe）"}
                return self._finish(result, outcome, started)

            baseline = {r["name"]: r["value"] for r in steady}

            # 2) 注入
            action("inject", exp.inject)

            # 3) SLO 度量
            measure = phase("measure", exp.measure)
            degraded = any(r["ok"] for r in measure)

            # 4) 中止条件（内部条件 + 外部信号）
            if self._aborted():
                outcome = "aborted_external"
                reason = self._external_abort_reason or abort_reason_of(self.home) or "external"
                result["slo_impact"] = {"degraded": degraded, "recovered": False,
                                        "abort_reason": reason}
            else:
                abort_eval = phase("abort_when", exp.abort_when)
                if any(r["ok"] for r in abort_eval):
                    outcome = "aborted_by_condition"
                    result["slo_impact"] = {
                        "degraded": degraded, "recovered": False,
                        "abort_reason": "中止条件命中: "
                                        + ", ".join(r["name"] for r in abort_eval if r["ok"]),
                    }

            during = {r["name"]: r["value"] for r in measure}
            result["slo_impact"].setdefault("baseline", baseline)
            result["slo_impact"]["during"] = during
            result["slo_impact"]["degraded"] = degraded

            # 5) 自动回滚（一律执行）
            action("rollback", exp.rollback)

            # 6) 恢复断言（稳态复测）
            recovery = phase("recovery", exp.recovery or exp.steady)
            recovered = all(r["ok"] for r in recovery)
            result["slo_impact"]["recovered"] = recovered
            if not recovered:
                outcome = "rollback_failed"
            elif outcome == "completed" and not degraded:
                outcome = "no_impact_detected"
            return self._finish(result, outcome, started)
        finally:
            # 网络类实验收尾：清空故障档案，防止泄漏到下一个实验
            if exp.via_proxy:
                try:
                    proxy = self.registry.proxy_for(exp.target)
                    proxy.profile.apply({"delay_ms": 0, "drop_rate": 0.0, "block_groups": []})
                except Exception:  # noqa: BLE001
                    pass
            dns.fail_hosts.clear()

    def _finish(self, result: dict, outcome: str, started: float) -> dict:
        result["outcome"] = outcome
        result["duration_s"] = round(time.perf_counter() - started, 4)
        result["completed_at"] = _now_iso()
        return result

    # ------------------------------------------------------------- 编排
    def run(self, ids: list[str] | tuple[str, ...], *, mode: str = "sequential",
            max_parallel: int = 3, every_s: float = 0.0, cycles: int = 1,
            progress: Any = None) -> dict:
        experiments = [experiment_by_id(i) for i in ids]
        report: dict[str, Any] = {
            "schema": "trident-chaos-run/1",
            "generated_at": _now_iso(),
            "mode": mode, "cycles": cycles, "every_s": every_s,
            "experiment_count": len(experiments),
            "boundary": "全部注入仅作用于本地 mock/仿真靶场（127.0.0.1 进程内）；"
                        "不对真实集群/GPU/交换机执行",
            "results": [],
            "summary": {},
        }
        self._abort_event.clear()
        self._active = True
        try:
            for cycle in range(max(1, cycles)):
                results = self._run_cycle(experiments, mode, max_parallel, progress)
                for r in results:
                    r["cycle"] = cycle
                report["results"].extend(results)
                if cycle + 1 < max(1, cycles) and every_s > 0:
                    time.sleep(every_s)
        finally:
            self._active = False
            if self._stop_targets:
                self.registry.shutdown_all()
        report["summary"] = _summarize(report["results"])
        self._write_report(report)
        return report

    def _run_cycle(self, experiments: list[ChaosExperiment], mode: str,
                   max_parallel: int, progress: Any = None) -> list[dict]:
        if mode == "parallel":
            workers = max(1, min(max_parallel, len(experiments)))
            results: list[dict] = []
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {pool.submit(self._run_one, exp): exp for exp in experiments}
                for fut in as_completed(futures):
                    results.append(fut.result())
                    if progress:
                        progress(futures[fut].id, fut.result()["outcome"])
            order = {e.id: i for i, e in enumerate(experiments)}
            results.sort(key=lambda r: order.get(r["id"], 0))
            return results
        results = []
        for exp in experiments:
            if self._aborted():
                results.append({"id": exp.id, "title": exp.title,
                                "outcome": "aborted_external",
                                "detail": "外部中止信号，未执行"})
                continue
            one = self._run_one(exp)
            results.append(one)
            if progress:
                progress(exp.id, one["outcome"])
        return results

    def _write_report(self, report: dict) -> None:
        out_dir = self.home / "chaos-runs"
        out_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        report["report_path"] = str((out_dir / f"chaos-{stamp}.json").resolve())
        (out_dir / f"chaos-{stamp}.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        index = out_dir / "latest.json"
        index.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")


def _summarize(results: list[dict]) -> dict:
    outcomes: dict[str, int] = {}
    for r in results:
        outcomes[r.get("outcome", "unknown")] = outcomes.get(r.get("outcome", "unknown"), 0) + 1
    degraded = sum(1 for r in results if r.get("slo_impact", {}).get("degraded"))
    recovered = sum(1 for r in results if r.get("slo_impact", {}).get("recovered"))
    ran = [r for r in results if r.get("outcome") not in ("aborted_external",)]
    return {
        "total": len(results), "outcomes": outcomes,
        "degraded": degraded, "recovered": recovered,
        "steady_break_then_recover": sum(
            1 for r in ran if r.get("slo_impact", {}).get("degraded")
            and r.get("slo_impact", {}).get("recovered")),
        "duration_s": round(sum(r.get("duration_s", 0.0) for r in results), 4),
    }


# --------------------------------------------------------------------------- 外部中止


def active_abort_file(home: str | Path) -> Path:
    return Path(home) / ".chaos" / "abort.json"


def abort_active_run(home: str | Path, reason: str = "manual") -> dict:
    """CLI `trident chaos abort`：写中止标记文件（运行中的编排器每阶段轮询）。"""
    path = active_abort_file(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = {"requested_at": _now_iso(), "reason": reason, "pid_hint": "any"}
    path.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
    return {"abort": True, "file": str(path), "reason": reason}


def abort_requested(home: str | Path) -> bool:
    return active_abort_file(home).is_file()


def abort_reason_of(home: str | Path) -> str:
    path = active_abort_file(home)
    if not path.is_file():
        return ""
    try:
        return str(json.loads(path.read_text(encoding="utf-8")).get("reason") or "")
    except ValueError:
        return "unreadable-abort-file"


def clear_abort(home: str | Path) -> None:
    path = active_abort_file(home)
    if path.is_file():
        path.unlink()
