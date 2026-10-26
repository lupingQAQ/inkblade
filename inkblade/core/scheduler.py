# -*- coding: utf-8 -*-
"""持续化周期重测（XBow 对标 ③）：cron 式计划 → 到期自动跑链子集 → 与上次 findings 差异 → drift 报告。

- 计划持久化：工作区 ``schedules.json``（id/cron 或 interval_seconds/chains/enabled）；
- cron 文法（5 字段 分 时 日 月 周）：* 、*/n 、a-b 、逗号清单（白名单解析，其余报错）；
- ``due(now)``/``run_due(store, session, now)``：到期计划逐链执行（chains.execute，
  全部闸门复用），完成后与该计划上次 run 的 findings 做 key 差异
  （新增 new / 已修复 fixed / 未变 unchanged），drift 报告落 run 目录 ``drift.json``
  并随返回值上抛；计划记住 last_run/next_fire。
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

SCHEDULES_RELPATH = "schedules.json"
_RANGES = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 6)]


class ScheduleError(ValueError):
    """计划/cron 表达式非法。"""


def _parse_field(field: str, idx: int) -> set[int]:
    lo, hi = _RANGES[idx]
    if field == "*":
        return set(range(lo, hi + 1))
    out: set[int] = set()
    for part in field.split(","):
        part = part.strip()
        if not part:
            raise ScheduleError(f"cron 字段含空段: {field!r}")
        step = 1
        if "/" in part:
            part, _, step_s = part.partition("/")
            try:
                step = int(step_s)
            except ValueError as exc:
                raise ScheduleError(f"cron 步长非法: {field!r}") from exc
            if step <= 0:
                raise ScheduleError(f"cron 步长非法: {field!r}")
        try:
            if part == "*":
                start, end = lo, hi
            elif "-" in part:
                a, _, b = part.partition("-")
                start, end = int(a), int(b)
            else:
                start = end = int(part)
        except ValueError as exc:
            raise ScheduleError(f"cron 字段非数字: {field!r}") from exc
        if not (lo <= start <= hi and lo <= end <= hi and start <= end):
            raise ScheduleError(f"cron 字段越界: {field!r}（允许 {lo}-{hi}）")
        out.update(range(start, end + 1, step))
    return out


def parse_cron(expr: str) -> tuple[set[int], set[int], set[int], set[int], set[int]]:
    parts = expr.split()
    if len(parts) != 5:
        raise ScheduleError(f"cron 须为 5 字段（分 时 日 月 周）: {expr!r}")
    return tuple(_parse_field(p, i) for i, p in enumerate(parts))  # type: ignore[return-value]


def next_fire(expr: str, after: datetime) -> datetime:
    """下次触发时刻：分钟粒度向前扫描（上限 366 天，防非法月日组合死循环）。"""
    sets = parse_cron(expr)
    t = after.replace(second=0, microsecond=0) + timedelta(minutes=1)
    horizon = after + timedelta(days=366)
    while t <= horizon:
        if (t.minute in sets[0] and t.hour in sets[1] and t.day in sets[2]
                and t.month in sets[3] and t.weekday() in sets[4]):
            return t
        t += timedelta(minutes=1)
    raise ScheduleError(f"cron 无未来触发点: {expr!r}")


def diff_findings(prev: list[dict], curr: list[dict]) -> dict[str, Any]:
    """按 (step_key|title) 键差异：new=新增，fixed=已修复（上有今无），unchanged=仍在。"""
    def key(f: dict) -> str:
        return f"{f.get('step_key', '')}|{f.get('title', '')}"

    prev_keys = {key(f): f for f in prev or []}
    curr_keys = {key(f): f for f in curr or []}
    return {
        "new": [curr_keys[k] for k in sorted(set(curr_keys) - set(prev_keys))],
        "fixed": [prev_keys[k] for k in sorted(set(prev_keys) - set(curr_keys))],
        "unchanged": sorted(set(prev_keys) & set(curr_keys)),
        "counts": {"new": len(set(curr_keys) - set(prev_keys)),
                   "fixed": len(set(prev_keys) - set(curr_keys)),
                   "unchanged": len(set(prev_keys) & set(curr_keys))},
    }


class Scheduler:
    def __init__(self, store, *, chains_dir: Path | str | None = None,
                 modules_dir: Path | str | None = None):
        self.store = store
        self.path = Path(store.ws_dir) / SCHEDULES_RELPATH
        self.chains_dir = Path(chains_dir) if chains_dir else Path(__file__).resolve().parent.parent / "chains"
        self.modules_dir = Path(modules_dir) if modules_dir else store.root / "modules"

    # ---------- 持久化 ----------
    def _load(self) -> list[dict]:
        if not self.path.exists():
            return []
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _save(self, items: list[dict]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(items, ensure_ascii=False, indent=1), encoding="utf-8")
        tmp.replace(self.path)

    # ---------- CRUD ----------
    def add(self, session, *, cron: str | None = None, interval_seconds: int | None = None,
            chains: list[str] | None = None, schedule_id: str = "") -> dict:
        if not chains:
            raise ScheduleError("chains 为空（须指定至少一条链）")
        if (cron is None) == (interval_seconds is None):
            raise ScheduleError("cron 与 interval_seconds 二选一")
        if cron is not None:
            parse_cron(cron)  # 校验
        if interval_seconds is not None and int(interval_seconds) <= 0:
            raise ScheduleError("interval_seconds 须为正")
        items = self._load()
        sid = schedule_id or f"sched-{time.strftime('%Y%m%d-%H%M%S')}-{len(items) + 1:03d}"
        if any(s["id"] == sid for s in items):
            raise ScheduleError(f"计划 id 重复 {sid}")
        item = {"id": sid, "cron": cron, "interval_seconds": interval_seconds,
                "chains": list(chains), "enabled": True, "created_by": session.name,
                "created_at": time.time(), "last_run": None, "last_run_name": None,
                "next_fire": None}
        items.append(item)
        self._save(items)
        return item

    def remove(self, schedule_id: str) -> dict:
        items = self._load()
        keep = [s for s in items if s["id"] != schedule_id]
        if len(keep) == len(items):
            raise ScheduleError(f"未知计划 {schedule_id}")
        self._save(keep)
        return {"removed": schedule_id}

    def set_enabled(self, schedule_id: str, enabled: bool) -> dict:
        items = self._load()
        for s in items:
            if s["id"] == schedule_id:
                s["enabled"] = bool(enabled)
                self._save(items)
                return s
        raise ScheduleError(f"未知计划 {schedule_id}")

    def list(self) -> list[dict]:
        return self._load()

    # ---------- 到期与执行 ----------
    def due(self, now: float | None = None) -> list[dict]:
        now = time.time() if now is None else now
        out = []
        for s in self._load():
            if not s.get("enabled"):
                continue
            if s.get("interval_seconds"):
                last = s.get("last_run") or s.get("created_at") or now
                if now - last >= s["interval_seconds"]:
                    out.append(s)
            elif s.get("cron"):
                base = s.get("last_run") or s.get("created_at") or now
                if next_fire(s["cron"], datetime.fromtimestamp(base)) <= datetime.fromtimestamp(now):
                    out.append(s)
        return out

    def run_due(self, session, *, now: float | None = None) -> dict[str, Any]:
        from .chains import execute as chain_execute
        from .chains import load_chains

        due_items = self.due(now)
        results: dict[str, Any] = {}
        all_items = self._load()
        for s in due_items:
            chains = load_chains(self.chains_dir) if self.chains_dir.exists() else {}
            prev_findings: list[dict] = []
            if s.get("last_run_name"):
                try:
                    prev_findings = self.store.open_run(s["last_run_name"]).findings
                except KeyError:
                    prev_findings = []
            per_chain = []
            last_run_name = None
            for cid in s["chains"]:
                chain = chains.get(cid)
                if chain is None:
                    per_chain.append({"chain": cid, "status": "skipped", "reason": "未知链"})
                    continue
                try:
                    res = chain_execute(chain, self.store, session, self.modules_dir,
                                        findings=prev_findings)
                    per_chain.append({"chain": cid, "status": "ok", "run": res["run"],
                                      "steps": {k: v["status"] for k, v in res["steps"].items()}})
                    last_run_name = res["run"]
                except Exception as exc:
                    per_chain.append({"chain": cid, "status": "failed",
                                      "error": f"{type(exc).__name__}: {exc}"})
            drift = {"new": [], "fixed": [], "unchanged": [], "counts": {"new": 0, "fixed": 0, "unchanged": 0}}
            if last_run_name:
                drift = diff_findings(prev_findings, self.store.open_run(last_run_name).findings)
                drift_run = self.store.open_run(last_run_name)
                (Path(drift_run.dir) / "drift.json").write_text(
                    json.dumps({"schedule": s["id"], "previous_run": s.get("last_run_name"),
                                "current_run": last_run_name, **drift}, ensure_ascii=False, indent=1),
                    encoding="utf-8")
            nf = next_fire(s["cron"], datetime.now()) if s.get("cron") else None
            for item in all_items:
                if item["id"] == s["id"]:
                    item["last_run"] = time.time()
                    item["last_run_name"] = last_run_name or item.get("last_run_name")
                    item["next_fire"] = nf.isoformat(timespec="minutes") if nf else None
            results[s["id"]] = {"chains": per_chain, "drift": drift}
        if due_items:
            self._save(all_items)
        return {"due": [s["id"] for s in due_items], "results": results,
                "next": {s["id"]: s.get("next_fire") for s in self.list()}}
