# -*- coding: utf-8 -*-
"""计划任务日历（clean-room 等价实现）：一次性测试窗口 + 暂停/恢复 + 日历视图。

与 ``core/scheduler.py`` 分工：
- scheduler 负责长期 ``cron`` / ``interval`` 周期；
- calendar 负责**一次性窗口**（``[start, end)`` 内只执行一次）以及窗口级暂停/恢复，
  窗口内链子集仍走 ``chains.execute``（ROE/角色/备份三闸门与审计不旁路）。

安全默认：
- 创建/暂停/恢复/删除要求 lead/admin（approve）；
- ``run_due`` 要求 execute 权限，且工作区 ROE 未签署时直接拒绝（ExecutionLocked）；
- 窗口只登记计划，不自动后台执行；没有到期窗口时 ``run_due`` 是空操作；
- 每个动作写工作区 ``audit.jsonl``，执行结果落 run 证据库。
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from . import jsonio
from .roe import ExecutionLocked, roe_status

CALENDAR_RELPATH = "calendar.json"


class CalendarError(ValueError):
    """窗口参数非法。"""


def _ts(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    try:
        return float(text)
    except ValueError:
        pass
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except ValueError as exc:
        raise CalendarError(f"无法解析时间 {value!r}（epoch 或 ISO 8601）") from exc


class Calendar:
    def __init__(self, store, *, chains_dir: Path | str | None = None,
                 modules_dir: Path | str | None = None, clock=time.time):
        self.store = store
        self.path = jsonio.ws_path(store, CALENDAR_RELPATH)
        self.chains_dir = Path(chains_dir) if chains_dir else \
            Path(__file__).resolve().parent.parent / "chains"
        self.modules_dir = Path(modules_dir) if modules_dir else Path(store.root) / "modules"
        self._clock = clock

    # ------------------------------------------------------------ 持久化
    def _load(self) -> list[dict]:
        doc = jsonio.read_json(self.path, None)
        if isinstance(doc, dict) and isinstance(doc.get("windows"), list):
            return doc["windows"]
        if isinstance(doc, list):
            return doc
        return []

    def _save(self, items: list[dict]) -> None:
        jsonio.write_json(self.path, {"version": 1, "windows": items})

    def list(self) -> list[dict]:
        return [self._view(w) for w in self._load()]

    def get(self, window_id: str) -> dict:
        for w in self._load():
            if w.get("id") == window_id:
                return w
        raise CalendarError(f"未知窗口 {window_id}")

    # ------------------------------------------------------------ CRUD
    def add_window(self, session, *, name: str, start: Any, end: Any,
                   chains: list[str], window_id: str = "", enabled: bool = True,
                   allow_past: bool = False) -> dict:
        if not session.can("approve"):
            raise PermissionError(f"{session.name}({session.role}) 无 approve 权限")
        if not chains:
            raise CalendarError("chains 为空（窗口须指定至少一条链）")
        start_ts, end_ts = _ts(start), _ts(end)
        if end_ts <= start_ts:
            raise CalendarError("窗口 end 必须晚于 start")
        now = self._clock()
        if end_ts <= now and not allow_past:
            raise CalendarError("窗口已过期（end <= now）；如为历史导入请显式 allow_past")
        items = self._load()
        wid = window_id or f"win-{len(items) + 1:03d}"
        if any(w.get("id") == wid for w in items):
            raise CalendarError(f"窗口 id 重复 {wid}")
        item = {"id": wid, "name": str(name or wid), "start": start_ts, "end": end_ts,
                "chains": list(chains), "enabled": bool(enabled), "paused": False,
                "created_by": session.name, "created_at": now,
                "last_run": None, "last_run_name": None, "results": []}
        items.append(item)
        self._save(items)
        jsonio.append_audit(self.store, session.name, "calendar.add", wid,
                            {"start": start_ts, "end": end_ts, "chains": list(chains)}, "ok")
        return self._view(item)

    def pause(self, session, window_id: str) -> dict:
        return self._set_paused(session, window_id, True)

    def resume(self, session, window_id: str) -> dict:
        return self._set_paused(session, window_id, False)

    def _set_paused(self, session, window_id: str, paused: bool) -> dict:
        if not session.can("approve"):
            raise PermissionError(f"{session.name}({session.role}) 无 approve 权限")
        items = self._load()
        for w in items:
            if w.get("id") == window_id:
                w["paused"] = bool(paused)
                w["paused_by"] = session.name if paused else ""
                w["paused_at"] = self._clock() if paused else None
                self._save(items)
                jsonio.append_audit(self.store, session.name,
                                    "calendar.pause" if paused else "calendar.resume",
                                    window_id, {}, "ok")
                return self._view(w)
        raise CalendarError(f"未知窗口 {window_id}")

    def remove(self, session, window_id: str) -> dict:
        if not session.can("approve"):
            raise PermissionError(f"{session.name}({session.role}) 无 approve 权限")
        items = self._load()
        keep = [w for w in items if w.get("id") != window_id]
        if len(keep) == len(items):
            raise CalendarError(f"未知窗口 {window_id}")
        self._save(keep)
        jsonio.append_audit(self.store, session.name, "calendar.remove", window_id, {}, "ok")
        return {"removed": window_id}

    # ------------------------------------------------------------ 到期
    def due(self, now: float | None = None) -> list[dict]:
        now = self._clock() if now is None else float(now)
        out = []
        for w in self._load():
            if not w.get("enabled", True) or w.get("paused"):
                continue
            if w.get("last_run") is not None:
                continue
            if float(w["start"]) <= now < float(w["end"]):
                out.append(w)
        return out

    def run_due(self, session, now: float | None = None) -> dict[str, Any]:
        if roe_status(self.store) != "complete":
            raise ExecutionLocked("工作区授权未完成（consent 未签署）")
        if not session.can("execute"):
            raise PermissionError(f"{session.name}({session.role}) 无 execute 权限")
        from .chains import execute as chain_execute
        from .chains import load_chains

        now = self._clock() if now is None else float(now)
        due = self.due(now)
        items = self._load()
        results: dict[str, Any] = {}
        for w in due:
            chains = load_chains(self.chains_dir) if self.chains_dir.exists() else {}
            per_chain = []
            last_run = None
            for cid in w.get("chains", []):
                chain = chains.get(cid)
                if chain is None:
                    per_chain.append({"chain": cid, "status": "skipped", "reason": "未知链"})
                    continue
                try:
                    res = chain_execute(chain, self.store, session, self.modules_dir)
                    per_chain.append({"chain": cid, "status": "ok", "run": res["run"]})
                    last_run = res["run"]
                except Exception as exc:
                    per_chain.append({"chain": cid, "status": "failed",
                                      "error": f"{type(exc).__name__}: {exc}"})
            for item in items:
                if item.get("id") == w.get("id"):
                    item["last_run"] = now
                    item["last_run_name"] = last_run
                    item["results"] = per_chain
            results[w["id"]] = {"chains": per_chain, "run": last_run}
        if due:
            self._save(items)
        for wid, res in results.items():
            jsonio.append_audit(self.store, session.name, "calendar.run", wid,
                                {"chains": res["chains"]}, "ok")
        return {"due": [w["id"] for w in due], "results": results,
                "next": {w["id"]: self._view(w).get("status") for w in self._load()}}

    # ------------------------------------------------------------ 视图
    @staticmethod
    def _view(w: dict) -> dict:
        out = dict(w)
        out["start_iso"] = _iso(w.get("start"))
        out["end_iso"] = _iso(w.get("end"))
        out["duration_hours"] = round((float(w.get("end", 0)) - float(w.get("start", 0))) / 3600, 2)
        return out

    def upcoming(self, *, now: float | None = None, days: int = 14) -> list[dict]:
        now = self._clock() if now is None else float(now)
        horizon = now + max(1, int(days)) * 86400
        out = []
        for w in self._load():
            if float(w.get("end", 0)) < now or float(w.get("start", 0)) > horizon:
                continue
            out.append({**self._view(w), "status": self.status(w, now=now)})
        return sorted(out, key=lambda x: x["start"])

    def status(self, window: dict, *, now: float | None = None) -> str:
        now = self._clock() if now is None else float(now)
        if window.get("last_run") is not None:
            return "ran"
        if window.get("paused"):
            return "paused"
        if not window.get("enabled", True):
            return "disabled"
        if now < float(window.get("start", 0)):
            return "scheduled"
        if now >= float(window.get("end", 0)):
            return "expired"
        return "due"

    def event_calendar(self, *, now: float | None = None, days: int = 42) -> dict:
        """UI 数据：按日分组（含状态与链数），只读。"""
        now = self._clock() if now is None else float(now)
        start_day = datetime.fromtimestamp(now).date()
        days = max(1, int(days))
        buckets: dict[str, list[dict]] = {}
        for i in range(days):
            d = start_day + timedelta(days=i)
            buckets[d.isoformat()] = []
        for w in self._load():
            d0 = datetime.fromtimestamp(float(w["start"])).date()
            d1 = datetime.fromtimestamp(float(w["end"])).date()
            d = d0
            while d <= d1 and d.isoformat() in buckets:
                buckets[d.isoformat()].append({
                    "id": w["id"], "name": w.get("name", ""),
                    "status": self.status(w, now=now), "chains": len(w.get("chains") or []),
                })
                d += timedelta(days=1)
        return {"days": [{"date": d, "windows": ws} for d, ws in buckets.items()],
                "now": now, "window_count": len(self._load())}


def _iso(ts: Any) -> str:
    try:
        return datetime.fromtimestamp(float(ts)).isoformat(timespec="minutes")
    except Exception:
        return ""
