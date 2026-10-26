# -*- coding: utf-8 -*-
"""Durable event-sourced runtime: journal, checkpoint, resume, replay, budgets.

Every agent decision, probe task, observation and evidence reference is an
append-only event.  The chain is SHA-256 linked (``prev`` + canonical body), so
truncation, deletion or editing is detected before resume/replay.  Checkpoints
store a graph snapshot for fast recovery; replay can rebuild any prefix for
time-travel and audit.

The runtime never executes probe or module code.  It only records and folds
state.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any, Iterable

RUN_SCHEMA = "inkblade-agent-run/1"
EVENT_SCHEMA = "inkblade-agent-event/1"
RUNTIME_VERSION = "2026.10"

RUNS_RELPATH = "agent/runs"
LAST_RUN_RELPATH = "agent/last_run.json"


class AgentRuntimeError(ValueError):
    """Invalid runtime operation or corrupt journal."""


class BudgetExceeded(AgentRuntimeError):
    """A hard budget cap was reached."""

    def __init__(self, kind: str, spent: int | float, limit: int | float):
        super().__init__(f"budget {kind} exceeded: spent={spent} limit={limit}")
        self.kind = kind
        self.spent = spent
        self.limit = limit


class StopRequested(AgentRuntimeError):
    """The kill switch or an operator stop was observed."""


def _canonical(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      default=str)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _event_hash(prev: str, body: dict) -> str:
    return _sha256(prev + _canonical(body))


def estimate_tokens(value: Any) -> int:
    """Deterministic token estimate (CJK per char, other text per 4 chars)."""
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False,
                                                           sort_keys=True, default=str)
    cjk = sum(1 for ch in text if "\u4e00" <= ch <= "\u9fff")
    rest = max(0, len(text) - cjk)
    return max(1, cjk + rest // 4)


class Budget:
    """Four-dimensional hard cap: tokens, steps, actions and wall-clock time."""

    KINDS = ("tokens", "steps", "actions", "duration_ms")

    def __init__(self, *, tokens: int = 0, steps: int = 0, actions: int = 0,
                 duration_ms: int = 0, clock=time.time):
        self.limits = {
            "tokens": max(0, int(tokens or 0)),
            "steps": max(0, int(steps or 0)),
            "actions": max(0, int(actions or 0)),
            "duration_ms": max(0, int(duration_ms or 0)),
        }
        self.spent = {kind: 0 for kind in self.KINDS}
        self._clock = clock
        self.started_at = float(clock())

    def __getitem__(self, kind: str) -> int:
        return int(self.spent.get(kind, 0))

    def remaining(self, kind: str) -> int | None:
        limit = self.limits.get(kind, 0)
        if not limit:
            return None
        return max(0, limit - int(self.spent.get(kind, 0)))

    def would_exceed(self, kind: str, amount: int | float = 1) -> bool:
        limit = self.limits.get(kind, 0)
        if not limit:
            return False
        return int(self.spent.get(kind, 0)) + int(amount) > limit

    def elapsed_ms(self) -> int:
        return int((float(self._clock()) - self.started_at) * 1000)

    def duration_would_exceed(self, reserve_ms: int = 0) -> bool:
        limit = self.limits.get("duration_ms", 0)
        return bool(limit) and self.elapsed_ms() + int(reserve_ms) > limit

    def consume(self, kind: str, amount: int | float = 1) -> int:
        if kind not in self.KINDS:
            raise AgentRuntimeError(f"未知预算维度: {kind!r}")
        if kind == "duration_ms":
            value = self.elapsed_ms()
            self.spent[kind] = value
            limit = self.limits.get(kind, 0)
            if limit and value > limit:
                raise BudgetExceeded(kind, value, limit)
            return value
        amount = max(0, int(amount))
        self.spent[kind] = int(self.spent.get(kind, 0)) + amount
        limit = self.limits.get(kind, 0)
        if limit and self.spent[kind] > limit:
            raise BudgetExceeded(kind, self.spent[kind], limit)
        return self.spent[kind]

    def check(self, *, reserve_tokens: int = 0, reserve_steps: int = 0) -> None:
        for kind, reserve in (("tokens", reserve_tokens), ("steps", reserve_steps)):
            limit = self.limits.get(kind, 0)
            if limit and int(self.spent.get(kind, 0)) + int(reserve) > limit:
                raise BudgetExceeded(kind, int(self.spent.get(kind, 0)) + int(reserve), limit)
        if self.duration_would_exceed():
            raise BudgetExceeded("duration_ms", self.elapsed_ms(), self.limits["duration_ms"])

    def to_dict(self) -> dict:
        return {"limits": dict(self.limits), "spent": dict(self.spent),
                "started_at": self.started_at, "elapsed_ms": self.elapsed_ms()}

    @classmethod
    def from_dict(cls, doc: dict, *, clock=time.time) -> "Budget":
        budget = cls(tokens=int((doc or {}).get("limits", {}).get("tokens", 0)),
                     steps=int((doc or {}).get("limits", {}).get("steps", 0)),
                     actions=int((doc or {}).get("limits", {}).get("actions", 0)),
                     duration_ms=int((doc or {}).get("limits", {}).get("duration_ms", 0)),
                     clock=clock)
        budget.spent.update({k: int(v) for k, v in ((doc or {}).get("spent") or {}).items()
                             if k in budget.KINDS})
        budget.started_at = float((doc or {}).get("started_at") or budget.started_at)
        return budget

    @classmethod
    def from_events(cls, events: Iterable[dict], *, limits: dict,
                    clock=time.time) -> "Budget":
        budget = cls(tokens=limits.get("tokens", 0), steps=limits.get("steps", 0),
                     actions=limits.get("actions", 0),
                     duration_ms=limits.get("duration_ms", 0), clock=clock)
        for event in events:
            if event.get("kind") != "budget.spent":
                continue
            payload = event.get("payload") or {}
            kind = str(payload.get("kind") or "")
            if kind in budget.KINDS and kind != "duration_ms":
                budget.spent[kind] = int(payload.get("total") or payload.get("amount") or 0)
        return budget


class EventLog:
    """Append-only, hash-chained JSONL journal for one agent run."""

    def __init__(self, path: Path | str, *, run_id: str, fsync: bool = True):
        self.path = Path(path)
        self.run_id = str(run_id)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fsync = bool(fsync)

    def exists(self) -> bool:
        return self.path.is_file() and self.path.stat().st_size > 0

    def append(self, kind: str, *, payload: dict | None = None,
               actor: str = "agent") -> dict:
        if not str(kind or "").strip():
            raise AgentRuntimeError("event kind 不能为空")
        if payload is not None and not isinstance(payload, dict):
            raise AgentRuntimeError("event payload 必须是对象")
        events = self.events(strict=False)
        seq = (int(events[-1]["seq"]) + 1) if events else 1
        prev = str(events[-1]["hash"]) if events else ""
        body = {
            "schema": EVENT_SCHEMA, "run_id": self.run_id, "seq": seq,
            "ts": time.time(), "kind": str(kind), "actor": str(actor),
            "payload": dict(payload or {}), "prev": prev,
        }
        event = {**body, "hash": _event_hash(prev, body)}
        line = json.dumps(event, ensure_ascii=False, separators=(",", ":"), default=str)
        with self.path.open("a", encoding="utf-8", newline="\n") as fh:
            fh.write(line + "\n")
            fh.flush()
            if self._fsync:
                os.fsync(fh.fileno())
        return event

    def events(self, *, strict: bool = True) -> list[dict]:
        if not self.path.exists():
            return []
        out: list[dict] = []
        for lineno, line in enumerate(self.path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except ValueError as exc:
                if strict:
                    raise AgentRuntimeError(f"事件第 {lineno} 行非法 JSON: {exc}") from exc
                continue
            if strict and not isinstance(event, dict):
                raise AgentRuntimeError(f"事件第 {lineno} 行不是对象")
            out.append(event)
        return out

    def verify(self) -> dict:
        if not self.path.exists():
            return {"ok": True, "events": 0, "broken_at": None, "reason": ""}
        prev = ""
        count = 0
        for lineno, line in enumerate(self.path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except ValueError:
                return {"ok": False, "events": count, "broken_at": lineno,
                        "reason": "invalid-json（半写/截断行）"}
            if not isinstance(event, dict):
                return {"ok": False, "events": count, "broken_at": lineno,
                        "reason": "not-an-event"}
            if event.get("seq") != count + 1:
                return {"ok": False, "events": count, "broken_at": lineno,
                        "reason": f"seq 不连续（期望 {count + 1}）"}
            if event.get("prev") != prev:
                return {"ok": False, "events": count, "broken_at": lineno,
                        "reason": "prev 与上一条 hash 不一致（删行/插行）"}
            body = {k: event.get(k) for k in
                    ("schema", "run_id", "seq", "ts", "kind", "actor", "payload", "prev")}
            if event.get("hash") != _event_hash(prev, body):
                return {"ok": False, "events": count, "broken_at": lineno,
                        "reason": "hash 不匹配（内容被改）"}
            prev = event["hash"]
            count += 1
        return {"ok": True, "events": count, "broken_at": None, "reason": ""}

    def verified_events(self) -> list[dict]:
        verdict = self.verify()
        if not verdict["ok"]:
            raise AgentRuntimeError(
                f"事件日志损坏（第 {verdict['broken_at']} 行：{verdict['reason']}），"
                "拒绝 resume/replay")
        return self.events()

    def checkpoint(self, label: str, data: dict | None = None) -> dict:
        if not str(label or "").strip():
            raise AgentRuntimeError("checkpoint label 不能为空")
        return self.append("checkpoint", payload={"label": str(label),
                                                  "data": dict(data or {})})

    def latest_checkpoint(self) -> dict | None:
        for event in reversed(self.verified_events()):
            if event.get("kind") == "checkpoint":
                payload = event.get("payload") or {}
                return {"seq": event["seq"], "label": payload.get("label", ""),
                        "data": payload.get("data") or {}}
        return None

    def replay(self, *, to_seq: int | None = None) -> dict:
        events = self.verified_events()
        if to_seq is not None:
            events = [e for e in events if int(e["seq"]) <= int(to_seq)]
        kinds: dict[str, int] = {}
        intents: dict[str, dict] = {}
        facts = 0
        evidence = 0
        for event in events:
            kind = event["kind"]
            kinds[kind] = kinds.get(kind, 0) + 1
            payload = event.get("payload") or {}
            if kind == "graph.fact.added":
                facts += 1
            elif kind == "graph.evidence.added":
                evidence += 1
            elif kind == "graph.intent.added":
                node = payload.get("intent") or {}
                if node.get("id"):
                    intents[node["id"]] = {"role": node.get("role"),
                                           "module": node.get("module"),
                                           "status": "open"}
            elif kind.startswith("intent."):
                iid = str(payload.get("intent") or "")
                if iid in intents:
                    intents[iid]["status"] = kind.split(".", 1)[1]
            elif kind == "run.completed":
                intents_status = payload.get("status", "completed")
            else:
                intents_status = None
        terminal = [e for e in events if e["kind"] in
                    ("run.completed", "run.failed", "run.stopped")]
        return {
            "run_id": self.run_id,
            "events": len(events),
            "last_seq": events[-1]["seq"] if events else 0,
            "kinds": kinds,
            "facts": facts,
            "evidence": evidence,
            "intents": intents,
            "terminal": (terminal[-1].get("payload") if terminal else None),
        }

    def state_at(self, seq: int) -> dict:
        return self.replay(to_seq=int(seq))

    def trace(self, *, limit: int | None = None, since: int = 0) -> list[dict]:
        events = [e for e in self.verified_events() if int(e["seq"]) > int(since)]
        if limit:
            events = events[-int(limit):]
        out = []
        for event in events:
            payload = event.get("payload") or {}
            summary = payload.get("summary") or payload.get("reason") \
                or payload.get("rationale") or payload.get("label") or ""
            out.append({
                "seq": event["seq"], "ts": event["ts"], "kind": event["kind"],
                "actor": event.get("actor", ""), "summary": str(summary)[:500],
                "digest": _sha256(_canonical(payload))[:16],
            })
        return out


class AgentRuntime:
    """A single durable run; graph/scheduler instances live in the supervisor."""

    def __init__(self, store, run_id: str, log: EventLog, meta: dict):
        self.store = store
        self.run_id = str(run_id)
        self.log = log
        self.meta = dict(meta)
        self.dir = Path(store.ws_dir) / RUNS_RELPATH / self.run_id
        self.dir.mkdir(parents=True, exist_ok=True)
        self._stop_path = self.dir / "STOP"

    # ------------------------------------------------------------ lifecycle
    @classmethod
    def create(cls, store, *, objective: str, mode: str = "graph-swarm",
               probe_id: str = "", llm: str = "", budgets: dict | None = None,
               workspace: str = "", authorization: dict | None = None,
               run_id: str | None = None, fsync: bool = True,
               objective_meta: dict | None = None) -> "AgentRuntime":
        rid = run_id or f"agent-{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
        root = Path(store.ws_dir) / RUNS_RELPATH / rid
        if root.exists() and (root / "events.jsonl").exists():
            raise AgentRuntimeError(f"run 已存在: {rid}")
        root.mkdir(parents=True, exist_ok=True)
        log = EventLog(root / "events.jsonl", run_id=rid, fsync=fsync)
        meta = {
            "schema": RUN_SCHEMA, "run_id": rid, "objective": str(objective),
            "objective_meta": dict(objective_meta or {}), "mode": str(mode),
            "probe": str(probe_id), "llm": str(llm),
            "workspace": str(workspace or store.workspace),
            "budgets": dict(budgets or {}),
            "authorization": dict(authorization or {}),
            "created_at": time.time(), "runtime": RUNTIME_VERSION,
        }
        runtime = cls(store, rid, log, meta)
        (root / "run.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2),
                                       encoding="utf-8")
        log.append("run.created", payload={
            "objective": meta["objective"], "mode": meta["mode"],
            "probe": meta["probe"], "llm": meta["llm"],
            "budgets": meta["budgets"], "authorization": meta["authorization"],
            "summary": f"run created: {meta['objective']} / {meta['mode']}",
        }, actor=str((authorization or {}).get("actor") or "agent"))
        cls._set_last(store, rid)
        return runtime

    @classmethod
    def load(cls, store, run_id: str | None = None) -> "AgentRuntime":
        rid = run_id or cls.last_run_id(store)
        if not rid:
            raise AgentRuntimeError("没有可用的 agent run")
        root = Path(store.ws_dir) / RUNS_RELPATH / rid
        if not root.is_dir():
            raise AgentRuntimeError(f"run 不存在: {rid}")
        meta_path = root / "run.json"
        meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}
        log = EventLog(root / "events.jsonl", run_id=rid)
        log.verify()
        meta.setdefault("run_id", rid)
        meta.setdefault("schema", RUN_SCHEMA)
        return cls(store, rid, log, meta)

    @classmethod
    def last_run_id(cls, store) -> str:
        path = Path(store.ws_dir) / LAST_RUN_RELPATH
        if path.is_file():
            try:
                doc = json.loads(path.read_text(encoding="utf-8"))
                if doc.get("run_id"):
                    return str(doc["run_id"])
            except ValueError:
                pass
        runs = Path(store.ws_dir) / RUNS_RELPATH
        if not runs.is_dir():
            return ""
        candidates = [p for p in runs.iterdir() if (p / "events.jsonl").is_file()]
        if not candidates:
            return ""
        return max(candidates, key=lambda p: p.stat().st_mtime).name

    @classmethod
    def _set_last(cls, store, run_id: str) -> None:
        path = Path(store.ws_dir) / LAST_RUN_RELPATH
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"run_id": run_id, "ts": time.time()},
                                  ensure_ascii=False), encoding="utf-8")
        tmp.replace(path)

    # ------------------------------------------------------------ events
    def emit(self, kind: str, payload: dict | None = None, *,
             actor: str = "agent") -> dict:
        event = self.log.append(kind, payload=payload, actor=actor)
        if kind == "checkpoint":
            pass
        return event

    def checkpoint(self, label: str, data: dict | None = None) -> dict:
        return self.log.checkpoint(label, data)

    def events(self) -> list[dict]:
        return self.log.verified_events()

    def replay(self, *, to_seq: int | None = None) -> dict:
        return self.log.replay(to_seq=to_seq)

    def state_at(self, seq: int) -> dict:
        return self.log.state_at(seq)

    def trace(self, *, limit: int | None = None, since: int = 0) -> list[dict]:
        return self.log.trace(limit=limit, since=since)

    # ------------------------------------------------------------ stop
    def request_stop(self, reason: str, *, actor: str = "operator") -> dict:
        payload = {"reason": str(reason), "summary": f"stop requested: {reason}"}
        event = self.emit("run.stopped", payload, actor=actor)
        self._stop_path.write_text(json.dumps({"reason": str(reason), "actor": actor,
                                               "ts": time.time()},
                                              ensure_ascii=False), encoding="utf-8")
        return event

    def is_stopped(self) -> bool:
        if self._stop_path.exists():
            return True
        try:
            from ..core.abort import abort_requested

            if abort_requested(self.store):
                return True
        except Exception:  # noqa: BLE001 - abort module must not break status
            pass
        events = self.log.events(strict=False)
        return any(e.get("kind") == "run.stopped" for e in events)

    def clear_stop(self) -> None:
        if self._stop_path.exists():
            self._stop_path.unlink()

    # ------------------------------------------------------------ views
    def status(self) -> dict:
        verdict = self.log.verify()
        replay = self.log.replay()
        return {
            "schema": RUN_SCHEMA,
            "run_id": self.run_id,
            "objective": self.meta.get("objective", ""),
            "mode": self.meta.get("mode", ""),
            "probe": self.meta.get("probe", ""),
            "llm": self.meta.get("llm", ""),
            "created_at": self.meta.get("created_at"),
            "journal": verdict,
            "events": replay["events"],
            "last_seq": replay["last_seq"],
            "kinds": replay["kinds"],
            "stopped": self.is_stopped(),
            "dir": str(self.dir),
            "state": replay,
        }

    def summary_doc(self) -> dict:
        return {"schema": RUN_SCHEMA, **self.meta, "status": self.status()}
