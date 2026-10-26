# -*- coding: utf-8 -*-
"""Three-layer memory + reflexion + decision-trace wiring.

* **working** — bounded context for the current graph round.
* **episodic** — append-only episodes (run, attempts, failures, reflection,
  evidence anchors) used to re-rank the frontier on the next run.
* **semantic** — versioned entity/asset/skill facts with provenance.  Writes
  require a source reference; skill/human writes require approval; every write
  can be rolled back (ASI06 memory-poisoning defence).

Reflexion produces ``reflection.md`` and an episodic record.  It performs no
probe or module execution.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .graph import PlanGraph

MEMORY_SCHEMA = "inkblade-agent-memory/1"
EPISODES_RELPATH = "agent/memory/episodes.jsonl"
SEMANTIC_RELPATH = "agent/memory/semantic.json"


class MemoryError(ValueError):
    """Invalid memory operation."""


class MemoryWriteRefused(MemoryError):
    """A semantic/skill write lacks provenance or approval (poisoning guard)."""


_WORD_RE = re.compile(r"[a-z0-9]+")
_CJK_RE = re.compile(r"[\u4e00-\u9fff]")


def score(query: str, text: str) -> float:
    q = set(_WORD_RE.findall(str(query).lower())) | set(_CJK_RE.findall(str(query)))
    if not q:
        return 0.0
    t = set(_WORD_RE.findall(str(text).lower())) | set(_CJK_RE.findall(str(text)))
    return round(len(q & t) / len(q), 4)


class WorkingMemory:
    def __init__(self, capacity: int = 32):
        self.capacity = max(2, int(capacity))
        self._items: list[dict] = []

    def add(self, text: str, *, kind: str = "note", ref: str = "") -> dict:
        item = {"text": str(text), "kind": str(kind), "ref": str(ref),
                "ts": time.time()}
        self._items.append(item)
        if len(self._items) > self.capacity:
            self._items = self._items[-self.capacity:]
        return dict(item)

    def items(self) -> list[dict]:
        return [dict(item) for item in self._items]

    def compact(self) -> dict:
        before = len(self._items)
        if before <= max(3, self.capacity // 2):
            return {"before": before, "after": before, "dropped": 0}
        keep = max(3, self.capacity // 2)
        head = self._items[:1]
        tail = self._items[-(keep - 1):]
        dropped = self._items[1:-(keep - 1)]
        digest = hashlib.sha256(json.dumps([i["text"] for i in dropped],
                                           ensure_ascii=False).encode("utf-8")).hexdigest()[:16]
        self._items = head + [{"text": f"[compacted {len(dropped)} items digest={digest}]",
                               "kind": "compacted", "ref": f"sha256:{digest}",
                               "ts": time.time()}] + tail
        return {"before": before, "after": len(self._items), "dropped": len(dropped),
                "digest": digest}

    def __len__(self) -> int:
        return len(self._items)


class EpisodicMemory:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._items: list[dict] | None = None

    def _load(self) -> list[dict]:
        if self._items is not None:
            return self._items
        items = []
        if self.path.is_file():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                except ValueError:
                    continue
                if isinstance(item, dict):
                    items.append(item)
        self._items = items
        return items

    def record(self, *, run_id: str, objective: str, success: bool,
               modules: list[str], role: str = "", attempts: int = 0,
               failures: list[dict] | None = None, reflection: str = "",
               evidence: list[str] | None = None, tokens: int = 0) -> dict:
        item = {
            "schema": MEMORY_SCHEMA, "run_id": str(run_id), "objective": str(objective),
            "success": bool(success), "modules": list(dict.fromkeys(modules)),
            "role": str(role), "attempts": int(attempts),
            "failures": list(failures or []), "reflection": str(reflection),
            "evidence": list(evidence or []), "tokens": int(tokens),
            "created_at": time.time(),
        }
        with self.path.open("a", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n")
        if self._items is not None:
            self._items.append(item)
        return item

    def search(self, query: str, k: int = 5) -> list[dict]:
        rows = [item for item in self._load()
                if score(query, f"{item.get('objective', '')} {item.get('reflection', '')} "
                                f"{' '.join(item.get('modules') or [])}") > 0]
        rows.sort(key=lambda i: (-score(query, f"{i.get('objective', '')} "
                                              f"{i.get('reflection', '')} "
                                              f"{' '.join(i.get('modules') or [])}"),
                                 -float(i.get("created_at") or 0)))
        return [json.loads(json.dumps(i, ensure_ascii=False)) for i in rows[:k]]

    def success_rate(self, *, module: str = "", role: str = "") -> tuple[float, int]:
        rows = [i for i in self._load() if (not module or module in (i.get("modules") or []))
                and (not role or i.get("role") == role)]
        if not rows:
            return 0.0, 0
        return round(sum(1 for i in rows if i.get("success")) / len(rows), 4), len(rows)

    def recent(self, k: int = 5) -> list[dict]:
        rows = sorted(self._load(), key=lambda i: float(i.get("created_at") or 0),
                      reverse=True)
        return [json.loads(json.dumps(i, ensure_ascii=False)) for i in rows[:k]]


class SemanticMemory:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._doc: dict | None = None

    def _load(self) -> dict:
        if self._doc is not None:
            return self._doc
        if self.path.is_file():
            try:
                doc = json.loads(self.path.read_text(encoding="utf-8"))
            except ValueError:
                doc = None
        else:
            doc = None
        if not isinstance(doc, dict) or not isinstance(doc.get("records"), list):
            doc = {"schema": MEMORY_SCHEMA, "version": 0, "records": []}
        self._doc = doc
        return doc

    def _save(self) -> None:
        doc = self._load()
        doc["version"] = int(doc.get("version", 0)) + 1
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self.path)

    def upsert(self, entity_id: str, kind: str, attrs: dict, *, source_ref: str,
               trust: str = "probe", approved_by: str = "",
               supersedes: str = "", ttl_seconds: int = 0) -> dict:
        if not str(source_ref or "").strip():
            raise MemoryWriteRefused("semantic 写入必须有 source_ref（防记忆投毒）")
        if trust in ("skill", "human", "llm") and not str(approved_by or "").strip():
            raise MemoryWriteRefused(f"trust={trust} 的语义写入需要 approved_by")
        doc = self._load()
        now = time.time()
        for record in doc["records"]:
            if record.get("entity_id") == entity_id and record.get("active", True):
                record["active"] = False
                record["superseded_by"] = f"{entity_id}@{now}"
                record["superseded_at"] = now
        version = 1 + max([int(r.get("version", 0)) for r in doc["records"]
                           if r.get("entity_id") == entity_id] or [0])
        record = {
            "entity_id": str(entity_id), "kind": str(kind),
            "attrs": dict(attrs or {}), "source_ref": str(source_ref),
            "trust": str(trust), "approved_by": str(approved_by),
            "version": version, "active": True, "superseded_by": "",
            "source_digest": hashlib.sha256(
                json.dumps({"entity_id": entity_id, "attrs": attrs, "source": source_ref},
                           ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest(),
            "valid_from": now,
            "expires_at": (now + int(ttl_seconds)) if int(ttl_seconds or 0) else 0,
            "supersedes": str(supersedes),
        }
        doc["records"].append(record)
        self._save()
        return json.loads(json.dumps(record, ensure_ascii=False))

    def get(self, entity_id: str, *, include_inactive: bool = False) -> list[dict]:
        rows = [r for r in self._load()["records"] if r.get("entity_id") == entity_id
                and (include_inactive or r.get("active", True))]
        return [json.loads(json.dumps(r, ensure_ascii=False)) for r in rows]

    def search(self, query: str, k: int = 5) -> list[dict]:
        now = time.time()
        rows = []
        for record in self._load()["records"]:
            if not record.get("active", True):
                continue
            if record.get("expires_at") and float(record["expires_at"]) < now:
                continue
            text = f"{record.get('entity_id')} {record.get('kind')} " \
                   f"{json.dumps(record.get('attrs') or {}, ensure_ascii=False)}"
            s = score(query, text)
            if query and s <= 0:
                continue
            rows.append({**record, "score": s})
        rows.sort(key=lambda r: (-r["score"], -float(r.get("valid_from") or 0)))
        return rows[:k]

    def rollback(self, entity_id: str, *, reason: str = "") -> dict:
        doc = self._load()
        records = [r for r in doc["records"] if r.get("entity_id") == entity_id]
        if not records:
            raise MemoryError(f"未知 semantic 实体: {entity_id}")
        active = [r for r in records if r.get("active", True)]
        active_ids = {id(record) for record in active}
        for record in active:
            record["active"] = False
            record["superseded_by"] = ""
            record["rolled_back_at"] = time.time()
            record["rollback_reason"] = str(reason)
        previous = [r for r in records if id(r) not in active_ids
                    and not r.get("active", True)]
        previous.sort(key=lambda r: int(r.get("version", 0)))
        if previous:
            previous[-1]["active"] = True
            previous[-1]["superseded_by"] = ""
        self._save()
        return {"entity_id": entity_id, "active": bool(previous),
                "restored_version": previous[-1].get("version") if previous else None}
    def stats(self) -> dict:
        records = self._load()["records"]
        return {"records": len(records),
                "active": sum(1 for r in records if r.get("active", True)),
                "entities": len({r.get("entity_id") for r in records})}


class AgentMemory:
    def __init__(self, store, *, capacity: int = 32):
        self.store = store
        self.working = WorkingMemory(capacity=capacity)
        self.episodic = EpisodicMemory(Path(store.ws_dir) / EPISODES_RELPATH)
        self.semantic = SemanticMemory(Path(store.ws_dir) / SEMANTIC_RELPATH)

    # ------------------------------------------------------------ ranking
    def priority_adjustment(self, intent: dict, graph: PlanGraph) -> tuple[float, str]:
        module = str(intent.get("module") or "")
        role = str(intent.get("role") or "")
        rate, count = self.episodic.success_rate(module=module)
        if count < 2:
            rate, count = self.episodic.success_rate(role=role)
        if count < 2:
            return 0.0, ""
        bonus = round((rate - 0.5) * 2.0, 3)
        reason = f"episodic {role or module}: {count} runs, success={rate:.2f}"
        if bonus:
            return bonus, reason
        return 0.0, reason

    def rank_intents(self, intents: list[dict], graph: PlanGraph) -> list[dict]:
        scored = []
        for intent in intents:
            bonus, reason = self.priority_adjustment(intent, graph)
            scored.append((float(intent.get("priority", 0)) + bonus,
                           -float(intent.get("cost_tokens", 0)), intent["id"],
                           intent, reason))
        scored.sort(key=lambda row: (-row[0], -row[1], row[2]))
        out = []
        for _, _, _, intent, reason in scored:
            item = dict(intent)
            if reason:
                item["priority_reason"] = reason
            out.append(item)
        return out

    # ------------------------------------------------------------ context
    def context(self, query: str = "", *, k: int = 5) -> dict:
        return {
            "working": self.working.items(),
            "episodic": self.episodic.search(query, k=k) if query else self.episodic.recent(k),
            "semantic": self.semantic.search(query, k=k) if query else [],
            "stats": {"working": len(self.working),
                      "episodic": len(self.episodic._load()),
                      "semantic": self.semantic.stats()},
        }

    def three_layer_view(self) -> dict:
        return {
            "working": self.working.items(),
            "episodic": self.episodic.recent(5),
            "semantic": self.semantic.stats(),
        }

    # ------------------------------------------------------------ reflexion
    def reflect(self, runtime, graph: PlanGraph, objective, *, write: bool = True) -> dict:
        """Zero-execution reflection; writes reflection.md and one episode."""
        intents = graph.intents()
        failures = [{"intent": i["id"], "module": i.get("module"),
                     "reason": i.get("last_error", ""), "attempts": i.get("attempts", 0)}
                    for i in intents if i.get("status") in ("failed", "blocked")]
        done = [i for i in intents if i.get("status") == "done"]
        evidence = list(graph.evidence_ids())
        evaluation = objective.evaluate(graph)
        next_avoid = []
        for failure in failures:
            if "backup" in str(failure.get("reason", "")).lower():
                next_avoid.append(f"{failure['module']}: 先补 backup_targets/回执再重试")
            elif "scope" in str(failure.get("reason", "")).lower():
                next_avoid.append(f"{failure['module']}: [scope] 目标不在 RoE，不要重复提议")
            elif "probe" in str(failure.get("reason", "")).lower():
                next_avoid.append(f"{failure['module']}: 先确认探针会话再执行")
            else:
                next_avoid.append(f"{failure['module']}: 失败 {failure.get('reason', '')}")
        if not next_avoid:
            next_avoid.append("保持证据门控；把成功链交给技能库晋升前先跑 eval 回归")
        reflection = [
            f"# Reflexion — {getattr(runtime, 'run_id', 'run')}",
            "",
            f"- objective: {objective.key}",
            f"- success: {evaluation['success']}",
            f"- intents: {len(done)} done / {len(intents)} total",
            f"- evidence anchors: {len(evidence)}",
            "",
            "## 失败与阻塞",
        ]
        if failures:
            for failure in failures:
                reflection.append(f"- {failure['intent']} ({failure['module']}): "
                                  f"{failure['reason']}")
        else:
            reflection.append("- 无")
        reflection += ["", "## 下次避免"]
        reflection += [f"- {item}" for item in next_avoid]
        text = "\n".join(reflection) + "\n"
        path = ""
        if write:
            try:
                path = str(runtime.dir / "reflection.md")
                (runtime.dir / "reflection.md").write_text(text, encoding="utf-8")
            except Exception:  # noqa: BLE001 - reflection is not allowed to break run
                path = ""
        self.episodic.record(
            run_id=getattr(runtime, "run_id", ""), objective=objective.key,
            success=bool(evaluation["success"]),
            modules=[i.get("module", "") for i in done],
            attempts=sum(int(i.get("attempts", 0)) for i in intents),
            failures=failures, reflection=text, evidence=evidence,
            tokens=0,
        )
        return {"run": getattr(runtime, "run_id", ""), "objective": objective.key,
                "success": bool(evaluation["success"]), "failures": failures,
                "next_avoid": next_avoid, "evidence": evidence,
                "reflection": text, "path": path, "executed": False}

    # ------------------------------------------------------------ trace
    def decision_trace(self, runtime, *, limit: int | None = None) -> list[dict]:
        rows = [e for e in runtime.trace(limit=limit)
                if e["kind"] in ("decision.made", "plan.proposed", "policy.refused",
                                 "budget.exceeded", "intent.claimed", "intent.completed",
                                 "intent.failed", "approval.required", "llm.degraded")]
        return rows
