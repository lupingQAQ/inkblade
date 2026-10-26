# -*- coding: utf-8 -*-
"""Versioned skill library: proposal → approval → success statistics → promotion.

Skills are procedural knowledge extracted from successful graph runs or loaded
from a SEP-2640 ``SKILL.md`` package.  Only approved skills are visible to the
planner/scheduler; every version keeps its digest, allowed tools and evaluation
score.  Approval is a lead action; success rate is updated from graph outcomes.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any

from .graph import PlanGraph
from .protocols import ProtocolError, SkillPackage

SKILLS_SCHEMA = "inkblade-agent-skills/1"
SKILLS_RELPATH = "agent/skills.json"


class SkillError(ValueError):
    """Invalid skill record."""


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(text or "").lower()).strip("-") or "skill"


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                     default=str).encode("utf-8")).hexdigest()


class SkillLibrary:
    def __init__(self, store, *, path: str | Path | None = None):
        self.store = store
        self.path = Path(path) if path else Path(store.ws_dir) / SKILLS_RELPATH
        self.path.parent.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------ persistence
    def _load(self) -> list[dict]:
        if not self.path.is_file():
            return []
        try:
            doc = json.loads(self.path.read_text(encoding="utf-8"))
        except ValueError:
            return []
        items = doc.get("skills") if isinstance(doc, dict) else doc
        return list(items or []) if isinstance(items, list) else []

    def _save(self, items: list[dict]) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"schema": SKILLS_SCHEMA, "skills": items},
                                  ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self.path)

    # ------------------------------------------------------------ proposal
    def propose_from_graph(self, graph: PlanGraph, *, name: str = "",
                           objective: str = "") -> dict:
        done = [i for i in graph.intents(status="done") if i.get("probe", True)]
        if not done:
            raise SkillError("graph 没有已成功的探针意图，无法提炼技能")
        playbook = []
        for intent in done:
            playbook.append({
                "order": len(playbook) + 1, "role": intent.get("role"),
                "module": intent.get("module"), "params": dict(intent.get("params") or {}),
                "writes": bool(intent.get("writes")), "cleanup": bool(intent.get("cleanup")),
                "expected_evidence": list(intent.get("expected_evidence") or []),
                "evidence": list(intent.get("evidence") or []),
            })
        skill_name = name or f"playbook-{objective or graph.objective or 'run'}"
        digest = _digest(playbook)[:8]
        return {
            "schema": SKILLS_SCHEMA,
            "id": f"skill-{_slug(skill_name)}-{digest}",
            "name": skill_name, "status": "draft", "version": 0,
            "playbook": playbook, "objective": objective or graph.objective,
            "source": "graph", "source_ref": f"graph:{graph.objective}",
            "digest": _digest(playbook), "allowed_tools": ["probe"],
            "stats": {"uses": 0, "success": 0, "failure": 0, "last_used": None},
            "history": [], "created_at": time.time(),
        }

    def submit(self, session, skill: dict) -> dict:
        if not session.can("execute"):
            raise PermissionError(f"{getattr(session, 'name', '?')} 无 execute 权限")
        if not isinstance(skill, dict) or not skill.get("name"):
            raise SkillError("skill 缺 name")
        playbook = list(skill.get("playbook") or [])
        if not playbook:
            raise SkillError("playbook 为空")
        for step in playbook:
            if not step.get("module") or step.get("role") not in (
                    "recon", "exploit", "verify", "report"):
                raise SkillError("playbook 步骤缺 module/合法 role")
        items = self._load()
        existing = next((s for s in items if s.get("id") == skill.get("id")), None)
        if existing is None:
            record = {
                "schema": SKILLS_SCHEMA,
                "id": skill.get("id") or f"skill-{_slug(skill['name'])}-{int(time.time())}",
                "name": skill["name"], "status": "pending", "version": 1,
                "playbook": playbook, "objective": skill.get("objective", ""),
                "source": skill.get("source", "manual"),
                "source_ref": skill.get("source_ref", ""),
                "digest": skill.get("digest") or _digest(playbook),
                "allowed_tools": list(skill.get("allowed_tools") or ["probe"]),
                "stats": {"uses": 0, "success": 0, "failure": 0, "last_used": None},
                "history": [{"version": 1, "status": "pending", "at": time.time(),
                             "by": getattr(session, "name", "")}],
                "created_by": getattr(session, "name", ""), "created_at": time.time(),
                "approved_by": "", "approved_at": None,
            }
            items.append(record)
        else:
            existing["version"] = int(existing.get("version", 0)) + 1
            existing["status"] = "pending"
            existing["playbook"] = playbook
            existing["name"] = skill["name"]
            existing["digest"] = skill.get("digest") or _digest(playbook)
            existing["allowed_tools"] = list(skill.get("allowed_tools") or
                                             existing.get("allowed_tools") or ["probe"])
            existing["history"].append({"version": existing["version"],
                                        "status": "pending", "at": time.time(),
                                        "by": getattr(session, "name", "")})
            record = existing
        self._save(items)
        return json.loads(json.dumps(record, ensure_ascii=False))

    def approve(self, session, skill_id: str, *, note: str = "") -> dict:
        if not session.can("approve"):
            raise PermissionError(f"{getattr(session, 'name', '?')} 无 approve 权限")
        items = self._load()
        record = next((s for s in items if s.get("id") == skill_id), None)
        if record is None:
            raise SkillError(f"未知技能 {skill_id}")
        record["status"] = "approved"
        record["approved_by"] = getattr(session, "name", "")
        record["approved_at"] = time.time()
        if note:
            record["approval_note"] = str(note)
        if record.get("history"):
            record["history"][-1].update({"status": "approved",
                                          "by": getattr(session, "name", "")})
        self._save(items)
        return json.loads(json.dumps(record, ensure_ascii=False))

    def reject(self, session, skill_id: str, *, reason: str = "") -> dict:
        if not session.can("approve"):
            raise PermissionError(f"{getattr(session, 'name', '?')} 无 approve 权限")
        items = self._load()
        record = next((s for s in items if s.get("id") == skill_id), None)
        if record is None:
            raise SkillError(f"未知技能 {skill_id}")
        record["status"] = "rejected"
        record["reject_reason"] = str(reason)
        if record.get("history"):
            record["history"][-1]["status"] = "rejected"
        self._save(items)
        return json.loads(json.dumps(record, ensure_ascii=False))

    # ------------------------------------------------------------ packages / eval
    def install_package(self, package: SkillPackage, session, *,
                        approved: bool = False) -> dict:
        if not isinstance(package, SkillPackage):
            raise SkillError("install_package 需要 SkillPackage")
        package.validate_tools({"probe", "report", "read"})
        skill = {
            "id": f"skill-{_slug(package.name)}-{package.digest[:8]}",
            "name": package.name,
            "playbook": [{"module": package.name, "role": "recon", "params": {},
                          "source": "skill-package"}],
            "objective": "", "source": "sep-2640",
            "source_ref": f"skill-package:{package.digest}",
            "digest": package.digest,
            "allowed_tools": list(package.allowed_tools),
            "package_meta": package.metadata(),
            "package_body": package.body,
        }
        record = self.submit(session, skill)
        if approved:
            record = self.approve(session, record["id"],
                                  note="installed with explicit approval")
        return record

    def promote(self, session, skill_id: str, *, eval_score: float,
                min_score: float = 0.6) -> dict:
        if not session.can("approve"):
            raise PermissionError(f"{getattr(session, 'name', '?')} 无 approve 权限")
        items = self._load()
        record = next((s for s in items if s.get("id") == skill_id), None)
        if record is None:
            raise SkillError(f"未知技能 {skill_id}")
        record["eval_score"] = float(eval_score)
        record["eval_at"] = time.time()
        if float(eval_score) >= float(min_score):
            record["status"] = "approved"
            record["approved_by"] = getattr(session, "name", "")
            record["approved_at"] = time.time()
        else:
            record["status"] = "pending"
        self._save(items)
        return json.loads(json.dumps(record, ensure_ascii=False))

    # ------------------------------------------------------------ lookup
    def get(self, skill_id: str) -> dict:
        record = next((s for s in self._load() if s.get("id") == skill_id), None)
        if record is None:
            raise SkillError(f"未知技能 {skill_id}")
        return json.loads(json.dumps(record, ensure_ascii=False))

    def list(self, *, status: str | None = None) -> list[dict]:
        items = self._load()
        if status:
            items = [s for s in items if s.get("status") == status]
        return json.loads(json.dumps(items, ensure_ascii=False))

    def search(self, query: str = "", k: int = 5) -> list[dict]:
        from .memory import score

        approved = [s for s in self._load() if s.get("status") == "approved"]
        scored = []
        for skill in approved:
            text = " ".join([skill.get("name", "")] +
                            [str(s.get("module", "")) for s in skill.get("playbook") or []])
            s = score(query, text) if query else 1.0
            if query and s <= 0:
                continue
            rate = _success_rate(skill)
            scored.append((s, rate, skill))
        scored.sort(key=lambda row: (-row[0], -row[1], row[2]["id"]))
        return json.loads(json.dumps([s for _, _, s in scored[:k]], ensure_ascii=False))

    def record_outcome(self, skill_id: str, ok: bool) -> dict:
        items = self._load()
        record = next((s for s in items if s.get("id") == skill_id), None)
        if record is None:
            raise SkillError(f"未知技能 {skill_id}")
        stats = record.setdefault("stats", {"uses": 0, "success": 0, "failure": 0,
                                            "last_used": None})
        stats["uses"] = int(stats.get("uses", 0)) + 1
        key = "success" if ok else "failure"
        stats[key] = int(stats.get(key, 0)) + 1
        stats["last_used"] = time.time()
        stats["success_rate"] = _success_rate(record)
        self._save(items)
        return json.loads(json.dumps(record, ensure_ascii=False))

    def index_into(self, memory) -> int:
        count = 0
        for skill in self.list(status="approved"):
            memory.semantic.upsert(
                skill["id"], "skill",
                {"name": skill.get("name"), "objective": skill.get("objective"),
                 "modules": [s.get("module") for s in skill.get("playbook") or []],
                 "success_rate": _success_rate(skill), "allowed_tools": skill.get("allowed_tools")},
                source_ref=skill.get("source_ref") or f"skill:{skill['id']}",
                trust="skill", approved_by=skill.get("approved_by", ""))
            count += 1
        return count


def _success_rate(skill: dict) -> float:
    stats = skill.get("stats") or {}
    uses = int(stats.get("uses", 0))
    if not uses:
        return 0.0
    return round(int(stats.get("success", 0)) / uses, 4)
