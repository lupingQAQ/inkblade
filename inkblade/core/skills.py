# -*- coding: utf-8 -*-
"""技能库：从成功 run 提炼可复用 playbook（版本 + 成功统计 + 审批入库）。

数据模型（工作区 ``skills/skills.json``，单条记录当前版本 + history 每版终态）::

    {id, name, status: draft|pending|approved, version, playbook: [{module, params,
     writes, min_level, evidence}], source, source_run, created_by, created_at,
     approved_by, approved_at, stats: {uses, success, failure, last_used}, history}

约束：
- 只有 **approved** 技能进入 ``search``（可供 explorer/agent 引用）；
- 提交（submit）任何 tester+ 可做，批准（approve）需 ``can("approve")``（lead/admin）；
- 同一 id 再次提交 → version+1（历史保留），批准后旧版本状态被新版本覆盖；
- 写类步骤保留 ``writes`` 标记，supervisor/explorer 引用时仍需逐动作审批。
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path

SKILLS_RELPATH = "skills/skills.json"


class SkillError(ValueError):
    """技能记录非法/不存在。"""


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-") or "skill"


class SkillLibrary:
    def __init__(self, store, *, modules_dir: Path | str | None = None):
        self.store = store
        self.path = Path(store.ws_dir) / SKILLS_RELPATH
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.modules_dir = Path(modules_dir) if modules_dir else Path(store.root) / "modules"

    # ---------------------------------------------------------------- 持久化
    def _load(self) -> list[dict]:
        if not self.path.exists():
            return []
        try:
            return list(json.loads(self.path.read_text(encoding="utf-8")))
        except ValueError:
            return []

    def _save(self, items: list[dict]) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(items, ensure_ascii=False, indent=1), encoding="utf-8")
        tmp.replace(self.path)

    # ---------------------------------------------------------------- 提炼
    def _meta(self, module_key: str):
        if not self.modules_dir.exists():
            return None
        try:
            from .registry import load_modules

            return load_modules(self.modules_dir).get(module_key)
        except Exception:
            return None

    def extract(self, run, *, name: str = "") -> dict:
        """从 run 的步骤/发现提炼 playbook（不落盘，返回 draft）。"""
        steps = run.query("SELECT step_key, result_summary FROM steps ORDER BY id")
        if not steps:
            raise SkillError(f"run {getattr(run, 'name', '?')} 无步骤，无法提炼 playbook")
        findings = run.findings
        playbook = []
        for step_key, summary in steps:
            meta = self._meta(step_key)
            related = [f for f in findings if f.get("step_key") == step_key]
            playbook.append({
                "module": step_key,
                "params": {},
                "writes": bool(getattr(meta, "writes", False)),
                "min_level": getattr(meta, "min_level", "") if meta else "",
                "evidence": {
                    "summary": summary or "",
                    "findings": len(related),
                    "titles": [f.get("title", "") for f in related[:3]],
                },
            })
        skill_name = name or f"playbook-{getattr(run, 'name', 'run')}"
        digest = hashlib.sha256(
            json.dumps(playbook, ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest()[:6]
        return {
            "id": f"skill-{_slug(skill_name)}-{digest}",
            "name": skill_name,
            "status": "draft",
            "version": 0,
            "playbook": playbook,
            "source": "extract",
            "source_run": getattr(run, "name", ""),
            "created_by": "",
            "created_at": time.time(),
            "stats": {"uses": 0, "success": 0, "failure": 0, "last_used": None},
            "history": [],
        }

    # ---------------------------------------------------------------- 提交/审批
    def submit(self, session, skill: dict) -> dict:
        if not session.can("execute"):
            raise PermissionError(f"{session.name}({session.role}) 无提交技能权限")
        if not isinstance(skill, dict) or not skill.get("name"):
            raise SkillError("技能缺 name")
        playbook = list(skill.get("playbook") or [])
        if not playbook:
            raise SkillError("playbook 为空")
        for step in playbook:
            if not step.get("module"):
                raise SkillError("playbook 步骤缺 module")

        items = self._load()
        skill_id = skill.get("id") or f"skill-{_slug(skill['name'])}-{int(time.time())}"
        record = next((s for s in items if s["id"] == skill_id), None)
        if record is None:
            record = {
                "id": skill_id, "name": skill["name"], "status": "pending", "version": 1,
                "playbook": playbook, "source": skill.get("source", "manual"),
                "source_run": skill.get("source_run", ""),
                "created_by": session.name, "created_at": time.time(),
                "approved_by": "", "approved_at": None,
                "stats": {"uses": 0, "success": 0, "failure": 0, "last_used": None},
                "history": [],
            }
            items.append(record)
        else:
            record["version"] = int(record.get("version", 0)) + 1
            record["status"] = "pending"
            record["playbook"] = playbook
            record["name"] = skill["name"]
            record["source"] = skill.get("source", record.get("source", "manual"))
            record["source_run"] = skill.get("source_run", record.get("source_run", ""))
        record["history"].append({"version": record["version"], "status": "pending",
                                  "at": time.time(), "by": session.name})
        self._save(items)
        return json.loads(json.dumps(record, ensure_ascii=False))

    def approve(self, session, skill_id: str, *, note: str = "") -> dict:
        if not session.can("approve"):
            raise PermissionError(f"{session.name}({session.role}) 无 approve 权限")
        items = self._load()
        record = next((s for s in items if s["id"] == skill_id), None)
        if record is None:
            raise SkillError(f"未知技能 {skill_id}")
        record["status"] = "approved"
        record["approved_by"] = session.name
        record["approved_at"] = time.time()
        if note:
            record["approval_note"] = note
        if record["history"]:
            record["history"][-1]["status"] = "approved"
            record["history"][-1]["by"] = session.name
        self._save(items)
        return json.loads(json.dumps(record, ensure_ascii=False))

    def reject(self, session, skill_id: str, *, reason: str = "") -> dict:
        if not session.can("approve"):
            raise PermissionError(f"{session.name}({session.role}) 无 approve 权限")
        items = self._load()
        record = next((s for s in items if s["id"] == skill_id), None)
        if record is None:
            raise SkillError(f"未知技能 {skill_id}")
        record["status"] = "rejected"
        record["reject_reason"] = reason
        if record["history"]:
            record["history"][-1]["status"] = "rejected"
        self._save(items)
        return json.loads(json.dumps(record, ensure_ascii=False))

    # ---------------------------------------------------------------- 检索/统计
    def get(self, skill_id: str, version: int | None = None) -> dict:
        record = next((s for s in self._load() if s["id"] == skill_id), None)
        if record is None:
            raise SkillError(f"未知技能 {skill_id}")
        if version is not None and int(record.get("version", 0)) != int(version):
            raise SkillError(f"技能 {skill_id} 无版本 {version}")
        return json.loads(json.dumps(record, ensure_ascii=False))

    def list(self, *, status: str | None = None) -> list[dict]:
        items = self._load()
        if status:
            items = [s for s in items if s.get("status") == status]
        return json.loads(json.dumps(items, ensure_ascii=False))

    def search(self, query: str, k: int = 5) -> list[dict]:
        from .memory import score

        approved = [s for s in self._load() if s.get("status") == "approved"]
        scored = []
        for skill in approved:
            text = " ".join([skill["name"]] + [s["module"] for s in skill["playbook"]])
            scored.append((score(query, text) if query else 1.0, skill))
        scored.sort(key=lambda pair: (-pair[0], pair[1]["id"]))
        if query:
            scored = [pair for pair in scored if pair[0] > 0]
        return json.loads(json.dumps([s for _, s in scored[: max(0, k)]], ensure_ascii=False))

    def record_outcome(self, skill_id: str, ok: bool) -> dict:
        items = self._load()
        record = next((s for s in items if s["id"] == skill_id), None)
        if record is None:
            raise SkillError(f"未知技能 {skill_id}")
        stats = record.setdefault("stats", {"uses": 0, "success": 0, "failure": 0, "last_used": None})
        stats["uses"] = int(stats.get("uses", 0)) + 1
        stats["success" if ok else "failure"] = int(stats.get("success" if ok else "failure", 0)) + 1
        stats["last_used"] = time.time()
        self._save(items)
        return json.loads(json.dumps(record, ensure_ascii=False))
