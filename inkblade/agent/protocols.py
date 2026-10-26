# -*- coding: utf-8 -*-
"""Protocol layer: MCP Tasks, SEP-2640 skill packages and A2A delegation.

These are data/control-plane contracts, not execution paths.  MCP tool calls
must be read-only; A2A delegation exposes read-only skills by default and
rejects write skills.  Task handles are durable and transition-checked, so a
remote caller can poll/cancel without keeping a process alive.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

MCP_TASK_SCHEMA = "inkblade-mcp-task/1"
A2A_CARD_SCHEMA = "inkblade-a2a-agent-card/1"
SKILL_SCHEMA = "inkblade-skill-package/1"

MCP_STATES = ("submitted", "working", "input-required", "completed", "failed", "canceled")
A2A_STATES = ("submitted", "working", "input-required", "completed", "failed",
              "canceled", "rejected")
_TERMINAL = {"completed", "failed", "canceled", "rejected"}
_TRANSITIONS = {
    "submitted": {"working", "input-required", "completed", "failed", "canceled"},
    "working": {"input-required", "completed", "failed", "canceled"},
    "input-required": {"working", "completed", "failed", "canceled"},
    "completed": set(), "failed": set(), "canceled": set(), "rejected": set(),
}


class ProtocolError(ValueError):
    """Invalid MCP/A2A/skill message."""


class TaskStateError(ProtocolError):
    """Invalid task state transition."""


class MCPTaskStore:
    """Durable MCP Tasks store (JSON file or in-memory)."""

    def __init__(self, path: str | Path | None = None, *, clock=time.time):
        self.path = Path(path) if path else None
        self._clock = clock
        self._tasks: dict[str, dict] = {}
        if self.path and self.path.is_file():
            try:
                doc = json.loads(self.path.read_text(encoding="utf-8"))
                self._tasks = dict((doc or {}).get("tasks") or {})
            except ValueError:
                self._tasks = {}

    def _save(self) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"schema": MCP_TASK_SCHEMA, "tasks": self._tasks},
                                  ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self.path)

    def create(self, request: dict, *, ttl_ms: int = 0,
               task_id: str | None = None) -> dict:
        if not isinstance(request, dict):
            raise ProtocolError("task request 必须是对象")
        tid = task_id or f"task-{uuid.uuid4().hex[:12]}"
        now = self._clock()
        task = {
            "schema": MCP_TASK_SCHEMA, "id": tid, "state": "submitted",
            "created_at": now, "updated_at": now, "ttl_ms": max(0, int(ttl_ms)),
            "request": request, "result": None, "error": "", "lease": "",
        }
        self._tasks[tid] = task
        self._save()
        return self.get(tid)

    def get(self, task_id: str) -> dict:
        task = self._tasks.get(str(task_id))
        if task is None:
            raise ProtocolError(f"未知 MCP task: {task_id}")
        return json.loads(json.dumps(task, ensure_ascii=False))

    def list(self, *, state: str | None = None) -> list[dict]:
        tasks = [self.get(tid) for tid in sorted(self._tasks)]
        if state:
            tasks = [t for t in tasks if t["state"] == state]
        return tasks

    def update(self, task_id: str, state: str, *, result: dict | None = None,
               error: str = "", lease: str = "") -> dict:
        task = self._tasks.get(str(task_id))
        if task is None:
            raise ProtocolError(f"未知 MCP task: {task_id}")
        if state not in MCP_STATES:
            raise TaskStateError(f"非法 MCP task 状态: {state}")
        if state != task["state"] and state not in _TRANSITIONS.get(task["state"], set()):
            raise TaskStateError(f"task {task_id} 不能从 {task['state']} 转到 {state}")
        task["state"] = state
        task["updated_at"] = self._clock()
        if result is not None:
            task["result"] = result
        if error:
            task["error"] = str(error)
        if lease:
            task["lease"] = str(lease)
        if state in _TERMINAL:
            task["lease"] = ""
        self._save()
        return self.get(task_id)

    def cancel(self, task_id: str, *, reason: str = "") -> dict:
        return self.update(task_id, "canceled", error=reason or "canceled by caller")

    def expire(self, *, now: float | None = None) -> list[dict]:
        ts = self._clock() if now is None else float(now)
        expired = []
        for task in list(self._tasks.values()):
            ttl = int(task.get("ttl_ms") or 0)
            if not ttl or task["state"] in _TERMINAL:
                continue
            if ts * 1000 - float(task["created_at"]) * 1000 > ttl:
                expired.append(self.update(task["id"], "failed", error="ttl-expired"))
        return expired


@dataclass
class MCPTool:
    namespace: str
    name: str
    description: str = ""
    read_only: bool = True
    input_schema: dict = field(default_factory=dict)
    source: str = "local"

    @property
    def qualified(self) -> str:
        return f"{self.namespace}.{self.name}" if self.namespace else self.name

    def as_dict(self) -> dict:
        return {"name": self.qualified, "description": self.description,
                "annotations": {"readOnlyHint": bool(self.read_only)},
                "inputSchema": dict(self.input_schema), "source": self.source}


class MCPToolRegistry:
    """Namespace-scoped tool discovery; write tools are visible but not callable."""

    def __init__(self):
        self._tools: dict[str, MCPTool] = {}

    def register(self, tool: MCPTool) -> MCPTool:
        if not isinstance(tool, MCPTool) or not tool.name:
            raise ProtocolError("MCPTool 需要 name")
        self._tools[tool.qualified] = tool
        return tool

    def discover(self, *, namespace: str | None = None, query: str = "",
                 read_only: bool | None = None) -> list[dict]:
        q = str(query or "").lower()
        out = []
        for tool in self._tools.values():
            if namespace and tool.namespace != namespace:
                continue
            if read_only is not None and tool.read_only != bool(read_only):
                continue
            text = f"{tool.qualified} {tool.description}".lower()
            if q and q not in text:
                continue
            out.append(tool.as_dict())
        return sorted(out, key=lambda t: t["name"])

    def call(self, name: str, args: dict | None = None,
             handler: Callable[[dict], Any] | None = None) -> dict:
        tool = self._tools.get(str(name))
        if tool is None:
            raise ProtocolError(f"未知 MCP 工具: {name}")
        if not tool.read_only:
            raise PermissionError(f"MCP 工具 {name} 非只读，agent 拒绝调用")
        if handler is not None:
            return {"ok": True, "tool": name, "result": handler(dict(args or {}))}
        return {"ok": True, "tool": name, "result": dict(args or {})}


class MCPFederation:
    """Multiple MCP servers with lazy discovery and a read-only call gate."""

    def __init__(self):
        self.servers: dict[str, dict] = {}

    def register_server(self, name: str, *, tools: list[MCPTool],
                        description: str = "") -> dict:
        registry = MCPToolRegistry()
        for tool in tools:
            registry.register(tool)
        self.servers[name] = {"description": description, "registry": registry}
        return {"server": name, "tools": len(tools)}

    def server_discover(self, name: str) -> dict:
        server = self.servers.get(str(name))
        if server is None:
            raise ProtocolError(f"未知 MCP server: {name}")
        tools = server["registry"].discover()
        return {"server": name, "description": server["description"],
                "capabilities": {"tools": tools, "tasks": True}}

    def tool_search(self, query: str = "", *, namespace: str | None = None,
                    read_only: bool = True) -> list[dict]:
        out = []
        for name, server in sorted(self.servers.items()):
            for tool in server["registry"].discover(query=query, namespace=namespace,
                                                    read_only=read_only):
                out.append({**tool, "server": name})
        return out

    def call(self, server: str, tool: str, args: dict | None = None) -> dict:
        entry = self.servers.get(str(server))
        if entry is None:
            raise ProtocolError(f"未知 MCP server: {server}")
        return entry["registry"].call(tool, args)


# --------------------------------------------------------------------------
# SEP-2640 skill packages
# --------------------------------------------------------------------------
def _front_matter(text: str) -> tuple[dict, str]:
    raw = str(text or "")
    if not raw.startswith("---"):
        return {}, raw
    lines = raw.splitlines()
    if len(lines) < 3:
        return {}, raw
    end = None
    for idx in range(1, len(lines)):
        if lines[idx].strip() == "---":
            end = idx
            break
    if end is None:
        raise ProtocolError("SKILL.md front matter 未闭合")
    meta: dict[str, Any] = {}
    for line in lines[1:end]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        value = value.strip()
        if value.startswith("[") and value.endswith("]"):
            meta[key.strip()] = [v.strip().strip("\"'") for v in value[1:-1].split(",") if v.strip()]
        elif "," in value and key.strip().endswith("tools"):
            meta[key.strip()] = [v.strip() for v in value.split(",") if v.strip()]
        else:
            meta[key.strip()] = value.strip("\"'")
    return meta, "\n".join(lines[end + 1:]).lstrip("\n")


@dataclass
class SkillPackage:
    name: str
    description: str = ""
    version: str = "1.0.0"
    allowed_tools: list[str] = field(default_factory=list)
    body: str = ""
    root: Path | None = None
    meta: dict = field(default_factory=dict)
    digest: str = ""

    @property
    def metadata_tokens(self) -> int:
        return max(1, len(self.name) + len(self.description) // 4 + 8)

    def metadata(self) -> dict:
        """Tier 1 disclosure: small index card only."""
        return {"name": self.name, "description": self.description,
                "version": self.version, "allowed_tools": list(self.allowed_tools),
                "digest": self.digest}

    def instructions(self) -> str:
        """Tier 2 disclosure: the SKILL.md body."""
        return self.body

    def resource(self, name: str) -> bytes:
        """Tier 3 disclosure: a file under references/scripts/assets."""
        if self.root is None:
            raise ProtocolError("skill package 没有根目录，无法读取资源")
        base = Path(self.root).resolve()
        target = (base / str(name)).resolve()
        if base not in target.parents and target != base:
            raise ProtocolError(f"资源路径越界: {name}")
        if not target.is_file():
            raise ProtocolError(f"资源不存在: {name}")
        return target.read_bytes()

    def as_dict(self) -> dict:
        return {"schema": SKILL_SCHEMA, **self.metadata(), "body": self.body,
                "root": str(self.root) if self.root else ""}

    @classmethod
    def from_text(cls, text: str, *, root: str | Path | None = None) -> "SkillPackage":
        meta, body = _front_matter(text)
        name = str(meta.get("name") or "").strip()
        if not name:
            raise ProtocolError("SKILL.md 缺 name")
        allowed = meta.get("allowed-tools") or meta.get("allowed_tools") or []
        if isinstance(allowed, str):
            allowed = [v.strip() for v in allowed.split(",") if v.strip()]
        version = str(meta.get("version") or "1.0.0")
        if not re.match(r"^\d+\.\d+\.\d+$", version):
            raise ProtocolError(f"技能 version 必须是 x.y.z: {version}")
        root_path = Path(root) if root else None
        digest = hashlib.sha256(str(text).encode("utf-8")).hexdigest()
        return cls(name=name, description=str(meta.get("description") or ""),
                   version=version, allowed_tools=[str(v) for v in allowed],
                   body=body, root=root_path, meta=meta, digest=digest)

    @classmethod
    def load(cls, path: str | Path) -> "SkillPackage":
        skill_md = Path(path) / "SKILL.md"
        if not skill_md.is_file():
            raise ProtocolError(f"缺 SKILL.md: {skill_md}")
        return cls.from_text(skill_md.read_text(encoding="utf-8"), root=path)

    def validate_tools(self, available: set[str]) -> None:
        unknown = [tool for tool in self.allowed_tools if tool not in available]
        if unknown:
            raise ProtocolError(f"技能声明了不可用工具: {unknown}")


# --------------------------------------------------------------------------
# A2A
# --------------------------------------------------------------------------
@dataclass
class A2ASkill:
    id: str
    name: str
    description: str = ""
    read_only: bool = True
    tags: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"id": self.id, "name": self.name, "description": self.description,
                "readOnly": bool(self.read_only), "tags": list(self.tags)}


@dataclass
class A2AAgentCard:
    name: str
    description: str = ""
    version: str = "1.0.0"
    url: str = ""
    skills: list[A2ASkill] = field(default_factory=list)
    capabilities: dict = field(default_factory=lambda: {"streaming": False,
                                                        "pushNotifications": False})

    def as_dict(self) -> dict:
        return {"schema": A2A_CARD_SCHEMA, "name": self.name,
                "description": self.description, "version": self.version,
                "url": self.url, "capabilities": dict(self.capabilities),
                "skills": [s.as_dict() for s in self.skills]}


class A2AServer:
    """Read-only agent federation endpoint with durable task handles."""

    def __init__(self, card: A2AAgentCard, *, tasks: MCPTaskStore | None = None,
                 allow_writes: bool = False, clock=time.time):
        self.card = card
        self.tasks = tasks or MCPTaskStore(clock=clock)
        self.allow_writes = bool(allow_writes)
        self._clock = clock
        self.rejected: list[dict] = []

    def _skill(self, skill_id: str) -> A2ASkill | None:
        return next((s for s in self.card.skills if s.id == str(skill_id)), None)

    def message_send(self, request: dict) -> dict:
        if not isinstance(request, dict):
            raise ProtocolError("A2A message/send 需要对象")
        skill_id = str(request.get("skill") or request.get("skillId") or "")
        skill = self._skill(skill_id)
        if skill is None:
            task = self.tasks.create({"request": request, "skill": skill_id})
            self.tasks.update(task["id"], "failed", error=f"unknown skill {skill_id}")
            self.rejected.append({"skill": skill_id, "reason": "unknown"})
            return self.tasks.get(task["id"])
        if not skill.read_only and not self.allow_writes:
            task = self.tasks.create({"request": request, "skill": skill_id})
            self.tasks.update(task["id"], "failed", error="write skill not exposed")
            self.rejected.append({"skill": skill_id, "reason": "write-skill"})
            return self.tasks.get(task["id"])
        task = self.tasks.create({"request": request, "skill": skill_id})
        self.tasks.update(task["id"], "completed",
                          result={"ok": True, "skill": skill_id,
                                  "read_only": skill.read_only,
                                  "echo": request.get("input")})
        return self.tasks.get(task["id"])

    def tasks_get(self, task_id: str) -> dict:
        return self.tasks.get(task_id)

    def tasks_cancel(self, task_id: str, *, reason: str = "") -> dict:
        return self.tasks.cancel(task_id, reason=reason)

    def handle(self, method: str, params: dict | None = None) -> dict:
        params = dict(params or {})
        if method in ("agent/getCard", "agent/card", "message/getCard"):
            return self.card.as_dict()
        if method in ("message/send", "tasks/send"):
            return self.message_send(params)
        if method in ("tasks/get", "tasks/status"):
            return self.tasks_get(str(params.get("id") or params.get("taskId") or ""))
        if method == "tasks/cancel":
            return self.tasks_cancel(str(params.get("id") or params.get("taskId") or ""),
                                     reason=str(params.get("reason") or ""))
        raise ProtocolError(f"未知 A2A 方法: {method}")


class A2AClient:
    def __init__(self, server: A2AServer):
        self.server = server

    def card(self) -> dict:
        return self.server.card.as_dict()

    def send(self, skill: str, input: Any = None) -> dict:
        task = self.server.handle("message/send", {"skill": skill, "input": input})
        if task.get("state") in ("failed", "canceled"):
            raise ProtocolError(task.get("error") or "A2A task failed")
        return task

    def get(self, task_id: str) -> dict:
        return self.server.handle("tasks/get", {"id": task_id})

    def cancel(self, task_id: str, reason: str = "") -> dict:
        return self.server.handle("tasks/cancel", {"id": task_id, "reason": reason})
